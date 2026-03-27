"""
Tests for stateless ScanManager refactoring.
Verifies Redis-backed state management, event history, and graceful fallback.
"""

import pytest
import time
import json
from unittest.mock import patch, MagicMock, PropertyMock
from collections import defaultdict


class TestScanManagerStatelessStatus:
    """Test that get_status() reads from Redis first."""

    def _make_manager(self):
        from app.scanner.scan_manager import ScanManager
        mgr = ScanManager()
        # Reset singleton for testing
        mgr.active_scans = {}
        mgr.sse_queues = {}
        mgr.event_history = defaultdict(list)
        mgr._redis_checked = False
        mgr._redis = None
        mgr._use_celery = False
        return mgr

    def test_get_status_reads_redis_hash(self):
        """get_status should read from Redis hash when available."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        start_time = str(time.time())
        mock_redis.hgetall.return_value = {
            b'status': b'running',
            b'tested_urls': b'5',
            b'total_urls': b'20',
            b'findings': b'3',
            b'start_time': start_time.encode(),
        }
        mgr._redis = mock_redis
        mgr._redis_checked = True
        mgr._use_celery = True

        status = mgr.get_status(42)

        assert status is not None
        assert status['status'] == 'running'
        assert status['tested_urls'] == 5
        assert status['total_urls'] == 20
        assert status['findings'] == 3
        mock_redis.hgetall.assert_called_once_with('scan:42:state')

    def test_get_status_falls_back_to_in_memory(self):
        """When Redis has no data, fall back to in-memory ctx."""
        mgr = self._make_manager()
        mgr._redis = None
        mgr._redis_checked = True
        mgr._use_celery = False

        # Simulate threading context
        import threading
        mgr.active_scans[99] = {
            'status': 'running',
            'tested_urls': 10,
            'total_urls': 50,
            'findings': [{'name': 'test'}],
            'start_time': time.time(),
            'mode': 'threading',
        }

        status = mgr.get_status(99)
        assert status is not None
        assert status['status'] == 'running'
        assert status['tested_urls'] == 10
        assert status['findings'] == 1  # len(findings)

    def test_get_status_falls_back_to_db(self):
        """When no Redis and no in-memory ctx, fall back to DB."""
        mgr = self._make_manager()
        mgr._redis = None
        mgr._redis_checked = True

        with patch('app.scanner.scan_manager.Scan') as mock_scan:
            mock_scan.get_by_id.return_value = {
                'status': 'completed',
                'tested_urls': 100,
                'total_urls': 100,
                'vuln_count': 5,
                'duration': 60
            }
            status = mgr.get_status(77)
            assert status['status'] == 'completed'
            assert status['findings'] == 5


class TestScanManagerEventHistory:
    """Test Redis-backed event history."""

    def _make_manager(self):
        from app.scanner.scan_manager import ScanManager
        mgr = ScanManager()
        mgr.active_scans = {}
        mgr.sse_queues = {}
        mgr.event_history = defaultdict(list)
        mgr._redis_checked = False
        mgr._redis = None
        mgr._use_celery = False
        return mgr

    def test_get_event_history_reads_redis(self):
        """get_event_history should read from Redis list when available."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        mock_redis.lrange.return_value = [
            b'data: {"type": "log", "data": "test"}\n\n',
            b'data: {"type": "progress", "data": {}}\n\n',
        ]
        mgr._redis = mock_redis
        mgr._redis_checked = True
        mgr._use_celery = True

        events = mgr.get_event_history(42)
        assert len(events) == 2
        mock_redis.lrange.assert_called_once_with('scan:42:event_history', 0, -1)

    def test_get_event_history_falls_back_to_in_memory(self):
        """When Redis is unavailable, fall back to in-memory history."""
        mgr = self._make_manager()
        mgr._redis = None
        mgr._redis_checked = True
        mgr.event_history[42] = ['data: {"type": "log"}\n\n']

        events = mgr.get_event_history(42)
        assert len(events) == 1


class TestScanManagerEmit:
    """Test _emit stores to Redis when available."""

    def _make_manager(self):
        from app.scanner.scan_manager import ScanManager
        mgr = ScanManager()
        mgr.active_scans = {}
        mgr.sse_queues = {}
        mgr.event_history = defaultdict(list)
        mgr._redis_checked = True
        mgr._redis = None
        mgr._use_celery = False
        return mgr

    def test_emit_stores_in_redis_list(self):
        """_emit should rpush to Redis event_history list."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        mgr._redis = mock_redis
        mgr._use_celery = True

        with patch('app.scanner.scan_manager.Scan'):
            mgr._emit(42, 'log', 'test message', 'info')

        # Verify Redis publish was called
        mock_redis.publish.assert_called_once()
        # Verify Redis rpush for event history
        mock_redis.rpush.assert_called_once()
        call_args = mock_redis.rpush.call_args
        assert 'scan:42:event_history' in call_args[0]
        # Verify TTL was set
        mock_redis.expire.assert_called_once_with('scan:42:event_history', 3600)

    def test_emit_falls_back_to_in_memory(self):
        """When no Redis, _emit stores in in-memory event_history."""
        mgr = self._make_manager()
        mgr._redis = None

        with patch('app.scanner.scan_manager.Scan'):
            mgr._emit(42, 'log', 'test message', 'info')

        assert len(mgr.event_history[42]) == 1
        assert 'test message' in mgr.event_history[42][0]


class TestScanManagerControlSignals:
    """Test Redis-backed pause/resume/stop."""

    def _make_manager(self):
        from app.scanner.scan_manager import ScanManager
        mgr = ScanManager()
        mgr.active_scans = {}
        mgr.sse_queues = {}
        mgr.event_history = defaultdict(list)
        mgr._redis_checked = True
        mgr._redis = None
        mgr._use_celery = False
        return mgr

    def test_pause_sets_redis_control(self):
        """pause_scan should set scan:{id}:control = 'paused' in Redis."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        mgr._redis = mock_redis
        mgr._use_celery = True

        with patch('app.scanner.scan_manager.Scan'):
            result = mgr.pause_scan(42)

        assert result is True
        mock_redis.set.assert_called_once_with('scan:42:control', 'paused')

    def test_resume_deletes_redis_control(self):
        """resume_scan should delete scan:{id}:control from Redis."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        mgr._redis = mock_redis
        mgr._use_celery = True

        with patch('app.scanner.scan_manager.Scan'):
            result = mgr.resume_scan(42)

        assert result is True
        mock_redis.delete.assert_called_once_with('scan:42:control')

    def test_stop_sets_redis_control_stopped(self):
        """stop_scan should set control to 'stopped' and try to revoke Celery task."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        mock_redis.get.return_value = None  # No task_id
        mgr._redis = mock_redis
        mgr._use_celery = True

        with patch('app.scanner.scan_manager.Scan'):
            result = mgr.stop_scan(42)

        assert result is True
        mock_redis.set.assert_any_call('scan:42:control', 'stopped')


class TestScanManagerStartScan:
    """Test that start_scan stores state in Redis."""

    def _make_manager(self):
        from app.scanner.scan_manager import ScanManager
        mgr = ScanManager()
        mgr.active_scans = {}
        mgr.sse_queues = {}
        mgr.event_history = defaultdict(list)
        mgr._redis_checked = True
        mgr._redis = None
        mgr._use_celery = False
        return mgr

    def test_celery_start_stores_in_redis_hash(self):
        """In Celery mode, start_scan should store state in Redis hash, not in-memory."""
        mgr = self._make_manager()
        mock_redis = MagicMock()
        mgr._redis = mock_redis
        mgr._use_celery = True

        with patch('app.scanner.scan_manager.ScanManager._get_redis', return_value=mock_redis):
            with patch('app.tasks.run_scan_task') as mock_task:
                mock_task.delay = MagicMock()
                result = mgr.start_scan(1, 'http://test.com', 'active', 'balanced', 3)

        assert result is True
        # Should NOT store in self.active_scans for Celery mode
        assert 1 not in mgr.active_scans
        # Should store in Redis hash
        mock_redis.hset.assert_called_once()
        call_kwargs = mock_redis.hset.call_args
        assert 'scan:1:state' in str(call_kwargs)
