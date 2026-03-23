import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * SSE hook for real-time scan progress updates.
 * @param {number} scanId - Scan ID to watch
 * @param {boolean} enabled - Whether to connect
 */
export function useScanStream(scanId, enabled = true) {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState({ findings: 0, tested: 0, total: 0, elapsed: 0 });
  const sourceRef = useRef(null);

  const disconnect = useCallback(() => {
    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!scanId || !enabled) return;

    const es = new EventSource(`/api/v2/scans/${scanId}/stream`);
    sourceRef.current = es;

    es.addEventListener('scan_update', (e) => {
      try {
        const d = JSON.parse(e.data);
        if (d.status) setStatus(d.status);
        setStats(prev => ({
          findings: d.findings ?? prev.findings,
          tested: d.tested_urls ?? prev.tested,
          total: d.total_urls ?? prev.total,
          elapsed: d.elapsed ?? prev.elapsed,
        }));
      } catch {}
    });

    es.addEventListener('scan_log', (e) => {
      try {
        const d = JSON.parse(e.data);
        setEvents(prev => [...prev.slice(-200), {
          message: d.message,
          level: d.level || 'info',
          time: new Date().toLocaleTimeString(),
        }]);
      } catch {}
    });

    es.addEventListener('finding', (e) => {
      try {
        const d = JSON.parse(e.data);
        setEvents(prev => [...prev.slice(-200), {
          message: `[${d.severity?.toUpperCase()}] ${d.vuln_type}: ${d.url}`,
          level: d.severity === 'critical' || d.severity === 'high' ? 'error' : 'warning',
          time: new Date().toLocaleTimeString(),
        }]);
      } catch {}
    });

    es.addEventListener('scan_complete', () => {
      setStatus('complete');
      disconnect();
    });

    es.addEventListener('scan_error', (e) => {
      setStatus('error');
      try {
        const d = JSON.parse(e.data);
        setEvents(prev => [...prev, { message: `Error: ${d.error}`, level: 'error', time: new Date().toLocaleTimeString() }]);
      } catch {}
      disconnect();
    });

    es.onerror = () => {
      // reconnect handled by browser, or scan ended
    };

    return disconnect;
  }, [scanId, enabled, disconnect]);

  return { events, status, stats, disconnect };
}
