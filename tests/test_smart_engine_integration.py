"""Integration tests for SmartEngine + analyzer + report_writer.

Run with: python -m pytest tests/test_smart_engine_integration.py -v
"""

import pytest
from unittest.mock import patch, MagicMock


class TestSmartEnginePortSwigger:
    """Test SmartEngine PortSwigger knowledge base integration."""

    def test_portswigger_context_returns_data(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        ctx = engine.get_portswigger_context('sql_injection', max_labs=2, max_payloads=3)
        # Should return non-trivial data if portswigger KB exists
        assert isinstance(ctx, str)
        assert len(ctx) > 10

    def test_portswigger_context_unknown_type(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        ctx = engine.get_portswigger_context('nonexistent_vuln_type')
        assert 'No PortSwigger context' in ctx

    def test_portswigger_labs_returns_list(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        labs = engine.get_portswigger_labs_for_vuln('xss')
        assert isinstance(labs, list)

    def test_portswigger_labs_have_titles(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        labs = engine.get_portswigger_labs_for_vuln('sql_injection')
        if labs:  # Only test if KB is loaded
            assert all('title' in lab for lab in labs)
            assert all('difficulty' in lab for lab in labs)

    def test_multiple_vuln_types_have_context(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        vuln_types = ['sql_injection', 'xss', 'command_injection', 'ssrf', 'xxe']
        for vt in vuln_types:
            ctx = engine.get_portswigger_context(vt, max_labs=1)
            assert isinstance(ctx, str)


class TestSmartEngineMLPrediction:
    """Test SmartEngine ML classifier integration."""

    SAMPLE_FEATURES = {
        'payload_length': 20,
        'payload_special_chars': 5,
        'payload_has_script_tag': 0,
        'payload_has_sql_keyword': 1,
        'payload_has_encoding': 0,
        'baseline_status': 200,
        'baseline_length': 5000,
        'test_status': 500,
        'test_length': 1200,
        'response_time': 0.5,
        'status_changed': 1,
        'length_diff': 3800,
        'length_ratio': 0.24,
        'error_count': 2,
        'has_db_error': 1,
        'payload_reflected': 0,
    }

    def test_ml_predict_returns_tuple(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        result = engine.ml_predict(self.SAMPLE_FEATURES)
        assert isinstance(result, tuple)
        assert len(result) == 2
        is_tp, confidence = result
        assert isinstance(is_tp, bool)
        assert isinstance(confidence, float)

    def test_ml_predict_empty_features_graceful(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        # Should not crash with empty features
        result = engine.ml_predict({})
        assert isinstance(result, tuple)

    def test_verify_finding_returns_triple(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        verdict, confidence, reasoning = engine.verify_finding(
            {'vuln_type': 'sql_injection', 'url': 'http://test.com', 'parameter': 'id',
             'payload': "' OR 1=1--", 'evidence': 'SQL error'},
            self.SAMPLE_FEATURES,
        )
        assert verdict in ('true_positive', 'false_positive', 'needs_manual_review')
        assert 0 <= confidence <= 1.0
        assert isinstance(reasoning, str)


class TestSmartEngineRemediation:
    """Test SmartEngine remediation enrichment."""

    def test_enrich_remediation_adds_portswigger_refs(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        original = 'Use parameterized queries.'
        enriched = engine.enrich_remediation('sql_injection', original)
        assert isinstance(enriched, str)
        assert len(enriched) >= len(original)
        # Should contain original text
        assert original.rstrip() in enriched

    def test_enrich_remediation_unknown_type_passes_through(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        original = 'Fix the issue.'
        enriched = engine.enrich_remediation('unknown_vuln', original)
        assert enriched == original


class TestSmartEngineSingleton:
    """Test SmartEngine singleton behavior."""

    def test_get_smart_engine_returns_same_instance(self):
        from app.ai.smart_engine import get_smart_engine
        e1 = get_smart_engine()
        e2 = get_smart_engine()
        assert e1 is e2

    def test_smart_engine_thread_safe(self):
        import threading
        from app.ai.smart_engine import get_smart_engine
        results = []

        def get_engine():
            results.append(get_smart_engine())

        threads = [threading.Thread(target=get_engine) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        assert all(r is results[0] for r in results)


class TestSmartEngineLLMGraceful:
    """Test that SmartEngine methods fail gracefully when LLM is unavailable."""

    def test_reconnaissance_without_llm(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        # With no LLM configured, should return None
        result = engine.reconnaissance('http://example.com', MagicMock(
            headers={}, text='<html></html>', status_code=200
        ))
        # May return None or a dict depending on LLM availability
        assert result is None or isinstance(result, dict)

    def test_generate_smart_payloads_without_llm(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        with patch.object(engine, '_get_llm', return_value=None):
            result = engine.generate_smart_payloads('sql_injection')
            assert result == []

    def test_generate_waf_bypass_without_llm(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        with patch.object(engine, '_get_llm', return_value=None):
            result = engine.generate_waf_bypass("' OR 1=1--", 'sql_injection')
            assert result == []

    def test_attack_narrative_without_llm(self):
        from app.ai.smart_engine import SmartEngine
        engine = SmartEngine()
        with patch.object(engine, '_get_llm', return_value=None):
            result = engine.generate_attack_narrative({'vuln_type': 'xss'})
            assert result is None


class TestBaseScanner:
    """Test BaseScanner's new ML/AI verification methods."""

    def test_ml_verify_finding_returns_tuple(self):
        from app.scanner.vulnerabilities.base import BaseScanner
        scanner = BaseScanner()
        result = scanner._ml_verify_finding(None, None, "' OR 1=1")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_ai_verify_finding_returns_triple(self):
        from app.scanner.vulnerabilities.base import BaseScanner
        scanner = BaseScanner()
        result = scanner._ai_verify_finding(
            {'vuln_type': 'sql_injection'},
            None, None, "' OR 1=1"
        )
        assert isinstance(result, tuple)
        assert len(result) == 3
        verdict, confidence, reasoning = result
        assert isinstance(verdict, str)
        assert isinstance(confidence, float)
        assert isinstance(reasoning, str)


class TestAnalyzerImports:
    """Test that enhanced analyzer functions are importable."""

    def test_analyze_vulnerability_importable(self):
        from app.ai.analyzer import analyze_vulnerability
        assert callable(analyze_vulnerability)

    def test_classify_false_positive_importable(self):
        from app.ai.analyzer import classify_false_positive
        assert callable(classify_false_positive)

    def test_analyze_with_portswigger_importable(self):
        from app.ai.analyzer import analyze_with_portswigger
        assert callable(analyze_with_portswigger)


class TestReportWriterImports:
    """Test that enhanced report writer functions are importable."""

    def test_executive_summary_importable(self):
        from app.ai.report_writer import generate_executive_summary
        assert callable(generate_executive_summary)

    def test_remediation_plan_importable(self):
        from app.ai.report_writer import generate_remediation_plan
        assert callable(generate_remediation_plan)

    def test_attack_narrative_importable(self):
        from app.ai.report_writer import generate_attack_narrative
        assert callable(generate_attack_narrative)

    def test_risk_score_explanation_importable(self):
        from app.ai.report_writer import generate_risk_score_explanation
        assert callable(generate_risk_score_explanation)

    def test_fallback_summary_works(self):
        from app.ai.report_writer import _fallback_summary
        result = _fallback_summary({
            'target_url': 'http://test.com',
            'scan_date': '2026-01-01',
            'total_urls': 10,
            'total_vulns': 3,
            'critical': 1,
            'high': 1,
        })
        assert isinstance(result, str)
        assert 'http://test.com' in result
        assert 'AI-powered' in result

    def test_fallback_risk_explanation_works(self):
        from app.ai.report_writer import _fallback_risk_explanation
        for score in [95, 75, 55, 35, 15]:
            result = _fallback_risk_explanation(score, {})
            assert isinstance(result, str)
            assert len(result) > 20
