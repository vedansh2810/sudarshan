"""AI Vulnerability Analyzer — LLM-powered analysis and false-positive classification.

Uses the LLMClient to analyze discovered vulnerabilities, providing:
- Detailed explanation and real-world impact
- Custom remediation advice
- False-positive classification with reasoning
- PortSwigger-enriched context and lab references
"""

import logging
from app.ai.llm_client import get_llm_client

logger = logging.getLogger(__name__)

# ── Prompt Templates ─────────────────────────────────────────────────

VULN_ANALYSIS_PROMPT = """You are a senior application security engineer. Analyze this vulnerability finding from a web vulnerability scanner.

Vulnerability Type: {vuln_type}
Severity: {severity}
Affected URL: {url}
Parameter: {parameter}
Payload Used: {payload}
Evidence: {evidence}

{portswigger_section}

Respond in JSON with these keys:
{{
  "explanation": "Clear 2-3 sentence explanation of what this vulnerability is and why it matters",
  "impact": "Specific real-world impact if exploited (data breach, account takeover, etc.)",
  "remediation": "Concrete code-level fix recommendation (be specific to the detected technology if possible)",
  "confidence": "high/medium/low — your confidence this is a true positive",
  "owasp_category": "The OWASP Top 10 2021 category (e.g., A03:2021 Injection)",
  "attack_vector": "Brief description of how an attacker would exploit this",
  "related_cwe": "The relevant CWE ID (e.g., CWE-89)"
}}"""

FALSE_POSITIVE_PROMPT = """You are a senior application security engineer reviewing scanner findings for false positives.

Vulnerability Type: {vuln_type}
Affected URL: {url}
Parameter: {parameter}
Payload: {payload}
HTTP Status Code: {status_code}
Response Length: {response_length}
Evidence from Scanner: {evidence}

{ml_section}

Response Snippet (first 500 chars):
{response_snippet}

Based on the evidence, classify this finding:

Respond in JSON:
{{
  "classification": "true_positive" or "false_positive" or "uncertain",
  "reasoning": "Brief explanation of why you classified it this way",
  "confidence": 0.0-1.0
}}"""

PORTSWIGGER_ANALYSIS_PROMPT = """You are a senior application security consultant. Analyze this vulnerability using your knowledge of PortSwigger Web Security Academy.

VULNERABILITY DETAILS:
- Type: {vuln_type}
- Severity: {severity}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Evidence: {evidence}

RELEVANT PORTSWIGGER LABS AND TECHNIQUES:
{portswigger_context}

Provide a comprehensive analysis that references the relevant PortSwigger lab techniques.

Respond in JSON:
{{
  "explanation": "Detailed explanation referencing PortSwigger techniques",
  "impact": "Specific real-world impact",
  "exploitation_difficulty": "easy/medium/hard",
  "remediation": {{
    "summary": "Brief remediation overview",
    "steps": ["Step 1...", "Step 2..."],
    "code_example": "Example secure code pattern"
  }},
  "portswigger_references": [
    {{
      "lab_title": "Relevant lab title",
      "technique": "Technique used",
      "relevance": "How this lab relates to the finding"
    }}
  ],
  "additional_tests": ["Suggestion 1 for deeper testing...", "Suggestion 2..."],
  "confidence": "high/medium/low"
}}"""


def analyze_vulnerability(vuln_data):
    """Analyze a vulnerability using the LLM with optional PortSwigger enrichment.

    Args:
        vuln_data: dict with keys: vuln_type, severity, url, parameter,
                   payload, evidence

    Returns:
        dict with keys: explanation, impact, remediation, confidence,
        owasp_category. Returns None if LLM is unavailable.
    """
    try:
        client = get_llm_client()
    except Exception:
        logger.debug("LLM client unavailable for analysis")
        return None

    # Try to get PortSwigger context
    portswigger_section = ''
    try:
        from app.ai.smart_engine import get_smart_engine
        engine = get_smart_engine()
        ps_ctx = engine.get_portswigger_context(
            vuln_data.get('vuln_type', ''), max_labs=2, max_payloads=3
        )
        if ps_ctx and 'No PortSwigger' not in ps_ctx:
            portswigger_section = f'PORTSWIGGER REFERENCE:\n{ps_ctx}'
    except Exception:
        pass

    prompt = VULN_ANALYSIS_PROMPT.format(
        vuln_type=vuln_data.get('vuln_type', 'Unknown'),
        severity=vuln_data.get('severity', 'medium'),
        url=vuln_data.get('url', ''),
        parameter=vuln_data.get('parameter', 'N/A'),
        payload=vuln_data.get('payload', 'N/A'),
        evidence=vuln_data.get('evidence', 'N/A'),
        portswigger_section=portswigger_section,
    )

    try:
        result = client.generate_json(prompt)
        if result and isinstance(result, dict):
            logger.info(f"AI analysis complete for {vuln_data.get('vuln_type')} on {vuln_data.get('url', '')[:60]}")
            return result
    except Exception as e:
        logger.warning(f"AI analysis failed: {e}")

    return None


def classify_false_positive(vuln_data, response_data=None):
    """Use LLM to classify whether a finding is a false positive.

    Enriches the prompt with ML classifier results when available.

    Args:
        vuln_data: dict with keys: vuln_type, url, parameter, payload, evidence
        response_data: optional dict with: status_code, length, snippet

    Returns:
        dict with keys: classification, reasoning, confidence.
        Returns None if LLM unavailable.
    """
    try:
        client = get_llm_client()
    except Exception:
        return None

    # Try to get ML classifier input
    ml_section = ''
    try:
        from app.ai.smart_engine import get_smart_engine
        engine = get_smart_engine()
        # Build minimal features for ML prediction if response data available
        if response_data:
            features = {
                'payload_length': len(vuln_data.get('payload', '') or ''),
                'payload_special_chars': sum(
                    1 for c in (vuln_data.get('payload', '') or '')
                    if c in "'\"<>;&|`$(){}[]\\"
                ),
                'payload_has_script_tag': 1 if '<script' in (vuln_data.get('payload', '') or '').lower() else 0,
                'payload_has_sql_keyword': 1 if any(
                    kw in (vuln_data.get('payload', '') or '').upper()
                    for kw in ('SELECT', 'UNION', 'DROP', 'SLEEP')
                ) else 0,
                'payload_has_encoding': 1 if '%' in (vuln_data.get('payload', '') or '') else 0,
                'baseline_status': 200,
                'baseline_length': response_data.get('length', 0),
                'test_status': response_data.get('status_code', 200),
                'test_length': response_data.get('length', 0),
                'response_time': 0,
                'status_changed': 0,
                'length_diff': 0,
                'length_ratio': 1.0,
                'error_count': 0,
                'has_db_error': 0,
                'payload_reflected': 0,
            }
            ml_is_tp, ml_conf = engine.ml_predict(features)
            ml_section = (
                f'ML CLASSIFIER PREDICTION:\n'
                f'  - Prediction: {"True Positive" if ml_is_tp else "False Positive"}\n'
                f'  - Confidence: {ml_conf:.1f}%\n'
            )
    except Exception:
        pass

    rd = response_data or {}
    prompt = FALSE_POSITIVE_PROMPT.format(
        vuln_type=vuln_data.get('vuln_type', 'Unknown'),
        url=vuln_data.get('url', ''),
        parameter=vuln_data.get('parameter', 'N/A'),
        payload=vuln_data.get('payload', 'N/A'),
        status_code=rd.get('status_code', 'N/A'),
        response_length=rd.get('length', 'N/A'),
        evidence=vuln_data.get('evidence', 'N/A'),
        ml_section=ml_section,
        response_snippet=rd.get('snippet', 'N/A'),
    )

    try:
        result = client.generate_json(prompt)
        if result and isinstance(result, dict):
            return result
    except Exception as e:
        logger.warning(f"AI false-positive classification failed: {e}")

    return None


def analyze_with_portswigger(vuln_data):
    """Deep analysis of a vulnerability with heavy PortSwigger context.

    Uses PortSwigger lab data to provide detailed exploitation techniques,
    remediation steps with code examples, and references to relevant labs.

    Args:
        vuln_data: dict with keys: vuln_type, severity, url, parameter,
                   payload, evidence

    Returns:
        dict with comprehensive analysis including portswigger_references,
        remediation with code_example, additional_tests.
        Returns None if LLM unavailable.
    """
    try:
        client = get_llm_client()
    except Exception:
        return None

    # Get PortSwigger context
    portswigger_context = 'No PortSwigger data available.'
    try:
        from app.ai.smart_engine import get_smart_engine
        engine = get_smart_engine()
        portswigger_context = engine.get_portswigger_context(
            vuln_data.get('vuln_type', ''), max_labs=5, max_payloads=8
        )
    except Exception:
        pass

    prompt = PORTSWIGGER_ANALYSIS_PROMPT.format(
        vuln_type=vuln_data.get('vuln_type', 'Unknown'),
        severity=vuln_data.get('severity', 'medium'),
        url=vuln_data.get('url', ''),
        parameter=vuln_data.get('parameter', 'N/A'),
        payload=vuln_data.get('payload', 'N/A'),
        evidence=vuln_data.get('evidence', 'N/A'),
        portswigger_context=portswigger_context,
    )

    try:
        result = client.generate_json(prompt)
        if result and isinstance(result, dict):
            # Enrich with actual PortSwigger lab URLs
            try:
                labs = engine.get_portswigger_labs_for_vuln(vuln_data.get('vuln_type', ''))
                result['portswigger_lab_urls'] = labs
            except Exception:
                pass
            logger.info(f"PortSwigger-enriched analysis complete for {vuln_data.get('vuln_type')}")
            return result
    except Exception as e:
        logger.warning(f"PortSwigger analysis failed: {e}")

    return None
