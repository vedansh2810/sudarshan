"""AI Report Writer — LLM-generated report sections with PortSwigger enrichment.

Generates executive summaries, remediation plans, attack narratives,
and risk explanations in a professional security consultant tone.
Enriched with PortSwigger Web Security Academy references.
"""

import logging
from app.ai.llm_client import get_llm_client

logger = logging.getLogger(__name__)

# ── Prompt Templates ─────────────────────────────────────────────────

EXECUTIVE_SUMMARY_PROMPT = """You are a senior application security consultant writing a report for a client.

Scan Target: {target_url}
Scan Date: {scan_date}
Total URLs Crawled: {total_urls}
Total Vulnerabilities Found: {total_vulns}

Vulnerability Breakdown:
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
- Info: {info}

Top vulnerability types found: {top_types}

AI Reconnaissance Results:
{recon_summary}

Write a professional executive summary (3-5 paragraphs) covering:
1. Overview of the assessment scope and methodology (mention AI-powered scanning)
2. Key risk findings and their business impact
3. Technology stack insights from AI reconnaissance
4. Overall security posture assessment
5. Recommended immediate actions (prioritized)

Write in a professional, clear security consultant tone. Do not use markdown headers.
Respond with plain text only (no JSON)."""

REMEDIATION_PLAN_PROMPT = """You are a senior application security consultant creating a remediation plan.

Here are the vulnerabilities found, grouped by type:
{vuln_summary}

PORTSWIGGER ACADEMY REFERENCES:
{portswigger_refs}

Create a prioritized remediation plan. For each vulnerability type:
1. Explain the risk in business terms
2. Provide specific, actionable remediation steps with code examples
3. Estimate effort level (quick fix / moderate / significant)
4. Reference relevant PortSwigger Academy labs for learning

Respond in JSON as an array:
[
  {{
    "priority": 1,
    "vuln_type": "SQL Injection",
    "risk_level": "Critical",
    "business_impact": "...",
    "remediation_steps": ["Step 1...", "Step 2..."],
    "code_example": "Example secure code pattern",
    "effort": "moderate",
    "portswigger_labs": ["Relevant lab title 1", "Relevant lab title 2"],
    "prevention_tips": ["Ongoing prevention tip 1", "Tip 2"]
  }}
]

Order by priority (most critical first)."""

ATTACK_NARRATIVE_PROMPT = """You are a senior penetration tester documenting a finding.

VULNERABILITY:
- Type: {vuln_type}
- Severity: {severity}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Evidence: {evidence}

Write a concise but thorough attack narrative (2-3 paragraphs) suitable for a
penetration testing report. Include:
1. How the vulnerability was discovered
2. Step-by-step exploitation scenario
3. Real-world impact and risk

Write in professional security consultant tone.
Respond with plain text only (no JSON)."""

RISK_SCORE_PROMPT = """You are a cybersecurity risk analyst explaining a security score to a non-technical executive.

Security Score: {score}/100
Critical vulnerabilities: {critical}
High vulnerabilities: {high}
Medium vulnerabilities: {medium}
Low vulnerabilities: {low}
Total URLs tested: {total_urls}
Top issues: {top_types}

Write a business-friendly explanation (2-3 sentences) of what this score means,
using analogies a CEO would understand. Include urgency level.

Respond with plain text only (no JSON)."""


def generate_executive_summary(scan_data):
    """Generate an executive summary for a scan report.

    Enriched with AI reconnaissance results and technology stack insights.

    Args:
        scan_data: dict with keys: target_url, scan_date, total_urls,
                   total_vulns, critical, high, medium, low, info, top_types,
                   recon_data (optional)

    Returns:
        str — executive summary text, or a fallback message.
    """
    try:
        client = get_llm_client()
    except Exception:
        return _fallback_summary(scan_data)

    # Format reconnaissance summary
    recon_data = scan_data.get('recon_data', {})
    recon_parts = []
    if recon_data:
        if recon_data.get('server'):
            recon_parts.append(f"Server: {recon_data['server']}")
        if recon_data.get('language'):
            recon_parts.append(f"Language: {recon_data['language']}")
        if recon_data.get('framework'):
            recon_parts.append(f"Framework: {recon_data['framework']}")
        if recon_data.get('waf_detected'):
            recon_parts.append(f"WAF: {recon_data.get('waf_name', 'Detected')}")
    recon_summary = '\n'.join(recon_parts) if recon_parts else 'No AI recon data available.'

    prompt = EXECUTIVE_SUMMARY_PROMPT.format(
        target_url=scan_data.get('target_url', 'Unknown'),
        scan_date=scan_data.get('scan_date', 'Unknown'),
        total_urls=scan_data.get('total_urls', 0),
        total_vulns=scan_data.get('total_vulns', 0),
        critical=scan_data.get('critical', 0),
        high=scan_data.get('high', 0),
        medium=scan_data.get('medium', 0),
        low=scan_data.get('low', 0),
        info=scan_data.get('info', 0),
        top_types=scan_data.get('top_types', 'N/A'),
        recon_summary=recon_summary,
    )

    try:
        result = client.generate(prompt)
        if result:
            logger.info("AI executive summary generated")
            return result
    except Exception as e:
        logger.warning(f"AI executive summary failed: {e}")

    return _fallback_summary(scan_data)


def generate_remediation_plan(vulnerabilities):
    """Generate a prioritized remediation plan with PortSwigger references.

    Args:
        vulnerabilities: list of dicts with vuln_type, severity, count

    Returns:
        list of remediation items, or None if LLM unavailable.
    """
    try:
        client = get_llm_client()
    except Exception:
        return None

    # Build summary text
    lines = []
    for v in vulnerabilities:
        lines.append(f"- {v.get('vuln_type', 'Unknown')} ({v.get('severity', 'medium')}): "
                     f"{v.get('count', 1)} instance(s)")
    vuln_summary = '\n'.join(lines) if lines else 'No vulnerabilities found.'

    # Get PortSwigger references for each vulnerability type
    portswigger_refs = ''
    try:
        from app.ai.smart_engine import get_smart_engine
        engine = get_smart_engine()
        ref_parts = []
        seen_types = set()
        for v in vulnerabilities:
            vtype = v.get('vuln_type', '')
            if vtype and vtype not in seen_types:
                seen_types.add(vtype)
                labs = engine.get_portswigger_labs_for_vuln(vtype)
                if labs:
                    ref_parts.append(f"\n{vtype}:")
                    for lab in labs[:3]:
                        ref_parts.append(
                            f"  - {lab.get('title', '')} [{lab.get('difficulty', '')}]"
                        )
        portswigger_refs = '\n'.join(ref_parts) if ref_parts else 'No PortSwigger references available.'
    except Exception:
        portswigger_refs = 'PortSwigger references unavailable.'

    prompt = REMEDIATION_PLAN_PROMPT.format(
        vuln_summary=vuln_summary,
        portswigger_refs=portswigger_refs,
    )

    try:
        result = client.generate_json(prompt)
        if result and isinstance(result, list):
            logger.info(f"AI remediation plan generated ({len(result)} items)")
            return result
    except Exception as e:
        logger.warning(f"AI remediation plan failed: {e}")

    return None


def generate_attack_narrative(finding):
    """Generate a professional attack narrative for a finding.

    Args:
        finding: dict with vuln_type, severity, url/affected_url, parameter,
                 payload, evidence/description

    Returns:
        str — attack narrative text, or None if LLM unavailable.
    """
    try:
        client = get_llm_client()
    except Exception:
        return None

    prompt = ATTACK_NARRATIVE_PROMPT.format(
        vuln_type=finding.get('vuln_type', 'Unknown'),
        severity=finding.get('severity', 'medium'),
        url=finding.get('affected_url', finding.get('url', '')),
        parameter=finding.get('parameter', 'N/A'),
        payload=finding.get('payload', 'N/A'),
        evidence=finding.get('evidence', finding.get('description', 'N/A')),
    )

    try:
        result = client.generate(prompt)
        if result:
            return result
    except Exception as e:
        logger.warning(f"Attack narrative generation failed: {e}")

    return None


def generate_risk_score_explanation(score, scan_data):
    """Generate a business-friendly explanation of a security score.

    Args:
        score: int 0-100 security score
        scan_data: dict with critical, high, medium, low, total_urls, top_types

    Returns:
        str — risk explanation text, or a fallback message.
    """
    try:
        client = get_llm_client()
    except Exception:
        return _fallback_risk_explanation(score, scan_data)

    prompt = RISK_SCORE_PROMPT.format(
        score=score,
        critical=scan_data.get('critical', 0),
        high=scan_data.get('high', 0),
        medium=scan_data.get('medium', 0),
        low=scan_data.get('low', 0),
        total_urls=scan_data.get('total_urls', 0),
        top_types=scan_data.get('top_types', 'N/A'),
    )

    try:
        result = client.generate(prompt)
        if result:
            return result
    except Exception as e:
        logger.warning(f"Risk score explanation failed: {e}")

    return _fallback_risk_explanation(score, scan_data)


def _fallback_summary(scan_data):
    """Generate a basic summary when LLM is unavailable."""
    total = scan_data.get('total_vulns', 0)
    critical = scan_data.get('critical', 0)
    high = scan_data.get('high', 0)

    if total == 0:
        risk = "No vulnerabilities were identified."
    elif critical > 0 or high > 0:
        risk = (f"The assessment identified {total} vulnerabilities, "
                f"including {critical} critical and {high} high severity issues "
                f"that require immediate attention.")
    else:
        risk = (f"The assessment identified {total} vulnerabilities. "
                f"While no critical or high severity issues were found, "
                f"the identified issues should be addressed to improve "
                f"the overall security posture.")

    return (
        f"A web application security assessment was conducted against "
        f"{scan_data.get('target_url', 'the target application')} on "
        f"{scan_data.get('scan_date', 'the specified date')}. "
        f"The assessment covered {scan_data.get('total_urls', 0)} URLs "
        f"using AI-powered scanning techniques. "
        f"{risk}"
    )


def _fallback_risk_explanation(score, scan_data):
    """Generate a basic risk explanation when LLM is unavailable."""
    if score >= 90:
        return "Excellent security posture. Minor issues may exist but overall risk is low."
    elif score >= 70:
        return "Good security posture with some areas for improvement. Address identified issues promptly."
    elif score >= 50:
        return ("Moderate security concerns detected. Several vulnerabilities require attention "
                "to prevent potential exploitation.")
    elif score >= 30:
        return ("Significant security risks identified. Immediate action is required to address "
                "critical and high severity vulnerabilities.")
    else:
        return ("Critical security posture. Multiple severe vulnerabilities detected. "
                "Urgent remediation is necessary to prevent data breaches and system compromise.")
