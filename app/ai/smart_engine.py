"""Smart AI Engine — Unified intelligence layer for Sudarshan scanner.

Integrates three systems:
  1. LLM (Groq / Llama 3.3 70B) — reasoning, payload generation, analysis
  2. PortSwigger knowledge base — 269 labs, 2197 payloads, 31 categories
  3. ML classifier (RF + GB ensemble) — false-positive prediction

All methods are non-blocking with graceful fallbacks — scanning NEVER stops
if LLM or ML is unavailable.

Usage:
    from app.ai.smart_engine import get_smart_engine
    engine = get_smart_engine()
    payloads = engine.generate_smart_payloads('sql_injection', target_ctx)
    verified, confidence, reasoning = engine.verify_finding(vuln_data, features)
"""

import json
import os
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


# ── Prompt Templates ─────────────────────────────────────────────────

PAYLOAD_GENERATION_PROMPT = """You are an expert penetration tester. Generate targeted payloads for a {vuln_type} vulnerability scan.

TARGET CONTEXT:
- Technology stack: {tech_stack}
- Target URL pattern: {url_pattern}
- WAF detected: {waf_detected}
- Previous findings on this target: {prev_findings}

PORTSWIGGER KNOWLEDGE (relevant lab solutions):
{portswigger_context}

Generate {num_payloads} creative, targeted payloads that:
1. Are adapted to the detected technology stack
2. Use techniques from the PortSwigger labs above
3. Include WAF bypass variants if a WAF is detected
4. Progress from simple to complex

Respond in JSON:
{{
  "payloads": [
    {{
      "payload": "the actual payload string",
      "technique": "brief technique name",
      "reasoning": "why this payload is likely to work against this target"
    }}
  ]
}}"""

WAF_BYPASS_PROMPT = """You are a WAF bypass expert. The following payload was blocked by a WAF:

ORIGINAL PAYLOAD: {payload}
VULNERABILITY TYPE: {vuln_type}
WAF INDICATORS: {waf_indicators}
BLOCKED RESPONSE: {blocked_response}

PORTSWIGGER WAF BYPASS TECHNIQUES:
{portswigger_bypass_context}

Generate {num_variants} alternative payloads that achieve the same goal but bypass the WAF.
Use techniques like encoding, case alternation, comment insertion, protocol-level tricks.

Respond in JSON:
{{
  "bypasses": [
    {{
      "payload": "bypass payload string",
      "technique": "bypass technique used",
      "reasoning": "why this might bypass the WAF"
    }}
  ]
}}"""

RECON_PROMPT = """You are a web application security expert performing reconnaissance.

Analyze this HTTP response to identify the target's technology stack:

URL: {url}
HTTP Status: {status_code}
Response Headers:
{headers}

Response Body (first 2000 chars):
{body_preview}

Respond in JSON:
{{
  "server": "web server software (e.g., Apache, Nginx, IIS)",
  "language": "backend language (e.g., PHP, Python, Java, Node.js, ASP.NET)",
  "framework": "framework if detectable (e.g., Django, Laravel, Express, Spring)",
  "cms": "CMS if detectable (e.g., WordPress, Drupal, Joomla) or null",
  "waf_detected": true/false,
  "waf_name": "WAF name if detected or null",
  "interesting_headers": ["list of security-relevant headers found"],
  "technologies": ["other detected technologies"],
  "scan_recommendations": ["specific scan recommendations based on detected stack"]
}}"""

ATTACK_NARRATIVE_PROMPT = """You are a senior penetration tester writing a detailed finding report.

VULNERABILITY DETAILS:
- Type: {vuln_type}
- Severity: {severity}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Evidence: {evidence}

PORTSWIGGER REFERENCE:
{portswigger_context}

Write a professional attack narrative that explains:
1. What the vulnerability is and how it was discovered
2. Step-by-step exploitation walkthrough (as if teaching a junior tester)
3. Real-world impact and attack scenarios
4. Specific remediation steps with code examples

Respond in JSON:
{{
  "narrative": "The detailed attack narrative (2-4 paragraphs)",
  "exploitation_steps": ["Step 1: ...", "Step 2: ...", ...],
  "impact_scenarios": ["Scenario 1: ...", "Scenario 2: ..."],
  "remediation": {{
    "description": "Overview of the fix",
    "code_example": "Specific code fix example",
    "prevention_checklist": ["Check 1", "Check 2", ...]
  }},
  "portswigger_labs": ["Relevant lab titles and URLs"],
  "cwe_id": "CWE-XX",
  "owasp_category": "A0X:2021 Category Name"
}}"""

FINDING_VERIFICATION_PROMPT = """You are a senior application security engineer reviewing a scanner finding.

FINDING:
- Vulnerability Type: {vuln_type}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Evidence: {evidence}

ML CLASSIFIER PREDICTION:
- Is True Positive: {ml_is_tp}
- ML Confidence: {ml_confidence}%

RESPONSE DETAILS:
- Status Code: {status_code}
- Response Length: {response_length}
- Response Time: {response_time}s
- Payload Reflected: {payload_reflected}

Response Snippet (first 500 chars):
{response_snippet}

Considering the ML classifier prediction and the raw evidence, provide your assessment.

Respond in JSON:
{{
  "verdict": "true_positive" or "false_positive" or "needs_manual_review",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of your assessment",
  "agrees_with_ml": true/false
}}"""


class SmartEngine:
    """Unified AI engine combining LLM + PortSwigger + ML.

    Thread-safe singleton. All methods fail gracefully — never blocks scanning.
    """

    def __init__(self):
        self._portswigger_kb = None
        self._ml_classifier = None
        self._ml_loaded = False
        self._kb_loaded = False
        self._lock = threading.Lock()

    # ─── PortSwigger Knowledge Base ──────────────────────────────────

    def _load_knowledge_base(self):
        """Lazy-load the PortSwigger knowledge base."""
        if self._kb_loaded:
            return
        with self._lock:
            if self._kb_loaded:
                return
            try:
                kb_path = Path('data/portswigger_knowledge/portswigger_knowledge.json')
                if kb_path.exists():
                    with open(kb_path, 'r', encoding='utf-8') as f:
                        self._portswigger_kb = json.load(f)
                    lab_count = len(self._portswigger_kb.get('labs', []))
                    logger.info(f'SmartEngine: PortSwigger KB loaded ({lab_count} labs)')
                else:
                    logger.warning('SmartEngine: PortSwigger KB not found')
                    self._portswigger_kb = {'labs': [], 'categories': {}, 'payloads': {}}
            except Exception as e:
                logger.error(f'SmartEngine: Failed to load KB: {e}')
                self._portswigger_kb = {'labs': [], 'categories': {}, 'payloads': {}}
            self._kb_loaded = True

    def get_portswigger_context(self, vuln_type: str, max_labs: int = 5,
                                 max_payloads: int = 10) -> str:
        """Get relevant PortSwigger context for a vulnerability type.

        Searches the knowledge base for labs matching the vuln type and returns
        a formatted string with lab descriptions, solutions, and payloads.

        Args:
            vuln_type: Scanner vuln type (e.g., 'sql_injection', 'xss')
            max_labs: Maximum number of labs to include
            max_payloads: Maximum number of example payloads

        Returns:
            Formatted context string for LLM prompts
        """
        self._load_knowledge_base()
        if not self._portswigger_kb:
            return 'No PortSwigger data available.'

        # Map scanner vuln_type to PortSwigger category slugs
        TYPE_TO_CATEGORIES = {
            'sql_injection': ['sql-injection'],
            'xss': ['cross-site-scripting', 'dom-based-vulnerabilities'],
            'csrf': ['cross-site-request-forgery-csrf'],
            'command_injection': ['os-command-injection'],
            'directory_traversal': ['path-traversal'],
            'xxe': ['xml-external-entity-xxe-injection'],
            'ssrf': ['server-side-request-forgery-ssrf'],
            'clickjacking': ['clickjacking'],
            'cors': ['cross-origin-resource-sharing-cors'],
            'ssti': ['server-side-template-injection'],
            'broken_auth': ['authentication'],
            'jwt_attacks': ['jwt'],
            'open_redirect': ['authentication'],  # often discussed together
            'idor': ['access-control-vulnerabilities'],
        }

        categories = TYPE_TO_CATEGORIES.get(vuln_type, [])
        if not categories:
            return f'No PortSwigger context for vulnerability type: {vuln_type}'

        # Find relevant labs
        labs = self._portswigger_kb.get('labs', [])
        relevant_labs = [
            lab for lab in labs
            if lab.get('category', '') in categories
        ]

        # Sort by difficulty (apprentice first, then practitioner, then expert)
        difficulty_order = {'apprentice': 0, 'practitioner': 1, 'expert': 2, 'unknown': 3}
        relevant_labs.sort(key=lambda l: difficulty_order.get(l.get('difficulty', 'unknown'), 3))

        # Build context string
        parts = []
        for lab in relevant_labs[:max_labs]:
            parts.append(f"Lab: {lab.get('title', 'Unknown')}")
            parts.append(f"  Difficulty: {lab.get('difficulty', 'unknown')}")
            if lab.get('description'):
                desc = lab['description'][:300]
                parts.append(f"  Description: {desc}")
            if lab.get('solution_steps'):
                steps = lab['solution_steps'][:5]
                parts.append(f"  Solution steps:")
                for i, step in enumerate(steps, 1):
                    parts.append(f"    {i}. {step[:150]}")
            if lab.get('payloads'):
                parts.append(f"  Payloads:")
                for p in lab['payloads'][:3]:
                    parts.append(f"    - {p.get('code', '')[:200]}")
            parts.append('')

        # Add category-level payloads
        payloads_data = self._portswigger_kb.get('payloads', {})
        for cat in categories:
            cat_payloads = payloads_data.get(cat, [])
            if cat_payloads:
                parts.append(f"Additional payloads from {cat}:")
                for p in cat_payloads[:max_payloads]:
                    parts.append(f"  - {p.get('payload', '')[:200]}")
                    if p.get('context'):
                        parts.append(f"    Context: {p['context'][:100]}")

        return '\n'.join(parts) if parts else 'No relevant PortSwigger data found.'

    def get_portswigger_labs_for_vuln(self, vuln_type: str) -> List[Dict]:
        """Get PortSwigger lab references for a vulnerability type.

        Returns list of {title, url, difficulty, description} dicts.
        """
        self._load_knowledge_base()
        if not self._portswigger_kb:
            return []

        TYPE_TO_CATEGORIES = {
            'sql_injection': ['sql-injection'],
            'xss': ['cross-site-scripting', 'dom-based-vulnerabilities'],
            'csrf': ['cross-site-request-forgery-csrf'],
            'command_injection': ['os-command-injection'],
            'directory_traversal': ['path-traversal'],
            'xxe': ['xml-external-entity-xxe-injection'],
            'ssrf': ['server-side-request-forgery-ssrf'],
            'ssti': ['server-side-template-injection'],
            'clickjacking': ['clickjacking'],
            'cors': ['cross-origin-resource-sharing-cors'],
            'broken_auth': ['authentication'],
            'jwt_attacks': ['jwt'],
            'idor': ['access-control-vulnerabilities'],
        }

        categories = TYPE_TO_CATEGORIES.get(vuln_type, [])
        labs = self._portswigger_kb.get('labs', [])

        return [
            {
                'title': lab.get('title', ''),
                'url': lab.get('url', ''),
                'difficulty': lab.get('difficulty', 'unknown'),
                'description': (lab.get('description', '') or '')[:200],
            }
            for lab in labs
            if lab.get('category', '') in categories
        ][:10]

    # ─── ML Classifier ───────────────────────────────────────────────

    def _load_ml_classifier(self):
        """Lazy-load the trained ML false-positive classifier."""
        if self._ml_loaded:
            return
        with self._lock:
            if self._ml_loaded:
                return
            try:
                from app.ml.false_positive_classifier import FalsePositiveClassifier
                classifier = FalsePositiveClassifier()

                # Find latest model
                model_dir = Path('data/ml_models')
                if model_dir.exists():
                    model_files = sorted(model_dir.glob('fp_classifier_v*.joblib'), reverse=True)
                    if model_files:
                        if classifier.load(str(model_files[0])):
                            self._ml_classifier = classifier
                            logger.info(f'SmartEngine: ML classifier loaded ({model_files[0].name})')
                        else:
                            logger.warning('SmartEngine: ML model file found but failed to load')
                    else:
                        logger.info('SmartEngine: No trained ML model found — ML verification disabled')
                else:
                    logger.info('SmartEngine: No ML models directory — ML verification disabled')
            except Exception as e:
                logger.warning(f'SmartEngine: ML classifier unavailable: {e}')
            self._ml_loaded = True

    def ml_predict(self, features: Dict) -> Tuple[bool, float]:
        """Run ML false-positive classifier prediction.

        Args:
            features: Dict with 16 feature values matching FEATURE_NAMES

        Returns:
            (is_true_positive, confidence_0_to_100)
            Returns (True, 50.0) if classifier unavailable (pass-through)
        """
        self._load_ml_classifier()
        if not self._ml_classifier or not self._ml_classifier.is_trained:
            return True, 50.0

        try:
            return self._ml_classifier.predict(features)
        except Exception as e:
            logger.debug(f'ML prediction failed: {e}')
            return True, 50.0

    # ─── LLM-Powered Functions ───────────────────────────────────────

    def _get_llm(self):
        """Get the LLM client. Returns None if unavailable."""
        try:
            from app.ai.llm_client import get_llm_client
            return get_llm_client()
        except Exception:
            return None

    def reconnaissance(self, url: str, response) -> Optional[Dict]:
        """Perform AI-powered reconnaissance on a target.

        Analyzes the target's HTTP response to detect technology stack,
        WAF presence, and generate scan recommendations.

        Args:
            url: Target URL
            response: requests.Response object from initial request

        Returns:
            Dict with server, language, framework, waf_detected, etc.
            Returns None if LLM unavailable.
        """
        llm = self._get_llm()
        if not llm:
            return None

        try:
            headers_str = '\n'.join(
                f'{k}: {v}' for k, v in (response.headers or {}).items()
            )
            body = (response.text or '')[:2000]

            prompt = RECON_PROMPT.format(
                url=url,
                status_code=response.status_code,
                headers=headers_str[:1500],
                body_preview=body,
            )

            result = llm.generate_json(prompt)
            if result and isinstance(result, dict):
                logger.info(f'AI Recon: {result.get("language", "?")} / '
                           f'{result.get("framework", "?")} / '
                           f'WAF: {result.get("waf_detected", False)}')
                return result
        except Exception as e:
            logger.debug(f'AI recon failed: {e}')

        return None

    def generate_smart_payloads(self, vuln_type: str,
                                 target_context: Optional[Dict] = None,
                                 num_payloads: int = 10) -> List[Dict]:
        """Generate context-aware payloads using LLM + PortSwigger knowledge.

        Args:
            vuln_type: Vulnerability type (e.g., 'sql_injection')
            target_context: Dict from reconnaissance() with tech stack info
            num_payloads: Number of payloads to generate

        Returns:
            List of {payload, technique, reasoning} dicts.
            Returns empty list if LLM unavailable (scanner falls back to PayloadManager).
        """
        llm = self._get_llm()
        if not llm:
            return []

        try:
            ctx = target_context or {}
            ps_context = self.get_portswigger_context(vuln_type, max_labs=3, max_payloads=5)

            prompt = PAYLOAD_GENERATION_PROMPT.format(
                vuln_type=vuln_type,
                tech_stack=f"{ctx.get('language', 'unknown')} / {ctx.get('framework', 'unknown')}",
                url_pattern=ctx.get('url_pattern', 'unknown'),
                waf_detected=ctx.get('waf_detected', False),
                prev_findings=json.dumps(ctx.get('prev_findings', []))[:500],
                portswigger_context=ps_context[:3000],
                num_payloads=num_payloads,
            )

            result = llm.generate_json(prompt)
            if result and isinstance(result, dict):
                payloads = result.get('payloads', [])
                logger.info(f'SmartEngine: Generated {len(payloads)} smart payloads for {vuln_type}')
                return payloads
        except Exception as e:
            logger.debug(f'Smart payload generation failed: {e}')

        return []

    def generate_waf_bypass(self, payload: str, vuln_type: str,
                             waf_indicators: str = '',
                             blocked_response: str = '',
                             num_variants: int = 5) -> List[Dict]:
        """Generate WAF bypass variants using LLM + PortSwigger techniques.

        Args:
            payload: The blocked payload
            vuln_type: Vulnerability type
            waf_indicators: Detected WAF signatures
            blocked_response: Response body from blocked request
            num_variants: Number of bypass variants to generate

        Returns:
            List of {payload, technique, reasoning} dicts.
        """
        llm = self._get_llm()
        if not llm:
            return []

        try:
            # Get WAF bypass context from PortSwigger
            self._load_knowledge_base()
            bypass_context = ''
            if self._portswigger_kb:
                labs = self._portswigger_kb.get('labs', [])
                # Look for labs mentioning "bypass", "filter", "WAF"
                bypass_labs = [
                    lab for lab in labs
                    if any(kw in (lab.get('title', '') + lab.get('description', '')).lower()
                           for kw in ('bypass', 'filter', 'waf', 'block', 'firewall'))
                ]
                for lab in bypass_labs[:3]:
                    bypass_context += f"Lab: {lab.get('title', '')}\n"
                    for step in lab.get('solution_steps', [])[:3]:
                        bypass_context += f"  - {step[:150]}\n"
                    for p in lab.get('payloads', [])[:2]:
                        bypass_context += f"  Payload: {p.get('code', '')[:200]}\n"

            prompt = WAF_BYPASS_PROMPT.format(
                payload=payload,
                vuln_type=vuln_type,
                waf_indicators=waf_indicators[:500],
                blocked_response=blocked_response[:500],
                portswigger_bypass_context=bypass_context[:2000] or 'No specific bypass labs found.',
                num_variants=num_variants,
            )

            result = llm.generate_json(prompt)
            if result and isinstance(result, dict):
                bypasses = result.get('bypasses', [])
                logger.info(f'SmartEngine: Generated {len(bypasses)} WAF bypass variants')
                return bypasses
        except Exception as e:
            logger.debug(f'WAF bypass generation failed: {e}')

        return []

    def verify_finding(self, vuln_data: Dict, features: Dict,
                        response_data: Optional[Dict] = None) -> Tuple[str, float, str]:
        """Three-layer finding verification: ML + LLM + combined.

        Args:
            vuln_data: Dict with vuln_type, url, parameter, payload, evidence
            features: Dict with 16 ML feature values
            response_data: Optional dict with status_code, length, snippet

        Returns:
            (verdict, confidence, reasoning) where:
            - verdict: 'true_positive', 'false_positive', or 'needs_manual_review'
            - confidence: 0.0-1.0 combined confidence
            - reasoning: Human-readable explanation
        """
        # Layer 1: ML classifier
        ml_is_tp, ml_confidence = self.ml_predict(features)

        # Layer 2: LLM verification (if available)
        llm = self._get_llm()
        llm_result = None

        if llm:
            try:
                rd = response_data or {}
                prompt = FINDING_VERIFICATION_PROMPT.format(
                    vuln_type=vuln_data.get('vuln_type', 'Unknown'),
                    url=vuln_data.get('url', ''),
                    parameter=vuln_data.get('parameter', 'N/A'),
                    payload=vuln_data.get('payload', 'N/A'),
                    evidence=vuln_data.get('evidence', 'N/A'),
                    ml_is_tp=ml_is_tp,
                    ml_confidence=f'{ml_confidence:.1f}',
                    status_code=rd.get('status_code', 'N/A'),
                    response_length=rd.get('content_length', 'N/A'),
                    response_time=rd.get('response_time', 'N/A'),
                    payload_reflected=rd.get('reflection_detected', 'N/A'),
                    response_snippet=(rd.get('body_preview', '') or 'N/A')[:500],
                )
                llm_result = llm.generate_json(prompt)
            except Exception as e:
                logger.debug(f'LLM verification failed: {e}')

        # Layer 3: Combine ML + LLM
        if llm_result and isinstance(llm_result, dict):
            llm_verdict = llm_result.get('verdict', 'needs_manual_review')
            llm_confidence = float(llm_result.get('confidence', 0.5))
            llm_reasoning = llm_result.get('reasoning', '')

            # Weighted combination: ML 40%, LLM 60%
            ml_score = (ml_confidence / 100.0) if ml_is_tp else (1 - ml_confidence / 100.0)
            llm_score = llm_confidence if llm_verdict == 'true_positive' else (1 - llm_confidence)

            combined = ml_score * 0.4 + llm_score * 0.6

            if combined >= 0.7:
                verdict = 'true_positive'
            elif combined <= 0.3:
                verdict = 'false_positive'
            else:
                verdict = 'needs_manual_review'

            reasoning = (
                f'ML: {"TP" if ml_is_tp else "FP"} ({ml_confidence:.0f}% confidence). '
                f'LLM: {llm_verdict} ({llm_confidence:.0%}). '
                f'{llm_reasoning}'
            )
            return verdict, combined, reasoning
        else:
            # LLM unavailable — use ML only
            if ml_confidence >= 70:
                verdict = 'true_positive' if ml_is_tp else 'false_positive'
            else:
                verdict = 'true_positive'  # Default: report finding, let user decide
            reasoning = f'ML only: {"TP" if ml_is_tp else "FP"} ({ml_confidence:.0f}% confidence)'
            return verdict, ml_confidence / 100.0, reasoning

    def generate_attack_narrative(self, finding: Dict) -> Optional[Dict]:
        """Generate a detailed attack narrative for a finding.

        Uses LLM with PortSwigger context to create professional
        exploitation writeups.

        Args:
            finding: Dict with vuln_type, severity, url, parameter, payload, evidence

        Returns:
            Dict with narrative, exploitation_steps, impact_scenarios,
            remediation, portswigger_labs. Returns None if LLM unavailable.
        """
        llm = self._get_llm()
        if not llm:
            return None

        try:
            vuln_type = finding.get('vuln_type', 'unknown')
            ps_context = self.get_portswigger_context(vuln_type, max_labs=3, max_payloads=3)

            prompt = ATTACK_NARRATIVE_PROMPT.format(
                vuln_type=vuln_type,
                severity=finding.get('severity', 'medium'),
                url=finding.get('affected_url', finding.get('url', '')),
                parameter=finding.get('parameter', 'N/A'),
                payload=finding.get('payload', 'N/A'),
                evidence=finding.get('evidence', finding.get('description', 'N/A')),
                portswigger_context=ps_context[:3000],
            )

            result = llm.generate_json(prompt)
            if result and isinstance(result, dict):
                # Enrich with actual PortSwigger lab URLs
                result['portswigger_labs'] = self.get_portswigger_labs_for_vuln(vuln_type)
                logger.info(f'Attack narrative generated for {vuln_type}')
                return result
        except Exception as e:
            logger.debug(f'Attack narrative generation failed: {e}')

        return None

    def enrich_remediation(self, vuln_type: str, current_remediation: str) -> str:
        """Enrich remediation text with PortSwigger context and lab links.

        Args:
            vuln_type: Vulnerability type
            current_remediation: Existing remediation text

        Returns:
            Enhanced remediation string with PortSwigger references
        """
        labs = self.get_portswigger_labs_for_vuln(vuln_type)
        if not labs:
            return current_remediation

        enriched = current_remediation.rstrip()

        # Add PortSwigger learning resources
        lab_refs = []
        for lab in labs[:5]:
            title = lab.get('title', '')
            url = lab.get('url', '')
            difficulty = lab.get('difficulty', '')
            if title and url:
                lab_refs.append(f'  • {title} [{difficulty}] — {url}')

        if lab_refs:
            enriched += (
                '\n\nPortSwigger Academy Resources (practice labs):\n'
                + '\n'.join(lab_refs)
            )

        return enriched


# ── Thread-safe Singleton ────────────────────────────────────────────

_engine_instance: Optional[SmartEngine] = None
_engine_lock = threading.Lock()


def get_smart_engine() -> SmartEngine:
    """Get or create the global SmartEngine instance.

    Thread-safe singleton for use across Flask requests and Celery workers.
    """
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = SmartEngine()
    return _engine_instance
