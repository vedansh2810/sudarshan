import re
import json
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode

from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class PrototypePollutionScanner(BaseScanner):
    """Detects JavaScript prototype pollution via __proto__ and
    constructor.prototype injection in query params, form data,
    and JSON request bodies."""

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)

    # ── Canary helpers ────────────────────────────────────────────────

    @staticmethod
    def _make_canary():
        """Generate a unique canary value with timestamp to avoid collisions."""
        return f"sudarshan_pp_test_{int(time.time() * 1000)}"

    # ── Query-parameter payloads ──────────────────────────────────────

    QUERY_TEMPLATES = [
        # __proto__ style
        "__proto__[polluted]={canary}",
        "__proto__[sudarshan_pp]={canary}",
        "__proto__.polluted={canary}",
        # constructor.prototype style
        "constructor[prototype][polluted]={canary}",
        "constructor.prototype.polluted={canary}",
    ]

    # ── JSON body payloads ────────────────────────────────────────────

    @staticmethod
    def _json_payloads(canary):
        """Return list of (label, dict) payloads for JSON body injection."""
        return [
            (
                "__proto__",
                {"__proto__": {"polluted": canary}},
            ),
            (
                "constructor.prototype",
                {"constructor": {"prototype": {"polluted": canary}}},
            ),
            (
                "nested __proto__",
                {"a": {"__proto__": {"polluted": canary}}},
            ),
            (
                "nested constructor",
                {"a": {"constructor": {"prototype": {"polluted": canary}}}},
            ),
        ]

    # ── Detection helpers ─────────────────────────────────────────────

    @staticmethod
    def _canary_reflected(text, canary):
        """Check if the canary value appears anywhere in the response."""
        if not text:
            return False
        return canary in text

    @staticmethod
    def _pollution_indicators(text):
        """Check for generic prototype-pollution side-effects in a response."""
        if not text:
            return []
        indicators = []
        # Property leaking into JSON
        if '"polluted"' in text or "'polluted'" in text:
            indicators.append("polluted_key_in_response")
        # Common framework pollution effects
        if '"__proto__"' in text:
            indicators.append("proto_key_reflected")
        if re.search(r'"constructor"\s*:', text):
            indicators.append("constructor_key_reflected")
        # Error messages hinting at pollution
        if re.search(r"Cannot\s+read\s+propert", text, re.IGNORECASE):
            indicators.append("property_error")
        if re.search(r"prototype\s+pollution", text, re.IGNORECASE):
            indicators.append("pollution_mentioned")
        return indicators

    # ── Test strategies ───────────────────────────────────────────────

    def _test_query_params(self, url):
        """Inject prototype-pollution payloads via query parameters."""
        results = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_qs = parsed.query

        for template in self.QUERY_TEMPLATES:
            canary = self._make_canary()
            payload_qs = template.format(canary=canary)

            # Append payload to existing query string
            if existing_qs:
                test_qs = f"{existing_qs}&{payload_qs}"
            else:
                test_qs = payload_qs

            inject_url = f"{base_url}?{test_qs}"
            resp = self._request("GET", inject_url)
            if resp is None:
                continue

            # Track for generic-response detection
            self._track_response(url, resp)

            reflected = self._canary_reflected(resp.text, canary)
            indicators = self._pollution_indicators(resp.text)

            if reflected or indicators:
                # Follow-up: make a clean request and check persistence
                followup = self._request("GET", url)
                persistent = False
                if followup and self._canary_reflected(followup.text, canary):
                    persistent = True

                results.append({
                    "technique": "query_parameter",
                    "payload_template": template,
                    "canary": canary,
                    "inject_url": inject_url,
                    "reflected": reflected,
                    "indicators": indicators,
                    "persistent": persistent,
                })
                break  # One confirmed hit per URL is sufficient

        return results

    def _test_form_post(self, form, target_url):
        """Inject prototype-pollution payloads via form POST data."""
        results = []
        url = form.get("action", target_url)
        method = form.get("method", "post").upper()
        inputs = form.get("inputs", [])

        if method != "POST":
            return results

        # Build base form data
        base_data = {}
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            if inp.get("type", "").lower() in ("submit", "button"):
                base_data[name] = inp.get("value", "Submit")
            else:
                base_data[name] = inp.get("value", "") or "test"

        # Try injecting pollution keys as additional form fields
        canary = self._make_canary()
        pollution_fields = [
            ("__proto__[polluted]", canary),
            ("constructor[prototype][polluted]", canary),
        ]

        for field_name, value in pollution_fields:
            test_data = dict(base_data)
            test_data[field_name] = value
            resp = self._request("POST", url, data=test_data)
            if resp is None:
                continue

            self._track_response(url, resp)
            reflected = self._canary_reflected(resp.text, canary)
            indicators = self._pollution_indicators(resp.text)

            if reflected or indicators:
                followup = self._request("GET", url)
                persistent = False
                if followup and self._canary_reflected(followup.text, canary):
                    persistent = True

                results.append({
                    "technique": "form_post",
                    "field_name": field_name,
                    "canary": canary,
                    "url": url,
                    "reflected": reflected,
                    "indicators": indicators,
                    "persistent": persistent,
                })
                break

        return results

    def _test_json_body(self, url, method="POST"):
        """Inject prototype-pollution payloads via JSON request bodies."""
        results = []

        for label, payload_dict in self._json_payloads(self._make_canary()):
            canary = payload_dict.get("__proto__", payload_dict.get("constructor", payload_dict.get("a", {})))
            # Extract canary string from nested dict
            canary_val = self._extract_canary(payload_dict)
            if not canary_val:
                continue

            try:
                body = json.dumps(payload_dict)
            except (TypeError, ValueError):
                continue

            resp = self._request(
                method, url,
                content=body.encode(),
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            self._track_response(url, resp)
            reflected = self._canary_reflected(resp.text, canary_val)
            indicators = self._pollution_indicators(resp.text)

            if reflected or indicators:
                followup = self._request("GET", url)
                persistent = False
                if followup and self._canary_reflected(followup.text, canary_val):
                    persistent = True

                results.append({
                    "technique": "json_body",
                    "label": label,
                    "canary": canary_val,
                    "url": url,
                    "payload": body,
                    "reflected": reflected,
                    "indicators": indicators,
                    "persistent": persistent,
                })
                break

        return results

    @staticmethod
    def _extract_canary(d):
        """Recursively extract the canary string from a nested dict."""
        if isinstance(d, str):
            return d
        if isinstance(d, dict):
            for v in d.values():
                result = PrototypePollutionScanner._extract_canary(v)
                if result:
                    return result
        return None

    # ── Finding builder ───────────────────────────────────────────────

    @staticmethod
    def _make_finding(result):
        technique = result["technique"]
        indicators = result.get("indicators", [])
        persistent = result.get("persistent", False)

        evidence_parts = []
        if result.get("reflected"):
            evidence_parts.append("canary value reflected in response")
        if indicators:
            evidence_parts.append(f"indicators: {', '.join(indicators)}")
        if persistent:
            evidence_parts.append("pollution persists across requests")
        evidence = "; ".join(evidence_parts) or "potential pollution detected"

        description = (
            f"Prototype pollution detected via {technique.replace('_', ' ')}. "
            f"Injecting __proto__ or constructor.prototype properties caused "
            f"observable effects in the application response."
        )
        if persistent:
            description += (
                " The pollution persists across requests, indicating "
                "server-side prototype pollution."
            )

        url = result.get("inject_url") or result.get("url", "")

        return {
            "vuln_type": "prototype_pollution",
            "name": f"Prototype Pollution — {technique.replace('_', ' ').title()}",
            "description": description,
            "impact": (
                "Denial of service, property injection leading to authentication "
                "bypass, remote code execution in server-side JS (Node.js), "
                "client-side XSS via DOM property manipulation."
            ),
            "severity": "high",
            "cvss_score": 7.5,
            "owasp_category": "A03",
            "cwe": "CWE-1321",
            "affected_url": url,
            "parameter": result.get("field_name", result.get("payload_template", "N/A")),
            "payload": result.get("payload", result.get("payload_template", "").format(
                canary=result.get("canary", "")
            )),
            "request_data": (
                f"Technique: {technique}\n"
                f"Canary: {result.get('canary', 'N/A')}"
            ),
            "response_data": evidence,
            "remediation": (
                "Freeze Object.prototype using Object.freeze(). "
                "Use Map instead of plain objects for user-controlled keys. "
                "Validate and sanitize property names — reject '__proto__', "
                "'constructor', and 'prototype'. Use --disable-proto=throw "
                "in Node.js ≥12. Apply schema validation on JSON input."
            ),
        }

    # ── Main scan ─────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        # Collect all unique URLs to test
        urls_to_test = {target_url}
        for point in injectable_points:
            if isinstance(point, dict):
                u = point.get("url") or point.get("action")
                if u:
                    urls_to_test.add(u)

        # 1. Query-parameter injection on all URLs
        for url in urls_to_test:
            key = f"query:{url}"
            if key in seen:
                continue
            hits = self._test_query_params(url)
            for hit in hits:
                seen.add(key)
                self.findings.append(self._make_finding(hit))

        # 2. Form POST injection
        for point in injectable_points:
            if not isinstance(point, dict) or point.get("type") != "form":
                continue
            form_url = point.get("action", target_url)
            key = f"form:{form_url}"
            if key in seen:
                continue
            hits = self._test_form_post(point, target_url)
            for hit in hits:
                seen.add(key)
                self.findings.append(self._make_finding(hit))

        # 3. JSON body injection on URLs that might accept JSON
        for url in urls_to_test:
            key = f"json:{url}"
            if key in seen:
                continue
            # Quick probe — only try JSON if endpoint doesn't 415
            probe = self._request(
                "POST", url,
                content=b'{"test":1}',
                headers={"Content-Type": "application/json"},
            )
            if probe and probe.status_code != 415:
                hits = self._test_json_body(url)
                for hit in hits:
                    seen.add(key)
                    self.findings.append(self._make_finding(hit))

        return self.findings
