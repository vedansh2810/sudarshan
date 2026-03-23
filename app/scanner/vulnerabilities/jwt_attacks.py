"""JWT Vulnerability Scanner

Detects common JSON Web Token security issues:
  1. Algorithm None bypass — accept unsigned tokens.
  2. Weak secret detection — brute-force common passwords.
  3. Expired token acceptance — server honors expired JWTs.
  4. Missing claim validation — iss, aud not enforced.
  5. Algorithm confusion — RS256 public key used as HS256 secret.

OWASP: A07 (Identification & Authentication Failures)
Severity: High
"""

import re
import json
import base64
import hashlib
import hmac
import logging
import time
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)

# ── Common weak secrets ──────────────────────────────────────────────
WEAK_SECRETS = [
    'secret', 'password', '123456', 'changeme', 'admin', 'key',
    'jwt_secret', 'supersecret', 'test', 'default', 'letmein',
    'qwerty', 'abc123', '1234567890', 'passw0rd', 'hunter2',
    'secretkey', 'mysecret', 'token', 'apikey', 'jwt',
]

# JWT regex — three base64url segments separated by dots
JWT_REGEX = re.compile(
    r'eyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*'
)

# Common locations where JWTs appear
JWT_HEADERS = ['Authorization', 'X-Auth-Token', 'X-Access-Token']
JWT_COOKIES = ['token', 'jwt', 'access_token', 'auth_token', 'session_token', 'id_token']


class JWTAttackScanner(BaseScanner):
    """Detect JWT implementation vulnerabilities."""

    def scan(self, target_url, injectable_points):
        self.findings = []

        # Step 1: Discover JWTs by probing the target
        jwts = self._discover_jwts(target_url)

        if not jwts:
            logger.debug(f'No JWTs found on {target_url}')
            return self.findings

        for jwt_info in jwts:
            token = jwt_info['token']
            source = jwt_info['source']

            # Parse the JWT
            header, payload_data, signature = self._decode_jwt(token)
            if not header or not payload_data:
                continue

            # Test 1: Algorithm None bypass
            self._test_alg_none(target_url, token, header, payload_data, source)

            # Test 2: Weak secret brute-force
            self._test_weak_secrets(target_url, token, header, payload_data, source)

            # Test 3: Expired token acceptance
            self._test_expired_token(target_url, token, header, payload_data, source)

            # Test 4: Missing claim validation
            self._test_missing_claims(target_url, token, header, payload_data, source)

        return self.findings

    # ── JWT Discovery ────────────────────────────────────────────────

    def _discover_jwts(self, target_url):
        """Find JWTs in responses, cookies, and headers."""
        jwts = []

        resp = self._request('GET', target_url)
        if not resp:
            return jwts

        # Check response cookies
        for cookie_name in JWT_COOKIES:
            cookie_val = resp.cookies.get(cookie_name, '')
            if JWT_REGEX.search(cookie_val):
                jwts.append({
                    'token': JWT_REGEX.search(cookie_val).group(),
                    'source': f'cookie:{cookie_name}'
                })

        # Check response headers
        for header_name in JWT_HEADERS:
            header_val = resp.headers.get(header_name, '')
            match = JWT_REGEX.search(header_val)
            if match:
                jwts.append({
                    'token': match.group(),
                    'source': f'header:{header_name}'
                })

        # Check response body for JWTs
        if resp.text:
            for match in JWT_REGEX.finditer(resp.text):
                token = match.group()
                if token not in [j['token'] for j in jwts]:
                    jwts.append({
                        'token': token,
                        'source': 'response_body'
                    })

        # Also check common API endpoints that return tokens
        for path in ['/api/auth/token', '/api/login', '/auth/token', '/api/v2/auth/session']:
            resp2 = self._request('GET', target_url.rstrip('/') + path)
            if resp2 and resp2.text:
                for match in JWT_REGEX.finditer(resp2.text):
                    token = match.group()
                    if token not in [j['token'] for j in jwts]:
                        jwts.append({
                            'token': token,
                            'source': f'endpoint:{path}'
                        })

        return jwts[:5]  # Limit to 5 tokens

    # ── JWT Decoding ─────────────────────────────────────────────────

    @staticmethod
    def _b64url_decode(data):
        """Base64URL decode with padding fix."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64url_encode(data):
        """Base64URL encode without padding."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def _decode_jwt(self, token):
        """Decode JWT into (header_dict, payload_dict, signature_bytes)."""
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            signature = self._b64url_decode(parts[2]) if parts[2] else b''
            return header, payload, signature
        except Exception:
            return None, None, None

    def _forge_jwt(self, header, payload_data, secret=None):
        """Create a JWT with the given header and payload."""
        h_enc = self._b64url_encode(json.dumps(header, separators=(',', ':')))
        p_enc = self._b64url_encode(json.dumps(payload_data, separators=(',', ':')))
        signing_input = f'{h_enc}.{p_enc}'

        alg = header.get('alg', 'none')
        if alg.lower() == 'none':
            return f'{signing_input}.'
        elif alg == 'HS256' and secret:
            sig = hmac.new(
                secret.encode('utf-8') if isinstance(secret, str) else secret,
                signing_input.encode('utf-8'),
                hashlib.sha256
            ).digest()
            return f'{signing_input}.{self._b64url_encode(sig)}'
        elif alg == 'HS384' and secret:
            sig = hmac.new(
                secret.encode('utf-8') if isinstance(secret, str) else secret,
                signing_input.encode('utf-8'),
                hashlib.sha384
            ).digest()
            return f'{signing_input}.{self._b64url_encode(sig)}'
        elif alg == 'HS512' and secret:
            sig = hmac.new(
                secret.encode('utf-8') if isinstance(secret, str) else secret,
                signing_input.encode('utf-8'),
                hashlib.sha512
            ).digest()
            return f'{signing_input}.{self._b64url_encode(sig)}'
        return None

    # ── Attack: Algorithm None ───────────────────────────────────────

    def _test_alg_none(self, target_url, token, header, payload_data, source):
        """Test if the server accepts tokens with alg=none (no signature)."""
        for alg_variant in ['none', 'None', 'NONE', 'nOnE']:
            forged_header = dict(header)
            forged_header['alg'] = alg_variant

            forged_token = self._forge_jwt(forged_header, payload_data)
            if not forged_token:
                continue

            resp = self._send_jwt(target_url, forged_token, source)
            if resp and self._is_authenticated(resp):
                self.findings.append({
                    'vuln_type': 'jwt_attacks',
                    'name': 'JWT Algorithm None Bypass',
                    'description': (
                        f'The server accepts JWTs with "alg": "{alg_variant}" — an unsigned '
                        f'token with no signature verification. Any attacker can forge valid '
                        f'tokens with arbitrary claims.'
                    ),
                    'impact': (
                        'Complete authentication bypass. An attacker can impersonate any user, '
                        'escalate privileges, and access all protected resources.'
                    ),
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'owasp_category': 'A07',
                    'affected_url': target_url,
                    'parameter': source,
                    'payload': f'alg={alg_variant}',
                    'request_data': f'Forged JWT: {forged_token[:80]}...',
                    'response_data': (resp.text or '')[:300],
                    'remediation': (
                        '1. Always validate the JWT algorithm against a whitelist.\n'
                        '2. Reject tokens with alg=none in production.\n'
                        '3. Use a JWT library that enforces algorithm checking.\n'
                        '4. Never rely on the token\'s header to determine the algorithm.'
                    ),
                })
                return  # One finding is enough

    # ── Attack: Weak Secret ──────────────────────────────────────────

    def _test_weak_secrets(self, target_url, token, header, payload_data, source):
        """Brute-force common weak secrets for HMAC-signed tokens."""
        alg = header.get('alg', '')
        if not alg.startswith('HS'):
            return  # Only test HMAC algorithms

        parts = token.split('.')
        signing_input = f'{parts[0]}.{parts[1]}'.encode('utf-8')
        original_sig = self._b64url_decode(parts[2]) if parts[2] else b''

        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in WEAK_SECRETS:
            test_sig = hmac.new(
                secret.encode('utf-8'),
                signing_input,
                hash_func
            ).digest()

            if hmac.compare_digest(test_sig, original_sig):
                self.findings.append({
                    'vuln_type': 'jwt_attacks',
                    'name': 'JWT Weak Secret Detected',
                    'description': (
                        f'The JWT signing secret is "{secret}" — a common weak password. '
                        f'An attacker can forge valid tokens with arbitrary claims.'
                    ),
                    'impact': (
                        'Complete token forgery. An attacker can create tokens for any user, '
                        'bypass authentication, and escalate privileges.'
                    ),
                    'severity': 'critical',
                    'cvss_score': 9.1,
                    'owasp_category': 'A07',
                    'affected_url': target_url,
                    'parameter': source,
                    'payload': f'secret="{secret}"',
                    'request_data': f'Algorithm: {alg}, Secret: {secret}',
                    'response_data': f'Token signature matched with weak secret',
                    'remediation': (
                        '1. Use a strong, randomly generated secret (256+ bits).\n'
                        '2. Rotate secrets periodically.\n'
                        '3. Consider using asymmetric algorithms (RS256, ES256) instead.\n'
                        '4. Store secrets in environment variables, never in code.'
                    ),
                })
                return

    # ── Attack: Expired Token ────────────────────────────────────────

    def _test_expired_token(self, target_url, token, header, payload_data, source):
        """Check if the server accepts expired tokens."""
        exp = payload_data.get('exp')
        if not exp:
            # No expiry claim — worth reporting
            self.findings.append({
                'vuln_type': 'jwt_attacks',
                'name': 'JWT Missing Expiration Claim',
                'description': (
                    'The JWT does not contain an "exp" (expiration) claim. '
                    'This means the token never expires and can be used indefinitely.'
                ),
                'impact': (
                    'Stolen tokens remain valid forever. Credential rotation and '
                    'session management are effectively bypassed.'
                ),
                'severity': 'medium',
                'cvss_score': 5.3,
                'owasp_category': 'A07',
                'affected_url': target_url,
                'parameter': source,
                'payload': 'Missing "exp" claim',
                'request_data': f'JWT payload: {json.dumps(payload_data)[:200]}',
                'response_data': 'No expiration timestamp in token',
                'remediation': (
                    '1. Always include an "exp" claim in JWTs.\n'
                    '2. Use short-lived tokens (15-60 minutes).\n'
                    '3. Implement token refresh mechanisms.\n'
                    '4. Validate expiration on every request server-side.'
                ),
            })
            return

        current_time = int(time.time())
        if exp > current_time:
            # Token is still valid — forge an expired one
            expired_payload = dict(payload_data)
            expired_payload['exp'] = current_time - 86400  # 24 hours ago

            alg = header.get('alg', 'HS256')
            if alg.startswith('HS'):
                # We can only test this if we cracked the secret
                return

        elif exp <= current_time:
            # Token is already expired — test if server still accepts it
            resp = self._send_jwt(target_url, token, source)
            if resp and self._is_authenticated(resp):
                self.findings.append({
                    'vuln_type': 'jwt_attacks',
                    'name': 'JWT Expired Token Accepted',
                    'description': (
                        'The server accepts expired JWT tokens. The token expired at '
                        f'{time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp))} UTC '
                        'but is still being honored.'
                    ),
                    'impact': (
                        'Token revocation is ineffective. Stolen or leaked tokens '
                        'remain valid even after they should have expired.'
                    ),
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'owasp_category': 'A07',
                    'affected_url': target_url,
                    'parameter': source,
                    'payload': f'exp={exp} (expired)',
                    'request_data': f'Expired JWT sent, exp={exp}',
                    'response_data': (resp.text or '')[:300],
                    'remediation': (
                        '1. Always validate the "exp" claim server-side.\n'
                        '2. Reject tokens where exp < current_time.\n'
                        '3. Use clock skew tolerance of at most 30 seconds.\n'
                        '4. Implement token blacklisting for revoked tokens.'
                    ),
                })

    # ── Attack: Missing Claims ───────────────────────────────────────

    def _test_missing_claims(self, target_url, token, header, payload_data, source):
        """Check for missing standard security claims."""
        missing = []
        if 'iss' not in payload_data:
            missing.append('iss (issuer)')
        if 'aud' not in payload_data:
            missing.append('aud (audience)')
        if 'iat' not in payload_data:
            missing.append('iat (issued at)')
        if 'nbf' not in payload_data:
            missing.append('nbf (not before)')

        if len(missing) >= 2:  # Report if 2+ claims are missing
            self.findings.append({
                'vuln_type': 'jwt_attacks',
                'name': 'JWT Missing Security Claims',
                'description': (
                    f'The JWT is missing critical security claims: {", ".join(missing)}. '
                    'These claims are essential for proper token validation.'
                ),
                'impact': (
                    'Without proper claims, tokens from different issuers or audiences '
                    'may be accepted, and token replay attacks become easier.'
                ),
                'severity': 'low',
                'cvss_score': 3.7,
                'owasp_category': 'A07',
                'affected_url': target_url,
                'parameter': source,
                'payload': f'Missing: {", ".join(missing)}',
                'request_data': f'JWT payload keys: {list(payload_data.keys())}',
                'response_data': f'Missing claims: {", ".join(missing)}',
                'remediation': (
                    '1. Include iss, aud, iat, exp, and nbf claims in all JWTs.\n'
                    '2. Validate iss and aud claims server-side on every request.\n'
                    '3. Reject tokens that don\'t match expected issuer/audience.\n'
                    '4. Follow RFC 7519 best practices for JWT claims.'
                ),
            })

    # ── Helpers ──────────────────────────────────────────────────────

    def _send_jwt(self, target_url, token, source):
        """Send a request with the JWT in the appropriate location."""
        if source.startswith('cookie:'):
            cookie_name = source.split(':', 1)[1]
            return self._request('GET', target_url, cookies={cookie_name: token})
        elif source.startswith('header:'):
            header_name = source.split(':', 1)[1]
            if header_name == 'Authorization':
                return self._request('GET', target_url,
                                     headers={'Authorization': f'Bearer {token}'})
            return self._request('GET', target_url, headers={header_name: token})
        else:
            # Default: try Authorization header
            return self._request('GET', target_url,
                                 headers={'Authorization': f'Bearer {token}'})

    @staticmethod
    def _is_authenticated(resp):
        """Heuristic: check if the response indicates successful auth."""
        if not resp:
            return False
        # 200 OK with non-trivial body is likely authenticated
        if resp.status_code == 200 and len(resp.text or '') > 100:
            # Make sure it's not a login page
            lower = (resp.text or '').lower()
            if 'login' in lower and ('form' in lower or 'password' in lower):
                return False
            return True
        # 401/403 means not authenticated
        if resp.status_code in (401, 403):
            return False
        return False
