"""LLM Client — Groq (Llama 3.3 70B).

Provides a unified interface for LLM calls with:
- Response caching (TTL-based) to avoid redundant API calls
- Rate limiting for Groq API (30 RPM free tier)
- Thread-safe singleton access
"""

import json
import time
import hashlib
import logging
import threading

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple token-bucket rate limiter for Groq API."""

    def __init__(self, max_calls=28, period=60):
        self.max_calls = max_calls
        self.period = period
        self._calls = []
        self._lock = threading.Lock()

    def acquire(self):
        """Block until a request slot is available."""
        with self._lock:
            now = time.time()
            # Remove expired timestamps
            self._calls = [t for t in self._calls if now - t < self.period]
            if len(self._calls) >= self.max_calls:
                sleep_time = self.period - (now - self._calls[0])
                if sleep_time > 0:
                    logger.debug(f"Rate limit: sleeping {sleep_time:.1f}s")
                    time.sleep(sleep_time)
                self._calls = [t for t in self._calls if time.time() - t < self.period]
            self._calls.append(time.time())


class ResponseCache:
    """Simple TTL cache for LLM responses."""

    def __init__(self, ttl=3600):
        self.ttl = ttl
        self._cache = {}
        self._lock = threading.Lock()

    def _key(self, prompt, context):
        raw = f"{prompt}::{context or ''}"
        return hashlib.md5(raw.encode('utf-8', errors='ignore')).hexdigest()

    def get(self, prompt, context=None):
        key = self._key(prompt, context)
        with self._lock:
            entry = self._cache.get(key)
            if entry and (time.time() - entry['ts']) < self.ttl:
                logger.debug("LLM cache hit")
                return entry['value']
            return None

    def set(self, prompt, context, value):
        key = self._key(prompt, context)
        with self._lock:
            self._cache[key] = {'value': value, 'ts': time.time()}
            # Evict stale entries if cache grows too large
            if len(self._cache) > 500:
                now = time.time()
                self._cache = {
                    k: v for k, v in self._cache.items()
                    if now - v['ts'] < self.ttl
                }


class LLMClient:
    """Groq LLM client using Llama 3.3 70B.

    Usage:
        client = LLMClient.from_config(app.config)
        result = client.generate("Analyze this vulnerability...", context="...")
    """

    def __init__(self, groq_api_key=None, model_name=None):
        self.groq_api_key = groq_api_key
        self.model_name = model_name or 'llama-3.3-70b-versatile'

        self._rate_limiter = RateLimiter(max_calls=28, period=60)  # Stay under 30 RPM
        self._cache = ResponseCache(ttl=3600)
        self._groq_client = None
        self._initialized = False

    @classmethod
    def from_config(cls, config):
        """Create LLMClient from Flask app config."""
        import os
        groq_key = config.get('GROQ_API_KEY', '') or os.environ.get('GROQ_API_KEY', '')
        model = config.get('GROQ_MODEL', '') or os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
        return cls(
            groq_api_key=groq_key,
            model_name=model,
        )

    def _init_groq(self):
        """Lazy-initialize Groq client."""
        if self._groq_client is not None:
            return
        if not self.groq_api_key:
            logger.warning("No GROQ_API_KEY set — Groq unavailable")
            return
        try:
            from groq import Groq
            self._groq_client = Groq(api_key=self.groq_api_key)
            logger.info(f"Groq client initialized (model: {self.model_name})")
        except Exception as e:
            logger.error(f"Failed to initialize Groq: {e}")
            self._groq_client = None

    def _groq_generate(self, prompt, context=None):
        """Call Groq API."""
        self._init_groq()
        if not self._groq_client:
            raise RuntimeError("Groq client not available")

        self._rate_limiter.acquire()

        messages = []
        if context:
            messages.append({
                'role': 'system',
                'content': f'You are a cybersecurity expert AI assistant helping with vulnerability analysis.\n\n--- CONTEXT ---\n{context}'
            })
        else:
            messages.append({
                'role': 'system',
                'content': 'You are a cybersecurity expert AI assistant helping with vulnerability analysis.'
            })
        messages.append({
            'role': 'user',
            'content': prompt
        })

        try:
            response = self._groq_client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=0.3,
                max_tokens=4096,
            )
            return response.choices[0].message.content or ''
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            raise

    def generate(self, prompt, context=None, use_cache=True):
        """Generate text using Groq LLM.

        Args:
            prompt: The instruction/question for the LLM.
            context: Optional context (e.g., vulnerability data).
            use_cache: Whether to check/store in cache.

        Returns:
            LLM response text, or None if the call fails.
        """
        # Check cache first
        if use_cache:
            cached = self._cache.get(prompt, context)
            if cached is not None:
                return cached

        result = None
        try:
            result = self._groq_generate(prompt, context)
        except Exception as e:
            logger.warning(f"Groq LLM call failed: {e}")

        # Cache successful result
        if result and use_cache:
            self._cache.set(prompt, context, result)

        return result

    def generate_json(self, prompt, context=None, use_cache=True):
        """Generate and parse a JSON response from the LLM.

        Appends instruction to respond in JSON format.
        Returns parsed dict/list, or None on failure.
        """
        json_prompt = (
            f"{prompt}\n\n"
            "IMPORTANT: Respond ONLY with valid JSON. No markdown, no code fences, "
            "no explanation outside the JSON object."
        )
        raw = self.generate(json_prompt, context, use_cache)
        if not raw:
            return None

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith('```'):
            lines = text.split('\n')
            # Remove first and last lines (code fences)
            lines = [l for l in lines if not l.strip().startswith('```')]
            text = '\n'.join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning(f"LLM returned invalid JSON: {e}\nRaw: {text[:200]}")
            return None

    @property
    def is_available(self):
        """Check if the LLM client is configured and ready."""
        return bool(self.groq_api_key)


# ── Singleton for app-wide use ───────────────────────────────────────

_client_instance = None


def get_llm_client(app=None):
    """Get or create the global LLMClient instance."""
    global _client_instance
    if _client_instance is None:
        if app is None:
            from flask import current_app
            app = current_app
        _client_instance = LLMClient.from_config(app.config)
    return _client_instance
