"""LLM Client — Groq (Llama 3.3 70B).

Provides a unified interface for LLM calls with:
- Multi-key rotation (round-robin) to spread rate limits across keys
- Automatic failover: if one key is rate-limited, tries the next key
- Response caching (TTL-based) to avoid redundant API calls
- Rate limiting per key for Groq API (30 RPM free tier)
- Thread-safe singleton access

Configuration:
    # Single key (backward compatible)
    GROQ_API_KEY=gsk_xxx

    # Multiple keys (comma-separated, round-robin rotation)
    GROQ_API_KEYS=gsk_key1,gsk_key2,gsk_key3
"""

import json
import time
import hashlib
import logging
import threading

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token-aware rate limiter for Groq API with concurrency control.

    Enforces three limits simultaneously:
      1. Request count (max_calls per period) — prevents RPM exhaustion
      2. Token budget (max_tokens per period) — prevents TPM exhaustion
      3. Concurrency (semaphore) — limits parallel LLM calls
    """

    def __init__(self, max_calls=28, period=60, max_tokens=10000, max_concurrent=2):
        self.max_calls = max_calls
        self.period = period
        self.max_tokens = max_tokens
        self._calls = []
        self._tokens = []  # list of (timestamp, token_count)
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(max_concurrent)

    def acquire(self, estimated_tokens=0):
        """Block until a request slot is available, respecting token budget."""
        self._semaphore.acquire()
        with self._lock:
            now = time.time()
            # Prune expired entries
            self._calls = [t for t in self._calls if now - t < self.period]
            self._tokens = [(t, c) for t, c in self._tokens if now - t < self.period]

            # Check call count limit
            if len(self._calls) >= self.max_calls:
                sleep_time = self.period - (now - self._calls[0])
                if sleep_time > 0:
                    logger.debug(f"Rate limit (RPM): sleeping {sleep_time:.1f}s")
                    time.sleep(sleep_time)
                now = time.time()
                self._calls = [t for t in self._calls if now - t < self.period]
                self._tokens = [
                    (t, c) for t, c in self._tokens if now - t < self.period
                ]

            # Check token budget
            if estimated_tokens > 0:
                used_tokens = sum(c for _, c in self._tokens)
                if used_tokens + estimated_tokens > self.max_tokens and self._tokens:
                    sleep_time = self.period - (now - self._tokens[0][0])
                    if sleep_time > 0:
                        logger.debug(
                            f"Rate limit (tokens): sleeping {min(sleep_time, 15):.1f}s "
                            f"({used_tokens}+{estimated_tokens} > {self.max_tokens})"
                        )
                        time.sleep(min(sleep_time, 15))

            self._calls.append(time.time())
            if estimated_tokens > 0:
                self._tokens.append((time.time(), estimated_tokens))

    def release(self):
        """Release the concurrency semaphore after a request completes."""
        self._semaphore.release()


class ResponseCache:
    """Simple TTL cache for LLM responses."""

    def __init__(self, ttl=3600):
        self.ttl = ttl
        self._cache = {}
        self._lock = threading.Lock()

    def _key(self, prompt, context):
        raw = f"{prompt}::{context or ''}"
        return hashlib.md5(raw.encode("utf-8", errors="ignore")).hexdigest()

    def get(self, prompt, context=None):
        key = self._key(prompt, context)
        with self._lock:
            entry = self._cache.get(key)
            if entry and (time.time() - entry["ts"]) < self.ttl:
                logger.debug("LLM cache hit")
                return entry["value"]
            return None

    def set(self, prompt, context, value):
        key = self._key(prompt, context)
        with self._lock:
            self._cache[key] = {"value": value, "ts": time.time()}
            # Evict stale entries if cache grows too large
            if len(self._cache) > 500:
                now = time.time()
                self._cache = {
                    k: v for k, v in self._cache.items() if now - v["ts"] < self.ttl
                }


class LLMClient:
    """Groq LLM client with multi-key rotation.

    Supports multiple API keys for round-robin rotation. If a key hits
    a rate limit, automatically tries the next key.

    Usage:
        client = LLMClient.from_config(app.config)
        result = client.generate("Analyze this vulnerability...", context="...")
    """

    def __init__(self, api_keys=None, model_name=None):
        # Accept a list of keys or a single key
        if isinstance(api_keys, str):
            api_keys = [k.strip() for k in api_keys.split(",") if k.strip()]
        self._api_keys = api_keys or []
        self.model_name = model_name or "llama-3.3-70b-versatile"

        self._rate_limiter = RateLimiter(max_calls=28, period=60)
        self._cache = ResponseCache(ttl=3600)
        self._groq_clients = {}  # key -> Groq client (lazy init)
        self._key_index = 0  # current round-robin position
        self._key_lock = threading.Lock()

        if len(self._api_keys) > 1:
            logger.info(f"Groq multi-key rotation enabled ({len(self._api_keys)} keys)")

    # Backward compat: expose first key as .groq_api_key
    @property
    def groq_api_key(self):
        return self._api_keys[0] if self._api_keys else None

    @classmethod
    def from_config(cls, config):
        """Create LLMClient from Flask app config."""
        import os

        # Try multi-key first (GROQ_API_KEYS), fall back to single key
        keys_str = (
            config.get("GROQ_API_KEYS", "")
            or os.environ.get("GROQ_API_KEYS", "")
        )
        if not keys_str:
            # Fall back to single GROQ_API_KEY
            single_key = (
                config.get("GROQ_API_KEY", "")
                or os.environ.get("GROQ_API_KEY", "")
            )
            keys_str = single_key

        model = config.get("GROQ_MODEL", "") or os.environ.get(
            "GROQ_MODEL", "llama-3.3-70b-versatile"
        )
        return cls(api_keys=keys_str, model_name=model)

    def _get_next_key(self):
        """Get the next API key in round-robin order (thread-safe)."""
        with self._key_lock:
            if not self._api_keys:
                return None
            key = self._api_keys[self._key_index % len(self._api_keys)]
            self._key_index += 1
            return key

    def _get_groq_client(self, api_key):
        """Get or create a Groq client for the given API key (lazy init)."""
        if api_key not in self._groq_clients:
            try:
                from groq import Groq
                self._groq_clients[api_key] = Groq(api_key=api_key)
                # Log with masked key for security
                masked = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
                logger.info(f"Groq client initialized for key {masked} (model: {self.model_name})")
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
                return None
        return self._groq_clients[api_key]

    def _groq_generate(self, prompt, context=None):
        """Call Groq API with key rotation and automatic failover."""
        if not self._api_keys:
            raise RuntimeError("No Groq API keys configured")

        # Estimate token count: ~4 chars per token for English text
        total_chars = len(prompt) + len(context or "")
        estimated_tokens = max(total_chars // 4, 100)

        messages = []
        if context:
            messages.append(
                {
                    "role": "system",
                    "content": f"You are a cybersecurity expert AI assistant helping with vulnerability analysis.\n\n--- CONTEXT ---\n{context}",
                }
            )
        else:
            messages.append(
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert AI assistant helping with vulnerability analysis.",
                }
            )
        messages.append({"role": "user", "content": prompt})

        # Try each key up to the total number of keys
        last_error = None
        attempts = len(self._api_keys)

        for attempt in range(attempts):
            api_key = self._get_next_key()
            client = self._get_groq_client(api_key)
            if not client:
                continue

            self._rate_limiter.acquire(estimated_tokens=estimated_tokens)
            try:
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=4096,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                self._rate_limiter.release()
                last_error = e
                error_str = str(e).lower()
                # If rate limited, try the next key
                if "rate_limit" in error_str or "429" in error_str:
                    masked = api_key[:8] + "..." if len(api_key) > 8 else "***"
                    logger.warning(
                        f"Groq key {masked} rate-limited, rotating to next key "
                        f"(attempt {attempt + 1}/{attempts})"
                    )
                    continue
                # For other errors, don't retry
                logger.error(f"Groq API error: {e}")
                raise
            finally:
                try:
                    self._rate_limiter.release()
                except ValueError:
                    pass  # Already released in the except block above

        # All keys exhausted
        logger.error(f"All {attempts} Groq API keys are rate-limited")
        raise last_error or RuntimeError("All Groq API keys exhausted")

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
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last lines (code fences)
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning(f"LLM returned invalid JSON: {e}\nRaw: {text[:200]}")
            return None

    @property
    def is_available(self):
        """Check if the LLM client is configured and ready."""
        return bool(self._api_keys)

    @property
    def key_count(self):
        """Number of API keys configured."""
        return len(self._api_keys)


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
