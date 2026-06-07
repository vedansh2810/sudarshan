"""Comprehensive tests for app.scanner.crawler.Crawler.

Covers:
- URL normalization (_normalize_url)
- URL validation (_is_valid_extracted_url)
- Domain scoping (_is_same_domain)
- Link & form extraction (_extract_links)

All HTTP interactions are mocked — no real network requests are made.
"""

import pytest
from unittest.mock import MagicMock, patch

from app.scanner.crawler import Crawler


# ── Helpers ──────────────────────────────────────────────────────────


def _make_crawler(target_url="http://example.com", **kwargs):
    """Create a Crawler with a mocked session so no network calls happen."""
    mock_session = MagicMock()
    # Prevent robots.txt fetch during __init__
    return Crawler(
        target_url,
        session=mock_session,
        respect_robots=False,
        delay=0,
        **kwargs,
    )


# ═══════════════════════════════════════════════════════════════════
# TestURLNormalization
# ═══════════════════════════════════════════════════════════════════


class TestURLNormalization:
    """Tests for Crawler._normalize_url() classmethod."""

    def test_strips_fragment(self):
        """Fragments (#section) should be removed."""
        result = Crawler._normalize_url("http://example.com/page#section")
        assert result == "http://example.com/page"

    def test_strips_trailing_slash(self):
        """Trailing slashes on non-root paths should be removed."""
        result = Crawler._normalize_url("http://example.com/page/")
        assert result == "http://example.com/page"

    def test_root_path_preserved(self):
        """The root path '/' must be preserved (not stripped to empty)."""
        result = Crawler._normalize_url("http://example.com/")
        assert result == "http://example.com/"

    def test_sorts_query_params(self):
        """Query parameters should be sorted alphabetically by key."""
        result = Crawler._normalize_url("http://example.com?b=2&a=1")
        assert result == "http://example.com/?a=1&b=2"

    def test_strips_utm_params(self):
        """UTM tracking parameters should be removed."""
        result = Crawler._normalize_url(
            "http://example.com/page?id=5&utm_source=twitter&utm_medium=social"
        )
        assert result == "http://example.com/page?id=5"

    def test_strips_cache_busters(self):
        """Cache-buster params (t, _) should be removed."""
        result = Crawler._normalize_url(
            "http://example.com/page?id=5&t=1234567890&_=abc"
        )
        assert result == "http://example.com/page?id=5"

    def test_strips_session_params(self):
        """Session-related params (jsessionid) should be removed."""
        result = Crawler._normalize_url(
            "http://example.com/page?jsessionid=abc123&user=bob"
        )
        assert result == "http://example.com/page?user=bob"

    def test_strips_fbclid(self):
        """Facebook click ID should be removed."""
        result = Crawler._normalize_url("http://example.com/page?fbclid=abc123")
        assert result == "http://example.com/page"

    def test_preserves_meaningful_params(self):
        """Non-tracking params like q, page, lang should be kept."""
        result = Crawler._normalize_url(
            "http://example.com/search?q=test&page=2&lang=en"
        )
        assert result == "http://example.com/search?lang=en&page=2&q=test"

    def test_empty_query_after_stripping(self):
        """When all params are tracking, the query string should vanish entirely (no trailing '?')."""
        result = Crawler._normalize_url(
            "http://example.com/page?utm_source=x&utm_medium=y"
        )
        assert result == "http://example.com/page"
        assert "?" not in result

    def test_strips_gclid(self):
        """Google click ID should be removed."""
        result = Crawler._normalize_url("http://example.com/page?gclid=xyz789")
        assert result == "http://example.com/page"

    def test_strips_multiple_tracking_params(self):
        """Multiple tracking params from different categories should all be removed."""
        result = Crawler._normalize_url(
            "http://example.com/page?utm_campaign=sale&fbclid=fb1&gclid=gc1&id=42"
        )
        assert result == "http://example.com/page?id=42"

    def test_preserves_scheme_and_netloc(self):
        """Scheme and netloc should be preserved exactly."""
        result = Crawler._normalize_url("https://sub.example.com:8080/path?a=1")
        assert result.startswith("https://sub.example.com:8080/")


# ═══════════════════════════════════════════════════════════════════
# TestURLValidation
# ═══════════════════════════════════════════════════════════════════


class TestURLValidation:
    """Tests for Crawler._is_valid_extracted_url() staticmethod."""

    def test_normal_url_valid(self):
        """A simple relative path should be valid."""
        assert Crawler._is_valid_extracted_url("/about") is True

    def test_rejects_long_url(self):
        """URLs longer than 200 characters should be rejected."""
        long_url = "/path/" + "a" * 200
        assert Crawler._is_valid_extracted_url(long_url) is False

    def test_rejects_js_concat(self):
        """Strings containing .concat( are JS artifacts and should be rejected."""
        assert Crawler._is_valid_extracted_url(".concat(something)") is False

    def test_rejects_function_keyword(self):
        """Strings containing 'function ' are JS code and should be rejected."""
        assert Crawler._is_valid_extracted_url("function something()") is False

    def test_rejects_arrow_function(self):
        """Strings containing '=>' are JS arrow functions and should be rejected."""
        assert Crawler._is_valid_extracted_url("path=>result") is False

    def test_rejects_excessive_encoding(self):
        """URLs with >15% percent-encoded characters should be rejected."""
        # Build a URL that's > 10 chars long with > 15% being '%'
        # 20 chars total, need > 3 '%' chars  →  use 4 encoded sequences
        encoded_url = "/path%20%21%22%23extra"  # 22 chars, 4 '%' → 18%
        assert Crawler._is_valid_extracted_url(encoded_url) is False

    def test_accepts_moderate_encoding(self):
        """URLs with ≤15% encoding should be accepted."""
        result = Crawler._is_valid_extracted_url("/path%20with%20spaces")
        assert result is True

    def test_rejects_return_keyword(self):
        """Strings containing 'return ' are JS code and should be rejected."""
        assert Crawler._is_valid_extracted_url("return /some/path") is False

    def test_rejects_void_keyword(self):
        """Strings with 'void ' are JS artifacts."""
        assert Crawler._is_valid_extracted_url("void 0") is False

    def test_rejects_strict_equality(self):
        """Strings with '===' are JS comparisons."""
        assert Crawler._is_valid_extracted_url("a===b") is False

    def test_rejects_strict_inequality(self):
        """Strings with '!==' are JS comparisons."""
        assert Crawler._is_valid_extracted_url("a!==b") is False

    def test_rejects_usecontext(self):
        """Strings referencing React's useContext are JS artifacts."""
        assert Crawler._is_valid_extracted_url("useContext(ThemeContext)") is False

    def test_rejects_createelement(self):
        """Strings referencing React's createElement are JS artifacts."""
        assert Crawler._is_valid_extracted_url("createElement('div')") is False

    def test_rejects_prototype(self):
        """Strings referencing prototype are JS artifacts."""
        assert Crawler._is_valid_extracted_url("Object.prototype.toString") is False

    def test_rejects_encoded_braces(self):
        """URL-encoded braces %7B/%7D should be rejected."""
        assert Crawler._is_valid_extracted_url("/path%7Bvar%7D") is False

    def test_rejects_encoded_brackets(self):
        """URL-encoded brackets %5B/%5D should be rejected."""
        assert Crawler._is_valid_extracted_url("/path%5B0%5D") is False

    def test_short_url_with_percent_not_rejected(self):
        """Very short URLs (≤10 chars) bypass the percent-encoding threshold."""
        # 10 chars exactly, 2 '%' = 20% but len ≤ 10 → not rejected
        assert Crawler._is_valid_extracted_url("/%20%21abc") is True

    def test_accepts_api_path(self):
        """Normal API-style paths should be accepted."""
        assert Crawler._is_valid_extracted_url("/api/v2/users/123") is True


# ═══════════════════════════════════════════════════════════════════
# TestCrawlerScoping
# ═══════════════════════════════════════════════════════════════════


class TestCrawlerScoping:
    """Tests for Crawler._is_same_domain() scoping logic."""

    def test_same_domain_in_scope(self):
        """A URL on the exact same domain should be in scope."""
        crawler = _make_crawler("http://example.com")
        assert crawler._is_same_domain("http://example.com/about") is True

    def test_subdomain_out_of_scope(self):
        """A subdomain is a different netloc and should be out of scope
        (the implementation does strict netloc equality)."""
        crawler = _make_crawler("http://example.com")
        assert crawler._is_same_domain("http://sub.example.com/page") is False

    def test_different_domain_out_of_scope(self):
        """A completely different domain should be out of scope."""
        crawler = _make_crawler("http://example.com")
        assert crawler._is_same_domain("http://other.com/page") is False

    def test_different_scheme_in_scope(self):
        """HTTP vs HTTPS with the same netloc should still be in scope
        (_is_same_domain only compares netloc, not scheme)."""
        crawler = _make_crawler("http://example.com")
        assert crawler._is_same_domain("https://example.com/page") is True

    def test_different_port_out_of_scope(self):
        """A different port produces a different netloc and is out of scope."""
        crawler = _make_crawler("http://example.com")
        assert crawler._is_same_domain("http://example.com:8080/page") is False

    def test_www_subdomain_out_of_scope(self):
        """www. prefix makes a different netloc from the bare domain."""
        crawler = _make_crawler("http://example.com")
        assert crawler._is_same_domain("http://www.example.com/page") is False

    def test_same_subdomain_target_in_scope(self):
        """When the target itself is a subdomain, matching URLs are in scope."""
        crawler = _make_crawler("http://app.example.com")
        assert crawler._is_same_domain("http://app.example.com/dashboard") is True


# ═══════════════════════════════════════════════════════════════════
# TestLinkExtraction
# ═══════════════════════════════════════════════════════════════════


class TestLinkExtraction:
    """Tests for Crawler._extract_links().

    The method signature is _extract_links(html, base_url).
    All tests create a Crawler with a mocked session.
    """

    def test_extracts_href_links(self):
        """Standard <a href='...'> links on the same domain should be extracted."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/about" in links
        assert "http://example.com/contact" in links

    def test_extracts_form_actions(self):
        """<form action='...'> URLs should NOT appear in _extract_links
        (forms are handled by _extract_forms), but <a> tags inside forms should."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <form action="/submit" method="post">
                <input type="text" name="q" />
                <a href="/help">Help</a>
            </form>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        # _extract_links picks up <a> tags, not form actions directly
        assert "http://example.com/help" in links

    def test_extracts_js_urls(self):
        """URLs found inside <script> blocks should be extracted."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <script>
                var endpoint = "/api/users";
                fetch('/api/data');
            </script>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/api/data" in links

    def test_ignores_external_links(self):
        """Links to external domains should not be included."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <a href="http://example.com/local">Local</a>
            <a href="http://evil.com/phish">External</a>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/local" in links
        assert not any("evil.com" in link for link in links)

    def test_ignores_mailto_and_tel(self):
        """mailto: and tel: links should not appear in extracted links."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <a href="mailto:user@example.com">Email</a>
            <a href="tel:+1234567890">Call</a>
            <a href="/real-page">Real</a>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/real-page" in links
        assert not any("mailto:" in link for link in links)
        assert not any("tel:" in link for link in links)

    def test_extracts_link_tags(self):
        """<link href='...'> tags (e.g. stylesheets) on same domain should be extracted."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><head>
            <link rel="stylesheet" href="/css/style.css">
        </head><body></body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/css/style.css" in links

    def test_extracts_img_src(self):
        """<img src='...'> tags on the same domain should be extracted."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <img src="/images/logo.png" alt="Logo">
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/images/logo.png" in links

    def test_extracts_iframe_src(self):
        """<iframe src='...'> tags on the same domain should be extracted."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <iframe src="/embed/widget"></iframe>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/embed/widget" in links

    def test_normalizes_extracted_links(self):
        """Extracted links should be normalized (no fragments, trailing slashes, tracking params)."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <a href="/page/#section">Link</a>
            <a href="/other/?utm_source=test">Other</a>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/page" in links
        assert "http://example.com/other" in links

    def test_skips_logout_urls(self):
        """Logout/sign-out links should be skipped to preserve auth sessions."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <a href="/dashboard">Dashboard</a>
            <a href="/logout">Logout</a>
            <a href="/auth/signout">Sign Out</a>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/")
        assert "http://example.com/dashboard" in links
        assert not any("logout" in link for link in links)
        assert not any("signout" in link for link in links)

    def test_resolves_relative_urls(self):
        """Relative URLs should be resolved against the base URL."""
        crawler = _make_crawler("http://example.com")
        html = """
        <html><body>
            <a href="../other">Relative</a>
        </body></html>
        """
        links = crawler._extract_links(html, "http://example.com/dir/page")
        assert "http://example.com/other" in links

    def test_empty_html_returns_empty_set(self):
        """Empty HTML should produce no links."""
        crawler = _make_crawler("http://example.com")
        links = crawler._extract_links("", "http://example.com/")
        assert len(links) == 0

    def test_returns_set_type(self):
        """_extract_links should return a set."""
        crawler = _make_crawler("http://example.com")
        links = crawler._extract_links("<html></html>", "http://example.com/")
        assert isinstance(links, set)


# ═══════════════════════════════════════════════════════════════════
# TestDynamicParamsConstant
# ═══════════════════════════════════════════════════════════════════


class TestDynamicParamsConstant:
    """Verify the _DYNAMIC_PARAMS frozenset contains expected entries."""

    @pytest.mark.parametrize(
        "param",
        [
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
            "fbclid",
            "gclid",
            "t",
            "timestamp",
            "sid",
            "session_id",
            "jsessionid",
            "phpsessid",
        ],
    )
    def test_expected_param_present(self, param):
        """Each known dynamic parameter should be in the frozenset."""
        assert param in Crawler._DYNAMIC_PARAMS

    def test_is_frozenset(self):
        """_DYNAMIC_PARAMS should be a frozenset (immutable)."""
        assert isinstance(Crawler._DYNAMIC_PARAMS, frozenset)
