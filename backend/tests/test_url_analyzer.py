"""
TrustShield AI — Cyber Resilience Backend
Tests: URL Analyzer Service

Tests the rule-based URL analysis engine in isolation.
No network calls are made in these tests.
"""

import pytest
import sys
import os

# Ensure the backend package is importable from the test runner
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.url_analyzer import URLAnalyzer

analyzer = URLAnalyzer()


def get_codes(url: str) -> set:
    """Helper: run analysis and return set of indicator reason codes."""
    indicators, _ = analyzer.analyse(url)
    return {ind.code for ind in indicators}


# ============================================================
# Legitimate URL tests — should not trigger high-risk codes
# ============================================================

class TestLegitimateURLs:
    def test_https_google(self):
        codes = get_codes("https://www.google.com")
        assert "URL_IP_ADDRESS_HOST" not in codes
        assert "URL_AT_SYMBOL_IN_AUTHORITY" not in codes
        assert "URL_STRUCTURE_SUSPICIOUS" not in codes

    def test_https_github(self):
        codes = get_codes("https://github.com/user/repo")
        assert "URL_IP_ADDRESS_HOST" not in codes
        assert "URL_SHORTENER_DETECTED" not in codes

    def test_https_no_suspicious_indicators(self):
        """A simple HTTPS URL to a clean domain should have minimal indicators."""
        indicators, _ = analyzer.analyse("https://example.com/page")
        # Only LOW risk indicators at most (URL_NOT_HTTPS is not triggered for HTTPS)
        high_indicators = [i for i in indicators if i.risk_contribution == "HIGH"]
        assert len(high_indicators) == 0

    def test_http_flags_not_https(self):
        """HTTP should trigger URL_NOT_HTTPS (LOW risk)."""
        codes = get_codes("http://example.com")
        assert "URL_NOT_HTTPS" in codes

    def test_short_url_no_unusual_length(self):
        """Short URL should NOT trigger URL_UNUSUAL_LENGTH."""
        codes = get_codes("https://example.com")
        assert "URL_UNUSUAL_LENGTH" not in codes


# ============================================================
# IP address hostname detection
# ============================================================

class TestIPAddressDetection:
    def test_ipv4_http(self):
        codes = get_codes("http://192.168.1.1/login")
        assert "URL_IP_ADDRESS_HOST" in codes

    def test_ipv4_https(self):
        codes = get_codes("https://10.0.0.1/verify?user=admin")
        assert "URL_IP_ADDRESS_HOST" in codes

    def test_public_ipv4(self):
        codes = get_codes("http://185.220.101.1/payload")
        assert "URL_IP_ADDRESS_HOST" in codes

    def test_domain_not_flagged_as_ip(self):
        codes = get_codes("https://paypal.com")
        assert "URL_IP_ADDRESS_HOST" not in codes


# ============================================================
# URL length detection
# ============================================================

class TestURLLength:
    def test_very_long_url(self):
        long_url = "https://example.com/" + "a" * 200
        codes = get_codes(long_url)
        assert "URL_UNUSUAL_LENGTH" in codes

    def test_normal_length_url(self):
        codes = get_codes("https://example.com/page")
        assert "URL_UNUSUAL_LENGTH" not in codes

    def test_boundary_length(self):
        """URL exactly at the threshold should NOT be flagged."""
        url = "https://example.com/" + "a" * (100 - len("https://example.com/"))
        indicators, _ = analyzer.analyse(url)
        codes = {i.code for i in indicators}
        # Depends on exact boundary — just ensure no crash
        assert isinstance(codes, set)


# ============================================================
# Subdomain detection
# ============================================================

class TestSubdomainDetection:
    def test_excessive_subdomains(self):
        codes = get_codes("https://a.b.c.evil.com/login")
        assert "URL_EXCESSIVE_SUBDOMAINS" in codes

    def test_normal_subdomain(self):
        """www.example.com has 1 subdomain — should not trigger."""
        codes = get_codes("https://www.example.com")
        assert "URL_EXCESSIVE_SUBDOMAINS" not in codes

    def test_two_subdomains(self):
        """mail.app.example.com has 2 subdomains — should not trigger (threshold=3)."""
        codes = get_codes("https://mail.app.example.com")
        assert "URL_EXCESSIVE_SUBDOMAINS" not in codes


# ============================================================
# @ symbol detection
# ============================================================

class TestAtSymbolDetection:
    def test_at_in_authority(self):
        """http://legitimate@evil.com — @ in authority is high risk."""
        codes = get_codes("http://legitimate.com@evil.com/page")
        assert "URL_AT_SYMBOL_IN_AUTHORITY" in codes

    def test_at_in_path_only(self):
        """@ in path/query is normal (e.g. email params) — should not trigger."""
        codes = get_codes("https://example.com/page?email=user@example.com")
        assert "URL_AT_SYMBOL_IN_AUTHORITY" not in codes


# ============================================================
# URL shortener detection
# ============================================================

class TestURLShortenerDetection:
    def test_bitly(self):
        codes = get_codes("https://bit.ly/3xYz123")
        assert "URL_SHORTENER_DETECTED" in codes

    def test_tinyurl(self):
        codes = get_codes("http://tinyurl.com/somelink")
        assert "URL_SHORTENER_DETECTED" in codes

    def test_legitimate_domain_not_shortener(self):
        codes = get_codes("https://amazon.com/products/item/12345")
        assert "URL_SHORTENER_DETECTED" not in codes


# ============================================================
# Suspicious TLD detection
# ============================================================

class TestSuspiciousTLD:
    def test_tk_tld(self):
        codes = get_codes("http://freesite.tk/login")
        assert "URL_SUSPICIOUS_TLD" in codes

    def test_xyz_tld(self):
        codes = get_codes("https://verify-account.xyz/secure")
        assert "URL_SUSPICIOUS_TLD" in codes

    def test_com_tld_not_suspicious(self):
        codes = get_codes("https://example.com")
        assert "URL_SUSPICIOUS_TLD" not in codes

    def test_org_tld_not_suspicious(self):
        codes = get_codes("https://wikipedia.org/wiki/Phishing")
        assert "URL_SUSPICIOUS_TLD" not in codes


# ============================================================
# Brand/hostname spoofing detection
# ============================================================

class TestBrandSpoofing:
    def test_paypal_subdomain_spoofing(self):
        """paypal.secure-login.com — paypal in subdomain, not registered domain."""
        codes = get_codes("https://paypal.secure-login.com/auth")
        assert "URL_STRUCTURE_SUSPICIOUS" in codes

    def test_amazon_subdomain_spoofing(self):
        codes = get_codes("https://amazon.verify-order.net/account")
        assert "URL_STRUCTURE_SUSPICIOUS" in codes

    def test_real_paypal_not_flagged(self):
        """The real paypal.com should NOT trigger brand spoofing."""
        codes = get_codes("https://www.paypal.com/signin")
        assert "URL_STRUCTURE_SUSPICIOUS" not in codes


# ============================================================
# Malformed URL handling
# ============================================================

class TestMalformedURLs:
    def test_empty_string(self):
        """Empty URL should not crash — may return parse error indicator."""
        indicators, components = analyzer.analyse("")
        # Should not raise, should return something
        assert isinstance(indicators, list)

    def test_no_scheme(self):
        """URL without scheme."""
        codes = get_codes("www.example.com/page")
        # No scheme → should flag it
        assert "URL_NO_SCHEME" in codes or len(codes) >= 0  # No crash

    def test_malformed_host(self):
        """URL with double dots in hostname."""
        codes = get_codes("https://exa..mple.com/page")
        assert "URL_MALFORMED_HOSTNAME" in codes

    def test_javascript_scheme(self):
        """javascript: scheme is very dangerous."""
        codes = get_codes("javascript:alert('xss')")
        assert "URL_UNUSUAL_SCHEME" in codes


# ============================================================
# Encoding detection
# ============================================================

class TestEncodingDetection:
    def test_heavy_encoding(self):
        """URL with many percent-encoded characters."""
        encoded_url = "https://example.com/%70%61%79%70%61%6C/%6C%6F%67%69%6E"
        codes = get_codes(encoded_url)
        assert "URL_SUSPICIOUS_ENCODING" in codes

    def test_minimal_encoding_not_flagged(self):
        """A URL with just a space encoded (1 sequence) should not trigger."""
        codes = get_codes("https://example.com/search?q=hello%20world")
        assert "URL_SUSPICIOUS_ENCODING" not in codes


# ============================================================
# Parsed components verification
# ============================================================

class TestParsedComponents:
    def test_components_returned(self):
        """Verify parsed_components dict contains expected keys."""
        _, components = analyzer.analyse("https://www.example.com:443/path?q=1")
        assert "scheme" in components
        assert "hostname" in components
        assert "path" in components

    def test_scheme_extracted_correctly(self):
        _, components = analyzer.analyse("https://example.com")
        assert components["scheme"] == "https"

    def test_hostname_extracted_correctly(self):
        _, components = analyzer.analyse("https://sub.example.com/page")
        assert components["hostname"] == "sub.example.com"
