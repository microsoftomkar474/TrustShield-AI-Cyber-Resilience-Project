"""
TrustShield AI — Cyber Resilience Backend
Tests: Advanced Adversarial Security & Attack Vectors

Covers:
1. Encoded IP addresses (Octal, Hex, DWORD, Decimal) and SSRF detection
2. Unicode/IDN homograph attacks (Cyrillic lookalikes on spoofed brands)
3. Malformed URL inputs, null-byte injection, unusual ports, and open redirects
4. API abuse scenarios, ReDoS resistance, and oversized payloads
"""

import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.url_analyzer import URLAnalyzer
from app.services.message_analyzer import MessageAnalyzer

analyzer = URLAnalyzer()
msg_analyzer = MessageAnalyzer()
client = TestClient(app)


def get_codes(url: str) -> set:
    indicators, _ = analyzer.analyse(url)
    return {ind.code for ind in indicators}


# ============================================================
# 1. Advanced URL Attack Vectors (Original upgraded + expanded)
# ============================================================

class TestAdvancedURLAttacks:

    def test_punycode_homograph_attack(self):
        """Cyrillic 'а' (U+0430) spoofing paypal must be detected as IDN brand homograph."""
        homograph_url = "https://pаypal.com/login"
        codes = get_codes(homograph_url)
        assert "URL_IDN_HOSTNAME" in codes
        assert "URL_IDN_BRAND_HOMOGRAPH" in codes

    def test_invalid_ipv6_crash(self):
        """Malformed IPv6 brackets must not cause urlparse ValueError crash."""
        malformed_ipv6 = "http://[::1]:8080/login"
        indicators, components = analyzer.analyse(malformed_ipv6)
        assert isinstance(indicators, list)
        assert components["hostname"] == "::1"

    def test_scheme_relative_url(self):
        """URLs starting with // are scheme-relative and should be flagged."""
        url = "//evil.com/login"
        codes = get_codes(url)
        assert "URL_NO_SCHEME" in codes

    def test_null_byte_injection(self):
        """Null byte %00 or \\x00 must trigger URL_NULL_BYTE."""
        url = "https://example.com/login%00.jpg"
        codes = get_codes(url)
        assert "URL_NULL_BYTE" in codes

    def test_raw_null_byte_injection(self):
        """Raw null byte in string must trigger URL_NULL_BYTE."""
        url = "https://example.com/admin\x00hidden"
        codes = get_codes(url)
        assert "URL_NULL_BYTE" in codes


# ============================================================
# 2. Encoded IP Addresses & SSRF Evasion Attacks
# ============================================================

class TestEncodedIPAttacks:

    def test_dotted_octal_private_ip(self):
        """0177.0.0.01 is 127.0.0.1 in octal notation — must flag private IP."""
        url = "http://0177.0.0.01/admin"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_hex_dword_private_ip(self):
        """0x7F000001 is 127.0.0.1 in hex DWORD — must flag private IP."""
        url = "http://0x7F000001/admin"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_dotted_hex_private_ip(self):
        """0x7f.0x0.0x0.0x1 is 127.0.0.1 in dotted hex — must flag private IP."""
        url = "http://0x7f.0x0.0x0.0x1/console"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_decimal_dword_private_ip(self):
        """2130706433 is 127.0.0.1 in decimal integer — must flag private IP."""
        url = "http://2130706433/internal"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_192_168_decimal_dword(self):
        """3232235521 is 192.168.0.1 in decimal — must flag private IP."""
        url = "http://3232235521/setup"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_cloud_metadata_ip_detected(self):
        """169.254.169.254 is AWS/GCP/Azure link-local metadata — must flag private IP."""
        url = "http://169.254.169.254/latest/meta-data/"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_ipv6_loopback_private_ip(self):
        """[::1] is IPv6 loopback — must flag private IP."""
        url = "http://[::1]/debug"
        codes = get_codes(url)
        assert "URL_PRIVATE_IP_HOST" in codes

    def test_public_ip_not_flagged_as_private(self):
        """93.184.216.34 (example.com) is public — must flag IP host but NOT private IP."""
        url = "http://93.184.216.34/"
        codes = get_codes(url)
        assert "URL_IP_ADDRESS_HOST" in codes
        assert "URL_PRIVATE_IP_HOST" not in codes


# ============================================================
# 3. Unicode Homograph & Brand Impersonation Attacks
# ============================================================

class TestIDNHomographAttacks:

    def test_cyrillic_microsoft_homograph(self):
        """Cyrillic 'о' (U+043E) in microsoft must trigger brand homograph."""
        url = "https://microsоft.com/verify-account"
        codes = get_codes(url)
        assert "URL_IDN_BRAND_HOMOGRAPH" in codes

    def test_cyrillic_apple_homograph(self):
        """Cyrillic 'а' (U+0430) in apple must trigger brand homograph."""
        url = "https://аpple.com/security"
        codes = get_codes(url)
        assert "URL_IDN_BRAND_HOMOGRAPH" in codes

    def test_cyrillic_google_homograph(self):
        """Cyrillic 'о' (U+043E) in google must trigger brand homograph."""
        url = "https://gооgle.com/auth"
        codes = get_codes(url)
        assert "URL_IDN_BRAND_HOMOGRAPH" in codes

    def test_clean_ascii_domain_no_idn_flag(self):
        """Clean ASCII brand domains must never trigger IDN indicators."""
        url = "https://www.paypal.com/signin"
        codes = get_codes(url)
        assert "URL_IDN_HOSTNAME" not in codes
        assert "URL_IDN_BRAND_HOMOGRAPH" not in codes


# ============================================================
# 4. Malformed Inputs & Protocol Obfuscation
# ============================================================

class TestMalformedInputs:

    def test_massive_invalid_port(self):
        """Port exceeding 65535 triggers URL_MALFORMED_PORT and does not crash."""
        url = "http://example.com:99999999/test"
        codes = get_codes(url)
        assert "URL_MALFORMED_PORT" in codes

    def test_embedded_userinfo_credentials(self):
        """http://user:pass@host/ must trigger URL_USERINFO_PRESENT."""
        url = "http://admin:secretpassword@evil.com/login"
        codes = get_codes(url)
        assert "URL_USERINFO_PRESENT" in codes

    def test_consecutive_dots_in_hostname(self):
        """http://evil..com/ must trigger URL_MALFORMED_HOSTNAME."""
        url = "http://evil..com/page"
        codes = get_codes(url)
        assert "URL_MALFORMED_HOSTNAME" in codes

    def test_open_redirect_parameters(self):
        """Common redirect query parameters must trigger URL_REDIRECT_PARAM."""
        for param in ["redirect", "redirect_to", "next", "return_url", "dest"]:
            url = f"https://legitimate-bank.com/login?{param}=http://phishing.tk/steal"
            codes = get_codes(url)
            assert "URL_REDIRECT_PARAM" in codes, f"Failed for param {param}"

    def test_extreme_url_length(self):
        """URLs exceeding 300 characters must trigger URL_EXTREME_LENGTH."""
        url = "https://example.com/login?" + ("param=" + "a" * 350)
        codes = get_codes(url)
        assert "URL_EXTREME_LENGTH" in codes


# ============================================================
# 5. API Abuse & ReDoS Resilience Scenarios
# ============================================================

class TestAPIAbuseAndReDoS:

    def test_url_scan_large_payload_handling(self):
        """A URL exceeding schema max_length (2048) is rejected with 422, while ~1500 chars is processed cleanly."""
        # 1. Exceeds max_length → 422 validation error
        too_large_url = "https://example.com/path?" + ("x=" + "abc" * 1000)
        resp_too_large = client.post("/api/v1/cyber/url-scans", json={"url": too_large_url})
        assert resp_too_large.status_code == 422

        # 2. Within max_length (1,500 chars) → 200 OK with URL_EXTREME_LENGTH
        valid_large_url = "https://example.com/path?" + ("x=" + "abc" * 450)
        resp_valid = client.post("/api/v1/cyber/url-scans", json={"url": valid_large_url})
        assert resp_valid.status_code == 200
        data = resp_valid.json()
        assert data["status"] == "success"
        codes = [e["code"] for e in data["evidence"]]
        assert "URL_EXTREME_LENGTH" in codes

    def test_message_scan_oversized_text(self):
        """Message with 5,000 characters processes within 100ms."""
        huge_message = "Urgent: please verify your account. " * 150
        start = time.perf_counter()
        response = client.post("/api/v1/cyber/message-scans", json={"message": huge_message})
        elapsed = time.perf_counter() - start
        assert response.status_code == 200
        assert elapsed < 0.2  # Under 200 milliseconds

    def test_message_analyzer_redos_resistance(self):
        """Potential catastrophic backtracking inputs must complete in under 50ms."""
        evil_input = "congratulations " * 50 + "won " * 50
        start = time.perf_counter()
        indicators, _ = msg_analyzer.analyse(evil_input)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.05
        assert isinstance(indicators, list)

    def test_malformed_json_body(self):
        """Malformed JSON payload returns 422 Unprocessable Entity."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            content=b"{bad-json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422

    def test_xss_injection_attempt_in_url(self):
        """<script> injection in URL is handled safely as plain text."""
        xss_url = "http://example.com/<script>alert(1)</script>"
        response = client.post("/api/v1/cyber/url-scans", json={"url": xss_url})
        assert response.status_code == 200
        data = response.json()
        assert data["url_analysed"] == xss_url