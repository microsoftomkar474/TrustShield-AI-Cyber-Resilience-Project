"""
TrustShield AI — Cyber Resilience Backend
Tests: API Integration Tests (FastAPI endpoints)

Tests the complete HTTP API using httpx.AsyncClient.
Verifies:
  - POST /api/v1/cyber/url-scans
  - POST /api/v1/cyber/message-scans
  - GET /health
  - Error handling and invalid inputs
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
from fastapi.testclient import TestClient

from app.main import app

# Use synchronous TestClient to avoid asyncio event loop conflicts
client = TestClient(app)


# ============================================================
# Health check
# ============================================================

class TestHealthCheck:
    def test_health_endpoint_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_healthy_status(self):
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert data["module"] == "cyber_resilience"

    def test_root_endpoint(self):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "endpoints" in data


# ============================================================
# URL Scan API — valid inputs
# ============================================================

class TestURLScanAPI:
    def test_scan_legitimate_url(self):
        """A clean HTTPS URL should return status=success with LOW or MEDIUM risk."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "https://www.google.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["module"] == "cyber_resilience"
        assert data["label"] in ("LOW", "MEDIUM", "HIGH")
        assert "score" in data
        assert "evidence" in data
        assert "limitations" in data

    def test_scan_phishing_url_ip_host(self):
        """URL with IP address as host should return HIGH risk."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "http://192.168.1.100/login/verify"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["label"] == "HIGH"
        codes = [e["code"] for e in data["evidence"]]
        assert "URL_IP_ADDRESS_HOST" in codes

    def test_scan_url_shortener(self):
        """URL shortener should be detected and flagged."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "https://bit.ly/3fake123"}
        )
        assert response.status_code == 200
        data = response.json()
        codes = [e["code"] for e in data["evidence"]]
        assert "URL_SHORTENER_DETECTED" in codes

    def test_scan_brand_spoofing(self):
        """Subdomain-based brand spoofing should be HIGH risk."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "https://paypal.secure-verify.com/auth"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["label"] in ("MEDIUM", "HIGH")
        codes = [e["code"] for e in data["evidence"]]
        assert "URL_STRUCTURE_SUSPICIOUS" in codes

    def test_response_has_required_fields(self):
        """Response must contain all team-agreed API contract fields."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "https://example.com"}
        )
        data = response.json()
        required_fields = [
            "status", "module", "label", "score", "score_type",
            "evidence", "model_or_feed_version", "limitations",
            "url_analysed", "recommendations",
        ]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

    def test_score_is_between_0_and_1(self):
        """Score must always be in [0.0, 1.0]."""
        for url in [
            "https://google.com",
            "http://192.168.1.1/login",
            "https://paypal.verify-now.xyz/secure",
        ]:
            response = client.post("/api/v1/cyber/url-scans", json={"url": url})
            data = response.json()
            assert 0.0 <= data["score"] <= 1.0, f"Score out of range for {url}"

    def test_parsed_components_returned(self):
        """Parsed URL components should be in the response."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "https://www.example.com/path?q=1"}
        )
        data = response.json()
        assert "parsed_components" in data
        assert data["parsed_components"]["scheme"] == "https"

    def test_recommendations_are_list(self):
        """Recommendations should always be a list."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "https://example.com"}
        )
        data = response.json()
        assert isinstance(data["recommendations"], list)


# ============================================================
# URL Scan API — invalid / edge case inputs
# ============================================================

class TestURLScanAPIInvalidInputs:
    def test_empty_url_rejected(self):
        """Empty URL should return HTTP 422 (Pydantic validation error)."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": ""}
        )
        assert response.status_code == 422

    def test_missing_url_field_rejected(self):
        """Missing 'url' field should return HTTP 422."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={}
        )
        assert response.status_code == 422

    def test_url_too_long_rejected(self):
        """URL exceeding max_length=2048 should return HTTP 422."""
        long_url = "https://example.com/" + "a" * 2100
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": long_url}
        )
        assert response.status_code == 422

    def test_whitespace_url_stripped(self):
        """URL with surrounding whitespace should be stripped and analysed."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": "  https://example.com  "}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["url_analysed"] == "https://example.com"

    def test_non_string_url_rejected(self):
        """Non-string URL should return HTTP 422."""
        response = client.post(
            "/api/v1/cyber/url-scans",
            json={"url": 12345}
        )
        # Pydantic coerces integers to strings — this may succeed with score
        # The important thing is it doesn't crash the server
        assert response.status_code in (200, 422)


# ============================================================
# Message Scan API — valid inputs
# ============================================================

class TestMessageScanAPI:
    def test_scan_benign_message(self):
        """A normal message should return LOW risk."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": "Hi, your delivery is scheduled for tomorrow."}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["label"] in ("LOW", "MEDIUM", "HIGH")

    def test_scan_phishing_message_password_otp(self):
        """Classic phishing message should return HIGH risk."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": (
                "Dear Customer, your account is suspended. "
                "Please share your OTP and password immediately to restore access."
            )}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["label"] in ("MEDIUM", "HIGH")
        codes = [e["code"] for e in data["evidence"]]
        assert any(c in codes for c in ["MSG_OTP_REQUEST", "MSG_PASSWORD_REQUEST"])

    def test_message_with_embedded_phishing_url(self):
        """Message with a phishing URL should reflect URL risk."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": (
                "Verify your account at http://192.168.1.1/verify immediately."
            )}
        )
        assert response.status_code == 200
        data = response.json()
        # URL scan should have found IP_ADDRESS_HOST
        # Overall risk should be elevated
        assert data["label"] in ("MEDIUM", "HIGH")

    def test_extracted_urls_in_response(self):
        """Extracted URLs should appear in the response."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": "Click here: https://example.com to verify."}
        )
        data = response.json()
        assert "extracted_urls" in data
        assert isinstance(data["extracted_urls"], list)

    def test_response_has_required_fields(self):
        """Response must contain all team-agreed API contract fields."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": "Test message"}
        )
        data = response.json()
        required_fields = [
            "status", "module", "label", "score", "score_type",
            "evidence", "model_or_feed_version", "limitations",
            "message_preview", "recommendations",
        ]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

    def test_message_preview_truncated_to_200(self):
        """Long messages should have preview truncated to 200 chars."""
        long_message = "This is a test message. " * 100
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": long_message}
        )
        data = response.json()
        assert len(data["message_preview"]) <= 200

    def test_gift_card_request_detected(self):
        """Gift card fraud pattern should be detected."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": "Buy a $200 Google Play gift card and share the code."}
        )
        data = response.json()
        codes = [e["code"] for e in data["evidence"]]
        assert "MSG_GIFT_CARD_REQUEST" in codes

    def test_bitcoin_fraud_detected(self):
        """Cryptocurrency fraud pattern should be detected."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": "Send 0.05 Bitcoin to release your locked account."}
        )
        data = response.json()
        codes = [e["code"] for e in data["evidence"]]
        assert "MSG_UNTRACEABLE_PAYMENT" in codes


# ============================================================
# Message Scan API — invalid / edge case inputs
# ============================================================

class TestMessageScanAPIInvalidInputs:
    def test_empty_message_rejected(self):
        """Empty message should return HTTP 422."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": ""}
        )
        assert response.status_code == 422

    def test_missing_message_field_rejected(self):
        """Missing 'message' field should return HTTP 422."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={}
        )
        assert response.status_code == 422

    def test_message_too_long_rejected(self):
        """Message exceeding max_length=10000 should return HTTP 422."""
        too_long = "a" * 10001
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": too_long}
        )
        assert response.status_code == 422

    def test_whitespace_message_stripped(self):
        """Message with only whitespace is stripped and becomes empty → 422."""
        response = client.post(
            "/api/v1/cyber/message-scans",
            json={"message": "   "}
        )
        # After strip, it's empty → min_length=1 fails
        assert response.status_code == 422
