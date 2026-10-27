import pytest
from app.services.report_generator import ReportGenerator


def test_report_generation_url():
    """Test report generation for a URL scan."""
    scan_data = {
        "label": "HIGH",
        "score": 0.56,
        "evidence": [
            {"code": "URL_IP_ADDRESS_HOST", "description": "IP address used", "risk_contribution": "HIGH"}
        ],
        "threat_intelligence": [
            {"source": "URLhaus", "found": False, "status": "not found", "error": ""}
        ],
        "recommendations": ["Do not click this URL."],
        "url_analysed": "http://192.168.1.1/login",
    }
    report = ReportGenerator.generate("url", scan_data)
    assert report["report_id"].startswith("TS-")
    assert report["scan_type"] == "URL"
    assert report["summary"]["risk_label"] == "HIGH"
    assert len(report["indicators"]) == 1


def test_report_generation_message():
    """Test report generation for a message scan."""
    scan_data = {
        "label": "HIGH",
        "score": 0.98,
        "evidence": [
            {"code": "MSG_PASSWORD_REQUEST", "description": "Password requested", "risk_contribution": "HIGH", "matched_text": "password"}
        ],
        "threat_intelligence": [],
        "recommendations": ["Do not respond to this message."],
        "message_preview": "Your account is suspended.",
    }
    report = ReportGenerator.generate("message", scan_data)
    assert report["scan_type"] == "MESSAGE"
    assert report["summary"]["risk_score"] == 0.98
    assert len(report["indicators"]) == 1