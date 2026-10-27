import pytest
from app.services.incident_assistant import IncidentAssistant

def test_guidance_for_credentials():
    indicators = ["MSG_PASSWORD_REQUEST", "MSG_URGENCY"]
    result = IncidentAssistant.generate_guidance(indicators, context="MESSAGE")
    assert result["severity"] == "CRITICAL"
    titles = [a["title"] for a in result["actions"]]
    assert "Secure Your Accounts" in titles
    assert "Enable Multi-Factor Authentication (MFA)" in titles
    assert "Contact Your Financial Institution" not in titles

def test_guidance_for_financial():
    indicators = ["MSG_BITCOIN", "MSG_SEND_MONEY"]
    result = IncidentAssistant.generate_guidance(indicators, context="MESSAGE")
    titles = [a["title"] for a in result["actions"]]
    assert "Contact Your Financial Institution" in titles

def test_guidance_for_malware():
    indicators = ["URL_IP_ADDRESS_HOST", "URL_SUSPICIOUS_PATH"]
    result = IncidentAssistant.generate_guidance(indicators, context="URL")
    titles = [a["title"] for a in result["actions"]]
    assert "Run a Full System Scan" in titles

def test_guidance_for_benign():
    indicators = ["URL_NOT_HTTPS"]
    result = IncidentAssistant.generate_guidance(indicators, context="URL")
    assert result["severity"] == "HIGH"
    assert len(result["actions"]) == 2  # Contain + Report