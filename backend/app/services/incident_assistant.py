"""
TrustShield AI — Cyber Resilience Backend
Incident Assistant Service

Generates personalized, step-by-step containment and recovery advice
based on the specific indicators detected in a URL or message scan.
"""

from typing import List, Dict

class IncidentAssistant:
    """
    Rule-based expert system that translates phishing indicators
    into actionable user guidance.
    """

    @staticmethod
    def generate_guidance(indicators: List[str], context: str = "URL") -> Dict:
        """
        Args:
            indicators: A list of indicator codes (e.g., ["URL_SUSPICIOUS_PATH", "MSG_PASSWORD_REQUEST"])
            context: "URL" or "MESSAGE" to tailor the advice.
        """
        actions = []
        
        # Always start with generic containment
        actions.append({
            "step": 1,
            "title": "Contain the Damage",
            "description": "Immediately disconnect from the internet (turn off Wi-Fi or unplug the ethernet cable). Do not restart the device."
        })

        # Core credential compromise checks
        credential_codes = [
            "MSG_PASSWORD_REQUEST", "MSG_OTP_REQUEST", "MSG_BANKING_REQUEST",
            "URL_SUSPICIOUS_PATH"
        ]
        
        if any(code in indicators for code in credential_codes):
            actions.append({
                "step": len(actions) + 1,
                "title": "Secure Your Accounts",
                "description": "From a different, safe device, immediately change the passwords for any accounts you entered on the suspicious page. Prioritize your email and banking accounts."
            })
            actions.append({
                "step": len(actions) + 1,
                "title": "Enable Multi-Factor Authentication (MFA)",
                "description": "If you haven't already, enable MFA (like an Authenticator app or SMS code) on your email, banking, and social media accounts."
            })

        # Financial threat checks
        financial_codes = [
            "MSG_GIFT_CARD", "MSG_BITCOIN", "MSG_WIRE_TRANSFER", "MSG_SEND_MONEY"
        ]
        
        if any(code in indicators for code in financial_codes):
            actions.append({
                "step": len(actions) + 1,
                "title": "Contact Your Financial Institution",
                "description": "Call your bank or credit card company immediately using the number on the back of your card. Report the suspected fraud and ask them to freeze the affected account."
            })

        # Malware/Download threat checks
        malware_codes = ["URL_MALWARE_DOWNLOAD", "URL_IP_ADDRESS_HOST"]
        
        if any(code in indicators for code in malware_codes):
            actions.append({
                "step": len(actions) + 1,
                "title": "Run a Full System Scan",
                "description": "Use a reputable antivirus or anti-malware tool to run a deep scan on your device. Isolate the device if the scan finds a threat."
            })

        # Reporting
        actions.append({
            "step": len(actions) + 1,
            "title": "Report the Incident",
            "description": "Report the phishing attempt to the relevant authorities (e.g., the platform where you received it, or your local cybercrime reporting center)."
        })

        return {
            "severity": "CRITICAL" if len(actions) > 3 else "HIGH",
            "context": context,
            "actions": actions,
            "disclaimer": "This guidance is based on the indicators detected. It does not guarantee that you are safe. Always consult an IT professional or law enforcement if you are unsure."
        }