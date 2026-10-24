"""
TrustShield AI — Cyber Resilience Backend
Message Analysis Service

Analyses text messages for phishing indicators.
Also extracts URLs from messages and passes them to URLAnalyzer.

Design decisions:
- Rule-based pattern matching — no ML, fully explainable
- Each rule category is a separate method
- URL extraction uses a conservative regex (avoids false positives)
- A message is NOT flagged high-risk for a single suspicious word alone
- The risk assessor combines message + URL scores fairly
"""

import re
from typing import List, Tuple

from ..schemas.cyber_schemas import MessageIndicator


# ============================================================
# Phishing keyword categories
# ============================================================
# Each entry is (regex_pattern, reason_code, description, contribution)

PASSWORD_OTP_PATTERNS = [
    (r"\bpassword\b", "MSG_PASSWORD_REQUEST",
     "Message requests or mentions a password.", "HIGH"),
    (r"\b(otp|one[- ]time[- ]password|verification[- ]code|auth[- ]code)\b",
     "MSG_OTP_REQUEST",
     "Message requests a one-time password or verification code.", "HIGH"),
    (r"\b(pin|passcode)\b",
     "MSG_PIN_REQUEST",
     "Message requests a PIN or passcode.", "MEDIUM"),
]

BANKING_PATTERNS = [
    (r"\b(cvv|cvc|card[- ]number|credit[- ]card|debit[- ]card)\b",
     "MSG_BANKING_DETAILS_REQUEST",
     "Message requests card details (CVV, card number, etc.).", "HIGH"),
    (r"\b(bank[- ]account|account[- ]number|ifsc|routing[- ]number|sort[- ]code)\b",
     "MSG_ACCOUNT_DETAILS_REQUEST",
     "Message requests bank account information.", "HIGH"),
    (r"\b(net[- ]banking|internet[- ]banking|online[- ]banking)\b",
     "MSG_NETBANKING_MENTION",
     "Message references online banking credentials.", "MEDIUM"),
]

URGENCY_PATTERNS = [
    (r"\b(immediately|urgent|urgently|act[- ]now|right[- ]away|asap|as[- ]soon[- ]as[- ]possible)\b",
     "MSG_URGENCY",
     "Message uses urgent language to pressure quick action.", "MEDIUM"),
    (r"\b(suspended|blocked|locked|disabled|terminated|closed)\b",
     "MSG_ACCOUNT_THREAT",
     "Message threatens account suspension, blocking, or closure.", "MEDIUM"),
    (r"\b(expires?|expiring|last[- ]chance|limited[- ]time|deadline)\b",
     "MSG_DEADLINE_PRESSURE",
     "Message creates artificial time pressure.", "LOW"),
    (r"\b(verify|confirm|validate|authenticate)\b.{0,30}\b(account|identity|details|information)\b",
     "MSG_VERIFY_PRESSURE",
     "Message pressures the reader to verify personal information.", "MEDIUM"),
]

IMPERSONATION_PATTERNS = [
    (r"\b(dear customer|valued customer|dear user|dear member)\b",
     "MSG_GENERIC_SALUTATION",
     "Uses generic salutation ('Dear Customer') typical of mass phishing campaigns.", "LOW"),
    (r"\b(rbi|reserve bank|income tax|irs|hmrc|government)\b",
     "MSG_AUTHORITY_IMPERSONATION",
     "Message claims to be from a government or regulatory authority.", "MEDIUM"),
    (r"\b(paypal|amazon|google|microsoft|apple|netflix|facebook|instagram|whatsapp)\b",
     "MSG_BRAND_IMPERSONATION",
     "Message mentions a major brand, which phishing campaigns often impersonate.", "LOW"),
    (r"\b(your (account|profile|subscription|service) (has been|is|will be))\b",
     "MSG_ACCOUNT_STATUS_CLAIM",
     "Message makes claims about the reader's account status.", "LOW"),
]

SENSITIVE_INFO_PATTERNS = [
    (r"\b(ssn|social security|national id|aadhar|aadhaar|pan number|passport number)\b",
     "MSG_IDENTITY_DOC_REQUEST",
     "Message requests national identity document information.", "HIGH"),
    (r"\b(send (money|payment|funds|transfer))\b",
     "MSG_PAYMENT_DEMAND",
     "Message requests a money transfer or payment.", "HIGH"),
    (r"\b(gift card|itunes card|google play card|amazon card)\b",
     "MSG_GIFT_CARD_REQUEST",
     "Message requests payment via gift cards — a major fraud indicator.", "HIGH"),
    (r"\b(wire transfer|western union|moneygram|crypto|bitcoin|btc|ethereum|eth)\b",
     "MSG_UNTRACEABLE_PAYMENT",
     "Message requests untraceable payment methods (wire transfer, crypto, etc.).", "HIGH"),
]

# Regex to extract URLs from message text
# This pattern is conservative — it prefers precision over recall
URL_EXTRACTION_PATTERN = re.compile(
    r"(?:https?://|www\.)"            # Must start with http/https or www.
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)"  # URL characters
    r"(?<![.,;:!?\'\"])",             # Don't include trailing punctuation
    re.IGNORECASE,
)


class MessageAnalyzer:
    """
    Rule-based message phishing analyser.

    Analyses text for phishing patterns and extracts URLs.
    Does not make network requests.
    """

    def analyse(self, message: str) -> Tuple[List[MessageIndicator], List[str]]:
        """
        Analyse a message for phishing indicators.

        Args:
            message: The raw message text to analyse

        Returns:
            indicators: List of MessageIndicator objects
            extracted_urls: List of URL strings found in the message
        """
        message_lower = message.lower()
        indicators: List[MessageIndicator] = []
        seen_codes = set()  # Prevent duplicate indicators

        # Run all pattern categories
        for pattern_group in [
            PASSWORD_OTP_PATTERNS,
            BANKING_PATTERNS,
            URGENCY_PATTERNS,
            IMPERSONATION_PATTERNS,
            SENSITIVE_INFO_PATTERNS,
        ]:
            for pattern, code, description, contribution in pattern_group:
                if code in seen_codes:
                    continue
                match = re.search(pattern, message_lower)
                if match:
                    indicators.append(MessageIndicator(
                        code=code,
                        description=description,
                        matched_text=self._safe_match_text(message, match),
                        risk_contribution=contribution,
                    ))
                    seen_codes.add(code)

        # Extract URLs
        extracted_urls = self._extract_urls(message)

        return indicators, extracted_urls

    def _extract_urls(self, message: str) -> List[str]:
        """
        Extract URLs from message text.
        Returns a deduplicated list preserving original casing.
        """
        matches = URL_EXTRACTION_PATTERN.findall(message)
        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for url in matches:
            url_lower = url.lower()
            if url_lower not in seen:
                seen.add(url_lower)
                unique_urls.append(url)
        return unique_urls

    @staticmethod
    def _safe_match_text(original_message: str, match) -> str:
        """
        Extract the matched text from the original message (not lowercased).
        Truncates to 100 characters for safety.
        """
        start, end = match.span()
        text = original_message[start:min(end, start + 100)]
        return text
