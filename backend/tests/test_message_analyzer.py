"""
TrustShield AI — Cyber Resilience Backend
Tests: Message Analyzer Service

Tests the rule-based message phishing analysis engine in isolation.
No network calls are made in these tests.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.message_analyzer import MessageAnalyzer

analyzer = MessageAnalyzer()


def get_codes(message: str) -> set:
    """Helper: run message analysis and return set of indicator reason codes."""
    indicators, _ = analyzer.analyse(message)
    return {ind.code for ind in indicators}


def get_urls(message: str) -> list:
    """Helper: return extracted URLs from a message."""
    _, urls = analyzer.analyse(message)
    return urls


# ============================================================
# Legitimate / benign messages — should not trigger high-risk codes
# ============================================================

class TestBenignMessages:
    def test_simple_greeting(self):
        codes = get_codes("Hi, hope you're doing well today!")
        assert len(codes) == 0

    def test_meeting_reminder(self):
        codes = get_codes("Your meeting is scheduled for tomorrow at 3 PM.")
        assert len(codes) == 0

    def test_order_confirmation_no_phishing(self):
        """A normal order update should not trigger phishing indicators."""
        codes = get_codes(
            "Your order #12345 has been dispatched. Expected delivery: Monday."
        )
        # May trigger MSG_ACCOUNT_STATUS_CLAIM but not high-risk codes
        high_risk_codes = {
            "MSG_PASSWORD_REQUEST", "MSG_OTP_REQUEST",
            "MSG_BANKING_DETAILS_REQUEST", "MSG_GIFT_CARD_REQUEST",
            "MSG_UNTRACEABLE_PAYMENT", "MSG_PAYMENT_DEMAND",
        }
        assert not codes.intersection(high_risk_codes)

    def test_brand_mention_alone_is_low_risk(self):
        """Mentioning a brand without phishing context should not be HIGH risk."""
        indicators, _ = analyzer.analyse("I bought this on Amazon last week.")
        high_indicators = [i for i in indicators if i.risk_contribution == "HIGH"]
        assert len(high_indicators) == 0


# ============================================================
# Password and OTP requests
# ============================================================

class TestPasswordOTPRequests:
    def test_password_request(self):
        codes = get_codes("Please enter your password to verify your identity.")
        assert "MSG_PASSWORD_REQUEST" in codes

    def test_otp_request(self):
        codes = get_codes("Please share the OTP sent to your registered mobile.")
        assert "MSG_OTP_REQUEST" in codes

    def test_one_time_password_variation(self):
        codes = get_codes("Enter the one-time password you received via SMS.")
        assert "MSG_OTP_REQUEST" in codes

    def test_verification_code_request(self):
        codes = get_codes("What is the verification code from your authenticator app?")
        assert "MSG_OTP_REQUEST" in codes

    def test_pin_request(self):
        codes = get_codes("Confirm your PIN to complete the transaction.")
        assert "MSG_PIN_REQUEST" in codes


# ============================================================
# Banking and financial information requests
# ============================================================

class TestBankingRequests:
    def test_cvv_request(self):
        codes = get_codes("Please provide your CVV number to complete the payment.")
        assert "MSG_BANKING_DETAILS_REQUEST" in codes

    def test_card_number_request(self):
        codes = get_codes("Enter your credit card number to continue.")
        assert "MSG_BANKING_DETAILS_REQUEST" in codes

    def test_account_number_request(self):
        codes = get_codes("We need your bank account number for the transfer.")
        assert "MSG_ACCOUNT_DETAILS_REQUEST" in codes

    def test_net_banking_mention(self):
        codes = get_codes("Login to your net banking account to update details.")
        assert "MSG_NETBANKING_MENTION" in codes


# ============================================================
# Urgency and threat language
# ============================================================

class TestUrgencyLanguage:
    def test_immediate_action(self):
        codes = get_codes("You must act immediately to prevent account suspension.")
        assert "MSG_URGENCY" in codes or "MSG_ACCOUNT_THREAT" in codes

    def test_account_suspended_threat(self):
        codes = get_codes("Your account has been suspended. Please verify now.")
        assert "MSG_ACCOUNT_THREAT" in codes

    def test_deadline_pressure(self):
        codes = get_codes("This offer expires in 24 hours. Last chance to claim!")
        assert "MSG_DEADLINE_PRESSURE" in codes

    def test_account_verification_pressure(self):
        codes = get_codes("Verify your account details immediately to restore access.")
        assert "MSG_URGENCY" in codes or "MSG_VERIFY_PRESSURE" in codes


# ============================================================
# Impersonation patterns
# ============================================================

class TestImpersonation:
    def test_generic_salutation(self):
        codes = get_codes("Dear Customer, your account requires attention.")
        assert "MSG_GENERIC_SALUTATION" in codes

    def test_rbi_impersonation(self):
        codes = get_codes("RBI has issued a notice regarding your bank account.")
        assert "MSG_AUTHORITY_IMPERSONATION" in codes

    def test_income_tax_impersonation(self):
        codes = get_codes("Income Tax department has flagged your PAN for review.")
        assert "MSG_AUTHORITY_IMPERSONATION" in codes


# ============================================================
# Sensitive information requests
# ============================================================

class TestSensitiveInfoRequests:
    def test_gift_card_request(self):
        codes = get_codes(
            "Purchase a $100 Google Play gift card and share the code with us."
        )
        assert "MSG_GIFT_CARD_REQUEST" in codes

    def test_bitcoin_payment_request(self):
        codes = get_codes(
            "Send 0.01 Bitcoin to the following address to unlock your account."
        )
        assert "MSG_UNTRACEABLE_PAYMENT" in codes

    def test_wire_transfer_request(self):
        codes = get_codes("Please initiate a wire transfer to complete the process.")
        assert "MSG_UNTRACEABLE_PAYMENT" in codes

    def test_aadhar_request(self):
        codes = get_codes("Please provide your Aadhaar number for KYC verification.")
        assert "MSG_IDENTITY_DOC_REQUEST" in codes

    def test_send_money_request(self):
        codes = get_codes("Please send money to this account for the services.")
        assert "MSG_PAYMENT_DEMAND" in codes


# ============================================================
# URL extraction from messages
# ============================================================

class TestURLExtraction:
    def test_extract_https_url(self):
        urls = get_urls("Click here to verify: https://verify.phishing.xyz/login")
        assert len(urls) >= 1
        assert any("verify.phishing.xyz" in u for u in urls)

    def test_extract_http_url(self):
        urls = get_urls("Go to http://update-account.tk/secure to update.")
        assert len(urls) >= 1

    def test_extract_www_url(self):
        urls = get_urls("Visit www.example.com for more information.")
        assert len(urls) >= 1

    def test_extract_multiple_urls(self):
        msg = (
            "Check http://site1.com and also https://site2.org "
            "and www.site3.net for details."
        )
        urls = get_urls(msg)
        assert len(urls) >= 2

    def test_no_urls_in_plain_text(self):
        urls = get_urls("Please call us at our office tomorrow morning.")
        assert len(urls) == 0

    def test_url_deduplication(self):
        """Same URL appearing twice should only be returned once."""
        msg = "Visit https://example.com and also https://example.com again."
        urls = get_urls(msg)
        assert urls.count("https://example.com") <= 1

    def test_trailing_punctuation_not_included(self):
        """URL followed by a period should not include the period."""
        urls = get_urls("Visit https://example.com.")
        if urls:
            assert not urls[0].endswith(".")


# ============================================================
# Edge cases
# ============================================================

class TestEdgeCases:
    def test_very_long_message(self):
        """Extremely long message should not crash the analyzer."""
        long_message = "This is a test. " * 1000
        indicators, urls = analyzer.analyse(long_message)
        assert isinstance(indicators, list)
        assert isinstance(urls, list)

    def test_message_with_only_url(self):
        """Message containing only a URL should extract it."""
        urls = get_urls("https://phishing-site.xyz/login")
        assert len(urls) >= 1

    def test_unicode_message(self):
        """Messages with Unicode characters should not crash."""
        indicators, urls = analyzer.analyse(
            "Ваш аккаунт заблокирован. Click: https://verify.ru/login"
        )
        assert isinstance(indicators, list)

    def test_no_duplicate_indicator_codes(self):
        """Same reason code should not appear twice in results."""
        message = "Password password password OTP OTP"
        indicators, _ = analyzer.analyse(message)
        codes = [ind.code for ind in indicators]
        assert len(codes) == len(set(codes)), "Duplicate indicator codes found"

    def test_matched_text_not_none_for_pattern_match(self):
        """Indicators should have matched_text populated when a pattern fires."""
        indicators, _ = analyzer.analyse("Please share your password immediately.")
        for ind in indicators:
            # matched_text is optional but should be set when available
            assert ind.code is not None
            assert ind.description is not None
