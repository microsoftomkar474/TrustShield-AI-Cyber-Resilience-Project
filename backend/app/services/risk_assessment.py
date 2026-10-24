"""
TrustShield AI — Cyber Resilience Backend
Risk Assessment Service

Converts raw URLIndicator and MessageIndicator lists into a final
risk score and classification (LOW / MEDIUM / HIGH).

Design decisions:
- Score is additive with a cap at 1.0
- Individual contributions are documented and testable
- No indicator double-counts the same underlying signal
- Thresholds are explicit constants — easy to tune
- Score is labelled 'rule_based', not a calibrated probability
"""

from typing import List
from ..schemas.cyber_schemas import URLIndicator, MessageIndicator, RiskLevel


# ============================================================
# Risk contribution weights — documented and tunable
# ============================================================
#
# These weights assign a numeric score contribution to each
# risk_contribution level. They were chosen to reflect relative
# severity:
#   HIGH   → a single indicator of this type can push into MEDIUM
#   MEDIUM → meaningful concern, several needed for HIGH classification
#   LOW    → contextual signal, many needed to cross a threshold
#
CONTRIBUTION_WEIGHTS = {
    "HIGH": 0.40,
    "MEDIUM": 0.20,
    "LOW": 0.08,
}

# Classification thresholds
# Chosen to balance sensitivity vs. false positives for rule-based analysis.
THRESHOLD_HIGH = 0.45    # score >= 0.45 → HIGH risk
                         # Rationale: a single HIGH-weight indicator (0.40) +
                         # any LOW indicator (0.08) = 0.48 correctly classifies
                         # as HIGH. A standalone HIGH indicator (0.40) alone
                         # falls into MEDIUM, which is intentionally conservative.
THRESHOLD_MEDIUM = 0.28  # score >= 0.28 → MEDIUM risk
# Below THRESHOLD_MEDIUM → LOW risk

# Known limitations string used in all responses
LIMITATIONS_TEXT = (
    "This analysis uses rule-based heuristics and optional threat-intelligence "
    "lookups. It does not use a statistically calibrated machine-learning model. "
    "False positives (legitimate URLs flagged) and false negatives (phishing URLs "
    "missed) are possible. Always apply independent judgement before taking action."
)


class RiskAssessor:
    """
    Converts detected indicators into a final risk verdict.

    Usage:
        assessor = RiskAssessor()
        label, score = assessor.assess_url(indicators)
    """

    def assess_url(
        self,
        indicators: List[URLIndicator],
        threat_intel_confirmed: bool = False,
    ) -> tuple[RiskLevel, float]:
        """
        Calculate risk level and score from URL indicators.

        Args:
            indicators: List of URLIndicator objects from URLAnalyzer
            threat_intel_confirmed: True if a TI feed positively matched

        Returns:
            (RiskLevel, float) — classification and score in [0.0, 1.0]
        """
        if threat_intel_confirmed:
            # Threat intel match overrides rule-based score
            return RiskLevel.HIGH, 1.0

        score = self._compute_score(
            [ind.risk_contribution for ind in indicators]
        )
        label = self._classify(score)
        return label, round(score, 4)

    def assess_message(
        self,
        message_indicators: List[MessageIndicator],
        url_labels: List[RiskLevel],
    ) -> tuple[RiskLevel, float]:
        """
        Calculate risk level and score for a message.

        The overall message score is the maximum of:
          1. Score from message-level indicators
          2. Highest URL risk score (if any URLs were analysed)

        This avoids double-counting when a message has both suspicious
        text and suspicious URLs.

        Args:
            message_indicators: Indicators from MessageAnalyzer
            url_labels: RiskLevel values from analysed embedded URLs

        Returns:
            (RiskLevel, float)
        """
        msg_score = self._compute_score(
            [ind.risk_contribution for ind in message_indicators]
        )

        # Convert URL labels to scores for comparison
        url_scores = [self._label_to_score(lbl) for lbl in url_labels]
        max_url_score = max(url_scores) if url_scores else 0.0

        # Take the higher of message score and highest URL score
        combined_score = max(msg_score, max_url_score)

        # But if both message AND URL signals exist, add a small penalty
        # to reflect the compounding risk — capped at 1.0
        if url_scores and msg_score > 0:
            combined_score = min(1.0, combined_score + 0.10)

        label = self._classify(combined_score)
        return label, round(combined_score, 4)

    # ----------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------

    def _compute_score(self, contributions: List[str]) -> float:
        """Sum contribution weights, capped at 1.0."""
        total = sum(
            CONTRIBUTION_WEIGHTS.get(c.upper(), 0.0)
            for c in contributions
        )
        return min(1.0, total)

    def _classify(self, score: float) -> RiskLevel:
        """Map numeric score to risk label using documented thresholds."""
        if score >= THRESHOLD_HIGH:
            return RiskLevel.HIGH
        elif score >= THRESHOLD_MEDIUM:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _label_to_score(self, label: RiskLevel) -> float:
        """Convert a risk label back to a reference score for comparison."""
        mapping = {
            RiskLevel.HIGH: THRESHOLD_HIGH,
            RiskLevel.MEDIUM: THRESHOLD_MEDIUM,
            RiskLevel.LOW: 0.0,
        }
        return mapping.get(label, 0.0)

    @staticmethod
    def get_url_recommendations(
        label: RiskLevel, indicators: List[URLIndicator]
    ) -> List[str]:
        """Generate actionable recommendations based on analysis results."""
        codes = {ind.code for ind in indicators}
        recs = []

        if label == RiskLevel.HIGH:
            recs.append(
                "Do NOT click this URL. The analysis found multiple strong indicators "
                "of phishing or malicious intent."
            )
            recs.append(
                "If you received this URL unexpectedly, report it to your IT security "
                "team or the relevant platform (e.g. email provider)."
            )
        elif label == RiskLevel.MEDIUM:
            recs.append(
                "Exercise caution. Independently verify this URL before clicking "
                "by contacting the organisation directly through their official website."
            )
        else:
            recs.append(
                "No strong phishing indicators were detected, but always remain "
                "vigilant. Do not enter sensitive information on unexpected pages."
            )

        # Code-specific recommendations
        if "URL_IP_ADDRESS_HOST" in codes:
            recs.append(
                "The URL uses an IP address as the host. Legitimate services "
                "almost always use domain names. Treat this with high suspicion."
            )
        if "URL_SHORTENER_DETECTED" in codes:
            recs.append(
                "Expand shortened URLs before clicking using a service like "
                "CheckShortURL (https://www.checkshorturl.com) or Unshorten.it."
            )
        if "URL_NOT_HTTPS" in codes:
            recs.append(
                "This URL uses HTTP (not HTTPS). Never submit passwords or "
                "financial information on HTTP pages."
            )
        if "URL_STRUCTURE_SUSPICIOUS" in codes or "URL_BRAND_IN_DOMAIN" in codes:
            recs.append(
                "The URL appears to impersonate a well-known brand. "
                "Always check the actual registered domain, not just the subdomain."
            )

        return recs

    @staticmethod
    def get_message_recommendations(
        label: RiskLevel, indicators: List[MessageIndicator]
    ) -> List[str]:
        """Generate actionable recommendations for suspicious messages."""
        codes = {ind.code for ind in indicators}
        recs = []

        if label == RiskLevel.HIGH:
            recs.append(
                "Do NOT respond to, click links in, or comply with this message. "
                "It shows strong indicators of a phishing or social-engineering attempt."
            )
            recs.append(
                "Report this message to the relevant platform, your IT team, "
                "or national cybercrime reporting services."
            )
        elif label == RiskLevel.MEDIUM:
            recs.append(
                "This message contains suspicious elements. Verify the sender's "
                "identity through an independent channel before taking any action."
            )
        else:
            recs.append(
                "No strong phishing indicators found. Stay alert and avoid sharing "
                "sensitive information in response to unsolicited messages."
            )

        if "MSG_PASSWORD_REQUEST" in codes or "MSG_OTP_REQUEST" in codes:
            recs.append(
                "Legitimate organisations NEVER ask for passwords or OTPs via "
                "message. This is a definitive phishing technique."
            )
        if "MSG_URGENCY" in codes:
            recs.append(
                "Artificial urgency ('act now', 'your account will be closed') is a "
                "classic social-engineering technique to prevent careful thinking."
            )
        if "MSG_IMPERSONATION" in codes:
            recs.append(
                "This message may impersonate a trusted organisation. "
                "Contact the organisation directly using official contact details "
                "from their official website, not from this message."
            )

        return recs
