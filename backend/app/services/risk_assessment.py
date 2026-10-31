"""
TrustShield AI — Cyber Resilience Backend
Risk Assessment Service

Converts raw URLIndicator and MessageIndicator lists into a final
risk score and classification (LOW / MEDIUM / HIGH / UNKNOWN).

Design decisions:
- Score is additive within semantic groups, with per-group caps (F6)
- Group caps prevent double-counting of correlated indicators
- Global cap at 1.0
- Individual contributions are documented and testable
- No indicator double-counts the same underlying signal
- Score is labelled 'rule_based', not a calibrated probability
- UNKNOWN is returned when evidence is insufficient for a reliable verdict (F5)

Upgrade history:
- v1.1: F5 — Integrated UNKNOWN RiskLevel for borderline scores with unavailable TI
- v1.1: F6 — Score group-capping to prevent double-counting correlated indicators
- v1.1: Extended recommendation logic for new indicator codes
"""

from typing import List, Optional
from ..schemas.cyber_schemas import URLIndicator, MessageIndicator, RiskLevel, LookupStatus


# ============================================================
# Risk contribution weights — documented and tunable
# ============================================================
CONTRIBUTION_WEIGHTS = {
    "HIGH": 0.40,
    "MEDIUM": 0.20,
    "LOW": 0.08,
}

# Classification thresholds
THRESHOLD_HIGH = 0.45
THRESHOLD_MEDIUM = 0.28

# Score below which we emit UNKNOWN (instead of LOW) when TI is fully unavailable
# Rationale: a borderline LOW score with no TI verification is not reliable enough
# to assure users the URL is safe.
THRESHOLD_UNKNOWN_MAX = 0.20

# Known limitations string used in all responses
LIMITATIONS_TEXT = (
    "This analysis uses rule-based heuristics and optional threat-intelligence "
    "lookups. It does not use a statistically calibrated machine-learning model. "
    "False positives (legitimate URLs flagged) and false negatives (phishing URLs "
    "missed) are possible. Always apply independent judgement before taking action."
)

# ============================================================
# Score groups — indicators within each group are correlated.
# The combined group contribution is capped at group_cap. (F6)
# This prevents double-counting signals for the same underlying threat.
# ============================================================
SCORE_GROUPS = {
    # Domain impersonation signals often co-occur for the same threat
    "domain_trust": {
        "codes": {
            "URL_STRUCTURE_SUSPICIOUS",
            "URL_BRAND_IN_DOMAIN",
            "URL_IDN_HOSTNAME",
            "URL_IDN_BRAND_HOMOGRAPH",
            "URL_SUSPICIOUS_TLD",
            "URL_MISLEADING_HOSTNAME",
        },
        "group_cap": 0.50,   # max contribution from this entire group
    },
    # Encoding/obfuscation signals
    "obfuscation": {
        "codes": {
            "URL_SUSPICIOUS_ENCODING",
            "URL_NULL_BYTE",
            "URL_DOUBLE_SLASH_REDIRECT",
            "URL_MALFORMED_HOSTNAME",
        },
        "group_cap": 0.30,
    },
    # IP-based routing signals
    "ip_routing": {
        "codes": {
            "URL_IP_ADDRESS_HOST",
            "URL_PRIVATE_IP_HOST",
        },
        "group_cap": 0.50,   # Both can co-occur legitimately on same IP
    },
    # Length signals: only the worse one should score
    "length": {
        "codes": {
            "URL_UNUSUAL_LENGTH",
            "URL_EXTREME_LENGTH",
        },
        "group_cap": 0.40,
    },
}


class RiskAssessor:
    """
    Converts detected indicators into a final risk verdict.

    Key behavioural guarantees:
    - Score is always in [0.0, 1.0]
    - UNKNOWN is returned instead of LOW when TI is fully unavailable
      and evidence is borderline (F5)
    - Correlated indicators within a group are capped to prevent
      score inflation (F6)
    """

    def assess_url(
        self,
        indicators: List[URLIndicator],
        threat_intel_confirmed: bool = False,
        ti_lookup_statuses: Optional[List[LookupStatus]] = None,
    ) -> tuple[RiskLevel, float]:
        """
        Calculate risk level and score from URL indicators.

        Args:
            indicators: URL analysis indicators
            threat_intel_confirmed: True if TI positively confirmed malicious
            ti_lookup_statuses: List of LookupStatus values from all TI sources.
                                 Used to decide whether to emit UNKNOWN (F5).
        """
        if threat_intel_confirmed:
            return RiskLevel.HIGH, 1.0

        score = self._compute_score_with_groups(
            [(ind.code, ind.risk_contribution) for ind in indicators]
        )
        label = self._classify(score)

        # F5: If TI was fully unavailable and the score is borderline LOW,
        # emit UNKNOWN rather than falsely assuring the user.
        if label == RiskLevel.LOW and ti_lookup_statuses:
            all_unavailable = all(
                s in (
                    LookupStatus.ERROR,
                    LookupStatus.TIMEOUT,
                    LookupStatus.NOT_CONFIGURED,
                    LookupStatus.DISABLED,
                )
                for s in ti_lookup_statuses
            )
            if all_unavailable and score <= THRESHOLD_UNKNOWN_MAX:
                return RiskLevel.UNKNOWN, round(score, 4)

        return label, round(score, 4)

    def assess_message(
        self,
        message_indicators: List[MessageIndicator],
        url_labels: List[RiskLevel],
    ) -> tuple[RiskLevel, float]:
        """
        Calculate risk level and score for a message.
        """
        msg_score = self._compute_score(
            [ind.risk_contribution for ind in message_indicators]
        )

        url_scores = [self._label_to_score(lbl) for lbl in url_labels]
        max_url_score = max(url_scores) if url_scores else 0.0

        combined_score = max(msg_score, max_url_score)

        if url_scores and msg_score > 0:
            combined_score = min(1.0, combined_score + 0.10)

        label = self._classify(combined_score)
        return label, round(combined_score, 4)

    def _compute_score(self, contributions: List[str]) -> float:
        """Sum contribution weights, capped at 1.0. No group logic."""
        total = sum(
            CONTRIBUTION_WEIGHTS.get(c.upper(), 0.0)
            for c in contributions
        )
        return min(1.0, total)

    def _compute_score_with_groups(
        self, code_contribution_pairs: List[tuple[str, str]]
    ) -> float:
        """
        Sum contribution weights with per-group caps. (F6)

        For each semantic group, contributions within the group are
        summed and then capped at group_cap before adding to the total.
        Indicators not in any group are added without a group cap.
        """
        # Track which codes have been assigned to a group
        grouped_codes: set[str] = set()
        group_contributions: float = 0.0

        # Build a lookup: code → (group_name, group_def)
        code_to_group = {}
        for group_name, group_def in SCORE_GROUPS.items():
            for code in group_def["codes"]:
                code_to_group[code] = (group_name, group_def)

        # Accumulate per-group scores
        group_scores: dict[str, float] = {}
        ungrouped_total: float = 0.0

        for code, contribution in code_contribution_pairs:
            weight = CONTRIBUTION_WEIGHTS.get(contribution.upper(), 0.0)
            if code in code_to_group:
                group_name, group_def = code_to_group[code]
                group_scores[group_name] = group_scores.get(group_name, 0.0) + weight
                grouped_codes.add(code)
            else:
                ungrouped_total += weight

        # Apply group caps
        for group_name, raw_score in group_scores.items():
            cap = SCORE_GROUPS[group_name]["group_cap"]
            group_contributions += min(raw_score, cap)

        total = group_contributions + ungrouped_total
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
            RiskLevel.UNKNOWN: 0.0,  # UNKNOWN treated conservatively in combination
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
        elif label == RiskLevel.UNKNOWN:
            recs.append(
                "Verification was inconclusive — threat intelligence was unavailable "
                "and heuristic evidence is limited. Treat this URL with caution and "
                "verify through an independent channel before clicking."
            )
        else:
            recs.append(
                "No strong phishing indicators were detected, but always remain "
                "vigilant. Do not enter sensitive information on unexpected pages."
            )

        if "URL_IP_ADDRESS_HOST" in codes or "URL_PRIVATE_IP_HOST" in codes:
            recs.append(
                "The URL uses an IP address as the host. Legitimate services "
                "almost always use domain names. Treat this with high suspicion."
            )
        if "URL_PRIVATE_IP_HOST" in codes:
            recs.append(
                "The IP address is in a private or reserved range. "
                "This could be a server-side request forgery (SSRF) attempt "
                "targeting internal infrastructure."
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
        if "URL_IDN_BRAND_HOMOGRAPH" in codes or "URL_IDN_HOSTNAME" in codes:
            recs.append(
                "The hostname contains non-ASCII characters that may be visually "
                "indistinguishable from legitimate domain names. This is a "
                "sophisticated homograph phishing technique."
            )
        if "URL_REDIRECT_PARAM" in codes:
            recs.append(
                "The URL contains redirect parameters. Verify where the link "
                "ultimately redirects before submitting any information."
            )
        if "URL_NULL_BYTE" in codes:
            recs.append(
                "The URL contains a null byte — this is an injection attack indicator. "
                "Do not click this URL."
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
        if "MSG_BRAND_IMPERSONATION" in codes or "MSG_AUTHORITY_IMPERSONATION" in codes:
            recs.append(
                "This message may impersonate a trusted organisation. "
                "Contact the organisation directly using official contact details "
                "from their official website, not from this message."
            )
        if "MSG_GIFT_CARD_REQUEST" in codes or "MSG_UNTRACEABLE_PAYMENT" in codes:
            recs.append(
                "Requests for gift cards, cryptocurrency, or wire transfers are "
                "hallmark fraud techniques. No legitimate organisation will ask for "
                "payment via these methods."
            )
        if "MSG_LOTTERY_SCAM" in codes or "MSG_INHERITANCE_SCAM" in codes:
            recs.append(
                "Unsolicited prize or inheritance notifications are advance-fee fraud. "
                "You have not won anything — do not pay any 'release fees'."
            )
        if "MSG_TECH_SUPPORT_SCAM" in codes:
            recs.append(
                "Legitimate tech companies do not proactively contact users about "
                "computer problems. Do not call the number provided."
            )

        return recs