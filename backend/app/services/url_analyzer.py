"""
TrustShield AI — Cyber Resilience Backend
URL Analysis Service

Analyses a URL for phishing indicators using rule-based heuristics.
Uses only urllib.parse (stdlib) for URL parsing — no external HTTP calls.

Design decisions:
- Each check is a separate method → easy to test individually
- Returns a list of URLIndicator objects + a raw score list
- The risk_assessment service converts those into the final verdict
- No indicator is treated as definitive proof on its own
"""

import re
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Any, Tuple

from ..schemas.cyber_schemas import URLIndicator, RiskLevel


# ============================================================
# Known URL shortener domains
# ============================================================
URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "shorturl.at", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "rb.gy", "dl.cl", "short.io", "tiny.cc", "lnkd.in",
    "bl.ink", "snip.ly", "clck.ru", "1url.com", "yourls.org",
})

# Suspicious TLDs that frequently appear in phishing campaigns
SUSPICIOUS_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free Freenom domains
    ".xyz", ".top", ".club", ".online", ".site", ".icu", ".buzz",
})

# Legitimate brand names often spoofed in phishing hostnames
SPOOFED_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "twitter", "x.com",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hdfc", "icici",
    "sbi", "axis", "kotak", "paytm", "phonepe", "gpay",
    "uber", "ola", "swiggy", "zomato",
]


class URLAnalyzer:
    """
    Rule-based URL phishing analyzer.

    Each public method returns a list of URLIndicator objects.
    The caller (risk_assessment) aggregates these into a final verdict.
    """

    # Maximum URL length before triggering the unusual-length indicator
    UNUSUAL_LENGTH_THRESHOLD = 100
    # Maximum number of subdomains before triggering excessive-subdomains
    EXCESSIVE_SUBDOMAIN_THRESHOLD = 3
    # Ports that are unusual for HTTP/HTTPS traffic
    UNUSUAL_PORTS = frozenset({
        8080, 8443, 8888, 9090, 3000, 4000, 5000, 7000, 9000,
        1080, 1234, 2020, 2121, 2222, 4444, 6666, 7777, 8008,
    })

    def analyse(self, url: str) -> Tuple[List[URLIndicator], Dict[str, Any]]:
        """
        Run all URL checks and return indicators + parsed components.

        Returns:
            indicators: List of URLIndicator objects (one per detected issue)
            parsed: Dict with key URL components for the response
        """
        indicators: List[URLIndicator] = []

        # --- Parse the URL ---
        try:
            parsed = urlparse(url)
        except Exception:
            indicators.append(URLIndicator(
                code="URL_PARSE_FAILED",
                description="The URL could not be parsed. It may be malformed.",
                risk_contribution="HIGH",
            ))
            return indicators, {}

        components = {
            "scheme": parsed.scheme,
            "hostname": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "full_url": url,
        }

        hostname = (parsed.hostname or "").lower()

        # Run all individual checks
        indicators.extend(self._check_scheme(parsed, url))
        indicators.extend(self._check_ip_hostname(hostname))
        indicators.extend(self._check_url_length(url))
        indicators.extend(self._check_subdomains(hostname))
        indicators.extend(self._check_at_symbol(parsed))
        indicators.extend(self._check_port(parsed))
        indicators.extend(self._check_encoding(url))
        indicators.extend(self._check_misleading_hostname(hostname))
        indicators.extend(self._check_url_shortener(hostname))
        indicators.extend(self._check_suspicious_tld(hostname))
        indicators.extend(self._check_suspicious_path_keywords(parsed.path))
        indicators.extend(self._check_double_slash_redirect(url))
        indicators.extend(self._check_multiple_dots(hostname))

        return indicators, components

    # ----------------------------------------------------------
    # Individual check methods — each returns List[URLIndicator]
    # ----------------------------------------------------------

    def _check_scheme(
        self, parsed, url: str
    ) -> List[URLIndicator]:
        """Detect non-HTTPS schemes and missing schemes."""
        results = []
        scheme = parsed.scheme.lower() if parsed.scheme else ""

        if not scheme:
            results.append(URLIndicator(
                code="URL_NO_SCHEME",
                description=(
                    "No URL scheme detected (e.g. http:// or https://). "
                    "This may indicate a malformed or relative URL."
                ),
                risk_contribution="MEDIUM",
            ))
        elif scheme not in ("http", "https"):
            results.append(URLIndicator(
                code="URL_UNUSUAL_SCHEME",
                description=(
                    f"Unusual URL scheme '{scheme}' detected. "
                    "Legitimate web URLs use http:// or https://."
                ),
                risk_contribution="HIGH",
            ))
        elif scheme == "http":
            results.append(URLIndicator(
                code="URL_NOT_HTTPS",
                description=(
                    "URL uses plain HTTP (not HTTPS). "
                    "Sensitive operations should always use HTTPS."
                ),
                risk_contribution="LOW",
            ))
        return results

    def _check_ip_hostname(self, hostname: str) -> List[URLIndicator]:
        """Detect IP address used as hostname instead of domain name."""
        if not hostname:
            return []
        try:
            ipaddress.ip_address(hostname)
            return [URLIndicator(
                code="URL_IP_ADDRESS_HOST",
                description=(
                    f"The URL uses an IP address ({hostname}) as the hostname "
                    "instead of a domain name. Legitimate services rarely do this."
                ),
                risk_contribution="HIGH",
            )]
        except ValueError:
            return []

    def _check_url_length(self, url: str) -> List[URLIndicator]:
        """Flag unusually long URLs."""
        if len(url) > self.UNUSUAL_LENGTH_THRESHOLD:
            return [URLIndicator(
                code="URL_UNUSUAL_LENGTH",
                description=(
                    f"URL is {len(url)} characters long "
                    f"(threshold: {self.UNUSUAL_LENGTH_THRESHOLD}). "
                    "Phishing URLs often use long strings to hide the real destination."
                ),
                risk_contribution="LOW",
            )]
        return []

    def _check_subdomains(self, hostname: str) -> List[URLIndicator]:
        """Detect excessive subdomain depth."""
        if not hostname:
            return []
        parts = hostname.split(".")
        # Subtract 2 for the domain + TLD (e.g. "example.com")
        subdomain_count = max(0, len(parts) - 2)
        if subdomain_count >= self.EXCESSIVE_SUBDOMAIN_THRESHOLD:
            return [URLIndicator(
                code="URL_EXCESSIVE_SUBDOMAINS",
                description=(
                    f"The hostname has {subdomain_count} subdomain level(s). "
                    "Phishing sites sometimes use many subdomains to appear legitimate "
                    "while the actual domain is malicious."
                ),
                risk_contribution="MEDIUM",
            )]
        return []

    def _check_at_symbol(self, parsed) -> List[URLIndicator]:
        """
        Detect @ in URL — browsers ignore everything before @ in the authority.
        E.g. http://legit.com@evil.com/ actually takes you to evil.com.
        """
        # netloc includes user info if present
        if parsed.netloc and "@" in parsed.netloc:
            return [URLIndicator(
                code="URL_AT_SYMBOL_IN_AUTHORITY",
                description=(
                    "The URL contains an '@' symbol in the authority section. "
                    "Browsers ignore text before '@', so "
                    "'http://legitimate.com@evil.com' actually visits evil.com. "
                    "This is a classic phishing technique."
                ),
                risk_contribution="HIGH",
            )]
        return []

    def _check_port(self, parsed) -> List[URLIndicator]:
        """Flag non-standard ports."""
        if parsed.port and parsed.port in self.UNUSUAL_PORTS:
            return [URLIndicator(
                code="URL_UNUSUAL_PORT",
                description=(
                    f"URL uses port {parsed.port}. "
                    "Legitimate websites typically use port 443 (HTTPS) or 80 (HTTP). "
                    "Unusual ports may indicate malicious infrastructure."
                ),
                risk_contribution="MEDIUM",
            )]
        return []

    def _check_encoding(self, url: str) -> List[URLIndicator]:
        """Detect suspicious percent-encoding that may obscure the real URL."""
        # Count percent-encoded sequences
        encoded_sequences = re.findall(r"%[0-9A-Fa-f]{2}", url)
        if len(encoded_sequences) >= 3:
            decoded = unquote(url)
            return [URLIndicator(
                code="URL_SUSPICIOUS_ENCODING",
                description=(
                    f"URL contains {len(encoded_sequences)} percent-encoded sequence(s). "
                    "Heavy encoding can be used to hide malicious content from "
                    "security filters. Decoded form: "
                    f"{decoded[:100]}{'...' if len(decoded) > 100 else ''}"
                ),
                risk_contribution="MEDIUM",
            )]
        return []

    def _check_misleading_hostname(self, hostname: str) -> List[URLIndicator]:
        """
        Detect brand names embedded in hostnames in potentially misleading ways.
        E.g. paypal-secure-login.com (paypal in subdomain of another domain).
        """
        if not hostname:
            return []
        results = []
        parts = hostname.split(".")
        # The actual registered domain is the last two parts
        registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        subdomains_str = ".".join(parts[:-2]) if len(parts) > 2 else ""

        for brand in SPOOFED_BRANDS:
            # Brand appears in subdomain but NOT as the actual registered domain
            if brand in subdomains_str and brand not in registered_domain:
                results.append(URLIndicator(
                    code="URL_STRUCTURE_SUSPICIOUS",
                    description=(
                        f"The hostname contains '{brand}' in its subdomain(s) "
                        f"but the actual domain is '{registered_domain}'. "
                        "This pattern is used to impersonate trusted brands."
                    ),
                    risk_contribution="HIGH",
                ))
                break  # Report once even if multiple brands match
            # Brand appears in the domain itself (could be legitimate or spoofed)
            elif brand in registered_domain and brand != registered_domain.split(".")[0]:
                results.append(URLIndicator(
                    code="URL_BRAND_IN_DOMAIN",
                    description=(
                        f"The registered domain '{registered_domain}' contains "
                        f"'{brand}' but does not appear to be the official "
                        f"'{brand}' domain. Verify this is a legitimate site."
                    ),
                    risk_contribution="MEDIUM",
                ))
                break
        return results

    def _check_url_shortener(self, hostname: str) -> List[URLIndicator]:
        """Detect known URL shortener services."""
        if hostname in URL_SHORTENERS:
            return [URLIndicator(
                code="URL_SHORTENER_DETECTED",
                description=(
                    f"'{hostname}' is a URL shortening service. "
                    "Shortened URLs hide the real destination, which is a common "
                    "phishing technique. Avoid clicking without expanding the URL first."
                ),
                risk_contribution="MEDIUM",
            )]
        return []

    def _check_suspicious_tld(self, hostname: str) -> List[URLIndicator]:
        """Flag domains with TLDs frequently associated with abuse."""
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return [URLIndicator(
                    code="URL_SUSPICIOUS_TLD",
                    description=(
                        f"Domain ends in '{tld}', a top-level domain frequently "
                        "associated with free registration and phishing campaigns."
                    ),
                    risk_contribution="MEDIUM",
                )]
        return []

    def _check_suspicious_path_keywords(self, path: str) -> List[URLIndicator]:
        """Detect suspicious keywords in the URL path."""
        suspicious_keywords = [
            "login", "signin", "verify", "account", "secure",
            "banking", "update", "confirm", "password", "credential",
            "wallet", "suspend", "unlock", "recover",
        ]
        path_lower = path.lower()
        matched = [kw for kw in suspicious_keywords if kw in path_lower]
        if len(matched) >= 2:
            return [URLIndicator(
                code="URL_SUSPICIOUS_PATH",
                description=(
                    f"The URL path contains multiple security-sensitive keywords: "
                    f"{', '.join(matched[:5])}. "
                    "Legitimate sites rarely combine these in a single path."
                ),
                risk_contribution="LOW",
            )]
        return []

    def _check_double_slash_redirect(self, url: str) -> List[URLIndicator]:
        """Detect double-slash redirect obfuscation patterns."""
        # Pattern: protocol followed by extra slashes before a different domain
        if re.search(r"https?://[^/]+/.*//", url):
            return [URLIndicator(
                code="URL_DOUBLE_SLASH_REDIRECT",
                description=(
                    "URL contains a double-slash (//) after the path start. "
                    "This pattern can be used to disguise redirect destinations."
                ),
                risk_contribution="LOW",
            )]
        return []

    def _check_multiple_dots(self, hostname: str) -> List[URLIndicator]:
        """Detect hostnames with many consecutive or multiple dots."""
        if ".." in hostname:
            return [URLIndicator(
                code="URL_MALFORMED_HOSTNAME",
                description=(
                    "The hostname contains consecutive dots ('..'), "
                    "which indicates a malformed or deliberately obfuscated URL."
                ),
                risk_contribution="HIGH",
            )]
        return []
