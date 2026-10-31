"""
TrustShield AI — Cyber Resilience Backend
URL Analysis Service

Analyses a URL for phishing indicators using rule-based heuristics.
Uses only stdlib (urllib.parse, ipaddress, unicodedata) — no external HTTP calls.

Design decisions:
- Each check is a separate method → easy to test individually
- Returns a list of URLIndicator objects + a raw score list
- The risk_assessment service converts those into the final verdict
- No indicator is treated as definitive proof on its own
- SSRF: this module never contacts the submitted URL

Upgrade history:
- v1.1: F1 — alternative IP notation (octal, hex, decimal) detection
- v1.1: F1 — private/loopback/reserved IP flagging
- v1.1: F2 — IDN homograph / non-ASCII hostname detection
- v1.1: F3 — open-redirect query parameter detection
- v1.1: F4 — URL length threshold raised 100→150; >300 chars = HIGH
- v1.1: null byte detection in URL
- v1.1: suspicious query-string depth detection
"""

import re
import ipaddress
import unicodedata
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

# Open-redirect query parameter names — strong phishing redirect indicator
REDIRECT_PARAM_NAMES = frozenset({
    "redirect", "redirect_to", "redirect_url", "redirecturi", "redirect_uri",
    "url", "next", "next_url", "return", "return_to", "returnurl", "return_url",
    "goto", "go", "continue", "dest", "destination", "target",
    "forward", "forward_url", "callback", "fallback",
    "link", "out", "site", "to",
})

# Private / reserved IP ranges that MUST NOT be accessed via SSRF
# These are used for detection only — the backend never contacts the URL
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("169.254.169.254/32"), # Cloud metadata (AWS/GCP/Azure)
]


# Unicode confusable homoglyphs mapping common non-Latin lookalikes to Latin ASCII
# Based on Unicode Technical Report #39 (confusables)
HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic lowercase lookalikes
    "\u0430": "a", "\u0441": "c", "\u0434": "d", "\u0435": "e", "\u0456": "i",
    "\u0458": "j", "\u043a": "k", "\u043e": "o", "\u0440": "p", "\u0455": "s",
    "\u0445": "x", "\u0443": "y", "\u0432": "b", "\u0433": "r", "\u043c": "m",
    "\u043d": "h", "\u0442": "t",
    # Cyrillic uppercase lookalikes
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041d": "H",
    "\u0406": "I", "\u0408": "J", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X", "\u0423": "Y",
    # Greek lowercase lookalikes
    "\u03bf": "o", "\u03bd": "v", "\u03b1": "a", "\u03c1": "p", "\u03b9": "i",
    "\u03ba": "k", "\u03b5": "e", "\u03c4": "t",
    # Fullwidth / compatibility Latin lookalikes
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d", "\uff45": "e",
    "\uff46": "f", "\uff47": "g", "\uff48": "h", "\uff49": "i", "\uff4a": "j",
    "\uff4b": "k", "\uff4c": "l", "\uff4d": "m", "\uff4e": "n", "\uff4f": "o",
    "\uff50": "p", "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x", "\uff59": "y",
    "\uff5a": "z",
})


def _is_private_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP belongs to a private, loopback, or reserved range."""
    for network in _PRIVATE_NETWORKS:
        try:
            if addr in network:
                return True
        except TypeError:
            # Address family mismatch (e.g. IPv4 vs IPv6 network)
            continue
    return False


def _try_parse_alternative_ip(hostname: str) -> ipaddress.IPv4Address | None:
    """
    Attempt to parse hostname as an alternative IP notation.

    Browsers and HTTP clients accept:
      - Decimal integer:  3232235521  → 192.168.0.1
      - Octal:            0300.0250.0.1
      - Hexadecimal:      0xC0A80001 or 0xC0.0xA8.0x0.0x1

    Returns an IPv4Address if any of these decode to a valid IP, else None.
    SECURITY: This is a detection-only function. We never make HTTP requests.
    """
    hostname = hostname.strip().lower()

    # Strip brackets (IPv6)
    if hostname.startswith("[") and hostname.endswith("]"):
        return None  # Handled by normal ip_address()

    # Pure decimal integer representation
    if re.fullmatch(r"\d{1,10}", hostname):
        try:
            val = int(hostname)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Hex: 0xC0A80001
    if re.fullmatch(r"0x[0-9a-f]{1,8}", hostname):
        try:
            return ipaddress.IPv4Address(int(hostname, 16))
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Dotted octal: 0300.0250.0.1
    if re.fullmatch(r"0\d+(?:\.0\d*){3}", hostname):
        try:
            parts = hostname.split(".")
            decimal_parts = [int(p, 8) for p in parts]
            return ipaddress.IPv4Address(".".join(str(p) for p in decimal_parts))
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Dotted hex: 0xC0.0xA8.0x00.0x01
    if re.fullmatch(r"0x[0-9a-f]+(?:\.0x[0-9a-f]+){3}", hostname):
        try:
            parts = hostname.split(".")
            decimal_parts = [int(p, 16) for p in parts]
            return ipaddress.IPv4Address(".".join(str(p) for p in decimal_parts))
        except (ValueError, ipaddress.AddressValueError):
            pass

    return None


class URLAnalyzer:
    """
    Rule-based URL phishing analyzer.

    Each public method returns a list of URLIndicator objects.
    The caller (risk_assessment) aggregates these into a final verdict.

    SECURITY: This class performs only offline string analysis.
               It never contacts the submitted URL.
    """

    # Maximum URL length before triggering the unusual-length indicator (MEDIUM)
    UNUSUAL_LENGTH_THRESHOLD = 150
    # URL length above which the indicator is upgraded to HIGH
    EXTREME_LENGTH_THRESHOLD = 300
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

        SECURITY: No network calls are made. This is purely string analysis.
        """
        indicators: List[URLIndicator] = []

        # --- Null byte detection (before parsing) ---
        if "\x00" in url or "%00" in url.lower():
            indicators.append(URLIndicator(
                code="URL_NULL_BYTE",
                description=(
                    "The URL contains a null byte (\\x00 or %00). "
                    "Null bytes are used in injection attacks and are never "
                    "present in legitimate URLs."
                ),
                risk_contribution="HIGH",
            ))

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

        # Safely extract port (urlparse raises ValueError for malformed ports)
        try:
            port = parsed.port
        except ValueError:
            port = None
            indicators.append(URLIndicator(
                code="URL_MALFORMED_PORT",
                description=(
                    "The URL contains a malformed port number. "
                    "This may indicate a deliberately obfuscated URL."
                ),
                risk_contribution="MEDIUM",
            ))

        components = {
            "scheme": parsed.scheme,
            "hostname": parsed.hostname or "",
            "port": port,
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
        indicators.extend(self._check_port(parsed, port))
        indicators.extend(self._check_encoding(url))
        indicators.extend(self._check_misleading_hostname(hostname))
        indicators.extend(self._check_url_shortener(hostname))
        indicators.extend(self._check_suspicious_tld(hostname))
        indicators.extend(self._check_suspicious_path_keywords(parsed.path))
        indicators.extend(self._check_double_slash_redirect(url))
        indicators.extend(self._check_multiple_dots(hostname))
        indicators.extend(self._check_idn_homograph(hostname))
        indicators.extend(self._check_redirect_params(parsed.query))
        indicators.extend(self._check_user_info(parsed))

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
        """
        Detect IP address used as hostname.

        Covers:
          - Standard dotted IPv4 and IPv6
          - Alternative notations: octal, hex, decimal integer (F1)
          - Private/loopback/reserved ranges (SSRF indicator, F1)

        SECURITY: Detection only. Never contacts the IP.
        """
        if not hostname:
            return []

        resolved_ip = None

        # Standard parsing via stdlib
        try:
            resolved_ip = ipaddress.ip_address(hostname)
        except ValueError:
            # Try alternative notations (octal, hex, decimal integer)
            resolved_ip = _try_parse_alternative_ip(hostname)

        if resolved_ip is None:
            return []

        results = []

        # All IP-as-hostname is suspicious
        results.append(URLIndicator(
            code="URL_IP_ADDRESS_HOST",
            description=(
                f"The URL uses an IP address ({hostname}) as the hostname "
                "instead of a domain name. Legitimate services rarely do this."
            ),
            risk_contribution="HIGH",
        ))

        # Private/loopback/reserved IPs are especially dangerous (SSRF target)
        if _is_private_ip(resolved_ip):
            results.append(URLIndicator(
                code="URL_PRIVATE_IP_HOST",
                description=(
                    f"The IP address ({hostname}) belongs to a private, loopback, "
                    "or reserved range. Clicking this URL could expose internal "
                    "services. This is a strong indicator of a phishing or SSRF attack."
                ),
                risk_contribution="HIGH",
            ))

        return results

    def _check_url_length(self, url: str) -> List[URLIndicator]:
        """
        Flag unusually long URLs.

        Two tiers:
          - >150 chars: MEDIUM (common in phishing to hide the real destination)
          - >300 chars: HIGH (extreme obfuscation)
        """
        length = len(url)
        if length > self.EXTREME_LENGTH_THRESHOLD:
            return [URLIndicator(
                code="URL_EXTREME_LENGTH",
                description=(
                    f"URL is {length} characters long "
                    f"(threshold: {self.EXTREME_LENGTH_THRESHOLD}). "
                    "Extremely long URLs are strongly associated with obfuscation "
                    "in phishing attacks."
                ),
                risk_contribution="HIGH",
            )]
        if length > self.UNUSUAL_LENGTH_THRESHOLD:
            return [URLIndicator(
                code="URL_UNUSUAL_LENGTH",
                description=(
                    f"URL is {length} characters long "
                    f"(threshold: {self.UNUSUAL_LENGTH_THRESHOLD}). "
                    "Phishing URLs often use long strings to hide the real destination."
                ),
                risk_contribution="MEDIUM",
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

    def _check_user_info(self, parsed) -> List[URLIndicator]:
        """
        Detect explicit username/password in URL userinfo component.
        E.g. http://user:pass@example.com/ — credential embedding in URL.
        """
        if parsed.username or parsed.password:
            return [URLIndicator(
                code="URL_USERINFO_PRESENT",
                description=(
                    "The URL contains embedded username or password credentials "
                    "in the userinfo field. Legitimate services never embed "
                    "credentials in URLs."
                ),
                risk_contribution="HIGH",
            )]
        return []

    def _check_port(self, parsed, port: int | None) -> List[URLIndicator]:
        """Flag non-standard ports."""
        if port and port in self.UNUSUAL_PORTS:
            return [URLIndicator(
                code="URL_UNUSUAL_PORT",
                description=(
                    f"URL uses port {port}. "
                    "Legitimate websites typically use port 443 (HTTPS) or 80 (HTTP). "
                    "Unusual ports may indicate malicious infrastructure."
                ),
                risk_contribution="MEDIUM",
            )]
        return []

    def _check_encoding(self, url: str) -> List[URLIndicator]:
        """Detect suspicious percent-encoding that may obscure the real URL."""
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

        Note: This check operates on ASCII hostnames. IDN homographs are handled
        separately by _check_idn_homograph().
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
        """Detect hostnames with consecutive or multiple dots."""
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

    def _check_idn_homograph(self, hostname: str) -> List[URLIndicator]:
        """
        Detect IDN homograph attacks — non-ASCII characters in hostname labels
        that visually resemble ASCII characters used in brand names. (F2)

        Examples:
          pаypal.com  — Cyrillic 'а' (U+0430) looks like ASCII 'a'
          microsоft.com — Cyrillic 'о' (U+043E) looks like ASCII 'o'

        Detection strategy:
          1. Check if hostname contains non-ASCII characters.
          2. Attempt to encode each label to Punycode (xn--...).
          3. Compare the NFKD-normalised ASCII-only form against known brands.

        False positive consideration:
          Legitimate IDN domains exist (e.g. Chinese, Arabic sites).
          We only flag when an IDN label resembles a known brand after
          normalisation.
        """
        if not hostname:
            return []

        # Fast path: purely ASCII hostname — no homograph risk
        try:
            hostname.encode("ascii")
            return []
        except UnicodeEncodeError:
            pass

        results = []

        # Attempt Punycode encoding to get the ACE form
        try:
            ace_hostname = hostname.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            # Could not encode — hostname is malformed Unicode
            ace_hostname = None

        # Translate confusable Unicode lookalikes (Cyrillic, Greek, fullwidth) to Latin ASCII
        translated = hostname.translate(HOMOGLYPH_MAP)

        # Normalise using NFKD to collapse remaining diacritics
        normalised = unicodedata.normalize("NFKD", translated)
        # Strip combining characters (diacritics) to get base characters
        ascii_approx = "".join(
            c for c in normalised
            if unicodedata.category(c) != "Mn" and ord(c) < 128
        )

        # Flag presence of non-ASCII labels in the hostname
        results.append(URLIndicator(
            code="URL_IDN_HOSTNAME",
            description=(
                f"The hostname contains non-ASCII characters "
                f"(Punycode: {ace_hostname or 'encoding failed'}). "
                "IDN hostnames can be used in homograph phishing attacks where "
                "characters from other scripts visually resemble Latin letters."
            ),
            risk_contribution="MEDIUM",
        ))

        # Check if the normalised form resembles a known brand
        for brand in SPOOFED_BRANDS:
            if brand in ascii_approx.lower():
                results.append(URLIndicator(
                    code="URL_IDN_BRAND_HOMOGRAPH",
                    description=(
                        f"The hostname appears to impersonate '{brand}' using "
                        "non-ASCII lookalike characters (homograph attack). "
                        f"Punycode form: {ace_hostname or 'encoding failed'}. "
                        "This is a sophisticated phishing technique."
                    ),
                    risk_contribution="HIGH",
                ))
                break  # Report once per URL

        return results

    def _check_redirect_params(self, query: str) -> List[URLIndicator]:
        """
        Detect open-redirect query parameters — hallmarks of phishing chains. (F3)

        Phishing campaigns often use legitimate domains with redirect parameters
        to pass link-scanners before redirecting victims to malicious sites.

        Examples:
          https://accounts.google.com/Login?continue=http://evil.com
          https://login.microsoftonline.com/?ru=http://phish.tk

        False positive consideration:
          Legitimate OAuth flows use redirect_uri. We flag at LOW contribution
          and require the parameter name to match known redirect param names.
          This is weak evidence on its own.
        """
        if not query:
            return []

        try:
            params = parse_qs(query, keep_blank_values=True)
        except Exception:
            return []

        matched_params = []
        for param_name in params:
            if param_name.lower() in REDIRECT_PARAM_NAMES:
                matched_params.append(param_name)

        if matched_params:
            param_list = ", ".join(f"'{p}'" for p in matched_params[:5])
            return [URLIndicator(
                code="URL_REDIRECT_PARAM",
                description=(
                    f"URL query string contains redirect parameter(s): {param_list}. "
                    "These parameters are used in open-redirect phishing chains where "
                    "a trusted domain is used to redirect victims to a malicious site. "
                    "Verify the redirect destination before clicking."
                ),
                risk_contribution="LOW",
            )]
        return []
