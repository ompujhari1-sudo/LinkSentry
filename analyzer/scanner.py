
import ipaddress
import re
from urllib.parse import urlsplit, unquote, parse_qsl


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rebrand.ly",
    "ow.ly", "buff.ly", "rb.gy"
}

SUSPICIOUS_WORDS = {
    "password", "verify", "account-suspended",
    "wallet-connect", "signin", "credential",
    "confirm-account", "login", "register",
    "reset-password", "banking", "seed-phrase"
}

REDIRECT_PARAMETERS = {
    "redirect", "redirect_url", "return", "return_url",
    "next", "continue", "url", "target"
}


def scan_url(url):
    original_url = url
    issues = []
    findings = []
    score = 0

    def add_finding(message, points, severity):
        nonlocal score

        if message in issues:
            return

        issues.append(message)
        findings.append({
            "message": message,
            "points": points,
            "severity": severity
        })
        score += points

    def result(level, details=None):
        return {
            "url": original_url,
            "risk_score": min(score, 100),
            "risk_level": level,
            "issues": issues,
            "findings": findings,
            "details": details or {}
        }

    if not isinstance(url, str) or not url.strip():
        add_finding("URL is empty", 40, "high")
        return result("High")

    url = url.strip()

    if len(url) > 4096:
        add_finding("URL exceeds the supported length", 25, "medium")
        return result("Medium")

    if any(ord(char) < 32 for char in url):
        add_finding("URL contains control characters", 20, "medium")
        return result("Medium")

    try:
        initial = urlsplit(url)

        if initial.scheme and initial.scheme.lower() not in ("http", "https"):
            add_finding("Unsupported URL protocol", 40, "high")
            return result("High")

        if not initial.scheme:
            url = "https://" + url

        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port

    except ValueError:
        add_finding("Invalid URL format or port", 40, "high")
        return result("High")

    if not hostname:
        add_finding("Invalid or missing hostname", 40, "high")
        return result("High")

    details = {
        "protocol": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port or (443 if parsed.scheme == "https" else 80),
        "path": parsed.path or "/",
        "query_present": bool(parsed.query),
        "fragment_present": bool(parsed.fragment)
    }

    # HTTPS check
    if parsed.scheme.lower() != "https":
        add_finding("HTTPS is not used", 15, "medium")

    # URL credentials check
    if "@" in parsed.netloc:
        add_finding(
            "URL contains an @ symbol, which can hide the actual hostname",
            20,
            "high"
        )

    # IP address check
    try:
        ip = ipaddress.ip_address(hostname)
        add_finding("IP address used as hostname", 25, "high")

        if not ip.is_global:
            add_finding("Non-public IP address detected", 20, "high")

    except ValueError:
        # Punycode check
        if "xn--" in hostname:
            add_finding(
                "Punycode domain detected; inspect for lookalike characters",
                15,
                "medium"
            )

        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_hostname = ""

        if not ascii_hostname:
            add_finding(
                "Hostname contains invalid international characters",
                30,
                "high"
            )
        else:
            labels = ascii_hostname.split(".")
            label_pattern = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"

            if len(labels) < 2:
                add_finding(
                    "Hostname has no recognizable domain extension",
                    15,
                    "medium"
                )

            if any(
                not re.fullmatch(label_pattern, label)
                for label in labels
            ):
                add_finding(
                    "Hostname contains suspicious characters",
                    20,
                    "high"
                )

            if any(len(label) > 63 for label in labels):
                add_finding(
                    "Hostname contains an unusually long domain label",
                    15,
                    "medium"
                )

            if len(ascii_hostname) > 253:
                add_finding(
                    "Hostname exceeds the maximum supported length",
                    25,
                    "medium"
                )

    # Localhost check
    if hostname in ("localhost", "localhost.localdomain"):
        add_finding("Localhost address detected", 15, "medium")

    # URL shortener check
    if any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in SHORTENERS
    ):
        add_finding(
            "URL shortener detected; final destination is unknown",
            20,
            "medium"
        )

    # Subdomain check
    if hostname.count(".") > 4:
        add_finding(
            "Unusually many subdomains detected",
            15,
            "medium"
        )

    # Port check
    if port and port not in (80, 443):
        add_finding("Non-standard port detected", 10, "medium")

    # Decode URL for keyword analysis
    decoded_url = unquote(url).lower()

    detected_words = []

    for word in SUSPICIOUS_WORDS:
        if re.search(
            r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])",
            decoded_url
        ):
            detected_words.append(word)

    for word in detected_words:
        add_finding(
            f"Suspicious keyword detected: {word}",
            10,
            "medium"
        )

    # Long path check
    if len(parsed.path) > 150:
        add_finding(
            "Unusually long URL path",
            10,
            "medium"
        )

    # Redirect parameter check
    query_keys = {
        key.lower()
        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
    }

    if REDIRECT_PARAMETERS.intersection(query_keys):
        add_finding(
            "Redirect parameter detected; destination should be checked",
            10,
            "medium"
        )

    # Final score
    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return result(level, details)
