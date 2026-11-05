
import ipaddress
import re
from urllib.parse import urlsplit, unquote


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rebrand.ly",
    "ow.ly", "buff.ly", "rb.gy"
}

SUSPICIOUS_WORDS = {
    "password", "verify", "account-suspended",
    "wallet-connect", "signin", "credential",
    "confirm-account", "login"
}


def scan_url(url):
    issues = []
    findings = []
    score = 0

    def add_finding(message, points, severity):
        nonlocal score
        issues.append(message)
        findings.append({
            "message": message,
            "points": points,
            "severity": severity
        })
        score += points

    def result(level, details=None):
        return {
            "url": url,
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
        add_finding("URL is unusually long", 15, "medium")
        return result("Low")

    if any(ord(char) < 32 for char in url):
        add_finding("URL contains control characters", 20, "medium")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        add_finding("Invalid URL format", 40, "high")
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

    if parsed.scheme.lower() not in ("http", "https"):
        add_finding("Unsupported URL protocol", 30, "high")

    if parsed.scheme.lower() != "https":
        add_finding("HTTPS is not used", 15, "medium")

    if "@" in parsed.netloc:
        add_finding("URL contains an @ symbol", 20, "high")

    try:
        ipaddress.ip_address(hostname)
        add_finding("IP address used as hostname", 25, "high")

        if not ipaddress.ip_address(hostname).is_global:
            add_finding("Non-public IP address detected", 20, "high")

    except ValueError:
        labels = hostname.split(".")

        if len(labels) < 2:
            add_finding("Hostname has no recognizable domain extension", 15, "medium")

        if any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            add_finding("Hostname contains suspicious characters", 20, "high")

    if hostname in SHORTENERS:
        add_finding(
            "URL shortener detected; final destination is unknown",
            20,
            "medium"
        )

    if hostname.count(".") > 4:
        add_finding("Unusually many subdomains detected", 15, "medium")

    if port and port not in (80, 443):
        add_finding("Non-standard port detected", 10, "medium")

    decoded_url = unquote(url).lower()

    for word in SUSPICIOUS_WORDS:
        if word in decoded_url:
            add_finding(
                f"Suspicious keyword detected: {word}",
                10,
                "medium"
            )

    if re.search(r"%[0-9a-fA-F]{2}", url):
        add_finding("URL contains encoded characters", 5, "low")

    if len(parsed.path) > 150:
        add_finding("Unusually long URL path", 10, "medium")

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return result(level, details)
