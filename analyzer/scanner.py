
import ipaddress
import re
from urllib.parse import urlsplit, unquote


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "ow.ly",
    "buff.ly",
    "rb.gy",
}

SUSPICIOUS_WORDS = {
    "password",
    "verify",
    "account-suspended",
    "wallet-connect",
    "signin",
    "credential",
    "confirm-account",
    "login",
}


def scan_url(url):
    result = {
        "url": url,
        "risk_score": 0,
        "risk_level": "Low",
        "issues": []
    }

    def add_issue(message, points):
        result["issues"].append(message)
        result["risk_score"] += points

    # 1. Basic input validation
    if not isinstance(url, str) or not url.strip():
        add_issue("Empty or invalid URL input", 40)
        result["risk_level"] = "Medium"
        return result

    url = url.strip()
    result["url"] = url

    # 2. URL length validation
    if len(url) > 4096:
        add_issue("URL is unusually long", 15)
        result["risk_score"] = min(result["risk_score"], 100)
        result["risk_level"] = "Medium"
        return result

    # 3. Control character validation
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        add_issue("URL contains invalid control characters", 40)
        result["risk_level"] = "Medium"
        return result

    # 4. Whitespace validation
    if any(char.isspace() for char in url):
        add_issue("URL contains whitespace", 20)
        result["risk_level"] = "Medium"
        return result

    # 5. Support URLs without a scheme
    normalized = url if "://" in url else "https://" + url

    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Unsupported URL scheme")

        if not hostname:
            raise ValueError("Missing hostname")

        # 6. Port validation
        port = parsed.port

        # 7. Embedded credentials check
        if parsed.username is not None or parsed.password is not None:
            add_issue(
                "URL contains embedded username or password",
                25
            )

        hostname = hostname.lower().rstrip(".")

        # 8. IP address analysis
        try:
            ip = ipaddress.ip_address(hostname)

            if not ip.is_global:
                add_issue(
                    "IP address used as hostname",
                    30
                )
            else:
                add_issue(
                    "IP address used as hostname",
                    20
                )

        except ValueError:

            # 9. Domain name validation
            try:
                ascii_hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError("Invalid international domain")

            labels = ascii_hostname.split(".")

            if len(ascii_hostname) > 253:
                raise ValueError("Hostname is too long")

            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label
                )
                for label in labels
            ):
                raise ValueError("Invalid hostname")

            if hostname == "localhost" or hostname.endswith(".localhost"):
                add_issue("Localhost address detected", 30)

            if any(label.startswith("xn--") for label in labels):
                add_issue(
                    "Internationalized or punycode domain detected",
                    15
                )

            if len(labels) > 4:
                add_issue("Unusually many subdomains", 15)

        # 10. HTTPS check
        if parsed.scheme.lower() != "https":
            add_issue("HTTPS is not used", 15)

        # 11. URL shortener detection
        if hostname in SHORTENERS:
            add_issue(
                "URL shortener detected; final destination is unknown",
                15
            )

        # 12. Suspicious authority check
        if "@" in parsed.netloc:
            add_issue(
                "URL contains an @ symbol in its authority",
                20
            )

        # 13. Suspicious keyword detection
        decoded_url = unquote(normalized).lower()

        for word in SUSPICIOUS_WORDS:
            if word in decoded_url:
                add_issue(
                    f"Suspicious keyword detected: {word}",
                    10
                )

        # 14. Encoded path detection
        if "%" in parsed.path and re.search(
            r"%[0-9a-f]{2}",
            parsed.path,
            re.I
        ):
            add_issue(
                "URL contains encoded path characters",
                5
            )

        # 15. Non-standard port detection
        if port and port not in (80, 443):
            add_issue(
                f"Non-standard port detected: {port}",
                10
            )

    except ValueError:
        add_issue("Invalid URL format or hostname", 40)

    # 16. Risk score limit
    result["risk_score"] = min(result["risk_score"], 100)

    # 17. Risk classification
    if result["risk_score"] >= 60:
        result["risk_level"] = "High"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "Medium"
    else:
        result["risk_level"] = "Low"

    return result
