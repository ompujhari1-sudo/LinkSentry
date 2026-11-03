import ipaddress
from urllib.parse import urlparse


def scan_url(url):
    result = {
        "url": url,
        "risk_score": 0,
        "risk_level": "Low",
        "issues": []
    }

    url = url.strip()
    parsed = urlparse(
        url if "://" in url else "https://" + url
    )

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        result["issues"].append("Invalid URL format")
        result["risk_score"] += 40
    else:
        hostname = parsed.hostname.lower()

        if parsed.scheme != "https":
            result["issues"].append("HTTPS is not used")
            result["risk_score"] += 15

        try:
            ipaddress.ip_address(hostname)
            result["issues"].append("IP address used as hostname")
            result["risk_score"] += 25
        except ValueError:
            pass

        keywords = [
            "login", "verify", "account",
            "banking", "password", "free",
            "secure", "update"
        ]

        for word in keywords:
            if word in url.lower():
                result["issues"].append(
                    f"Suspicious keyword: {word}"
                )
                result["risk_score"] += 10

        if len(hostname.split(".")) > 3:
            result["issues"].append("Excessive subdomains")
            result["risk_score"] += 15

    result["risk_score"] = min(result["risk_score"], 100)

    if result["risk_score"] >= 60:
        result["risk_level"] = "High"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "Medium"

    return result