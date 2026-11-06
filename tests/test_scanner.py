import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer.scanner import scan_url


def test_safe_url():
    result = scan_url("https://google.com")
    assert result["risk_level"] == "Low"


def test_http_url():
    result = scan_url("http://example.com")
    assert "HTTPS is not used" in result["issues"]


def test_ip_address():
    result = scan_url("http://192.168.1.1")
    assert "IP address used as hostname" in result["issues"]


def test_suspicious_keyword():
    result = scan_url("https://example.com/login")
    assert any("Suspicious keyword" in issue for issue in result["issues"])


def test_risk_score_limit():
    result = scan_url("http://192.168.1.1/login")
    assert result["risk_score"] <= 100


def test_redirect_parameter():
    result = scan_url(
        "https://example.com/login?redirect=https://example.org"
    )

    assert any(
        "Redirect parameter detected" in finding["message"]
        for finding in result["findings"]
    )
def test_invalid_hostname():
    result = scan_url("https://bad_domain.com")
    assert "Hostname contains suspicious characters" in result["issues"]


def test_leading_hyphen_hostname():
    result = scan_url("https://-bad.com")
    assert "Hostname contains suspicious characters" in result["issues"]


def test_trailing_hyphen_hostname():
    result = scan_url("https://bad-.com")
    assert "Hostname contains suspicious characters" in result["issues"]


def test_safe_domain_has_no_findings():
    result = scan_url("https://google.com")
    assert result["risk_level"] == "Low"


def test_shortener_detection():
    result = scan_url("https://bit.ly/example")
    assert any("URL shortener detected" in issue for issue in result["issues"])