import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer.scanner import scan_url


def test_safe_url():
    result = scan_url("https://example.com")
    assert result["risk_level"] == "Low"


def test_http_url():
    result = scan_url("http://example.com")
    assert result["risk_score"] >= 15


def test_ip_address():
    result = scan_url("http://192.168.1.1")
    assert "IP address used as hostname" in result["issues"]


def test_suspicious_keyword():
    result = scan_url("https://example.com/login")
    assert any("login" in issue for issue in result["issues"])


def test_risk_score_limit():
    result = scan_url("http://192.168.1.1/login/verify")
    assert 0 <= result["risk_score"] <= 100
