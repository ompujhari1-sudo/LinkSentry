
import unittest
from analyzer.scanner import scan_url


class TestLinkSentry(unittest.TestCase):

    def test_instagram_url(self):
        result = scan_url("https://www.instagram.com/")
        self.assertEqual(result["risk_level"], "Low")

    def test_google_url(self):
        result = scan_url("https://www.google.com/")
        self.assertEqual(result["risk_level"], "Low")

    def test_url_without_scheme(self):
        result = scan_url("www.youtube.com")
        self.assertEqual(result["risk_level"], "Low")

    def test_http_warning(self):
        result = scan_url("http://example.com")
        self.assertIn("HTTPS is not used", result["issues"])

    def test_empty_url(self):
        result = scan_url("")
        self.assertGreater(result["risk_score"], 0)

    def test_shortener(self):
        result = scan_url("https://bit.ly/example")
        self.assertIn(
            "URL shortener detected; final destination is unknown",
            result["issues"]
        )

    def test_invalid_scheme(self):
        result = scan_url("ftp://example.com")
        self.assertGreater(result["risk_score"], 0)

    def test_ip_address(self):
        result = scan_url("http://8.8.8.8")
        self.assertGreater(result["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
