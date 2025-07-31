import unittest
import os
from email_cli import EmailParser

class TestEmailCLI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a minimal valid test .eml file
        cls.test_eml = "test_email.eml"
        with open(cls.test_eml, "w") as f:
            f.write("""From: John <a@example.com>
To: Jane <jane@example.com>
Subject: Invoice - Please verify
Date: Fri, 1 Jan 2021 10:00:00 +0000
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain

This is a test email body with the keyword password in it.
""")

    def test_parse_email_contains_subject(self):
        """Check subject field is parsed correctly"""
        parser = EmailParser(self.test_eml, geoip_enabled=False)
        result = parser.parse_email()
        self.assertIn("Subject: Invoice - Please verify", result)

    def test_detect_phishing_indicators(self):
        """Check phishing indicators are flagged"""
        parser = EmailParser(self.test_eml, geoip_enabled=False)
        parser.parse_email()
        self.assertTrue(any("Suspicious keyword" in i for i in parser.phishing_indicators))

    def test_metadata_hash_exists(self):
        """Ensure metadata SHA256 hash is generated"""
        parser = EmailParser(self.test_eml, geoip_enabled=False)
        parser.parse_email()
        self.assertIn("Metadata SHA256 Hash", parser.latest_email_data)

    def test_body_preview_present(self):
        """Ensure body preview shows partial content"""
        parser = EmailParser(self.test_eml, geoip_enabled=False)
        parser.parse_email()
        self.assertIn("Body Preview", parser.latest_email_data)
        self.assertTrue(len(parser.latest_email_data["Body Preview"]) > 10)

    def test_risk_score_medium(self):
        """Ensure phishing score returns Medium based on indicators"""
        parser = EmailParser(self.test_eml, geoip_enabled=False)
        parser.parse_email()
        self.assertEqual(parser.calculate_risk_score(), "Medium ")

    @classmethod
    def tearDownClass(cls):
        # Clean up temporary file
        if os.path.exists(cls.test_eml):
            os.remove(cls.test_eml)

if __name__ == '__main__':
    unittest.main()
