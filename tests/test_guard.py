import unittest

from data_guard import Redactor, scan


class TestScan(unittest.TestCase):
    def test_email(self):
        f = scan("reach me at kulraj@example.com please")
        self.assertEqual([x[0] for x in f], ["EMAIL"])

    def test_aws_key(self):
        f = scan("key AKIAIOSFODNN7EXAMPLE end")
        self.assertEqual([x[0] for x in f], ["AWS_KEY"])

    def test_jwt(self):
        f = scan("token eyJhbGciOiJ9.eyJzdWIiOiIxIn0.abcdefgh123 done")
        self.assertIn("JWT", [x[0] for x in f])

    def test_ssn(self):
        f = scan("ssn 123-45-6789 here")
        self.assertIn("SSN", [x[0] for x in f])

    def test_ipv4(self):
        f = scan("from 192.168.1.1 to host")
        self.assertIn("IPV4", [x[0] for x in f])

    def test_ipv4_invalid_octet_rejected(self):
        f = scan("version 999.1.2.3 build")
        self.assertNotIn("IPV4", [x[0] for x in f])

    def test_card_luhn_valid(self):
        f = scan("card 4111 1111 1111 1111 charged")
        self.assertIn("CARD", [x[0] for x in f])

    def test_card_luhn_invalid_rejected(self):
        f = scan("card 4111 1111 1111 1112 charged")
        self.assertNotIn("CARD", [x[0] for x in f])

    def test_clean_text_no_findings(self):
        self.assertEqual(scan("the weather is nice today"), [])

    def test_version_string_not_card(self):
        f = scan("release 1.2.3.4.5 shipped")
        self.assertNotIn("CARD", [x[0] for x in f])


class TestRedactor(unittest.TestCase):
    def test_redact_and_restore_roundtrip(self):
        r = Redactor()
        text = "email kulraj@example.com or 4111 1111 1111 1111"
        redacted, findings = r.redact(text)
        self.assertNotIn("kulraj@example.com", redacted)
        self.assertNotIn("4111", redacted)
        self.assertEqual(r.restore(redacted), text)
        self.assertEqual(len(findings), 2)

    def test_stable_placeholders(self):
        r = Redactor()
        a, _ = r.redact("mail a@x.com then a@x.com again")
        self.assertEqual(a.count("[EMAIL_1]"), 2)

    def test_distinct_values_distinct_placeholders(self):
        r = Redactor()
        a, _ = r.redact("a@x.com and b@y.com")
        self.assertIn("[EMAIL_1]", a)
        self.assertIn("[EMAIL_2]", a)

    def test_idempotent(self):
        r = Redactor()
        once, _ = r.redact("key AKIAIOSFODNN7EXAMPLE ok")
        twice, findings2 = r.redact(once)
        self.assertEqual(once, twice)
        self.assertEqual(findings2, [])

    def test_no_false_positive_on_plain_numbers(self):
        r = Redactor()
        text = "order 12345 total 9999 items"
        redacted, findings = r.redact(text)
        self.assertEqual(redacted, text)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
