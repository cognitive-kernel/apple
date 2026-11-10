import unittest

from activation_log_analyzer import analyze_text, classify_line, redact


class ActivationLogAnalyzerTests(unittest.TestCase):
    def test_detects_known_activation_request_markers(self):
        report = analyze_text(
            "ActivationSendRequest\n"
            "Buddy Activation: Created arbitrary data task\n"
            "activationData length = 238, error: (null)\n"
            "Canceling any in-flight activation\n"
            "trustd matched albert.apple.com\n"
        )
        counts = report["summary"]["category_counts"]
        self.assertGreaterEqual(counts["activation_request"], 1)
        self.assertGreaterEqual(counts["activation_task"], 1)
        self.assertGreaterEqual(counts["activation_cancel"], 1)
        self.assertGreaterEqual(counts["tls_or_trust"], 1)
        self.assertEqual(
            report["summary"]["server_observation"],
            "request_activity_seen_response_not_proven",
        )

    def test_extracts_explicit_http_status(self):
        report = analyze_text("Activation response HTTP status: 403")
        self.assertEqual(report["summary"]["http_status_codes"], ["403"])
        self.assertEqual(report["summary"]["server_observation"], "http_status_observed")

    def test_fmf_error_is_not_activation_failure_proof(self):
        report = analyze_text("FMFErrorNoAccount")
        self.assertEqual(
            report["summary"]["server_observation"],
            "insufficient_activation_log_evidence",
        )
        self.assertFalse(report["summary"]["activation_state_confirmed"])

    def test_redacts_email_and_long_number(self):
        result = redact("user@example.com serial 1234567890123456")
        self.assertNotIn("user@example.com", result)
        self.assertNotIn("1234567890123456", result)

    def test_unrelated_line_is_ignored(self):
        self.assertEqual(classify_line("ordinary SpringBoard message"), [])


if __name__ == "__main__":
    unittest.main()
