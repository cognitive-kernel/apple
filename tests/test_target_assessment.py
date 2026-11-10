import unittest

from target_assessment import assess_target


class TargetAssessmentTests(unittest.TestCase):
    def test_iphone_16_old_ios_is_advisory_affected_but_not_bypassed(self):
        snapshot = {"properties": {
            "ProductType": {"available": True, "value": "iPhone17,3"},
            "ProductVersion": {"available": True, "value": "18.3.2"},
        }}
        claims = {"tested_model": "iPhone13,2", "tested_ios_version": "26.0.1",
                  "claimed_upper_range": "26.2 beta 1",
                  "activation_lock_removal_claimed": False}
        report = assess_target(snapshot, claims)
        self.assertEqual(
            report["vendor_advisory"]["assessment"],
            "within_vendor_advisory_affected_version_range")
        self.assertEqual(
            report["public_poc"]["assessment"],
            "published_test_does_not_validate_target")
        self.assertEqual(
            report["overall_assessment"],
            "advisory_applies_but_no_validated_activation_lock_solution")
        self.assertFalse(report["activation_lock_removal_demonstrated"])
        self.assertFalse(report["device_modified"])

    def test_missing_device_values_are_not_guessed(self):
        report = assess_target({"properties": {}}, {})
        self.assertEqual(report["overall_assessment"],
                         "insufficient_or_unconfirmed_evidence")
        self.assertEqual(report["vendor_advisory"]["assessment"],
                         "insufficient_device_snapshot")
        self.assertFalse(report["activation_lock_removal_demonstrated"])


if __name__ == "__main__":
    unittest.main()
