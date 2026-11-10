import unittest

from poc_compatibility import compare


class PocCompatibilityTests(unittest.TestCase):
    def test_target_different_from_published_test_is_not_validated(self):
        snapshot = {"properties": {
            "ProductType": {"available": True, "value": "iPhone17,3"},
            "ProductVersion": {"available": True, "value": "18.3.2"},
        }}
        claims = {"tested_model": "iPhone13,2", "tested_ios_version": "26.0.1",
                  "claimed_upper_range": "26.2 beta 1"}
        report = compare(snapshot, claims)
        self.assertEqual(report["assessment"], "published_test_does_not_validate_target")
        self.assertFalse(report["comparisons"]["model_exact_match"])
        self.assertFalse(report["comparisons"]["ios_version_exact_match"])

    def test_missing_snapshot_data_is_not_guessed(self):
        report = compare({"properties": {}}, {"tested_model": "iPhone13,2",
                                              "tested_ios_version": "26.0.1"})
        self.assertEqual(report["assessment"], "insufficient_device_snapshot")
        self.assertIsNone(report["comparisons"]["model_exact_match"])

    def test_exact_match_only_means_same_test_environment(self):
        snapshot = {"properties": {
            "ProductType": {"available": True, "value": "iPhone13,2"},
            "ProductVersion": {"available": True, "value": "26.0.1"},
        }}
        report = compare(snapshot, {"tested_model": "iPhone13,2",
                                    "tested_ios_version": "26.0.1"})
        self.assertEqual(report["assessment"], "same_as_published_test_environment")
        self.assertIn("does not prove exploitability", report["limitations"][0])


if __name__ == "__main__":
    unittest.main()
