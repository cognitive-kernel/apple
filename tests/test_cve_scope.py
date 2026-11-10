import unittest

from cve_scope import assess, parse_version


class CveScopeTests(unittest.TestCase):
    def test_parses_version(self):
        self.assertEqual(parse_version("18.3.2"), (18, 3, 2))

    def test_rejects_non_version(self):
        self.assertIsNone(parse_version("18.3 beta"))

    def test_iphone_16_ios_18_3_2_is_in_advisory_version_range(self):
        result = assess("iPhone17,3", "18.3.2")
        self.assertEqual(
            result["assessment"],
            "within_vendor_advisory_affected_version_range",
        )
        self.assertEqual(result["known_model_name"], "iPhone 16")
        self.assertEqual(result["model_scope"], "listed")
        self.assertFalse(result["exploitability_confirmed"])
        self.assertFalse(result["device_modified"])

    def test_fixed_version_is_not_in_affected_range(self):
        result = assess("iPhone17,3", "18.7.7")
        self.assertEqual(result["assessment"], "at_or_above_vendor_fixed_version")

    def test_ios_26_fixed_version(self):
        result = assess("iPhone17,3", "26.2")
        self.assertEqual(result["assessment"], "at_or_above_vendor_fixed_version")

    def test_unknown_major_is_not_guessed(self):
        result = assess("iPhone17,3", "19.0")
        self.assertEqual(result["assessment"], "version_branch_not_assessed")

    def test_non_iphone_is_not_assessed_as_iphone(self):
        result = assess("iPad14,1", "18.3.2")
        self.assertEqual(result["assessment"], "unsupported_or_unknown_product")


if __name__ == "__main__":
    unittest.main()
