import unittest
from cve_scope import assess, parse_version


class CveScopeTests(unittest.TestCase):
    def test_parses_version(self):
        self.assertEqual(parse_version("18.3.2"), (18, 3, 2))

    def test_rejects_non_version(self):
        self.assertIsNone(parse_version("18.3 beta"))

    def test_iphone_16_ios_18_3_2_is_in_advisory_range(self):
        result = assess("iPhone17,3", "18.3.2")
        self.assertEqual(result["assessment"], "within_vendor_advisory_affected_version_range")
        self.assertEqual(result["known_model_name"], "iPhone 16")
        self.assertFalse(result["exploitability_confirmed"])

    def test_fixed_versions(self):
        self.assertEqual(assess("iPhone17,3", "18.7.7")["assessment"],
                         "at_or_above_vendor_fixed_version")
        self.assertEqual(assess("iPhone17,3", "26.2")["assessment"],
                         "at_or_above_vendor_fixed_version")

    def test_unknown_major_is_not_guessed(self):
        self.assertEqual(assess("iPhone17,3", "19.0")["assessment"],
                         "version_branch_not_assessed")

    def test_non_iphone_is_rejected(self):
        self.assertEqual(assess("iPad14,1", "18.3.2")["assessment"],
                         "unsupported_or_unknown_product")


if __name__ == "__main__":
    unittest.main()
