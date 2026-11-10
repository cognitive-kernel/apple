import unittest

from snapshot_diff import compare_snapshots


class SnapshotDiffTests(unittest.TestCase):
    def test_detects_activation_state_change(self):
        before = {"properties": {"ActivationState": {"available": True, "value": "Unactivated"}}}
        after = {"properties": {"ActivationState": {"available": True, "value": "Activated"}}}
        report = compare_snapshots(before, after)
        self.assertTrue(report["activation_state_changed"])
        self.assertEqual(report["changes"][0]["property"], "ActivationState")

    def test_reports_unchanged_activation_state(self):
        snapshot = {"properties": {"ActivationState": {"available": True, "value": "Unactivated"}}}
        report = compare_snapshots(snapshot, snapshot)
        self.assertFalse(report["activation_state_changed"])
        self.assertIn("ActivationState", report["unchanged_properties"])

    def test_missing_values_are_not_guessed(self):
        report = compare_snapshots({"properties": {}}, {"properties": {}})
        self.assertEqual(report["unavailable_properties"], [])
        self.assertFalse(report["activation_state_changed"])
        self.assertIn("does not prove server-side status", report["interpretation"])


if __name__ == "__main__":
    unittest.main()
