import unittest
from unittest.mock import patch

import activation_snapshot


class ActivationSnapshotTests(unittest.TestCase):
    def test_reads_only_allowlisted_properties(self):
        with patch("activation_snapshot.read_key", return_value={"available": True, "value": "x"}) as read:
            report = activation_snapshot.collect(executable="ideviceinfo")
        self.assertEqual(set(report["properties"]), set(activation_snapshot.SAFE_KEYS))
        self.assertTrue(report["privacy"]["udid_included"] is False)
        self.assertTrue(report["safety"]["read_only"])
        self.assertEqual(read.call_count, len(activation_snapshot.SAFE_KEYS))

    def test_read_key_returns_value_without_identifier_fields(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": "Unactivated\n", "stderr": ""})()
        with patch("activation_snapshot.subprocess.run", return_value=completed) as run:
            result = activation_snapshot.read_key("ideviceinfo", "ActivationState")
        self.assertEqual(result, {"available": True, "value": "Unactivated"})
        command = run.call_args.args[0]
        self.assertIn("ActivationState", command)
        self.assertNotIn("SerialNumber", command)
        self.assertNotIn("UniqueChipID", command)

    def test_finds_ideviceinfo_in_sibling_tools_directory(self):
        with patch("activation_snapshot.shutil.which", return_value=None), \\
             patch("activation_snapshot.Path.is_file", return_value=True), \\
             patch("activation_snapshot.read_key", return_value={"available": True, "value": "x"}):
            report = activation_snapshot.collect()
        self.assertTrue(report["safety"]["read_only"])

    def test_failed_key_is_nonfatal(self):
        completed = type("Completed", (), {"returncode": 1, "stdout": "", "stderr": "not found"})()
        with patch("activation_snapshot.subprocess.run", return_value=completed):
            result = activation_snapshot.read_key("ideviceinfo", "fm-activation-locked")
        self.assertEqual(result, {"available": False, "error": "ideviceinfo_failed"})


if __name__ == "__main__":
    unittest.main()
