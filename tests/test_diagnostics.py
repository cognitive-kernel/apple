import json
import unittest
from unittest.mock import patch

import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_run_command_missing_executable(self):
        with patch("diagnostics.subprocess.run", side_effect=FileNotFoundError):
            result = diagnostics.run_command(["missing-tool"])
        self.assertFalse(result["available"])
        self.assertEqual(result["error"], "FileNotFoundError")

    def test_report_is_read_only(self):
        with patch("diagnostics.platform.system", return_value="Linux"), \
             patch("diagnostics.platform.platform", return_value="test"), \
             patch("diagnostics.platform.python_version", return_value="3.test"), \
             patch("diagnostics.platform.machine", return_value="x86_64"), \
             patch("diagnostics.run_command", return_value={"available": True}):
            report = diagnostics.collect()
        self.assertTrue(report["scope"]["read_only"])
        self.assertFalse(report["scope"]["activation_server_checked"])
        self.assertFalse(report["scope"]["activation_lock_changed"])
        self.assertEqual(report["apple_usb"]["error"], "WindowsOnly")

    def test_classifies_apple_dfu(self):
        device = {"FriendlyName": "Apple USB", "HardwareIds": ["USB\\VID_05AC&PID_1227"]}
        self.assertEqual(diagnostics.classify_apple_device(device), "DFU")

    def test_classifies_apple_recovery(self):
        device = {"FriendlyName": "Apple USB", "HardwareIds": ["USB\\VID_05AC&PID_1281"]}
        self.assertEqual(diagnostics.classify_apple_device(device), "Recovery")

    def test_rejects_non_apple_vendor(self):
        device = {"FriendlyName": "Unknown", "HardwareIds": ["USB\\VID_1234&PID_1227"]}
        self.assertEqual(diagnostics.classify_apple_device(device), "AppleDeviceUnknown")

    def test_normal_iphone_is_heuristic(self):
        self.assertEqual(diagnostics.classify_apple_device(
            {"FriendlyName": "Apple iPhone", "HardwareIds": []}), "NormalLikely")

    def test_normalizes_single_powershell_device(self):
        raw = {"devices": {"FriendlyName": "Apple iPhone", "HardwareIds": [], "Status": "OK"},
               "services": None}
        with patch("diagnostics.shutil.which", return_value="powershell"), \
             patch("diagnostics.run_command", return_value={
                 "available": True, "returncode": 0, "stdout": json.dumps(raw), "stderr": ""}):
            result = diagnostics.collect_windows_devices()
        self.assertTrue(result["available"])
        self.assertEqual(result["overall_mode"], "NormalLikely")
        self.assertEqual(len(result["devices"]), 1)

    def test_overall_mode_prioritizes_dfu(self):
        self.assertEqual(diagnostics._overall_mode([
            {"detected_mode": "NormalLikely"}, {"detected_mode": "DFU"}]), "DFU")


if __name__ == "__main__":
    unittest.main()
