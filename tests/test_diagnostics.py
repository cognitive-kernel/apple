import unittest
from unittest.mock import patch

import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_run_command_reports_missing_executable(self):
        with patch("diagnostics.subprocess.run", side_effect=FileNotFoundError):
            result = diagnostics.run_command(["missing-tool"])
        self.assertFalse(result["available"])
        self.assertEqual(result["error"], "FileNotFoundError")

    def test_collect_marks_report_read_only(self):
        with patch("diagnostics.platform.system", return_value="Linux"):
            with patch("diagnostics.platform.platform", return_value="test-platform"):
                with patch("diagnostics.platform.python_version", return_value="3.test"):
                    with patch("diagnostics.platform.machine", return_value="x86_64"):
                        with patch("diagnostics.run_command", return_value={"available": True}):
                            report = diagnostics.collect()
        self.assertTrue(report["scope"]["read_only"])
        self.assertFalse(report["scope"]["activation_server_checked"])
        self.assertFalse(report["scope"]["activation_lock_changed"])
        self.assertFalse(report["scope"]["firmware_changed"])
        self.assertEqual(report["apple_usb"]["error"], "WindowsOnly")
        self.assertIn("irecovery", report["tools"]["apple_cli"])

    def test_classifies_known_apple_dfu_product_id(self):
        device = {
            "FriendlyName": "Apple Mobile Device USB Device",
            "HardwareIds": ["USB\\VID_05AC&PID_1227&REV_0000"],
        }
        self.assertEqual(diagnostics.classify_apple_device(device), "DFU")

    def test_classifies_known_apple_recovery_product_id(self):
        device = {
            "FriendlyName": "Apple Mobile Device USB Device",
            "HardwareIds": ["USB\\VID_05AC&PID_1281&REV_0000"],
        }
        self.assertEqual(diagnostics.classify_apple_device(device), "Recovery")

    def test_does_not_classify_non_apple_vendor_by_product_id(self):
        device = {
            "FriendlyName": "Unknown USB Device",
            "HardwareIds": ["USB\\VID_1234&PID_1227&REV_0000"],
        }
        self.assertEqual(diagnostics.classify_apple_device(device), "AppleDeviceUnknown")

    def test_normal_iphone_name_is_only_likely_classification(self):
        device = {"FriendlyName": "Apple iPhone", "HardwareIds": []}
        self.assertEqual(diagnostics.classify_apple_device(device), "NormalLikely")

    def test_normalizes_single_powershell_device_object(self):
        raw = {
            "devices": {
                "FriendlyName": "Apple iPhone",
                "HardwareIds": [],
                "Status": "OK",
            },
            "services": None,
        }
        with patch("diagnostics.shutil.which", return_value="powershell"):
            with patch(
                "diagnostics.run_command",
                return_value={
                    "available": True,
                    "returncode": 0,
                    "stdout": __import__("json").dumps(raw),
                    "stderr": "",
                },
            ):
                result = diagnostics.collect_windows_devices()

        self.assertTrue(result["available"])
        self.assertEqual(result["overall_mode"], "NormalLikely")
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(result["services"], [])

    def test_overall_mode_prefers_dfu(self):
        devices = [
            {"detected_mode": "NormalLikely"},
            {"detected_mode": "DFU"},
        ]
        self.assertEqual(diagnostics._overall_mode(devices), "DFU")


if __name__ == "__main__":
    unittest.main()
