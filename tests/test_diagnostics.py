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


if __name__ == "__main__":
    unittest.main()
