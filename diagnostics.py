"""Read-only Windows diagnostics for Apple mobile-device connectivity.

This utility inspects local Plug-and-Play metadata only. It does not communicate
with Apple's activation servers and cannot remove Activation Lock.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


APPLE_VID = "05AC"
# Common Apple USB product IDs. Product IDs can vary by device and software.
APPLE_USB_MODES = {
    "1227": "DFU",
    "1281": "Recovery",
}


def run_command(command: list[str], timeout: int = 15) -> dict[str, Any]:
    """Run a local read-only command and return a sanitized result."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "available": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return {"available": False, "error": type(exc).__name__}


def _as_list(value: Any) -> list[Any]:
    """Normalize PowerShell JSON values that may be null, scalar, or arrays."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def classify_apple_device(device: dict[str, Any]) -> str:
    """Classify only when a known USB product ID or explicit name is present."""
    name = str(device.get("FriendlyName") or "").lower()
    hardware_ids = _as_list(device.get("HardwareIds"))

    for hardware_id in hardware_ids:
        match = re.search(
            r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})",
            str(hardware_id),
            re.IGNORECASE,
        )
        if match and match.group(1).upper() == APPLE_VID:
            mode = APPLE_USB_MODES.get(match.group(2).upper())
            if mode:
                return mode

    if "dfu" in name:
        return "DFU"
    if "recovery" in name or "iboot" in name:
        return "Recovery"
    if name == "apple iphone":
        return "NormalLikely"
    if "apple mobile device usb" in name:
        return "AppleUSBTransport"
    return "AppleDeviceUnknown"


def _overall_mode(devices: list[dict[str, Any]]) -> str:
    modes = {device.get("detected_mode") for device in devices}
    if "DFU" in modes:
        return "DFU"
    if "Recovery" in modes:
        return "Recovery"
    if "NormalLikely" in modes:
        return "NormalLikely"
    if "AppleUSBTransport" in modes:
        return "AppleUSBTransport"
    return "Unknown"


def collect_windows_devices() -> dict[str, Any]:
    """Collect present Apple PnP devices without exporting instance IDs."""
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return {"available": False, "error": "PowerShellNotFound"}

    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$devices = @(
  Get-PnpDevice -PresentOnly |
  Where-Object { $_.FriendlyName -match 'Apple|iPhone|iPad|iPod|Recovery|iBoot|DFU' } |
  ForEach-Object {
    $id = $_.InstanceId
    $hardwareIds = @(
      (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_HardwareIds').Data
    )
    # Hardware IDs are reduced to VID/PID only; instance IDs and serial-like
    # suffixes are deliberately excluded from the report.
    $safeIds = @(
      foreach ($hardwareId in $hardwareIds) {
        if ($hardwareId -match '^USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') {
          'USB\VID_' + $Matches[1].ToUpper() + '&PID_' + $Matches[2].ToUpper()
        }
      }
    )
    $service = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Service').Data
    $problem = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_ProblemCode').Data
    [pscustomobject]@{
      Status = $_.Status
      Class = $_.Class
      FriendlyName = $_.FriendlyName
      Service = $service
      ProblemCode = $problem
      HardwareIds = $safeIds
    }
  }
)
$services = @(
  Get-Service |
  Where-Object { $_.Name -match 'Apple|Bonjour' -or $_.DisplayName -match 'Apple|Bonjour' } |
  ForEach-Object {
    [pscustomobject]@{
      Name = $_.Name
      DisplayName = $_.DisplayName
      Status = [string]$_.Status
    }
  }
)
[pscustomobject]@{ devices = $devices; services = $services } |
  ConvertTo-Json -Depth 5 -Compress
"""

    result = run_command(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=30,
    )
    if not result["available"] or result.get("returncode") != 0:
        return result

    try:
        parsed = json.loads(result["stdout"] or "{}")
        devices = _as_list(parsed.get("devices"))
        services = _as_list(parsed.get("services"))

        normalized_devices: list[dict[str, Any]] = []
        for raw_device in devices:
            if not isinstance(raw_device, dict):
                continue
            device = dict(raw_device)
            device["HardwareIds"] = [
                str(item) for item in _as_list(device.get("HardwareIds"))
            ]
            device["detected_mode"] = classify_apple_device(device)
            normalized_devices.append(device)

        return {
            "available": True,
            "overall_mode": _overall_mode(normalized_devices),
            "mode_confidence": "heuristic",
            "devices": normalized_devices,
            "services": [
                item for item in services if isinstance(item, dict)
            ],
        }
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {"available": False, "error": "InvalidPowerShellOutput"}


def collect() -> dict[str, Any]:
    """Collect diagnostics without changing device or host configuration."""
    is_windows = platform.system() == "Windows"
    optional_tools = ("ideviceinfo", "idevice_id", "irecovery")
    report: dict[str, Any] = {
        "schema_version": 2,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "architecture": platform.machine(),
            "windows": is_windows,
        },
        "tools": {
            "python": run_command([shutil.which("python") or "python", "--version"]),
            "git": run_command([shutil.which("git") or "git", "--version"]),
            "apple_cli": {
                name: {"available": shutil.which(name) is not None}
                for name in optional_tools
            },
        },
        "apple_usb": collect_windows_devices() if is_windows else {
            "available": False,
            "error": "WindowsOnly",
        },
        "scope": {
            "read_only": True,
            "activation_server_checked": False,
            "activation_lock_changed": False,
            "firmware_changed": False,
            "device_identifiers_collected": False,
            "usb_hardware_ids_collected": True,
        },
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only iPhone/Apple USB diagnostics"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("iphone-diagnostics.json"),
        help="JSON report path (default: iphone-diagnostics.json)",
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = collect()
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Report written to: {args.output.resolve()}")
    print("Read-only report only; no activation or firmware operation was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
