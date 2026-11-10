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
APPLE_USB_MODES = {"1227": "DFU", "1281": "Recovery"}


def run_command(command: list[str], timeout: int = 15) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   errors="replace", timeout=timeout, check=False)
        return {"available": True, "returncode": completed.returncode,
                "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return {"available": False, "error": type(exc).__name__}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def classify_apple_device(device: dict[str, Any]) -> str:
    name = str(device.get("FriendlyName") or "").lower()
    for hardware_id in _as_list(device.get("HardwareIds")):
        match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})",
                          str(hardware_id), re.IGNORECASE)
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
    modes = {item.get("detected_mode") for item in devices}
    for mode in ("DFU", "Recovery", "NormalLikely", "AppleUSBTransport"):
        if mode in modes:
            return mode
    return "Unknown"


def collect_windows_devices() -> dict[str, Any]:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return {"available": False, "error": "PowerShellNotFound"}
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$devices = @(Get-PnpDevice -PresentOnly |
 Where-Object { $_.FriendlyName -match 'Apple|iPhone|iPad|iPod|Recovery|iBoot|DFU' } |
 ForEach-Object {
  $id = $_.InstanceId
  $hardwareIds = @((Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_HardwareIds').Data)
  $safeIds = @(foreach ($hardwareId in $hardwareIds) {
   if ($hardwareId -match '^USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') {
    'USB\VID_' + $Matches[1].ToUpper() + '&PID_' + $Matches[2].ToUpper()
   }
  })
  [pscustomobject]@{
   Status = $_.Status; Class = $_.Class; FriendlyName = $_.FriendlyName
   Service = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Service').Data
   ProblemCode = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_ProblemCode').Data
   HardwareIds = $safeIds
  }
 })
$services = @(Get-Service |
 Where-Object { $_.Name -match 'Apple|Bonjour' -or $_.DisplayName -match 'Apple|Bonjour' } |
 ForEach-Object { [pscustomobject]@{Name=$_.Name; DisplayName=$_.DisplayName; Status=[string]$_.Status} })
[pscustomobject]@{devices=$devices; services=$services} | ConvertTo-Json -Depth 5 -Compress
"""
    result = run_command([powershell, "-NoProfile", "-NonInteractive", "-Command", script], 30)
    if not result["available"] or result.get("returncode") != 0:
        return result
    try:
        parsed = json.loads(result["stdout"] or "{}")
        devices = []
        for raw in _as_list(parsed.get("devices")):
            if isinstance(raw, dict):
                item = dict(raw)
                item["HardwareIds"] = [str(x) for x in _as_list(item.get("HardwareIds"))]
                item["detected_mode"] = classify_apple_device(item)
                devices.append(item)
        return {"available": True, "overall_mode": _overall_mode(devices),
                "mode_confidence": "heuristic", "devices": devices,
                "services": [x for x in _as_list(parsed.get("services")) if isinstance(x, dict)]}
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {"available": False, "error": "InvalidPowerShellOutput"}


def resolve_apple_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    root = Path(__file__).resolve().parent
    suffix = ".exe" if platform.system() == "Windows" else ""
    candidates = (root / "tools" / "libimobiledevice" / f"{name}{suffix}",
                  root.parent / "tools" / "libimobiledevice" / f"{name}{suffix}")
    return next((str(candidate) for candidate in candidates if candidate.is_file()), None)


def collect() -> dict[str, Any]:
    is_windows = platform.system() == "Windows"
    optional = ("ideviceinfo", "idevice_id", "irecovery")
    return {
        "schema_version": 2,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": platform.python_version(),
                 "architecture": platform.machine(), "windows": is_windows},
        "tools": {"python": run_command([shutil.which("python") or "python", "--version"]),
                  "git": run_command([shutil.which("git") or "git", "--version"]),
                  "apple_cli": {name: {"available": resolve_apple_tool(name) is not None,
                                      "path": resolve_apple_tool(name)}
                                for name in optional}},
        "apple_usb": collect_windows_devices() if is_windows else
                     {"available": False, "error": "WindowsOnly"},
        "scope": {"read_only": True, "activation_server_checked": False,
                  "activation_lock_changed": False, "firmware_changed": False,
                  "device_identifiers_collected": False, "usb_hardware_ids_collected": True},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only iPhone/Apple USB diagnostics")
    parser.add_argument("--output", type=Path, default=Path("iphone-diagnostics.json"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(collect(), ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Report written to: {args.output.resolve()}")
    print("Read-only report only; no activation or firmware operation was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
