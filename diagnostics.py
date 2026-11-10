"""Read-only Windows diagnostics for Apple mobile-device connectivity.

This utility does not communicate with Apple's activation servers and cannot
remove Activation Lock. It collects local Windows/tooling information only.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def collect_windows_devices() -> dict[str, Any]:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return {"available": False, "error": "PowerShellNotFound"}

    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$devices = Get-PnpDevice -PresentOnly |
  Where-Object { $_.FriendlyName -match 'Apple|iPhone|iPad|iPod' } |
  Select-Object Status, Class, FriendlyName, InstanceId
$services = Get-Service |
  Where-Object { $_.Name -match 'Apple|Bonjour' -or $_.DisplayName -match 'Apple|Bonjour' } |
  Select-Object Status, Name, DisplayName
[pscustomobject]@{ devices = @($devices); services = @($services) } |
  ConvertTo-Json -Depth 4 -Compress
"""
    result = run_command(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=25,
    )
    if not result["available"] or result.get("returncode") != 0:
        return result
    try:
        parsed = json.loads(result["stdout"] or "{}")
        # Instance IDs can contain hardware identifiers; omit them from reports.
        for device in parsed.get("devices", []):
            device.pop("InstanceId", None)
        return {"available": True, **parsed}
    except (json.JSONDecodeError, AttributeError):
        return {"available": False, "error": "InvalidPowerShellOutput"}


def collect() -> dict[str, Any]:
    """Collect diagnostics without changing device or host configuration."""
    is_windows = platform.system() == "Windows"
    report: dict[str, Any] = {
        "schema_version": 1,
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
        },
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only iPhone/Apple USB diagnostics")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("iphone-diagnostics.json"),
        help="JSON report path (default: iphone-diagnostics.json)",
    )
    args = parser.parse_args()
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
