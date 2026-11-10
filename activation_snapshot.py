"""Read-only, privacy-minimized snapshot of selected iOS device properties."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAFE_KEYS = (
    "ProductType",
    "ProductVersion",
    "BuildVersion",
    "ActivationState",
    "BrickState",
    "BasebandVersion",
    "TelephonyCapability",
    "SIMStatus",
    "SIMTrayStatus",
    "fm-activation-locked",
)


def read_key(executable: str, key: str, udid: str | None = None) -> dict[str, Any]:
    command = [executable]
    if udid:
        command.extend(["-u", udid])
    command.extend(["-k", key])
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                errors="replace", timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "error": type(exc).__name__}
    if result.returncode != 0:
        return {"available": False, "error": "ideviceinfo_failed"}
    value = result.stdout.strip()
    if not value:
        return {"available": False, "error": "empty_value"}
    return {"available": True, "value": value}


def collect(executable: str | None = None, udid: str | None = None) -> dict[str, Any]:
    executable = executable or shutil.which("ideviceinfo")
    if not executable:
        raise FileNotFoundError("ideviceinfo was not found on PATH")
    properties = {key: read_key(executable, key, udid) for key in SAFE_KEYS}
    return {
        "schema_version": 1,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "properties": properties,
        "privacy": {
            "udid_included": False,
            "serial_number_included": False,
            "ecid_included": False,
        },
        "safety": {
            "read_only": True,
            "activation_state_changed": False,
            "firmware_changed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture selected iPhone properties without collecting device identifiers")
    parser.add_argument("--udid", help="Optional UDID used only to select the connected device")
    parser.add_argument("--output", type=Path, default=Path("activation-snapshot.json"))
    args = parser.parse_args()
    try:
        report = collect(udid=args.udid)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Snapshot written to: {args.output.resolve()}")
    print("Read-only; UDID, serial number, and ECID are not included.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
