""""Non-invasive applicability check for Apple's CVE-2025-43534 advisory.

This tool reads ProductType and ProductVersion from a connected device using
ideviceinfo. It does not exercise the vulnerability or change device state.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from typing import Optional


FIXED_VERSIONS = {
    18: (18, 7, 7),
    26: (26, 2, 0),
}
KNOWN_MODELS = {
    "iPhone17,3": "iPhone 16",
}


def parse_version(value: str) -> Optional[tuple[int, int, int]]:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+){1,2})\s*", value or "")
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    return tuple((parts + [0, 0])[:3])


def assess(product_type: str, product_version: str) -> dict:
    version = parse_version(product_version)
    model_name = KNOWN_MODELS.get(product_type)
    model_scope = "listed" if model_name else "unverified"
    fixed = FIXED_VERSIONS.get(version[0]) if version else None

    if not product_type.startswith("iPhone"):
        status = "unsupported_or_unknown_product"
    elif version is None:
        status = "unknown_version"
    elif fixed is None:
        status = "version_branch_not_assessed"
    elif version < fixed:
        status = "within_vendor_advisory_affected_version_range"
    else:
        status = "at_or_above_vendor_fixed_version"

    return {
        "cve": "CVE-2025-43534",
        "product_type": product_type,
        "known_model_name": model_name,
        "model_scope": model_scope,
        "product_version": product_version,
        "fixed_version_for_branch": ".".join(map(str, fixed)) if fixed else None,
        "assessment": status,
        "exploitability_confirmed": False,
        "activation_lock_changed": False,
        "device_modified": False,
        "advisory": "https://support.apple.com/en-us/126793",
        "note": (
            "This is an advisory-scope check only. Being in an affected version "
            "range does not prove that a working exploit exists for this device "
            "or that it will remove Activation Lock."
        ),
    }


def read_device_value(executable: str, key: str, udid: str | None) -> str:
    command = [executable]
    if udid:
        command.extend(["-u", udid])
    command.extend(["-k", key])
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=15, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"ideviceinfo failed for {key}")
    value = result.stdout.strip()
    if not value:
        raise RuntimeError(f"Device returned an empty {key}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check device/version scope for CVE-2025-43534 (read-only)"
    )
    parser.add_argument("--udid", help="Optional device UDID")
    parser.add_argument("--product-type", help="Use supplied ProductType instead of USB")
    parser.add_argument("--product-version", help="Use supplied ProductVersion instead of USB")
    args = parser.parse_args()

    if args.product_type and args.product_version:
        product_type, product_version = args.product_type, args.product_version
    elif args.product_type or args.product_version:
        parser.error("Provide both --product-type and --product-version together")
    else:
        executable = shutil.which("ideviceinfo")
        if not executable:
            print("ERROR: ideviceinfo was not found in PATH.", file=sys.stderr)
            return 2
        try:
            product_type = read_device_value(executable, "ProductType", args.udid)
            product_version = read_device_value(executable, "ProductVersion", args.udid)
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(assess(product_type, product_version), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
