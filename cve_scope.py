"""Non-invasive applicability check for Apple's CVE-2025-43534 advisory."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

FIXED_VERSIONS = {18: (18, 7, 7), 26: (26, 2, 0)}
KNOWN_MODELS = {"iPhone17,3": "iPhone 16"}


def parse_version(value: str) -> Optional[tuple[int, int, int]]:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+){1,2})\s*", value or "")
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    return tuple((parts + [0, 0])[:3])


def assess(product_type: str, product_version: str) -> dict:
    version = parse_version(product_version)
    model_name = KNOWN_MODELS.get(product_type)
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
        "cve": "CVE-2025-43534", "product_type": product_type,
        "known_model_name": model_name,
        "model_scope": "listed" if model_name else "unverified",
        "product_version": product_version,
        "fixed_version_for_branch": ".".join(map(str, fixed)) if fixed else None,
        "assessment": status, "exploitability_confirmed": False,
        "activation_lock_changed": False, "device_modified": False,
        "advisory": "https://support.apple.com/en-us/126793",
        "note": "Advisory version scope does not prove a working exploit or Activation Lock removal.",
    }


def read_device_value(executable: str, key: str, udid: str | None) -> str:
    command = [executable]
    if udid:
        command.extend(["-u", udid])
    command.extend(["-k", key])
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"ideviceinfo failed for {key}")
    value = result.stdout.strip()
    if not value:
        raise RuntimeError(f"Device returned an empty {key}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only CVE-2025-43534 scope check")
    parser.add_argument("--udid")
    parser.add_argument("--product-type")
    parser.add_argument("--product-version")
    args = parser.parse_args()
    if bool(args.product_type) != bool(args.product_version):
        parser.error("Provide both --product-type and --product-version together")
    if args.product_type:
        product_type, product_version = args.product_type, args.product_version
    else:
        executable = shutil.which("ideviceinfo")
        root = Path(__file__).resolve().parent
        bundled_candidates = (root / "tools" / "libimobiledevice" / "ideviceinfo.exe",
                              root.parent / "tools" / "libimobiledevice" / "ideviceinfo.exe")
        if not executable:
            bundled = next((candidate for candidate in bundled_candidates if candidate.is_file()), None)
            if bundled:
                executable = str(bundled)
        if not executable:
            print("ERROR: ideviceinfo not found.", file=sys.stderr)
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
