"""Combine vendor advisory scope and public PoC evidence without device modification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cve_scope import assess as assess_cve
from poc_compatibility import compare as compare_poc


def assess_target(snapshot: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
    properties = snapshot.get("properties", {})
    product_type_item = properties.get("ProductType", {})
    version_item = properties.get("ProductVersion", {})
    product_type = (str(product_type_item.get("value", ""))
                    if isinstance(product_type_item, dict) and product_type_item.get("available")
                    else "")
    product_version = (str(version_item.get("value", ""))
                       if isinstance(version_item, dict) and version_item.get("available")
                       else "")

    if product_type and product_version:
        vendor = assess_cve(product_type, product_version)
    else:
        vendor = {
            "cve": "CVE-2025-43534",
            "assessment": "insufficient_device_snapshot",
            "exploitability_confirmed": False,
            "activation_lock_changed": False,
            "device_modified": False,
        }

    poc = compare_poc(snapshot, claims)
    return {
        "schema_version": 1,
        "target": {"product_type": product_type or None,
                   "product_version": product_version or None},
        "vendor_advisory": vendor,
        "public_poc": poc,
        "overall_assessment": (
            "advisory_applies_but_no_validated_activation_lock_solution"
            if vendor.get("assessment") == "within_vendor_advisory_affected_version_range"
            else "insufficient_or_unconfirmed_evidence"
        ),
        "activation_lock_removal_demonstrated": False,
        "device_modified": False,
        "limitations": [
            "Vendor advisory applicability is not proof that a public exploit is available.",
            "The bl_sbx published test environment and outcome do not validate this target.",
            "No exploit is executed and no activation, firmware, or protected device state is changed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Combine CVE advisory and public PoC evidence (read-only)")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--claims", type=Path,
                        default=Path(__file__).resolve().parent / "research" / "bl_sbx_claims.json")
    parser.add_argument("--output", type=Path, default=Path("target-assessment.json"))
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    claims = json.loads(args.claims.read_text(encoding="utf-8"))
    report = assess_target(snapshot, claims)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Assessment written to: {args.output.resolve()}")
    print(report["overall_assessment"])
    print("Read-only: no exploit or device modification was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
