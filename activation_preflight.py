"""Evaluate evidence prerequisites for a non-invasive iPhone inspection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TARGET = {
    "product_type": "iPhone17,3",
    "product_version": "18.3.2",
    "build_version": "22D82",
}


def _property(snapshot: dict[str, Any], key: str) -> str | None:
    item = snapshot.get("properties", {}).get(key)
    if isinstance(item, dict) and item.get("available") is True:
        value = item.get("value")
        return str(value) if value is not None else None
    return None


def evaluate_preflight(
    snapshot: dict[str, Any],
    ipsw_report: dict[str, Any],
    expected: dict[str, str] | None = None,
) -> dict[str, Any]:
    expected = expected or TARGET
    observed = {
        "product_type": _property(snapshot, "ProductType"),
        "product_version": _property(snapshot, "ProductVersion"),
        "build_version": _property(snapshot, "BuildVersion"),
        "activation_state": _property(snapshot, "ActivationState"),
    }
    properties_match = all(
        observed[key] == expected[key]
        for key in ("product_type", "product_version", "build_version")
    )
    activation_state_known = observed["activation_state"] == "Unactivated"
    snapshot_read_only = snapshot.get("safety", {}).get("read_only") is True
    privacy = snapshot.get("privacy", {})
    privacy_minimized = all(
        privacy.get(key) is False
        for key in ("udid_included", "serial_number_included", "ecid_included")
    )
    ipsw_checks = ipsw_report.get("checks", {})
    ipsw_matches = ipsw_checks.get("inspection_passed") is True
    ipsw_target = ipsw_report.get("expected_target", {})
    ipsw_target_matches = (
        ipsw_target.get("product_type") == expected["product_type"]
        and ipsw_target.get("product_version") == expected["product_version"]
        and ipsw_target.get("product_build_version") == expected["build_version"]
    )

    checks = {
        "device_identity_matches_expected_target": properties_match,
        "activation_state_is_unactivated": activation_state_known,
        "snapshot_is_read_only": snapshot_read_only,
        "snapshot_excludes_device_identifiers": privacy_minimized,
        "ipsw_manifest_and_checksum_checks_passed": ipsw_matches,
        "ipsw_expected_target_matches": ipsw_target_matches,
    }
    passed = all(checks.values())
    return {
        "schema_version": 1,
        "assessment": (
            "ready_for_non_invasive_inspection"
            if passed else "blocked_missing_or_mismatched_evidence"
        ),
        "expected_target": expected,
        "observed_device": observed,
        "checks": checks,
        "preflight_passed": passed,
        "allowed_next_scope": "read_only_observation_only",
        "trust_limitations": [
            "A matching IPSW manifest and checksum do not prove Apple's cryptographic signature.",
            "This preflight does not verify TSS signing status or exploitability.",
            "Passing preflight is not authorization to modify firmware or protected activation state.",
        ],
        "safety": {
            "device_accessed": False,
            "firmware_installed": False,
            "activation_state_changed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check evidence prerequisites for non-invasive iPhone inspection")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("ipsw_report", type=Path)
    parser.add_argument("--output", type=Path, default=Path("activation-preflight.json"))
    args = parser.parse_args()
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        ipsw_report = json.loads(args.ipsw_report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    report = evaluate_preflight(snapshot, ipsw_report)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Preflight written to: {args.output.resolve()}")
    print(report["assessment"])
    return 0 if report["preflight_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
