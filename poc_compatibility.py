"""Compare a device snapshot with a researcher's published PoC test claims.

A mismatch means the published test does not validate the target environment;
it is not a proof that the PoC cannot work.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _value(snapshot: dict[str, Any], key: str) -> str | None:
    item = snapshot.get("properties", {}).get(key, {})
    if isinstance(item, dict) and item.get("available"):
        return str(item.get("value", ""))
    return None


def compare(snapshot: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
    target_model = _value(snapshot, "ProductType")
    target_version = _value(snapshot, "ProductVersion")
    tested_model = claims.get("tested_model")
    tested_version = claims.get("tested_ios_version")

    model_match = target_model == tested_model if target_model and tested_model else None
    version_match = target_version == tested_version if target_version and tested_version else None

    if target_model is None or target_version is None:
        status = "insufficient_device_snapshot"
    elif model_match and version_match:
        status = "same_as_published_test_environment"
    else:
        status = "published_test_does_not_validate_target"

    return {
        "schema_version": 1,
        "assessment": status,
        "target": {"product_type": target_model, "ios_version": target_version},
        "published_test": {"model": tested_model, "ios_version": tested_version,
                           "claimed_upper_range": claims.get("claimed_upper_range")},
        "comparisons": {"model_exact_match": model_match,
                        "ios_version_exact_match": version_match},
        "limitations": [
            "A match does not prove exploitability or the claimed outcome.",
            "A mismatch does not prove incompatibility; it means the cited test is not validation.",
            "This tool does not execute PoC code or modify a device.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare device snapshot with public PoC test claims")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--claims", type=Path,
                        default=Path(__file__).resolve().parent / "research" / "bl_sbx_claims.json")
    parser.add_argument("--output", type=Path, default=Path("poc-compatibility.json"))
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    claims = json.loads(args.claims.read_text(encoding="utf-8"))
    report = compare(snapshot, claims)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Compatibility assessment written to: {args.output.resolve()}")
    print(report["assessment"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
