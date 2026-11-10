"""Compare two privacy-minimized activation snapshots without changing the device."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_props = before.get("properties", {})
    after_props = after.get("properties", {})
    keys = sorted(set(before_props) | set(after_props))
    changes = []
    unchanged = []
    unavailable = []
    for key in keys:
        left = before_props.get(key, {})
        right = after_props.get(key, {})
        left_ok = isinstance(left, dict) and left.get("available") is True
        right_ok = isinstance(right, dict) and right.get("available") is True
        if not left_ok or not right_ok:
            unavailable.append(key)
            continue
        old = str(left.get("value", ""))
        new = str(right.get("value", ""))
        if old == new:
            unchanged.append(key)
        else:
            changes.append({"property": key, "before": old, "after": new})
    activation_changed = any(item["property"] == "ActivationState" for item in changes)
    return {
        "schema_version": 1,
        "changes": changes,
        "unchanged_properties": unchanged,
        "unavailable_properties": unavailable,
        "activation_state_changed": activation_changed,
        "interpretation": (
            "ActivationState property changed between snapshots."
            if activation_changed else
            "No ActivationState change is visible in these snapshots; this does not prove server-side status."
        ),
        "safety": {"read_only_comparison": True, "device_modified": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare before/after activation snapshots")
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path, default=Path("activation-snapshot-diff.json"))
    args = parser.parse_args()
    before = json.loads(args.before.read_text(encoding="utf-8"))
    after = json.loads(args.after.read_text(encoding="utf-8"))
    report = compare_snapshots(before, after)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Snapshot comparison written to: {args.output.resolve()}")
    print(report["interpretation"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
