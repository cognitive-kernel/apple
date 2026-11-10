"""Offline analyzer for captured iOS activation-related syslog text.

This module only reads a log file supplied by the user. It does not connect to
a device, contact Apple, change activation state, or infer server acceptance
without an explicit response code/body in the captured log.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PATTERNS = [
    ("activation_request", re.compile(r"ActivationSendRequest|activationData", re.I)),
    ("activation_task", re.compile(r"arbitrary data task|activation task", re.I)),
    ("activation_cancel", re.compile(r"Canceling any in-flight activation|cancel.*activation", re.I)),
    ("activation_success_marker", re.compile(r"ActivationRecord|ActivationState.*Activated|activation.*success", re.I)),
    ("activation_failure_marker", re.compile(r"activation.{0,100}(failed|failure|denied|rejected|not authorized|invalid)|HTTP.*[4-5]\d\d", re.I)),
    ("http_status", re.compile(r"HTTP[^\r\n]{0,40}\b([1-5]\d\d)\b", re.I)),
    ("tls_or_trust", re.compile(r"trustd|TLS|SSL|certificate", re.I)),
    ("dns_or_network", re.compile(r"DNS|resolve|timed out|network is down|not connected", re.I)),
    ("account_service", re.compile(r"FMFError|NoAccount|account.*locked", re.I)),
]

REDACTIONS = [
    (re.compile(r"(?i)\b[a-f0-9]{40}\b"), "[REDACTED_HEX_ID]"),
    (re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f-]{27,}\b"), "[REDACTED_UUID]"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){14,20}(?!\d)"), "[REDACTED_LONG_NUMBER]"),
]


def redact(line: str) -> str:
    for pattern, replacement in REDACTIONS:
        line = pattern.sub(replacement, line)
    return line


def classify_line(line: str) -> list[str]:
    return [name for name, pattern in PATTERNS if pattern.search(line)]


def analyze_text(text: str) -> dict[str, Any]:
    events = []
    counts = {name: 0 for name, _ in PATTERNS}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        categories = classify_line(raw_line)
        if not categories:
            continue
        for category in categories:
            counts[category] += 1
        events.append({
            "line": line_number,
            "categories": categories,
            "text": redact(raw_line.strip())[:1000],
        })

    http_codes = sorted({
        match.group(1)
        for line in text.splitlines()
        for match in re.finditer(r"HTTP[^\r\n]{0,40}\b([1-5]\d\d)\b", line, re.I)
    })
    has_success = counts["activation_success_marker"] > 0
    ("activation_failure_marker", re.compile(r"activation.{0,100}(failed|failure|denied|rejected|not authorized|invalid)|HTTP.*[4-5]\d\d", re.I)),
    if http_codes:
        server_observation = "http_status_observed"
    elif has_success:
        server_observation = "success_like_log_marker_only"
    elif has_failure:
        server_observation = "failure_like_log_marker_only"
    elif counts["activation_request"] or counts["activation_task"]:
        server_observation = "request_activity_seen_response_not_proven"
    else:
        server_observation = "insufficient_activation_log_evidence"

    return {
        "schema_version": 1,
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_lines": len(text.splitlines()),
            "matched_lines": len(events),
            "category_counts": counts,
            "http_status_codes": http_codes,
            "server_observation": server_observation,
            "activation_state_confirmed": False,
        },
        "events": events,
        "limitations": [
            "Log markers do not prove that Apple's server accepted or rejected activation.",
            "A cancellation marker alone does not establish the cause of cancellation.",
            "No device state or Activation Lock setting was changed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze an existing iOS activation syslog offline")
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--output", type=Path, default=Path("activation-log-analysis.json"))
    args = parser.parse_args()
    try:
        raw = args.log_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        parser.error(str(exc))
    report = analyze_text(raw)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Analysis written to: {args.output.resolve()}")
    print(f"Matched {report['summary']['matched_lines']} lines; "
          f"{report['summary']['server_observation']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
