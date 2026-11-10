"""Static, non-executing inventory for third-party iOS research PoC bundles.

The auditor never extracts archives, imports modules, launches binaries, or
runs scripts. It records hashes and metadata so a research bundle can be
reviewed and pinned before any separate, authorized analysis.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".js", ".pl", ".rb"}
BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".7z", ".rar", ".xz"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _classify(name: str) -> str:
    suffix = Path(name).suffix.lower()
    if suffix in SCRIPT_SUFFIXES:
        return "script_not_executed"
    if suffix in BINARY_SUFFIXES:
        return "binary_not_executed"
    if suffix in ARCHIVE_SUFFIXES:
        return "nested_archive_not_opened"
    return "data"


def audit_directory(root: Path) -> list[dict[str, Any]]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Input directory required")
    records: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if not (current_path / d).is_symlink())
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records.append({"path": relative, "kind": "symlink_not_followed",
                                "size": info.st_size, "sha256": None})
            elif stat.S_ISREG(info.st_mode):
                records.append({"path": relative, "kind": _classify(name),
                                "size": info.st_size, "sha256": sha256_file(path)})
            else:
                records.append({"path": relative, "kind": "special_file_not_read",
                                "size": info.st_size, "sha256": None})
    return records


def _unsafe_zip_name(name: str) -> bool:
    normalized = name.replace("\\\\", "/")
    path = PurePosixPath(normalized)
    return (normalized.startswith("/") or
            any(part == ".." for part in path.parts) or
            (len(normalized) >= 2 and normalized[1] == ":"))


def audit_zip(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        for item in sorted(archive.infolist(), key=lambda x: x.filename):
            mode = (item.external_attr >> 16) & 0xFFFF
            is_symlink = stat.S_ISLNK(mode)
            encrypted = bool(item.flag_bits & 0x1)
            unsafe_name = _unsafe_zip_name(item.filename)
            record: dict[str, Any] = {
                "path": item.filename,
                "kind": "directory" if item.is_dir() else _classify(item.filename),
                "size": item.file_size,
                "compressed_size": item.compress_size,
                "encrypted": encrypted,
                "path_traversal_name": unsafe_name,
                "symlink": is_symlink,
                "sha256": None,
            }
            if not item.is_dir() and not encrypted and not unsafe_name and not is_symlink:
                digest = hashlib.sha256()
                with archive.open(item, "r") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                record["sha256"] = digest.hexdigest()
            records.append(record)
    return records


def audit(target: Path) -> dict[str, Any]:
    target = target.resolve(strict=True)
    if target.is_dir():
        kind = "directory"
        files = audit_directory(target)
        source_hash = None
    elif target.is_file() and zipfile.is_zipfile(target):
        kind = "zip"
        source_hash = sha256_file(target)
        files = audit_zip(target)
    elif target.is_file():
        kind = "single_file"
        source_hash = sha256_file(target)
        files = [{"path": target.name, "kind": _classify(target.name),
                  "size": target.stat().st_size, "sha256": source_hash}]
    else:
        raise ValueError("Unsupported input")
    return {
        "schema_version": 1,
        "audited_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": {"name": target.name, "kind": kind, "sha256": source_hash},
        "files": files,
        "summary": {
            "file_count": len(files),
            "scripts_not_executed": sum(x["kind"] == "script_not_executed" for x in files),
            "binaries_not_executed": sum(x["kind"] == "binary_not_executed" for x in files),
            "archive_path_warnings": sum(bool(x.get("path_traversal_name")) for x in files),
            "symlinks_not_followed": sum(bool(x.get("symlink")) or
                                         x["kind"] == "symlink_not_followed" for x in files),
        },
        "safety": {
            "extracted": False, "executed": False, "imported": False,
            "device_accessed": False, "activation_state_changed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory a research bundle without extracting or executing it")
    parser.add_argument("target", type=Path, help="Directory, ZIP, or single file")
    parser.add_argument("--output", type=Path, default=Path("poc-audit.json"))
    args = parser.parse_args()
    try:
        report = audit(args.target)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\\n",
                           encoding="utf-8")
    print(f"Static inventory written to: {args.output.resolve()}")
    print(f"Files: {report['summary']['file_count']}; no code was executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
