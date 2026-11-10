"""Read-only inspection of an IPSW BuildManifest.plist; never restores or extracts firmware."""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import sys
import zipfile
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 32 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


class IpswInspectionError(ValueError):
    """Raised when an IPSW cannot be safely inspected."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_manifest(archive: zipfile.ZipFile) -> bytes:
    matches = [item for item in archive.infolist()
               if item.filename == "BuildManifest.plist"]
    if len(matches) != 1:
        raise IpswInspectionError(
            "IPSW must contain exactly one root BuildManifest.plist")
    item = matches[0]
    if item.file_size <= 0 or item.file_size > MAX_MANIFEST_BYTES:
        raise IpswInspectionError("BuildManifest.plist size is outside the safe limit")
    if item.flag_bits & 0x1:
        raise IpswInspectionError("Encrypted BuildManifest.plist is not supported")
    try:
        with archive.open(item, "r") as stream:
            data = stream.read(MAX_MANIFEST_BYTES + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise IpswInspectionError("BuildManifest.plist could not be read") from exc
    if len(data) != item.file_size or len(data) > MAX_MANIFEST_BYTES:
        raise IpswInspectionError("BuildManifest.plist size does not match ZIP metadata")
    return data


def inspect_ipsw(
    ipsw_path: Path,
    expected_product_type: str = "iPhone17,3",
    expected_version: str = "18.3.2",
    expected_build: str = "22D82",
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    path = Path(ipsw_path)
    if not path.is_file():
        raise IpswInspectionError("IPSW path is not a regular file")

    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = [item.filename for item in archive.infolist()]
            if len(names) != len(set(names)):
                raise IpswInspectionError("IPSW contains duplicate ZIP entry names")
            manifest_bytes = _read_manifest(archive)
            manifest = plistlib.loads(manifest_bytes)
    except IpswInspectionError:
        raise
    except (OSError, zipfile.BadZipFile, plistlib.InvalidFileException, ValueError) as exc:
        raise IpswInspectionError("File is not a readable IPSW ZIP with a valid plist manifest") from exc

    if not isinstance(manifest, dict):
        raise IpswInspectionError("BuildManifest.plist root must be a dictionary")

    product_version = manifest.get("ProductVersion")
    product_build = manifest.get("ProductBuildVersion")
    supported = manifest.get("SupportedProductTypes")
    identities = manifest.get("BuildIdentities")
    if not isinstance(supported, list) or not all(isinstance(x, str) for x in supported):
        raise IpswInspectionError("Manifest has no valid SupportedProductTypes list")
    if not isinstance(identities, list) or not identities:
        raise IpswInspectionError("Manifest has no BuildIdentities")

    product_match = expected_product_type in supported
    version_match = product_version == expected_version
    build_match = product_build == expected_build
    archive_sha256 = sha256_file(path)
    checksum_match = (
        archive_sha256.lower() == expected_sha256.lower()
        if expected_sha256 else None
    )

    return {
        "schema_version": 1,
        "file": {"name": path.name, "size_bytes": path.stat().st_size,
                 "sha256": archive_sha256},
        "manifest": {
            "product_version": product_version,
            "product_build_version": product_build,
            "supported_product_types": supported,
            "build_identity_count": len(identities),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "expected_target": {
            "product_type": expected_product_type,
            "product_version": expected_version,
            "product_build_version": expected_build,
        },
        "checks": {
            "product_type_matches": product_match,
            "product_version_matches": version_match,
            "build_version_matches": build_match,
            "expected_sha256_matches": checksum_match,
            "manifest_consistent_with_target": (
                product_match and version_match and build_match
            ),
        },
        "trust": {
            "apple_signature_verified": False,
            "tss_signing_status_checked": False,
            "manifest_is_self_asserted_archive_metadata": True,
        },
        "safety": {
            "archive_extracted": False,
            "firmware_installed": False,
            "device_connected": False,
            "activation_state_changed": False,
        },
        "limitations": [
            "A matching BuildManifest does not authenticate the IPSW publisher.",
            "This tool does not verify Apple's cryptographic signatures or TSS signing status.",
            "This tool does not establish exploitability or Activation Lock removal.",
            "No archive member is extracted and no device operation is performed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect IPSW build metadata offline without restoring a device")
    parser.add_argument("ipsw", type=Path)
    parser.add_argument("--product-type", default="iPhone17,3")
    parser.add_argument("--version", default="18.3.2")
    parser.add_argument("--build", default="22D82")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        report = inspect_ipsw(
            args.ipsw, args.product_type, args.version, args.build,
            args.expected_sha256)
    except (OSError, IpswInspectionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Report written to: {args.output.resolve()}")
    else:
        print(rendered, end="")
    return 0 if report["checks"]["manifest_consistent_with_target"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
