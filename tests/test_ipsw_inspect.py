import hashlib
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from ipsw_inspect import IpswInspectionError, inspect_ipsw


def make_ipsw(path: Path, *, product="iPhone17,3", version="18.3.2", build="22D82"):
    manifest = {
        "ProductVersion": version,
        "ProductBuildVersion": build,
        "SupportedProductTypes": [product],
        "BuildIdentities": [{"Info": {"DeviceClass": "D47AP"}}],
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("BuildManifest.plist", plistlib.dumps(manifest))


class IpswInspectTests(unittest.TestCase):
    def test_matching_target_manifest_is_reported_without_trust_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.ipsw"
            make_ipsw(path)
            report = inspect_ipsw(path)
        self.assertTrue(report["checks"]["manifest_consistent_with_target"])
        self.assertEqual(report["manifest"]["product_build_version"], "22D82")
        self.assertFalse(report["trust"]["apple_signature_verified"])
        self.assertFalse(report["safety"]["archive_extracted"])
        self.assertFalse(report["safety"]["activation_state_changed"])

    def test_wrong_product_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong.ipsw"
            make_ipsw(path, product="iPhone17,1")
            report = inspect_ipsw(path)
        self.assertFalse(report["checks"]["product_type_matches"])
        self.assertFalse(report["checks"]["manifest_consistent_with_target"])

    def test_wrong_version_or_build_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong.ipsw"
            make_ipsw(path, version="18.3.1", build="22D72")
            report = inspect_ipsw(path)
        self.assertFalse(report["checks"]["product_version_matches"])
        self.assertFalse(report["checks"]["build_version_matches"])

    def test_expected_checksum_is_compared(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.ipsw"
            make_ipsw(path)
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            report = inspect_ipsw(path, expected_sha256=expected)
            mismatch = inspect_ipsw(path, expected_sha256="0" * 64)
        self.assertTrue(report["checks"]["expected_sha256_matches"])
        self.assertTrue(report["checks"]["inspection_passed"])
        self.assertFalse(mismatch["checks"]["expected_sha256_matches"])
        self.assertFalse(mismatch["checks"]["inspection_passed"])

    def test_missing_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.ipsw"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/placeholder", b"x")
            with self.assertRaises(IpswInspectionError):
                inspect_ipsw(path)


if __name__ == "__main__":
    unittest.main()
