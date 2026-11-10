import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from poc_audit import audit, audit_zip, sha256_file


class PocAuditTests(unittest.TestCase):
    def test_hash_matches_sha256(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.txt"
            path.write_bytes(b"research")
            self.assertEqual(sha256_file(path), hashlib.sha256(b"research").hexdigest())

    def test_directory_inventory_does_not_execute_scripts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "payload.py").write_text("raise RuntimeError('must not run')", encoding="utf-8")
            report = audit(root)
            self.assertEqual(report["summary"]["scripts_not_executed"], 1)
            self.assertFalse(report["safety"]["executed"])
            self.assertEqual(report["files"][0]["kind"], "script_not_executed")

    def test_zip_inventory_flags_parent_traversal_without_extracting(self):
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / "bundle.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.txt", "not extracted")
                archive.writestr("src/tool.py", "print('not executed')")
            records = audit_zip(archive_path)
            traversal = next(item for item in records if item["path"] == "../outside.txt")
            script = next(item for item in records if item["path"] == "src/tool.py")
            self.assertTrue(traversal["path_traversal_name"])
            self.assertIsNone(traversal["sha256"])
            self.assertEqual(script["kind"], "script_not_executed")
            self.assertIsNotNone(script["sha256"])

    def test_zip_does_not_extract_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive_path = root / "bundle.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("inside.txt", "content")
            audit(archive_path)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["bundle.zip"])


if __name__ == "__main__":
    unittest.main()
