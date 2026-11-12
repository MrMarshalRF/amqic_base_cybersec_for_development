"""Synthetic fixtures only. Run with python3 scripts/test_operations.py."""
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import backup


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="amqic-backup-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "hello.txt").write_text("Synthetic payload\n", encoding="utf-8")
        self.archive = self.root / "copy.tar.gz"

    def test_roundtrip_and_exclusion(self):
        (self.source / ".env").write_text("SYNTHETIC_ONLY=1")
        (self.source / "folder").mkdir()
        (self.source / "folder" / "item.txt").write_bytes(b"\x00\x01\xff")
        backup.create(self.source, self.archive, ["hello.txt", "folder"])
        self.assertEqual(backup.verify(self.archive), 2)
        target = self.root / "restored"
        backup.restore(self.archive, target)
        self.assertEqual((target / "hello.txt").read_bytes(), (self.source / "hello.txt").read_bytes())
        self.assertEqual((target / "folder" / "item.txt").read_bytes(), b"\x00\x01\xff")
        self.assertFalse((target / ".env").exists())

    def test_existing_targets_untouched(self):
        backup.create(self.source, self.archive, ["hello.txt"])
        original = self.archive.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            backup.create(self.source, self.archive, ["hello.txt"])
        self.assertEqual(self.archive.read_bytes(), original)
        target = self.root / "restored"
        target.mkdir()
        with self.assertRaises((ValueError, OSError)):
            backup.restore(self.archive, target)
        self.assertEqual(list(target.iterdir()), [])

    def test_path_rejections(self):
        for path in ["../outside", "/absolute", "a//b", "a/./b", "a\\b", "C:drive", "a/"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                backup.safe_relative(path)
        with self.assertRaises(ValueError):
            backup.create(self.source, self.archive, [".env"])

    def test_malicious_members_and_corruption(self):
        for name in ["../escape", "/absolute", "nested//alias"]:
            with tarfile.open(self.archive, "w:gz") as archive:
                member = tarfile.TarInfo(name)
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                backup.verify(self.archive)
        self.archive.unlink()
        backup.create(self.source, self.archive, ["hello.txt"])
        self.archive.write_bytes(self.archive.read_bytes()[:-8])
        with self.assertRaises((ValueError, OSError, EOFError, tarfile.TarError)):
            backup.verify(self.archive)

    def test_payload_hash_mismatch(self):
        manifest = json.dumps({"format": 1, "files": [{"path": "a", "size": 1, "sha256": "0" * 64}]}).encode()
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, data in [("a", b"x"), (backup.MANIFEST, manifest)]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        with self.assertRaises(ValueError):
            backup.restore(self.archive, self.root / "rejected")
        self.assertFalse((self.root / "rejected").exists())

    def test_hardlink_rejected(self):
        os.link(self.source / "hello.txt", self.source / "alias")
        with self.assertRaises(ValueError):
            backup.create(self.source, self.archive, ["hello.txt"])

    def write_archive(self, names):
        entries = [{"path": name, "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()} for name in names]
        manifest = json.dumps({"format": 1, "files": entries}).encode()
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, data in [(name, b"x") for name in names] + [(backup.MANIFEST, manifest)]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def assert_link_boundaries(self, link):
        # The directory target is synthetic and contains an otherwise valid file/archive.
        backup.create(self.source, self.archive, ["hello.txt"])
        outside = link.resolve()
        (outside / "copy.tar.gz").write_bytes(self.archive.read_bytes())
        for root, output, includes in [
            (self.source, self.root / "child.tar.gz", [link.name]),
            (link, self.root / "root.tar.gz", ["hello.txt"]),
            (link / "nested", self.root / "parent.tar.gz", ["hello.txt"]),
            (self.source, link / "output.tar.gz", ["hello.txt"]),
        ]:
            with self.subTest(root=root, output=output), self.assertRaisesRegex(ValueError, "link|reparse"):
                backup.create(root, output, includes)
            self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, "link|reparse"):
            backup.verify(link / "copy.tar.gz")
        with self.assertRaisesRegex(ValueError, "link|reparse"):
            backup.restore(self.archive, link / "restored")
        self.assertFalse((outside / "restored").exists())
        output = self.root / "cli-refused.tar.gz"
        command = [sys.executable, "-B", str(Path(backup.__file__)), "create", "--root", str(self.source),
                   "--output", str(output), "--include", link.name, "--allow-plaintext"]
        result = subprocess.run(command, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def link_target(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "hello.txt").write_text("Synthetic outside payload")
        (outside / "nested").mkdir()
        (outside / "nested" / "hello.txt").write_text("Synthetic nested payload")
        return outside

    def test_directory_symlink_boundaries(self):
        outside = self.link_target()
        link = self.source / "selected"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks unavailable")
        self.addCleanup(link.unlink)
        self.assert_link_boundaries(link)

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_windows_junction_boundaries(self):
        outside = self.link_target()
        link = self.source / "selected"
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(os.rmdir, link)
        self.assertFalse(link.is_symlink())
        self.assert_link_boundaries(link)

    def test_file_symlink_refused(self):
        link = self.source / "alias"
        try:
            link.symlink_to(self.source / "hello.txt")
        except (OSError, NotImplementedError):
            self.skipTest("file symlinks unavailable")
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(ValueError, "link|reparse"):
            backup.create(self.source, self.archive, ["alias"])

    def test_file_directory_conflict_rejected_before_restore(self):
        self.write_archive(["a", "a/b"])
        target = self.root / "rejected"
        with self.assertRaises(ValueError):
            backup.restore(self.archive, target)
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob(".restore-*")), [])

    @unittest.skipUnless(os.name == "nt", "Windows archive-name regression")
    def test_windows_unsafe_archive_names(self):
        for name in ["notes.", "notes ", "nested./item", "CON", "nul.txt", "COM1.log", "LPT².txt", "CONIN$", "a?b"]:
            with self.subTest(name=name):
                self.write_archive([name])
                for command in [["verify", str(self.archive)], ["restore", str(self.archive), "--target", str(self.root / "rejected")]]:
                    result = subprocess.run([sys.executable, "-B", str(Path(backup.__file__)), *command], capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "rejected").exists())
                self.assertEqual(list(self.root.glob(".restore-*")), [])

    @unittest.skipUnless(os.name == "nt", "Windows archive collisions")
    def test_windows_archive_collisions(self):
        for names in [["Case", "case"], ["Dir/a", "dir/b"], ["manifest.json"]]:
            with self.subTest(names=names):
                self.write_archive(names)
                with self.assertRaises(ValueError):
                    backup.restore(self.archive, self.root / "rejected")
                self.assertFalse((self.root / "rejected").exists())

    def test_distinct_unicode_names_roundtrip(self):
        names = ["é/item.txt", "e\u0301/item.txt", "Straße/item.txt", "STRASSE/item.txt"]
        for name in names:
            path = self.source / name
            path.parent.mkdir()
            path.write_text("Synthetic Unicode payload", encoding="utf-8")
        self.assertEqual(backup.create(self.source, self.archive, [name.split("/")[0] for name in names]), len(names))
        target = self.root / "restored"
        self.assertEqual(backup.restore(self.archive, target), len(names))
        self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()), sorted(names))

    @unittest.skipIf(os.name == "nt", "POSIX filename preservation")
    def test_posix_distinct_names_preserved(self):
        names = ["notes.", "notes ", "CON", "Case", "case", "Dir/a", "dir/b", "é/a", "e\u0301/b"]
        self.write_archive(names)
        target = self.root / "restored"
        self.assertEqual(backup.restore(self.archive, target), len(names))
        self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()), sorted(names))


if __name__ == "__main__":
    unittest.main()
