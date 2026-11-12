#!/usr/bin/env python3
"""Bounded static-file backup. Archive hashes detect corruption, not authenticity."""
import argparse
import ctypes
from functools import cmp_to_key
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile

MAX_FILES = 100000
MAX_BYTES = 8 * 1024 ** 3
MANIFEST = "MANIFEST.json"
DENIED_DIRS = {".git", ".ssh", ".gnupg", "secrets", ".secrets", ".agent-secrets", "amqic-protected-input", "node_modules", ".venv"}
DENIED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".keyx", ".secret"}
WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    prefix + number for prefix in ("COM", "LPT") for number in "123456789¹²³"
}


def reject_linklike(path, allow_missing_leaf=False):
    # Check before resolve(): Windows junctions are reparse points, not symlinks.
    path = path.absolute()
    for current in (*reversed(path.parents), path):
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and current == path:
                return
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("link or reparse point refused")


def safe_relative(value):
    path = PurePosixPath(value)
    if not value or "\\" in value or ":" in value or path.is_absolute() or value != path.as_posix() or any(p in {".", ".."} for p in value.split("/")):
        raise ValueError("unsafe relative path")
    if any(ord(c) < 32 for c in value):
        raise ValueError("control character in path")
    if os.name == "nt":
        for part in path.parts:
            stem = part.split(".", 1)[0].rstrip(" ").upper()
            if part.endswith((".", " ")) or any(c in '<>"|?*' for c in part) or stem in WINDOWS_DEVICES:
                raise ValueError("unsafe Windows path")
    return path


def validate_names(names):
    # Files may not also be directories; Windows aliases must not merge paths.
    files = set(names)
    prefixes = set()
    for name in names:
        parts = safe_relative(name).parts
        for end in range(1, len(parts) + 1):
            prefix = parts[:end]
            if end < len(parts) and "/".join(prefix) in files:
                raise ValueError("file used as directory")
            prefixes.add("/".join(prefix))
    if os.name == "nt":
        compare = ctypes.WinDLL("kernel32", use_last_error=True).CompareStringOrdinal
        compare.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_wchar_p, ctypes.c_int, ctypes.c_int]
        compare.restype = ctypes.c_int

        def ordinal(left, right):
            result = compare(left, -1, right, -1, 1)
            if not result:
                raise ctypes.WinError(ctypes.get_last_error())
            return result - 2

        # Sort native ordinal keys without Python's broader Unicode casefold.
        ordered = sorted(prefixes, key=cmp_to_key(ordinal))
        if any(ordinal(left, right) == 0 for left, right in zip(ordered, ordered[1:])):
            raise ValueError("Windows path collision")


def excluded(path):
    return any(p.lower() in DENIED_DIRS or p.lower().startswith(".env") for p in path.parts) or path.suffix.lower() in DENIED_SUFFIXES


def digest_stream(stream):
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
        size += len(block)
        if size > MAX_BYTES:
            raise ValueError("size limit exceeded")
    return digest.hexdigest(), size


def source_files(root, includes):
    found = set()
    for item in includes:
        relative = safe_relative(item)
        if excluded(relative):
            raise ValueError("requested include is excluded")
        path = root
        for part in relative.parts:
            path = path / part
            reject_linklike(path)
        if not path.exists():
            raise ValueError("include missing")
        candidates = [path]
        while candidates:
            current = candidates.pop()
            rel = PurePosixPath(current.relative_to(root).as_posix())
            reject_linklike(current)
            if excluded(rel):
                continue
            info = current.lstat()
            if stat.S_ISDIR(info.st_mode):
                candidates.extend(current.iterdir())
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                found.add(rel.as_posix())
            else:
                raise ValueError("special file or hard link refused")
            if len(found) > MAX_FILES:
                raise ValueError("file limit exceeded")
    if not found:
        raise ValueError("no eligible files")
    validate_names([*found, MANIFEST])
    return sorted(found)


def inspect_archive(archive):
    by_name = {}
    total = 0
    for member in archive:
        if len(by_name) >= MAX_FILES + 1:
            raise ValueError("archive member limit")
        safe_relative(member.name)
        if member.name in by_name or not member.isfile() or member.size < 0:
            raise ValueError("duplicate or nonregular archive member")
        total += member.size
        if total > MAX_BYTES:
            raise ValueError("archive size limit")
        by_name[member.name] = member
    manifest = by_name.pop(MANIFEST, None)
    if manifest is None or manifest.size > 32 * 1024 * 1024:
        raise ValueError("manifest missing or too large")
    document = json.load(archive.extractfile(manifest))
    if set(document) != {"format", "files"} or document["format"] != 1 or not isinstance(document["files"], list):
        raise ValueError("invalid manifest schema")
    expected = {}
    for entry in document["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise ValueError("invalid manifest entry")
        name = entry["path"]
        relative = safe_relative(name)
        if name in expected or excluded(relative) or name == MANIFEST:
            raise ValueError("invalid manifest path")
        expected[name] = entry
    if set(expected) != set(by_name):
        raise ValueError("membership mismatch")
    validate_names([*by_name, MANIFEST])
    for name, member in by_name.items():
        with archive.extractfile(member) as stream:
            digest, size = digest_stream(stream)
        if expected[name]["size"] != size or expected[name]["sha256"] != digest:
            raise ValueError("payload verification failed")
    return by_name, expected


def verify(path):
    path = Path(path)
    reject_linklike(path)
    # Reading through EOF validates every gzip member, CRC and uncompressed size.
    with gzip.open(path, "rb") as stream:
        digest_stream(stream)
    with tarfile.open(path, "r:gz") as archive:
        members, _ = inspect_archive(archive)
    return len(members)


def create(root, output, includes):
    reject_linklike(root)
    reject_linklike(output, allow_missing_leaf=True)
    root = root.resolve(strict=True)
    output = output.absolute()
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if not root.is_dir() or root == parent or root in parent.parents:
        raise ValueError("archive destination must be outside source")
    if output.exists() or output.is_symlink():
        raise ValueError("archive destination already exists")
    names = source_files(root, includes)
    if MANIFEST in names:
        raise ValueError("reserved manifest name")
    descriptor, temporary = tempfile.mkstemp(prefix=".backup-", suffix=".tar.gz", dir=parent)
    try:
        os.close(descriptor)
        entries = []
        total = 0
        with tarfile.open(temporary, "w:gz") as archive:
            for name in names:
                reject_linklike(root / name)
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                with os.fdopen(os.open(root / name, flags), "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        raise ValueError("source identity changed")
                    digest, size = digest_stream(stream)
                    total += size
                    if total > MAX_BYTES:
                        raise ValueError("total size limit")
                    stream.seek(0)
                    member = tarfile.TarInfo(name)
                    member.size = size
                    member.mode = 0o600
                    archive.addfile(member, stream)
                    after = os.fstat(stream.fileno())
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise ValueError("source changed during backup")
                    entries.append({"path": name, "size": size, "sha256": digest})
            payload = json.dumps({"format": 1, "files": entries}, ensure_ascii=False, sort_keys=True).encode("utf-8")
            member = tarfile.TarInfo(MANIFEST)
            member.size = len(payload)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(payload))
        count = verify(temporary)
        with open(temporary, "r+b") as stream:
            os.fsync(stream.fileno())
        os.link(temporary, output)
    finally:
        os.unlink(temporary)
    return count


def restore(source, target):
    reject_linklike(target, allow_missing_leaf=True)
    count = verify(source)
    parent = target.absolute().parent.resolve(strict=True)
    target = parent / target.name
    if target.exists() or target.is_symlink():
        raise ValueError("restore target exists")
    staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=parent))
    with tarfile.open(source, "r:gz") as archive:
        members, expected = inspect_archive(archive)
        for name, member in members.items():
            destination = staging.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(descriptor, "wb") as output, archive.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    output.write(block)
                    digest.update(block)
                    size += len(block)
                output.flush()
                os.fsync(output.fileno())
            if digest.hexdigest() != expected[name]["sha256"] or size != expected[name]["size"]:
                raise ValueError("restore copy changed")
    publish_directory(staging, target)
    return count


def publish_directory(staging, target):
    if os.name == "nt":
        # Windows rename refuses any existing target.
        os.rename(staging, target)
        return
    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        rename = getattr(library, "renameat2", None)
        if rename is None:
            raise ValueError("exclusive directory rename unavailable")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staging), -100, os.fsencode(target), 1) != 0:
            raise OSError(ctypes.get_errno(), "exclusive restore publication failed")
        return
    raise ValueError("restore publication supported on Linux and Windows")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    creation = commands.add_parser("create")
    creation.add_argument("--root", type=Path, required=True)
    creation.add_argument("--output", type=Path, required=True)
    creation.add_argument("--include", action="append", required=True)
    creation.add_argument("--allow-plaintext", action="store_true", required=True)
    verification = commands.add_parser("verify")
    verification.add_argument("archive", type=Path)
    restoration = commands.add_parser("restore")
    restoration.add_argument("archive", type=Path)
    restoration.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        count = create(args.root, args.output, args.include)
    elif args.command == "verify":
        count = verify(args.archive)
    else:
        count = restore(args.archive, args.target)
    print(json.dumps({"status": "verified", "operation": args.command, "files": count}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, tarfile.TarError, json.JSONDecodeError, TypeError, KeyError):
        print('{"status":"failed","detail":"invalid input or incomplete operation; preserve artifacts and inspect locally"}', file=sys.stderr)
        sys.exit(1)
