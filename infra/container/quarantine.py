#!/usr/bin/env python3
"""Fetch one bounded pinned artifact, or inspect its hash offline. Never execute it."""
import hashlib
import contextlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
import stat

MAX_BYTES = 64 * 1024 * 1024
PAYLOAD = Path("/payload/artifact.bin")
MAX_MEMBERS = 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024


class BoundedReader:
    def __init__(self, source):
        self.source = source
        self.count = 0

    def read(self, size=-1):
        data = self.source.read(min(size if size >= 0 else MAX_BYTES + 1, MAX_BYTES + 1))
        self.count += len(data)
        if self.count > MAX_BYTES:
            raise ValueError("Expanded archive exceeds 64 MiB")
        return data


def inventory(path):
    """Read archive members in memory with fixed bounds. Never extract or import."""
    records = []
    names = set()
    total = 0
    text_total = 0

    def member(name, size, source, directory=False):
        nonlocal total, text_total
        normalized = name.rstrip("/")
        parts = normalized.split("/")
        if (not normalized or len(name) > 512 or "\\" in name or ":" in name
                or name.startswith("/") or any(part in {"", ".", ".."} for part in parts)
                or any(ord(character) < 32 or ord(character) == 127 for character in name)):
            raise ValueError("Unsafe archive member path")
        key = normalized.casefold()
        if key in names or len(names) >= MAX_MEMBERS:
            raise ValueError("Duplicate/colliding path or too many archive members")
        names.add(key)
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise ValueError("Archive member exceeds 16 MiB")
        total += size
        if total > MAX_BYTES:
            raise ValueError("Archive members exceed 64 MiB")
        if directory:
            records.append({"path": name, "type": "directory"})
            return
        content = source.read(size + 1)
        if len(content) != size:
            raise ValueError("Archive member size mismatch")
        record = {"path": name, "type": "file", "bytes": size,
                  "sha256": hashlib.sha256(content).hexdigest()}
        base = parts[-1].lower()
        selected = (base in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml",
                             "setup.py", "setup.cfg", "requirements.txt", "cargo.toml", "cargo.lock",
                             "go.mod", "go.sum", "composer.json", "composer.lock"}
                    or base.startswith(("license", "copying", "readme"))
                    or base.endswith((".sh", ".ps1", ".bat", ".cmd")))
        if selected:
            allowed = min(32768, MAX_TEXT_BYTES - text_total)
            preview = content[:allowed]
            text_total += len(preview)
            record["text_preview"] = preview.decode("utf-8", errors="replace")
            record["text_truncated"] = len(preview) != len(content)
        records.append(record)

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_MEMBERS:
                raise ValueError("Too many archive members")
            for item in entries:
                mode = item.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if (item.flag_bits & 1 or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or item.file_size > max(1, item.compress_size) * 100):
                    raise ValueError("Encrypted, special or over-compressed ZIP member")
                with archive.open(item) as stream:
                    # orig_filename preserves NULs/backslashes normalized by zipfile.
                    member(item.orig_filename, item.file_size, stream, item.is_dir())
    else:
        with path.open("rb") as raw, contextlib.ExitStack() as cleanup:
            magic = raw.read(2)
            raw.seek(0)
            source = cleanup.enter_context(gzip.GzipFile(fileobj=raw)) if magic == b"\x1f\x8b" else raw
            bounded = BoundedReader(source)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for item in archive:
                    if item.issym() or item.islnk() or item.sparse or not (item.isfile() or item.isdir()):
                        raise ValueError("Links, sparse files and special TAR members are forbidden")
                    stream = archive.extractfile(item) if item.isfile() else io.BytesIO()
                    with stream:
                        member(item.name, item.size, stream, item.isdir())
            # TAR stops at its end marker, which can precede the gzip trailer or
            # further gzip members. Consume the whole source through the same
            # bound so CRC/truncation failures and trailing expansion cannot hide.
            while bounded.read(65536):
                pass
    if not records:
        raise ValueError("Empty or unsupported archive")
    return records


def expected_digest():
    value = os.environ.get("ARTIFACT_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("A lowercase independently verified SHA-256 is required")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        raise ValueError("Redirect refused; verify and supply the final URL")


def fetch():
    expected = expected_digest()
    url = os.environ.get("ARTIFACT_URL", "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("An exact public HTTPS URL without credentials or fragment is required")
    temporary = PAYLOAD.with_suffix(".partial")
    digest = hashlib.sha256()
    count = 0
    # Empty ProxyHandler avoids inherited proxy environment variables.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=30) as response, temporary.open("xb") as output:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_BYTES:
                raise ValueError("Artifact exceeds 64 MiB")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("SHA-256 mismatch; artifact remains untrusted")
    # Do not replace an artifact already awaiting review. Failed partials stay quarantined.
    os.link(temporary, PAYLOAD)
    temporary.unlink()
    print(json.dumps({"status": "fetched-untrusted", "bytes": count, "sha256": expected}))


def inspect():
    expected = expected_digest()
    size = PAYLOAD.stat().st_size
    if size > MAX_BYTES or not PAYLOAD.is_file() or PAYLOAD.is_symlink():
        raise ValueError("Invalid payload")
    with PAYLOAD.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise ValueError("Offline artifact SHA-256 mismatch")
    records = inventory(PAYLOAD)
    # JSON escapes control characters. Every string remains untrusted artifact data.
    print(json.dumps({"status": "content-inventoried-ai-review-required", "bytes": size,
                      "sha256": actual, "members": records, "executed": False,
                      "installed": False, "extracted": False}, ensure_ascii=True))


if __name__ == "__main__":
    if sys.argv[1:] == ["fetch"]:
        fetch()
    elif sys.argv[1:] == ["inspect"]:
        inspect()
    else:
        raise SystemExit("Choose fetch or inspect")
