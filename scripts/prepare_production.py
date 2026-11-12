#!/usr/bin/env python3
"""Prepare an explicit, text-only production source payload without editing its source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import unicodedata

from backup import publish_directory, safe_relative

MANIFEST = "PRODUCTION-MANIFEST.json"
MAX_FILES = 10000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
DENIED_PARTS = {
    ".git", ".hg", ".svn", ".ssh", ".gnupg", ".aws", ".azure", ".config",
    ".dev", ".idea", ".vscode", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "__pycache__", "node_modules", ".venv", "venv", "coverage", ".nyc_output",
    "test", "tests", "__tests__", "fixtures", "secrets", ".secrets", "private",
    "backups", "backup", "logs", ".agent-private", ".agent-secrets",
    "amqic-protected-input", ".codex", ".agents", "state", "debug", "tmp", "temp", ".kube",
    ".graphify", "graphify-out", "graphify-output", ".internal", "receipts", "checkpoints", "plans",
    ".github", ".gitlab", ".devcontainer", ".cursor", ".windsurf",
}
DENIED_SUFFIXES = {".key", ".keyx", ".pem", ".p12", ".pfx", ".kdbx", ".secret", ".log", ".bak", ".old", ".pyc", ".map", ".zip", ".gz", ".tar", ".sqlite", ".db"}
TEXT_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".txt", ".md", ".html", ".css", ".sh", ".sql", ".xml", ".svg"}
TEXT_FILENAMES = {"license", "notice", "copying"}
INTERNAL_FILES = {
    "agents.md", "agents.override.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", "config.local.toml", ".mcp.json", "mcp.json", "mcp.local.json",
    ".graphifyignore", "graphify.json", "graphify.config.json", "graphify.config.yaml", "graphify.config.yml",
    "graphify.config.toml", "graphify-index.json", "graphify.index.json", "graphify-index.sqlite",
    ".gitignore", ".gitattributes", ".editorconfig", ".dockerignore",
}
CREDENTIAL_NAME = r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)"
QUOTED_VALUE = r'''["'][^"'\r\n]+["']'''
ASSIGNMENT_LITERAL = rf'''\b{CREDENTIAL_NAME}(?:["']\s*\])?\s*=\s*{QUOTED_VALUE}'''
KEY_LITERAL = rf'''(?:^|[{{,])\s*["']?{CREDENTIAL_NAME}["']?\s*:\s*{QUOTED_VALUE}'''
RULES = {
    "private-key-material": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "credential-literal": re.compile(rf"(?:{ASSIGNMENT_LITERAL})|(?:{KEY_LITERAL})", re.IGNORECASE | re.MULTILINE),
    "provider-token": re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "bearer-literal": re.compile(r"(?i)\bBearer [A-Za-z0-9._~+/=-]{12,}"),
    "unquoted-credential-config": re.compile(r"(?im)^\s*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*(?![\s#;]|$)[^\r\n]+"),
    "uri-password": re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
}


class Blocked(ValueError):
    def __init__(self, path, rule):
        super().__init__("production preparation blocked")
        self.finding = {"path": path, "rule": rule}


def fingerprint(info):
    # Windows lstat/fstat disagree on legacy ctime semantics; birthtime is stable.
    if os.name == "nt" and not hasattr(info, "st_birthtime_ns"):
        raise Blocked("", "windows-python312-required")
    change_time = info.st_ctime_ns if os.name != "nt" else info.st_birthtime_ns
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, change_time, info.st_nlink)


def is_linklike(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def check_ancestors(path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if is_linklike(current):
            raise Blocked("", "linked-root-or-parent")


def allowed_path(name):
    try:
        path = safe_relative(name)
    except (ValueError, TypeError):
        raise Blocked("", "unsafe-relative-path") from None
    for part in path.parts:
        lower = part.casefold()
        if lower in {".netrc", ".npmrc", ".pypirc", "id_ed25519", "id_rsa", "kubeconfig"} or re.fullmatch(r"(?:credentials|secrets)\.(?:json|ya?ml)", lower) or re.fullmatch(r"service[-_]account.*\.json", lower):
            raise Blocked(name, "credential-file-name")
        if lower in DENIED_PARTS or lower.startswith((".env", ".aider", "test_")) or ".test." in lower or ".spec." in lower:
            raise Blocked(name, "excluded-file-or-directory")
        if part.endswith((".", " ")) or lower.split(".")[0] in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}:
            raise Blocked(name, "nonportable-path")
    if path.suffix.casefold() in DENIED_SUFFIXES or path.name.casefold() in INTERNAL_FILES | {MANIFEST.casefold()}:
        raise Blocked(name, "excluded-file-or-directory")
    if path.suffix.casefold() not in TEXT_SUFFIXES and path.name.casefold() not in TEXT_FILENAMES:
        raise Blocked(name, "unsupported-file-needs-separate-review")
    return path


def check_names(names):
    if not names or len(names) > MAX_FILES:
        raise Blocked("", "file-count-bound")
    canonical = set()
    prefixes = {}
    for name in names:
        allowed_path(name)
        identity = unicodedata.normalize("NFC", name).casefold()
        if identity in canonical:
            raise Blocked(name, "duplicate-or-case-collision")
        canonical.add(identity)
        parts = name.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            key = unicodedata.normalize("NFC", prefix).casefold()
            if key in prefixes and prefixes[key] != prefix:
                raise Blocked(name, "directory-case-collision")
            prefixes[key] = prefix
    return sorted(names)


def inspect_file(root, name):
    path = root
    for part in Path(name).parts:
        path /= part
        if is_linklike(path):
            raise Blocked(name, "linked-file-or-parent")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Blocked(name, "nonregular-or-hardlinked-file")
    if info.st_size > MAX_FILE_BYTES:
        raise Blocked(name, "file-size-bound")
    return info


def read_scanned(root, name, expected):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(root / name, flags), "rb") as stream:
        if fingerprint(os.fstat(stream.fileno())) != expected:
            raise Blocked(name, "source-changed")
        payload = stream.read(MAX_FILE_BYTES + 1)
        if len(payload) > MAX_FILE_BYTES or fingerprint(os.fstat(stream.fileno())) != expected:
            raise Blocked(name, "source-changed-or-size-bound")
    if fingerprint(inspect_file(root, name)) != expected:
        raise Blocked(name, "source-changed")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError:
        raise Blocked(name, "unsupported-encoding-or-binary") from None
    if "\x00" in text:
        raise Blocked(name, "unsupported-encoding-or-binary")
    for rule, pattern in RULES.items():
        if pattern.search(text):
            raise Blocked(name, rule)
    return payload


def manifest_for(entries):
    inventory = json.dumps(entries, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return {"format": 1, "files": entries, "root_sha256": hashlib.sha256(inventory).hexdigest()}


def prepare(source, target, names):
    source = source.absolute()
    check_ancestors(source)
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise Blocked("", "source-directory-required")
    check_ancestors(target.absolute().parent)
    target = target.absolute().parent.resolve(strict=True) / target.name
    if target == source or source in target.parents:
        raise Blocked("", "destination-inside-source")
    if target.exists() or target.is_symlink():
        raise Blocked("", "destination-exists")
    names = check_names(names)
    snapshots = {name: fingerprint(inspect_file(source, name)) for name in names}
    if sum(info[2] for info in snapshots.values()) > MAX_TOTAL_BYTES:
        raise Blocked("", "total-size-bound")
    staging = Path(tempfile.mkdtemp(prefix=".production-", dir=target.parent))
    try:
        entries = []
        for name in names:
            payload = read_scanned(source, name, snapshots[name])
            destination = staging / name
            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            entries.append({"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        for name in names:
            if fingerprint(inspect_file(source, name)) != snapshots[name]:
                raise Blocked(name, "source-changed")
        document = manifest_for(entries)
        (staging / MANIFEST).write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        validate(staging)
        publish_directory(staging, target)
        return document
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def validate(root):
    root = root.absolute()
    check_ancestors(root)
    root = root.resolve(strict=True)
    manifest_info = inspect_file(root, MANIFEST)
    if manifest_info.st_size > MAX_FILE_BYTES:
        raise Blocked("", "manifest-size-bound")
    document = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if set(document) != {"format", "files", "root_sha256"} or type(document["format"]) is not int or document["format"] != 1 or not isinstance(document["files"], list):
        raise Blocked("", "invalid-manifest")
    entries = document["files"]
    if not all(isinstance(entry, dict) and set(entry) == {"path", "size", "sha256"} and type(entry["size"]) is int and entry["size"] >= 0 and isinstance(entry["sha256"], str) for entry in entries):
        raise Blocked("", "invalid-manifest")
    names = check_names([entry["path"] for entry in entries])
    if entries != sorted(entries, key=lambda entry: entry["path"]) or manifest_for(entries) != document:
        raise Blocked("", "manifest-root-mismatch")
    observed = set()
    expected_directories = {parent.as_posix() for name in names for parent in Path(name).parents if parent != Path(".")}
    observed_directories = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            if is_linklike(path):
                raise Blocked(relative, "linked-file-or-parent")
            if path.is_dir():
                if relative not in expected_directories:
                    raise Blocked(relative, "unexpected-directory")
                observed_directories.add(relative)
                pending.append(path)
            else:
                observed.add(relative)
            if len(observed) + len(observed_directories) > MAX_FILES * 16 + 1:
                raise Blocked("", "file-count-bound")
    if observed != set(names) | {MANIFEST} or observed_directories != expected_directories:
        raise Blocked("", "unexpected-or-missing-payload")
    total = 0
    for entry in entries:
        info = inspect_file(root, entry["path"])
        payload = read_scanned(root, entry["path"], fingerprint(info))
        total += len(payload)
        if total > MAX_TOTAL_BYTES or len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise Blocked(entry["path"], "payload-hash-or-size-mismatch")
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    creation = commands.add_parser("prepare")
    creation.add_argument("--source", type=Path, required=True)
    creation.add_argument("--target", type=Path, required=True)
    creation.add_argument("--include", action="append", required=True)
    verification = commands.add_parser("validate")
    verification.add_argument("target", type=Path)
    args = parser.parse_args()
    document = prepare(args.source, args.target, args.include) if args.command == "prepare" else validate(args.target)
    print(json.dumps({"status": "verified", "files": len(document["files"]), "root_sha256": document["root_sha256"]}))


if __name__ == "__main__":
    try:
        main()
    except Blocked as error:
        print(json.dumps({"status": "blocked", "findings": [error.finding]}))
        sys.exit(1)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('{"status":"blocked","findings":[{"path":"","rule":"invalid-input-or-io-failure"}]}')
        sys.exit(1)
