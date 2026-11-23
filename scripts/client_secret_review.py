#!/usr/bin/env python3
"""Bounded, offline review of explicitly supplied logical-path/text snapshots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_FILES = 256
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_INPUT_BYTES = 4 * 1024 * 1024
PREFIXES = ("PUBLIC_", "VITE_", "NEXT_PUBLIC_", "NUXT_PUBLIC_", "REACT_APP_")
PUBLIC_NAME = r"(?:NEXT_PUBLIC_|NUXT_PUBLIC_|REACT_APP_|PUBLIC_|VITE_)[A-Z0-9_]+"
ASSIGNMENTS = re.compile(
    r'''(?<![\w])(?P<quote>["']?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)'''
    r'''(?P=quote)\s*(?:=|:)\s*(?:"(?P<double>[^"\r\n]*)"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s,;}#\r\n]+))'''
)
SECRET_NAME = re.compile(r"(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY)(?:_|$)", re.I)
PLACEHOLDER = re.compile(r"(?:|<[^<>]+>|\$\{[^{}]+\}|(?:YOUR|REPLACE|CHANGE|INSERT|EXAMPLE|PLACEHOLDER)(?:[_ -].*)?|CHANGEME|REDACTED|NONE|NULL|UNSET|TODO|X{3,})", re.I)
REFERENCE = re.compile(r"(?:process\.env\.|import\.meta\.env\.|\$[A-Za-z_{]|os\.environ|env\[)")


class InvalidReview(ValueError):
    def __init__(self):
        super().__init__("invalid-review-input")


def etag(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return '"sha256-' + hashlib.sha256(encoded).hexdigest() + '"'


def secret_like(name, value):
    """A name AND literal-value heuristic, not an entropy or validity test."""
    return bool(SECRET_NAME.search(name) and len(value) >= 8
                and not PLACEHOLDER.fullmatch(value.strip())
                and not REFERENCE.match(value))


def public_secret_rules(text):
    """Return rule IDs only; callers retain ownership of text and paths."""
    return ["client-public-secret-literal"] if any(
        re.fullmatch(PUBLIC_NAME, match["name"], re.I)
        and secret_like(match["name"], next(value for value in
            (match["double"], match["single"], match["bare"]) if value is not None))
        for match in ASSIGNMENTS.finditer(text)) else []


def checked_snapshot(document):
    if type(document) is not dict or set(document) != {"format", "files"} or type(document["format"]) is not int or document["format"] != 1:
        raise InvalidReview()
    files = document["files"]
    if type(files) is not list or not 1 <= len(files) <= MAX_FILES:
        raise InvalidReview()
    identities, total = set(), 0
    for item in files:
        if type(item) is not dict or set(item) != {"path", "text", "committed"}:
            raise InvalidReview()
        path, text = item["path"], item["text"]
        if type(path) is not str or len(path) > 240 or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path) or any(part in {".", ".."} or part.endswith(".") for part in path.split("/")):
            raise InvalidReview()
        if path.casefold() in identities or type(text) is not str or type(item["committed"]) is not bool or "\x00" in text:
            raise InvalidReview()
        identities.add(path.casefold())
        size = len(text.encode("utf-8"))
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise InvalidReview()
    return files


def review(document, expected_input_etag=None):
    files = checked_snapshot(document)
    input_tag = etag(document)
    if expected_input_etag is not None and expected_input_etag != input_tag:
        raise InvalidReview()
    findings = []
    def add(path, rule, severity):
        findings.append({"path": path, "rule": rule, "severity": severity})
    for item in files:
        path, text = item["path"], item["text"]
        for rule in public_secret_rules(text):
            add(path, rule, "high")
        name = path.rsplit("/", 1)[-1].lower()
        example = bool(re.fullmatch(r"\.env(?:\.[a-z0-9_-]+)*\.(?:example|sample|template)|(?:example|sample)\.env", name))
        environment = name == ".env" or name.startswith(".env.") or example
        if environment and item["committed"] and not example:
            add(path, "committed-environment-file", "high")
        if example and any(secret_like(match["name"], next(value for value in
                (match["double"], match["single"], match["bare"]) if value is not None))
                for match in ASSIGNMENTS.finditer(text)):
            add(path, "example-environment-nonplaceholder", "high")
        if path == ".gitignore":
            # Deliberately conservative: only these two unconditional root rules
            # provide a hint of coverage; negation/other syntax requires review.
            lines = {line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")}
            if not ({".env", ".env.*"} <= lines or {"/.env", "/.env.*"} <= lines) or any(line.startswith("!") for line in lines):
                add(path, "environment-ignore-review", "low")
    findings.sort(key=lambda item: (item["path"], item["rule"]))
    result = {"format": 1, "status": "review-required" if findings else "no-known-pattern", "input_etag": input_tag, "findings": findings}
    return {**result, "result_etag": etag(result)}


def read_input(path):
    path = path.absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InvalidReview()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_INPUT_BYTES:
        raise InvalidReview()
    def identity(value):
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if identity(info) != identity(before):
            raise InvalidReview()
        raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES or identity(before) != identity(os.fstat(stream.fileno())):
            raise InvalidReview()
    if identity(before) != identity(path.lstat()):
        raise InvalidReview()
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise InvalidReview()
            value[key] = item
        return value
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_pairs)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise InvalidReview()


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument("input", type=Path, help="one explicit JSON snapshot; logical paths are never opened")
    parser.add_argument("--expected-input-etag")
    args = parser.parse_args()
    result = review(read_input(args.input), args.expected_input_etag)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('{"status":"blocked","rule":"invalid-review-input"}')
        sys.exit(2)
