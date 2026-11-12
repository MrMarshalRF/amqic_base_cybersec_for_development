"""Run synthetic local archive regressions with python -B test_quarantine.py."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
from unittest.mock import patch
import warnings
import zipfile


def make_archive(kind, entries, compressed=False):
    buffer = io.BytesIO()
    if kind == "zip":
        compression = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
        with zipfile.ZipFile(buffer, "w", compression=compression) as target:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                info.compress_type = compression
                target.writestr(info, data)
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz" if compressed else "w") as target:
            for name, data, mode in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                if mode in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
                    info.type = mode
                    info.size = 0
                    info.linkname = "target"
                target.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def verify_benign(records):
    assert len(records) == 3
    assert records[0]["text_preview"] == "safe documentation\n"
    assert records[0]["sha256"] == hashlib.sha256(b"safe documentation\n").hexdigest()
    assert records[1]["text_preview"] == "echo SYNTHETIC_DO_NOT_EXECUTE\n"
    assert "text_preview" not in records[2]


def run_checks(module, fixture_directory):
    results = []

    def inspect_payload(path):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        output = io.StringIO()
        with patch.object(module, "PAYLOAD", path), patch.dict(os.environ, {"ARTIFACT_SHA256": digest}):
            with contextlib.redirect_stdout(output):
                module.inspect()
        return output.getvalue()

    def check(name, payload, accepted, verify=None, inspect_archive=False):
        path = fixture_directory / (name + ".bin")
        path.write_bytes(payload)
        try:
            records = (json.loads(inspect_payload(path))["members"] if inspect_archive
                       else module.inventory(path))
            if not accepted:
                raise AssertionError("unsafe fixture accepted")
            if verify:
                verify(records)
            results.append((name, True, "accepted"))
        except Exception as error:
            expected_error = isinstance(error, (ValueError, tarfile.TarError, zipfile.BadZipFile,
                                               gzip.BadGzipFile, EOFError))
            results.append((name, not accepted and expected_error, str(error)))

    benign = [("README.md", b"safe documentation\n", stat.S_IFREG),
              ("install.sh", b"echo SYNTHETIC_DO_NOT_EXECUTE\n", stat.S_IFREG),
              ("module.py", b'raise RuntimeError("SYNTHETIC_NEVER_EXECUTE")\n', stat.S_IFREG)]
    for kind in ("zip", "tar"):
        check(kind + "-benign", make_archive(kind, benign), True, verify_benign)
        check(kind + "-benign-compressed", make_archive(kind, benign, True), True, verify_benign)
        unsafe_names = ("../escape", "/absolute", "C:/absolute", "a\\b", "a/./b", "a//b", "line\nname")
        for index, unsafe in enumerate(unsafe_names):
            payload = make_archive(kind, [(unsafe, b"x", stat.S_IFREG)])
            if kind == "zip" and unsafe == "a\\b":
                # Windows zipfile normalizes names while writing. Restore both raw names.
                payload = payload.replace(b"a/b", b"a\\b")
            check(kind + "-unsafe-" + str(index), payload, False)
        for label, names in [("duplicate", ["same", "same"]), ("case-collision", ["SAME", "same"])]:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                payload = make_archive(kind, [(name, b"x", stat.S_IFREG) for name in names])
            check(kind + "-" + label, payload, False)
        check(kind + "-member-count", make_archive(kind, [(f"f{i}", b"", stat.S_IFREG) for i in range(1025)]), False)
        check(kind + "-member-size", make_archive(kind, [("large", b"x" * (16 * 1024 * 1024 + 1), stat.S_IFREG)]), False)
        mode = stat.S_IFLNK if kind == "zip" else tarfile.SYMTYPE
        check(kind + "-symlink", make_archive(kind, [("link", b"target", mode)]), False)
    check("tar-hardlink", make_archive("tar", [("link", b"", tarfile.LNKTYPE)]), False)
    check("tar-fifo", make_archive("tar", [("fifo", b"", tarfile.FIFOTYPE)]), False)
    check("zip-ratio-bomb", make_archive("zip", [("compressible", b"0" * 1000000, stat.S_IFREG)], True), False)
    nul_payload = make_archive("zip", [("safeXevil", b"x", stat.S_IFREG)])
    check("zip-nul-name", nul_payload.replace(b"safeXevil", b"safe\x00evil"), False)

    benign_tar = make_archive("tar", benign)
    benign_gzip = gzip.compress(benign_tar, mtime=0)
    bad_crc = bytearray(benign_gzip)
    bad_crc[-8] ^= 1
    bad_size = bytearray(benign_gzip)
    bad_size[-4] ^= 1
    zero_member = gzip.compress(b"\0" * 1024, mtime=0)
    bad_second_crc = bytearray(zero_member)
    bad_second_crc[-8] ^= 1
    # Count TAR headers/padding and all gzip members, including ignored tails.
    boundary_tail = gzip.compress(b"\0" * (module.MAX_BYTES - len(benign_tar)), mtime=0)
    over_limit_tail = gzip.compress(b"\0" * module.MAX_BYTES, mtime=0)
    single_over_limit = gzip.compress(benign_tar + b"\0" * module.MAX_BYTES, mtime=0)
    gzip_cases = [
        ("gzip-valid-tail", benign_gzip + zero_member, True),
        ("gzip-exact-expanded-limit", benign_gzip + boundary_tail, True),
        ("gzip-bad-crc", bytes(bad_crc), False),
        ("gzip-bad-size", bytes(bad_size), False),
        ("gzip-missing-trailer", benign_gzip[:-8], False),
        ("gzip-truncated-data", benign_gzip[:len(benign_gzip) // 2], False),
        ("gzip-bad-second-crc", benign_gzip + bytes(bad_second_crc), False),
        ("gzip-truncated-second", benign_gzip + zero_member[:-8], False),
        ("gzip-trailing-junk", benign_gzip + b"invalid gzip suffix", False),
        ("gzip-expanded-tail", single_over_limit, False),
        ("gzip-concatenated-expanded-tail", benign_gzip + over_limit_tail, False),
    ]
    for name, payload, accepted in gzip_cases:
        check(name, payload, accepted, verify_benign if accepted else None)
        check(name + "-inspect", payload, accepted, verify_benign if accepted else None,
              inspect_archive=True)

    output = inspect_payload(fixture_directory / "zip-benign.bin")
    status = json.loads(output)
    inert = all(status[key] is False for key in ("executed", "extracted", "installed"))
    results.append(("inspect-end-to-end-local", inert, "inert status flags"))
    escaped = fixture_directory / "escaped-preview.bin"
    escaped.write_bytes(make_archive("zip", [("README.md", b"line\x1b[31m\ntext", stat.S_IFREG)]))
    output = inspect_payload(escaped)
    results.append(("json-preview-escaping", "\x1b" not in output and "\\u001b" in output, "escaped terminal controls"))
    return results


def main():
    sys.dont_write_bytecode = True
    source = Path(__file__).with_name("quarantine.py")
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("reviewed_quarantine", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="quarantine-regression-") as temporary:
        results = run_checks(module, Path(temporary))
    if hashlib.sha256(source.read_bytes()).hexdigest() != before:
        raise RuntimeError("Inspector source changed during test run")
    failures = [(name, message) for name, passed, message in results if not passed]
    for name, message in failures:
        print(f"FAIL {name}: {message}", file=sys.stderr)
    print(f"{len(results) - len(failures)}/{len(results)} passed; inspector SHA-256 {before}")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
