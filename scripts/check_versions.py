#!/usr/bin/env python3
"""Bounded version-currency evidence. Never installs or updates packages."""
import argparse
from datetime import date, datetime, timezone
import hashlib
from html.parser import HTMLParser
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request

MAX_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 200
NODE_INDEX = "https://nodejs.org/dist/index.json"
NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
PYTHON_STATUS = "https://devguide.python.org/versions/"
PYTHON_RELEASES = "https://www.python.org/doc/versions/"
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
NPM_NAME = re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*\Z")
PYPI_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def version(value):
    if not isinstance(value, str) or len(value) > 64 or not VERSION.fullmatch(value):
        return None
    numbers = tuple(int(part) for part in value.split("."))
    return numbers + (0,) * (4 - len(numbers))


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    if path.name.casefold() in {".npmrc", ".pypirc", ".netrc", ".env", "credentials.json", "secrets.json"} or path.suffix.casefold() in {".key", ".pem", ".kdbx", ".secret"}:
        raise ValueError("credential file refused")
    if path.is_symlink() or (os.name == "nt" and path.lstat().st_file_attributes & 0x400):
        raise ValueError("linked metadata refused")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("metadata size limit")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("metadata size limit")
    return json.loads(data)


def write_json(path, value):
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        print(data, end="")
    else:
        with path.open("x", encoding="utf-8") as output:
            output.write(data)


def item(ecosystem, name, observed, source, eligible=True):
    return {"ecosystem": ecosystem, "name": name, "observed": observed if version(observed) else None,
            "source": source, "version_origin": "declared-record", "public_registry": eligible, "input_status": "exact" if version(observed) else "unknown-or-unpinned"}


def node_candidates():
    if os.name == "nt":
        roots = [os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
        return [Path(root) / "nodejs" / "node.exe" for root in roots]
    return [Path("/usr/bin/node"), Path("/usr/local/bin/node"), Path("/opt/homebrew/bin/node")]


def runtime_node(project):
    project = project.resolve(strict=True)
    environment = {"SYSTEMROOT": os.environ["SYSTEMROOT"]} if "SYSTEMROOT" in os.environ else {}
    for candidate in node_candidates():
        try:
            executable = candidate.resolve(strict=True)
            if not executable.is_file() or executable == project or project in executable.parents:
                continue
            result = subprocess.run([str(executable), "--version"], cwd=executable.parent, env=environment, capture_output=True, timeout=3, check=False)
            match = re.fullmatch(rb"v([0-9]+\.[0-9]+\.[0-9]+)\s*", result.stdout)
            if match and result.returncode == 0:
                return match.group(1).decode("ascii")
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def inventory(project, node_override=None, scope="project"):
    project = project.resolve(strict=True)
    records = [item("node", "node", node_override or runtime_node(project), "fixed-node-version-probe"),
               item("python", "python", ".".join(map(str, sys.version_info[:3])), "checker-python-runtime")]
    records[0]["version_origin"] = "declared-override" if node_override else "measured-process"
    records[1]["version_origin"] = "measured-interpreter"
    coverage = ["Runtime probes describe this command environment, not a deployed target.",
                "Only package-lock v2/v3 and simple pinned requirements.txt are inspected; other manifests remain unassessed."]
    gaps = []
    lock = project / "package-lock.json"
    if scope == "project" and lock.exists():
        document = read_json(lock)
        if document.get("lockfileVersion") not in (2, 3) or not isinstance(document.get("packages"), dict):
            records.append(item("npm", "unknown-lockfile", None, "package-lock.json", False))
        else:
            if len(document["packages"]) > MAX_RECORDS:
                raise ValueError("inventory record limit")
            for index, (path, entry) in enumerate(document["packages"].items()):
                if path == "":
                    continue
                valid_path = isinstance(path, str) and path.startswith("node_modules/") and not any(part in {"", ".", ".."} for part in path.split("/")) and "\\" not in path
                name = path.rsplit("node_modules/", 1)[-1] if valid_path else ""
                if not NPM_NAME.fullmatch(name) or not isinstance(entry, dict):
                    records.append(item("npm", "unknown-package", None, f"package-lock.json:entry-{index}", False))
                    continue
                resolved = entry.get("resolved", "")
                parsed = urlsplit(resolved) if isinstance(resolved, str) else None
                public = bool(parsed and parsed.scheme == "https" and parsed.hostname == "registry.npmjs.org" and parsed.port in (None, 443) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and not entry.get("link"))
                records.append(item("npm", name, entry.get("version"), f"package-lock.json:entry-{index}", public))
                records[-1]["version_origin"] = "lockfile-not-installed"
    requirements = project / "requirements.txt"
    if scope == "project" and requirements.exists():
        if requirements.is_symlink() or (os.name == "nt" and requirements.lstat().st_file_attributes & 0x400) or requirements.stat().st_size > MAX_BYTES:
            raise ValueError("unsupported requirements file")
        for index, line in enumerate(requirements.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            exact = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9]+(?:\.[0-9]+){1,3})(?:\s+#.*)?", line)
            if exact:
                records.append(item("pypi", exact[1], exact[2], f"requirements.txt:line-{index}"))
                records[-1]["version_origin"] = "pin-not-installed"
            else:
                name = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line)
                records.append(item("pypi", name[0] if name else "unknown-requirement", None, f"requirements.txt:line-{index}", False))
        coverage.append("Flat requirements do not prove transitive dependency coverage.")
        gaps.append("flat-requirements-transitive-coverage-unknown")
    if scope == "project":
        if (project / "package.json").exists() and not lock.exists():
            gaps.append("node-lock-missing")
        unsupported = [name for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "Gemfile", "Package.swift") if (project / name).exists()]
        for index, path in enumerate(project.iterdir()):
            if index >= 2000:
                gaps.append("root-manifest-scan-bound")
                break
            if path.suffix.casefold() in {".csproj", ".fsproj", ".vbproj"}:
                unsupported.append(path.name)
        if unsupported:
            gaps.append("unsupported-manifest-present")
        if not lock.exists() and not requirements.exists():
            gaps.append("no-supported-dependency-inventory")
    if len(records) > MAX_RECORDS:
        raise ValueError("inventory record limit")
    return {"format": 1, "created_at": timestamp(), "scope": scope, "coverage_complete": not gaps, "coverage_gaps": gaps, "records": records, "coverage_notes": coverage}


def allowed_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        return False
    if url in {NODE_INDEX, NODE_SCHEDULE, PYTHON_STATUS, PYTHON_RELEASES}:
        return True
    if parsed.hostname == "registry.npmjs.org":
        return bool(re.fullmatch(r"/(?:%40[a-z0-9._-]+%2F)?[a-z0-9][a-z0-9._-]*/(?:latest|[0-9]+(?:\.[0-9]+){1,3})", parsed.path))
    if parsed.hostname == "pypi.org":
        return bool(re.fullmatch(r"/pypi/[A-Za-z0-9][A-Za-z0-9._-]*/(?:[0-9]+(?:\.[0-9]+){1,3}/)?json", parsed.path))
    return False


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ValueError("redirect refused")


class Fetcher:
    def __init__(self):
        self.deadline = time.monotonic() + 60
        self.requests = 0
        self.cache = {}
        self.total_bytes = 0
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def fetch(self, url):
        if not allowed_url(url):
            raise ValueError("unapproved metadata endpoint")
        if url in self.cache:
            return self.cache[url]
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= 64:
            raise ValueError("metadata request budget")
        self.requests += 1
        request = Request(url, headers={"User-Agent": "AMQIC-Version-Evidence/1", "Accept": "application/json,text/html"})
        with self.opener.open(request, timeout=min(5, remaining)) as response:
            chunks = []
            size = 0
            while True:
                if response.fp is None:
                    break
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("metadata deadline")
                response.fp.raw._sock.settimeout(min(5, remaining))
                chunk = response.read1(min(65536, MAX_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError("metadata size limit")
                chunks.append(chunk)
            data = b"".join(chunks)
        self.total_bytes += len(data)
        if self.total_bytes > 32 * 1024 * 1024 or time.monotonic() > self.deadline:
            raise ValueError("metadata bound exceeded")
        result = (data, {"url": url, "retrieved_at": timestamp(), "sha256": hashlib.sha256(data).hexdigest()})
        self.cache[url] = result
        return result


class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.row = []
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th"):
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.row:
            self.rows.append(self.row)


def latest(values):
    stable = [value for value in values if version(value)]
    return max(stable, key=version) if stable else None


def collect(record, fetcher):
    ecosystem, name, observed = record["ecosystem"], record["name"], record["observed"]
    result = {"ecosystem": ecosystem, "name": name, "observed": observed, "latest": None, "latest_in_line": None,
              "support": "unknown", "eol": None, "withdrawn": None, "deprecated": None, "advisory_status": "not_assessed", "advisories": [], "sources": []}
    if not version(observed) or not record["public_registry"]:
        result["error"] = "unresolved-version-or-unapproved-registry"
        return result
    try:
        if ecosystem == "node":
            data, source = fetcher.fetch(NODE_INDEX)
            releases = [entry["version"].removeprefix("v") for entry in json.loads(data) if isinstance(entry.get("version"), str)]
            schedule_data, schedule_source = fetcher.fetch(NODE_SCHEDULE)
            schedule = json.loads(schedule_data).get("v" + observed.split(".")[0])
            result["sources"] = [source, schedule_source]
            result["latest"] = latest(releases)
            result["latest_in_line"] = latest([value for value in releases if value.split(".")[0] == observed.split(".")[0]])
            if not schedule or observed not in releases:
                raise ValueError("missing Node release or policy")
            result["eol"] = schedule["end"]
            today = date.today().isoformat()
            result["support"] = "end-of-life" if today >= schedule["end"] else "maintenance" if today >= schedule.get("maintenance", "9999") else "lts" if isinstance(schedule.get("lts"), str) and today >= schedule["lts"] else "current"
        elif ecosystem == "python":
            data, source = fetcher.fetch(PYTHON_RELEASES)
            releases = re.findall(r"Python\s+([0-9]+\.[0-9]+\.[0-9]+)(?![0-9a-zA-Z.])", data.decode("utf-8"))
            status_data, status_source = fetcher.fetch(PYTHON_STATUS)
            table = Tables()
            table.feed(status_data.decode("utf-8"))
            branch = ".".join(observed.split(".")[:2])
            policy = next((row for row in table.rows if len(row) >= 6 and row[0] == branch), None)
            result["sources"] = [source, status_source]
            result["latest"] = latest(releases)
            result["latest_in_line"] = latest([value for value in releases if value.startswith(branch + ".")])
            if not policy or policy[2] not in {"bugfix", "security", "end-of-life", "feature", "prerelease"} or observed not in releases:
                raise ValueError("unrecognized Python metadata")
            result["support"], result["eol"] = policy[2], policy[4]
        elif ecosystem == "npm":
            if not NPM_NAME.fullmatch(name):
                raise ValueError("invalid public package name")
            base = "https://registry.npmjs.org/" + quote(name, safe="")
            data, source = fetcher.fetch(base + "/latest")
            exact_data, exact_source = fetcher.fetch(base + "/" + observed)
            current, exact = json.loads(data), json.loads(exact_data)
            if current.get("name") != name or exact.get("name") != name or exact.get("version") != observed:
                raise ValueError("registry identity mismatch")
            result["latest"] = current.get("version")
            result["deprecated"] = bool(exact.get("deprecated"))
            result["support"] = "not-published-by-registry"
            result["sources"] = [source, exact_source]
        elif ecosystem == "pypi":
            if not PYPI_NAME.fullmatch(name):
                raise ValueError("invalid public package name")
            base = "https://pypi.org/pypi/" + quote(name, safe="")
            data, source = fetcher.fetch(base + "/json")
            exact_data, exact_source = fetcher.fetch(base + "/" + observed + "/json")
            current, exact = json.loads(data), json.loads(exact_data)
            normalize = lambda value: re.sub(r"[-_.]+", "-", value).lower()
            if normalize(current["info"]["name"]) != normalize(name) or normalize(exact["info"]["name"]) != normalize(name) or exact["info"]["version"] != observed:
                raise ValueError("registry identity mismatch")
            result["latest"] = latest([value for value, files in current["releases"].items() if files and any(not entry.get("yanked", False) for entry in files)])
            result["withdrawn"] = all(entry.get("yanked", False) for entry in exact["urls"]) if exact["urls"] else None
            advisories = exact.get("vulnerabilities")
            if isinstance(advisories, list):
                result["advisory_status"] = "reported" if advisories else "none-reported-by-pypi"
                result["advisories"] = [entry["id"] for entry in advisories if isinstance(entry.get("id"), str) and re.fullmatch(r"[A-Za-z0-9_-]{2,100}", entry["id"])]
            result["support"] = "not-published-by-registry"
            result["sources"] = [source, exact_source]
        else:
            raise ValueError("unsupported ecosystem")
        if not version(result["latest"]):
            raise ValueError("unsupported latest version")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, HTTPException, RecursionError):
        result["error"] = "metadata-unavailable-or-unrecognized"
    return result


def validated_inventory(document):
    if document.get("format") != 1 or not isinstance(document.get("records"), list) or not 1 <= len(document["records"]) <= MAX_RECORDS:
        raise ValueError("invalid inventory")
    result = []
    seen = set()
    for record in document["records"]:
        ecosystem, name = record.get("ecosystem"), record.get("name")
        if ecosystem not in {"node", "python", "npm", "pypi"} or not isinstance(name, str) or len(name) > 214:
            raise ValueError("invalid inventory identity")
        if ecosystem in {"node", "python"} and name != ecosystem:
            raise ValueError("invalid runtime name")
        if ecosystem == "npm" and not NPM_NAME.fullmatch(name) or ecosystem == "pypi" and not PYPI_NAME.fullmatch(name):
            raise ValueError("invalid package name")
        identity = (ecosystem, name, record.get("observed"))
        if identity not in seen:
            result.append(item(ecosystem, name, record.get("observed"), "declared-inventory", record.get("public_registry") is True))
            origin = record.get("version_origin", "declared-record")
            result[-1]["version_origin"] = origin if origin in {"declared-record", "declared-override", "measured-process", "measured-interpreter", "lockfile-not-installed", "pin-not-installed"} else "declared-record"
            seen.add(identity)
    return result


def assess(records, snapshot, max_age_hours, mode):
    available = {}
    if not isinstance(snapshot.get("records"), list) or len(snapshot["records"]) > MAX_RECORDS:
        raise ValueError("invalid snapshot records")
    for entry in snapshot.get("records", []):
        key = (entry.get("ecosystem"), entry.get("name"), entry.get("observed"))
        if key in available:
            raise ValueError("duplicate snapshot binding")
        available[key] = entry
    findings = []
    now = datetime.now(timezone.utc)
    for record in records:
        row = {"ecosystem": record["ecosystem"], "name": record["name"], "observed": record["observed"], "version_origin": record["version_origin"], "currency": "unknown", "support": "unknown", "advisory_status": "not_assessed"}
        evidence = available.get((record["ecosystem"], record["name"], record["observed"]))
        try:
            if not evidence or evidence.get("error") or not record["public_registry"] or not version(record["observed"]) or not version(evidence.get("latest")):
                raise ValueError("missing or unresolved evidence")
            sources = evidence.get("sources", [])
            if {source.get("url") for source in sources} != set(expected_urls(record)):
                raise ValueError("missing provenance")
            for source in sources:
                if set(source) != {"url", "retrieved_at", "sha256"}:
                    raise ValueError("invalid provenance fields")
                age = (now - datetime.fromisoformat(source["retrieved_at"])).total_seconds()
                if not allowed_url(source["url"]) or not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]) or not 0 <= age <= max_age_hours * 3600:
                    raise ValueError("stale or invalid provenance")
            if evidence.get("support") not in {"current", "lts", "maintenance", "bugfix", "security", "end-of-life", "feature", "prerelease", "not-published-by-registry"}:
                raise ValueError("unknown support metadata")
            if evidence.get("eol") is not None and not re.fullmatch(r"[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?", evidence["eol"]):
                raise ValueError("invalid policy date")
            if evidence.get("withdrawn") not in (True, False, None) or evidence.get("deprecated") not in (True, False, None):
                raise ValueError("invalid package status")
            advisories = evidence.get("advisories", [])
            if evidence.get("advisory_status") not in {"not_assessed", "reported", "none-reported-by-pypi"} or not isinstance(advisories, list) or len(advisories) > 100 or not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{2,100}", value) for value in advisories):
                raise ValueError("invalid advisory metadata")
            if evidence.get("latest_in_line") is not None and not version(evidence["latest_in_line"]):
                raise ValueError("invalid line version")
            comparison = evidence.get("latest_in_line") if record["ecosystem"] in {"node", "python"} else evidence["latest"]
            if not version(comparison):
                raise ValueError("unknown runtime line")
            row.update({key: evidence.get(key) for key in ("latest", "latest_in_line", "support", "eol", "withdrawn", "deprecated", "advisory_status", "advisories", "sources")})
            row["comparison_basis"] = "runtime-line" if record["ecosystem"] in {"node", "python"} else "registry-stable-release"
            row["currency"] = "newer-release" if version(record["observed"]) < version(comparison) else "current" if version(record["observed"]) == version(comparison) else "unknown"
            if evidence.get("support") in {"end-of-life", "feature", "prerelease"} or evidence.get("withdrawn") or evidence.get("deprecated") or evidence.get("advisory_status") == "reported":
                row["currency"] = "blocked-or-policy-review"
        except (ValueError, KeyError, TypeError):
            row["reason"] = "unresolved-or-stale-metadata"
        findings.append(row)
    return {"format": 1, "checked_at": timestamp(), "source_mode": mode, "snapshot_authenticity": "supplied-snapshot-requires-owner-review" if mode == "offline" else "retrieved-over-system-trusted-https",
            "currency_ready": all(row["currency"] == "current" for row in findings), "production_ready": False,
            "scope": "Explicit inventory only; transitive coverage is not guaranteed. Version currency, support and advisory coverage are separate; current versions do not prove security.", "records": findings}


def expected_urls(record):
    ecosystem, name, observed = record["ecosystem"], record["name"], record["observed"]
    if ecosystem == "node":
        return [NODE_INDEX, NODE_SCHEDULE]
    if ecosystem == "python":
        return [PYTHON_RELEASES, PYTHON_STATUS]
    base = ("https://registry.npmjs.org/" if ecosystem == "npm" else "https://pypi.org/pypi/") + quote(name, safe="")
    return [base + "/latest", base + "/" + observed] if ecosystem == "npm" else [base + "/json", base + "/" + observed + "/json"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    discover = commands.add_parser("inventory")
    discover.add_argument("--project", type=Path, required=True)
    discover.add_argument("--node-version")
    discover.add_argument("--scope", choices=["project", "runtime"], default="project")
    discover.add_argument("--output", type=Path)
    check = commands.add_parser("check")
    check.add_argument("--inventory", type=Path, required=True)
    source = check.add_mutually_exclusive_group()
    source.add_argument("--snapshot", type=Path)
    source.add_argument("--online", action="store_true")
    check.add_argument("--save-snapshot", type=Path)
    check.add_argument("--public-package", action="append", default=[], help="Explicit online approval, for example npm:express or pypi:requests")
    check.add_argument("--max-age-hours", type=int, default=24)
    check.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "inventory":
        write_json(args.output, inventory(args.project, args.node_version, args.scope))
        return 0
    if not 1 <= args.max_age_hours <= 720 or (args.save_snapshot or args.public_package) and not args.online:
        raise ValueError("invalid snapshot options")
    inventory_document = read_json(args.inventory)
    records = validated_inventory(inventory_document)
    if args.online:
        fetcher = Fetcher()
        approved = set(args.public_package)
        known = {record["ecosystem"] + ":" + record["name"] for record in records if record["ecosystem"] in {"npm", "pypi"}}
        if not approved <= known:
            raise ValueError("unrecognized package approval")
        online_records = [dict(record, public_registry=record["public_registry"] and (record["ecosystem"] in {"node", "python"} or record["ecosystem"] + ":" + record["name"] in approved)) for record in records]
        snapshot = {"format": 1, "records": [collect(record, fetcher) for record in online_records]}
        if args.save_snapshot:
            write_json(args.save_snapshot, snapshot)
    else:
        snapshot = read_json(args.snapshot) if args.snapshot else {"format": 1, "records": []}
    if snapshot.get("format") != 1:
        raise ValueError("invalid snapshot")
    result = assess(records, snapshot, args.max_age_hours, "online" if args.online else "offline")
    result["inventory_scope"] = inventory_document.get("scope", "explicit-records") if inventory_document.get("scope", "explicit-records") in {"project", "runtime", "explicit-records"} else "unknown"
    incomplete = result["inventory_scope"] == "unknown" or result["inventory_scope"] == "project" and inventory_document.get("coverage_complete") is not True
    result["coverage_complete"] = not incomplete
    if incomplete:
        result["currency_ready"] = False
        result["coverage_status"] = "incomplete-project-dependency-inventory"
    known_gaps = {"flat-requirements-transitive-coverage-unknown", "node-lock-missing", "unsupported-manifest-present", "no-supported-dependency-inventory", "root-manifest-scan-bound"}
    result["coverage_gaps"] = [gap for gap in inventory_document.get("coverage_gaps", []) if isinstance(gap, str) and gap in known_gaps]
    write_json(args.output, result)
    return 0 if result["currency_ready"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, AttributeError, HTTPException, RecursionError):
        print('{"status":"unknown","currency_ready":false,"production_ready":false,"reason":"invalid-input-or-metadata-unavailable"}')
        sys.exit(2)
