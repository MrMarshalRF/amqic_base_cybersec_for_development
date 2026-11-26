"""Offline public-metadata fixtures only; no downloads or package installations."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_versions as versions


class FixtureFetcher:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        payload = self.responses[url]
        data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        return data, {"url": url, "retrieved_at": versions.timestamp(), "sha256": "a" * 64}


def node_fixture():
    return FixtureFetcher({
        versions.NODE_INDEX: [{"version": "v22.1.0"}, {"version": "v22.2.0"}, {"version": "v24.0.0"}],
        versions.NODE_SCHEDULE: {"v22": {"start": "2020-01-01", "lts": "2020-02-01", "maintenance": "2020-03-01", "end": "2099-01-01"}},
    })


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="amqic-version-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_inventory_runtime_and_missing_coverage(self):
        with patch.object(versions, "runtime_node", return_value="22.1.0"):
            result = versions.inventory(self.root)
            limited = versions.inventory(self.root, scope="runtime")
        self.assertFalse(result["coverage_complete"])
        self.assertTrue(limited["coverage_complete"])
        self.assertEqual({row["ecosystem"] for row in result["records"]}, {"node", "python"})
        (self.root / "package.json").write_text('{"dependencies":{"example":"1.0.0"}}')
        with patch.object(versions, "runtime_node", return_value="22.1.0"):
            self.assertIn("node-lock-missing", versions.inventory(self.root)["coverage_gaps"])

    def test_lock_and_requirements_privacy(self):
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/example": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/example/-/example.tgz"}, "node_modules/private-example": {"version": "1.0.0", "resolved": "https://user:SYNTHETIC_ONLY@private.invalid/file?token=SYNTHETIC_ONLY"}}}
        (self.root / "package-lock.json").write_text(json.dumps(lock))
        (self.root / "requirements.txt").write_text("example==1.2.3\nother>=2.0\nhttps://user:SYNTHETIC_ONLY@private.invalid/file\n")
        with patch.object(versions, "runtime_node", return_value="22.1.0"):
            result = versions.inventory(self.root)
        self.assertNotIn("SYNTHETIC_ONLY", json.dumps(result))
        self.assertNotIn("private.invalid", json.dumps(result))
        self.assertFalse(next(row for row in result["records"] if row["name"] == "private-example")["public_registry"])
        self.assertFalse(next(row for row in result["records"] if row["name"] == "other")["observed"])
        self.assertIn("flat-requirements-transitive-coverage-unknown", result["coverage_gaps"])

    def test_node_supported_line_differs_from_latest_major(self):
        record = versions.item("node", "node", "22.2.0", "fixture")
        evidence = versions.collect(record, node_fixture())
        result = versions.assess([record], {"records": [evidence]}, 24, "offline")
        self.assertTrue(result["currency_ready"])
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["records"][0]["latest"], "24.0.0")
        self.assertEqual(result["records"][0]["advisory_status"], "not_assessed")

    def test_root_and_direct_lock_coverage(self):
        dependencies = {"example": "1.0.0", "other-example": "2.0.0"}
        (self.root / "package.json").write_text(json.dumps({"dependencies": dependencies}))
        entries = {"node_modules/" + name: {"version": value, "resolved": "https://registry.npmjs.org/" + name + "/-/fixture.tgz"} for name, value in dependencies.items()}
        cases = [({}, False), ({"": {}}, False),
                 ({"": {"dependencies": dependencies}, "node_modules/example": entries["node_modules/example"]}, False),
                 ({"": {"dependencies": {"example": "0.9.0"}}, **entries}, False),
                 ({"": {"dependencies": dependencies}, **entries}, True)]
        for lock_version in (2, 3):
            for packages, complete in cases:
                with self.subTest(lock_version=lock_version, packages=packages):
                    (self.root / "package-lock.json").write_text(json.dumps({"lockfileVersion": lock_version, "packages": packages}))
                    result = versions.inventory(self.root, node_override="22.1.0")
                    self.assertEqual(result["coverage_complete"], complete)
                    self.assertEqual("node-lock-direct-coverage-incomplete" in result["coverage_gaps"], not complete)
                    self.assertNotIn("other-example", json.dumps(result["coverage_gaps"]))
        # An actual dependency-free project is a valid neighbor.
        (self.root / "package.json").write_text("{}")
        (self.root / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}')
        self.assertTrue(versions.inventory(self.root, node_override="22.1.0")["coverage_complete"])
        (self.root / "package.json").write_text("null")
        self.assertFalse(versions.inventory(self.root, node_override="22.1.0")["coverage_complete"])

    def test_direct_lock_dependency_groups_and_absent_manifest(self):
        package = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/example/-/fixture.tgz"}
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            root = {group: {"example": "^1.0.0"}}
            self.assertFalse(versions.direct_lock_coverage({"": root}, root))
            self.assertTrue(versions.direct_lock_coverage({"": root, "node_modules/example": package}, root))
            self.assertFalse(versions.direct_lock_coverage({"": root, "node_modules/example": None}, root))
        self.assertFalse(versions.direct_lock_coverage({}))
        self.assertTrue(versions.direct_lock_coverage({"": {}}))

    def test_direct_lock_gap_propagates_through_cli(self):
        (self.root / "package.json").write_text('{"dependencies":{"example":"1.0.0"}}')
        (self.root / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}')
        with patch.object(versions, "runtime_node", return_value="22.2.0"):
            inventory = versions.inventory(self.root)
        source, snapshot = self.root / "inventory.json", self.root / "snapshot.json"
        source.write_text(json.dumps(inventory))
        evidence = []
        for record in inventory["records"]:
            row = {"ecosystem": record["ecosystem"], "name": record["name"], "observed": record["observed"], "latest": record["observed"], "latest_in_line": record["observed"], "support": "maintenance", "eol": "2099-01-01", "advisory_status": "not_assessed", "advisories": [], "sources": [{"url": url, "retrieved_at": versions.timestamp(), "sha256": "a" * 64} for url in versions.expected_urls(record)]}
            evidence.append(row)
        self.assertTrue(versions.assess(inventory["records"], {"records": evidence}, 24, "offline")["currency_ready"])
        snapshot.write_text(json.dumps({"format": 1, "records": evidence}))
        output = io.StringIO()
        with patch.object(sys, "argv", ["check_versions.py", "check", "--inventory", str(source), "--snapshot", str(snapshot)]), contextlib.redirect_stdout(output):
            self.assertEqual(versions.main(), 2)
        result = json.loads(output.getvalue())
        self.assertFalse(result["currency_ready"])
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["coverage_gaps"], ["node-lock-direct-coverage-incomplete"])

    def test_assessment_rechecks_eol_after_fresh_snapshot(self):
        record = versions.item("node", "node", "22.2.0", "fixture")
        evidence = versions.collect(record, node_fixture())
        today = datetime.now(timezone.utc).date()
        for offset, ready in ((-1, False), (0, False), (1, True)):
            with self.subTest(offset=offset):
                evidence["eol"] = (today + timedelta(days=offset)).isoformat()
                evidence["support"] = "maintenance"
                result = versions.assess([record], {"records": [evidence]}, 24, "offline")
                self.assertEqual(result["currency_ready"], ready)
                self.assertEqual(result["records"][0]["eol_precision"], "day")
                if not ready:
                    self.assertEqual(result["records"][0]["support"], "end-of-life")

    def test_runtime_eol_calendar_and_python_month_precision(self):
        for ecosystem, observed in (("node", "22.2.0"), ("python", "3.13.1")):
            record = versions.item(ecosystem, ecosystem, observed, "fixture")
            evidence = versions.collect(versions.item("node", "node", "22.2.0", "fixture"), node_fixture())
            evidence.update(ecosystem=ecosystem, name=ecosystem, observed=observed, latest=observed, latest_in_line=observed, support="security", sources=[{"url": url, "retrieved_at": versions.timestamp(), "sha256": "a" * 64} for url in versions.expected_urls(record)])
            for invalid in ("2099-02-29", "2099-13-01", "0000-01-01", "2099-01-00", "2099-01-01\n", None):
                evidence["eol"] = invalid
                result = versions.assess([record], {"records": [evidence]}, 24, "offline")
                self.assertFalse(result["currency_ready"])
                self.assertEqual(result["records"][0]["currency"], "unknown")
            evidence["eol"] = "2096-02-29"
            self.assertTrue(versions.assess([record], {"records": [evidence]}, 24, "offline")["currency_ready"])
            today = datetime.now(timezone.utc).date()
            for month, ready in ((today.strftime("%Y-%m"), False), ("2099-12", True), ("2099-13", False)):
                evidence["eol"] = month
                result = versions.assess([record], {"records": [evidence]}, 24, "offline")
                self.assertEqual(result["currency_ready"], ready if ecosystem == "python" else False)
                if ecosystem == "python" and month != "2099-13":
                    self.assertEqual(result["records"][0]["eol_precision"], "month")
                    self.assertEqual(result["records"][0]["eol_policy"], "hold-from-month-start")

    def test_older_runtime_patch(self):
        record = versions.item("node", "node", "22.1.0", "fixture")
        result = versions.assess([record], {"records": [versions.collect(record, node_fixture())]}, 24, "offline")
        self.assertEqual(result["records"][0]["currency"], "newer-release")

    def test_python_rows_and_unknown_markup(self):
        record = versions.item("python", "python", "3.13.1", "fixture")
        table = "<table><tr><td>3.13</td><td>PEP</td><td>security</td><td>2024-01-01</td><td>2099-10</td><td>Owner</td></tr></table>"
        fetcher = FixtureFetcher({versions.PYTHON_RELEASES: "Python 3.13.1 Python 3.13.2 Python 3.14.0 Python 3.15.0rc1", versions.PYTHON_STATUS: table})
        result = versions.collect(record, fetcher)
        self.assertEqual(result["latest_in_line"], "3.13.2")
        self.assertEqual(result["latest"], "3.14.0")
        fetcher.responses[versions.PYTHON_STATUS] = "changed markup"
        self.assertIn("error", versions.collect(record, fetcher))

    def test_npm_identity_deprecation_and_no_implicit_fetch(self):
        record = versions.item("npm", "example", "1.0.0", "fixture")
        latest, exact = versions.expected_urls(record)
        fetcher = FixtureFetcher({latest: {"name": "example", "version": "1.0.0"}, exact: {"name": "wrong", "version": "1.0.0"}})
        self.assertIn("error", versions.collect(record, fetcher))
        fetcher.responses[exact] = {"name": "example", "version": "1.0.0", "deprecated": "SYNTHETIC_PRIVATE_REASON"}
        evidence = versions.collect(record, fetcher)
        self.assertNotIn("SYNTHETIC_PRIVATE_REASON", json.dumps(evidence))
        self.assertTrue(evidence["deprecated"])
        fetcher.calls.clear()
        versions.collect(dict(record, public_registry=False), fetcher)
        self.assertEqual(fetcher.calls, [])

    def test_pypi_yanked_and_advisory(self):
        record = versions.item("pypi", "example", "1.0.0", "fixture")
        latest, exact = versions.expected_urls(record)
        fetcher = FixtureFetcher({latest: {"info": {"name": "example"}, "releases": {"1.0.0": [{"yanked": False}], "2.0.0": [{"yanked": True}]}}, exact: {"info": {"name": "example", "version": "1.0.0"}, "urls": [{"yanked": True}], "vulnerabilities": [{"id": "PYSEC-2026-0001"}]}})
        evidence = versions.collect(record, fetcher)
        self.assertEqual(evidence["latest"], "1.0.0")
        self.assertTrue(evidence["withdrawn"])
        result = versions.assess([record], {"records": [evidence]}, 24, "offline")
        self.assertFalse(result["currency_ready"])

    def test_snapshot_age_binding_and_endpoint_role(self):
        record = versions.item("node", "node", "22.2.0", "fixture")
        for mutation in ("stale", "identity", "endpoint", "extra-source-field"):
            evidence = versions.collect(record, node_fixture())
            if mutation == "stale":
                evidence["sources"][0]["retrieved_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            elif mutation == "identity":
                evidence["observed"] = "22.1.0"
            elif mutation == "endpoint":
                evidence["sources"][0]["url"] = "https://pypi.org/pypi/example/json"
            else:
                evidence["sources"][0]["private"] = "SYNTHETIC_ONLY"
            result = versions.assess([record], {"records": [evidence]}, 24, "offline")
            self.assertFalse(result["currency_ready"])
            self.assertNotIn("SYNTHETIC_ONLY", json.dumps(result))

    def test_network_allowlist_and_deadline(self):
        for url in ["http://nodejs.org/dist/index.json", "https://nodejs.org.evil.invalid/dist/index.json", "https://user:pass@nodejs.org/dist/index.json", "https://registry.npmjs.org/example/latest?token=secret"]:
            self.assertFalse(versions.allowed_url(url))
        fetcher = versions.Fetcher()
        fetcher.deadline = 0
        with self.assertRaises(ValueError):
            fetcher.fetch(versions.NODE_INDEX)
        with self.assertRaises(ValueError):
            fetcher.fetch("https://private.invalid")

    def test_cli_default_offline_and_exclusive_output(self):
        source = self.root / "inventory.json"
        source.write_text(json.dumps({"format": 1, "records": [versions.item("npm", "example", "1.0.0", "fixture")]}))
        output = io.StringIO()
        with patch.object(sys, "argv", ["check_versions.py", "check", "--inventory", str(source)]), contextlib.redirect_stdout(output):
            self.assertEqual(versions.main(), 2)
        self.assertFalse(json.loads(output.getvalue())["currency_ready"])
        protected = self.root / "existing.json"
        protected.write_text("keep")
        with self.assertRaises(FileExistsError):
            versions.write_json(protected, {})
        self.assertEqual(protected.read_text(), "keep")

    def test_no_implicit_package_name_transmission(self):
        source = self.root / "inventory.json"
        source.write_text(json.dumps({"format": 1, "records": [versions.item("npm", "private-name", "1.0.0", "fixture")]}))
        seen = []
        def collect(record, fetcher):
            seen.append(record["public_registry"])
            return {"ecosystem": record["ecosystem"], "name": record["name"], "observed": record["observed"], "error": "held"}
        with patch.object(sys, "argv", ["check_versions.py", "check", "--inventory", str(source), "--online"]), patch.object(versions, "collect", side_effect=collect), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(versions.main(), 2)
        self.assertEqual(seen, [False])

    def test_coverage_gap_blocks_positive_versions(self):
        record = versions.item("node", "node", "22.2.0", "fixture")
        source = self.root / "inventory.json"
        snapshot = self.root / "snapshot.json"
        source.write_text(json.dumps({"format": 1, "scope": "project", "coverage_complete": False, "records": [record]}))
        snapshot.write_text(json.dumps({"format": 1, "records": [versions.collect(record, node_fixture())]}))
        output = io.StringIO()
        with patch.object(sys, "argv", ["check_versions.py", "check", "--inventory", str(source), "--snapshot", str(snapshot)]), contextlib.redirect_stdout(output):
            self.assertEqual(versions.main(), 2)
        self.assertFalse(json.loads(output.getvalue())["currency_ready"])

    def test_eol_and_credential_files(self):
        fetcher = node_fixture()
        fetcher.responses[versions.NODE_SCHEDULE]["v22"]["end"] = "2020-01-01"
        record = versions.item("node", "node", "22.2.0", "fixture")
        result = versions.assess([record], {"records": [versions.collect(record, fetcher)]}, 24, "offline")
        self.assertFalse(result["currency_ready"])
        with patch.object(Path, "open", side_effect=AssertionError("must not read")), self.assertRaises(ValueError):
            versions.read_json(self.root / ".npmrc")
        with self.assertRaises(ValueError):
            versions.NoRedirect().redirect_request(None, None, 302, "", {}, "https://nodejs.org/")

    def test_project_local_node_never_runs(self):
        executable = self.root / "node.exe"
        executable.write_bytes(b"synthetic fake executable")
        child = self.root / "child"
        child.mkdir()
        with patch.object(versions, "node_candidates", return_value=[executable]), patch.object(versions.subprocess, "run", side_effect=AssertionError("must not execute project file")):
            self.assertIsNone(versions.runtime_node(self.root))
            self.assertIsNone(versions.runtime_node(child / ".."))


if __name__ == "__main__":
    unittest.main()
