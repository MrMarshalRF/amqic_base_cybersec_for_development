"""Synthetic production-staging regression fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare_production as production


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="amqic-production-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "app").mkdir()
        (self.source / "app" / "main.mjs").write_text("export const value = 42;\n", encoding="utf-8")
        (self.source / "config.example.json").write_text('{"authenticationRequired": true, "passwordEnv": "APP_PASSWORD"}', encoding="utf-8")
        self.names = ["app/main.mjs", "config.example.json"]
        self.target = self.root / "ready"

    def prepare(self):
        return production.prepare(self.source, self.target, self.names)

    def test_deep_manifest_cli_refuses_without_traceback(self):
        self.target.mkdir()
        (self.target / production.MANIFEST).write_text("[" * 10000 + "0" + "]" * 10000, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(Path(production.__file__)), "validate", str(self.target)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "blocked")
        self.assertEqual(result.stderr, "")

    def test_roundtrip_deterministic_inventory(self):
        original = (self.source / "app" / "main.mjs").read_bytes()
        first = self.prepare()
        self.assertEqual(first, production.validate(self.target))
        second = production.prepare(self.source, self.root / "other", list(reversed(self.names)))
        self.assertEqual(first, second)
        self.assertEqual((self.source / "app" / "main.mjs").read_bytes(), original)
        manifest = (self.target / production.MANIFEST).read_text(encoding="utf-8")
        self.assertNotIn(str(self.source), manifest)

    def test_excluded_names_never_read(self):
        for name in [".env", "secrets/key.txt", "tests/test_api.py", "private.pem", "vault.kdbx", "state/data.json", "config.local.toml", "credentials.json", "secrets.yaml", "service-account-prod.json", "service_account.json", ".npmrc", "kubeconfig", ".kube/config"]:
            with self.subTest(name=name), patch.object(production, "read_scanned", side_effect=AssertionError("must not read")), self.assertRaises(production.Blocked):
                production.prepare(self.source, self.target, [name])
        self.assertFalse(self.target.exists())

    def test_traversal_and_collisions(self):
        for names in [["../escape.py"], ["/escape.py"], ["a//b.py"], ["A.py", "a.py"], ["Dir/a.py", "dir/b.py"], ["NUL.txt"], ["a./b.py"]]:
            with self.subTest(names=names), self.assertRaises(production.Blocked):
                production.check_names(names)

    def test_internal_tools_blocked_before_read(self):
        names = [".git/config", ".hg/cache.txt", ".svn/entries", ".graphify/index.json", "graphify-out/nested/index.json", "graphify-output/graph.json", ".graphifyignore", "graphify.config.json", "graphify-index.json", ".agent-private/receipt.json", "AGENTS.override.md", ".mcp.json", "mcp.json", "mcp.local.json", "receipts/task.json", "checkpoints/current.md", "plans/internal.md", "CLAUDE.md", "GEMINI.md", ".cursor/rules.md", ".windsurf/config.json", ".aider.chat.history.md", ".aider.conf.yml"]
        with patch.object(production, "read_scanned", side_effect=AssertionError("must not read")):
            for name in names:
                with self.subTest(name=name), self.assertRaises(production.Blocked):
                    production.prepare(self.source, self.target, [name])
        (self.source / "app" / "graph.json").write_text('{"nodes": []}', encoding="utf-8")
        (self.source / "app" / "mcp_client.mjs").write_text('export const enabled = true;', encoding="utf-8")
        (self.source / "LICENSE").write_text('Synthetic license notice.', encoding="utf-8")
        (self.source / "NOTICE").write_text('Synthetic attribution notice.', encoding="utf-8")
        (self.source / "COPYING").write_text('Synthetic redistribution notice.', encoding="utf-8")
        result = production.prepare(self.source, self.target, ["app/graph.json", "app/mcp_client.mjs", "LICENSE", "NOTICE", "COPYING"])
        self.assertEqual(len(result["files"]), 5)

    def test_private_artifact_names_blocked_before_read(self):
        names = [
            ".agent-work/task.json", "nested/.AGENT-WORK/task.md",
            "private-evidence/check.md", "nested/PRIVATE-EVIDENCE/check.json",
            "api-delegations/task.json", "nested/API-DELEGATIONS/task.md",
            ".dpapi/store.json", "nested/.DPAPI/store.json",
            "session.dpapi", "nested/SESSION.DPAPI",
            ".claude/settings.json", "nested/.CLAUDE/rules.md",
        ]
        with patch.object(production, "read_scanned", side_effect=AssertionError("must not read")):
            for name in names:
                with self.subTest(name=name), self.assertRaises(production.Blocked):
                    production.prepare(self.source, self.target, [name])
        self.assertFalse(self.target.exists())

    def test_agent_home_and_override_blocked_before_source_inspection(self):
        names = [".dsh/config.json", "nested/.dsh/config.json",
                 ".DSH/settings.json", "nested/.DsH/rules.md",
                 "prompt-inject.md", "nested/prompt-inject.md",
                 "PROMPT-INJECT.MD", "nested/Prompt-Inject.Md"]
        with patch.object(production, "inspect_file", side_effect=AssertionError("must not inspect")), \
             patch.object(production, "read_scanned", side_effect=AssertionError("must not read")):
            for name in names:
                with self.subTest(name=name), self.assertRaises(production.Blocked) as failure:
                    production.prepare(self.source, self.target, [name])
                self.assertEqual(failure.exception.finding,
                                 {"path": name, "rule": "excluded-file-or-directory"})
        self.assertFalse(self.target.exists())

    def test_agent_home_and_override_manifest_is_rejected(self):
        self.target.mkdir()
        for name in ("nested/.DSH/settings.json", "nested/PROMPT-INJECT.MD"):
            document = production.manifest_for([{"path": name, "size": 0, "sha256": "0" * 64}])
            (self.target / production.MANIFEST).write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(name=name), patch.object(production, "read_scanned", side_effect=AssertionError("must not read")), self.assertRaises(production.Blocked):
                production.validate(self.target)

    def test_tracked_private_artifact_is_still_rejected(self):
        name = ".agent-work/task.json"
        path = self.source / name
        path.parent.mkdir()
        path.write_text('{"synthetic": true}', encoding="utf-8")
        (self.source / ".gitignore").write_text('.agent-work/\n', encoding="utf-8")
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        template = self.root / "empty-template"
        template.mkdir()
        for arguments in [["init", "--quiet", "--template", str(template)], ["add", "--force", "--", name]]:
            result = subprocess.run(["git", "-C", str(self.source), *arguments], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        tracked = subprocess.run(["git", "-C", str(self.source), "ls-files", "--", name], env=environment, capture_output=True, text=True)
        self.assertEqual(tracked.returncode, 0, tracked.stderr)
        self.assertEqual(tracked.stdout.strip(), name)
        with patch.object(production, "read_scanned", side_effect=AssertionError("must not read")), self.assertRaises(production.Blocked):
            production.prepare(self.source, self.target, [name])
        self.assertFalse(self.target.exists())

    def test_private_artifact_manifest_is_rejected(self):
        self.target.mkdir()
        for name in [".agent-work/task.json", "private-evidence/check.md", "api-delegations/task.json", ".dpapi/store.json", "session.dpapi", ".claude/settings.json"]:
            document = production.manifest_for([{"path": name, "size": 0, "sha256": "0" * 64}])
            (self.target / production.MANIFEST).write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(name=name), patch.object(production, "read_scanned", side_effect=AssertionError("must not read")), self.assertRaises(production.Blocked):
                production.validate(self.target)

    def test_ordinary_source_names_are_not_private_artifacts(self):
        names = ["app/evidence.json", "app/agent-workflow.mjs", "package-lock.json", "deploy/compose.yaml",
                 "app/prompt-inject-public.md", "app/dsh-client.mjs", ".dsh-public/config.json"]
        for name in names:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        result = production.prepare(self.source, self.target, names)
        self.assertEqual([entry["path"] for entry in result["files"]], sorted(names))
        self.assertEqual(result, production.validate(self.target))

    def test_secret_literal_returns_no_value(self):
        fixture = 'secret = "PUBLIC_SYNTHETIC_FIXTURE_123456"\n'
        path = self.source / "app" / "main.mjs"
        path.write_text(fixture, encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", str(Path(production.__file__)), "prepare", "--source", str(self.source), "--target", str(self.target), "--include", "app/main.mjs"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PUBLIC_SYNTHETIC_FIXTURE", result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"][0]["rule"], "credential-literal")
        self.assertFalse(self.target.exists())
        self.assertEqual(path.read_text(encoding="utf-8"), fixture)

    def test_public_prefix_secret_staging_and_validation(self):
        path = self.source / "app" / "main.mjs"
        for prefix in ("PUBLIC_", "VITE_", "NEXT_PUBLIC_", "NUXT_PUBLIC_", "REACT_APP_"):
            text = 'export const ' + prefix + 'API_KEY = "INERT_NOT_A_CREDENTIAL_5739";\n'
            path.write_text(text, encoding="utf-8")
            with self.subTest(prefix=prefix), self.assertRaises(production.Blocked) as failure:
                self.prepare()
            self.assertEqual(failure.exception.finding, {"path": "app/main.mjs", "rule": "client-public-secret-literal"})
            self.assertFalse(self.target.exists())
            self.assertEqual(path.read_text(encoding="utf-8"), text)
        path.write_text('const config = { "VITE_API_KEY": "INERT_NOT_A_CREDENTIAL_5739" };', encoding="utf-8")
        with self.assertRaises(production.Blocked):
            self.prepare()
        # A self-consistent attacker-edited manifest cannot bypass content checks.
        self.target.mkdir()
        (self.target / "app").mkdir()
        payload = path.read_bytes()
        (self.target / "app/main.mjs").write_bytes(payload)
        document = production.manifest_for([{"path": "app/main.mjs", "size": len(payload), "sha256": production.hashlib.sha256(payload).hexdigest()}])
        (self.target / production.MANIFEST).write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(production.Blocked) as failure:
            production.validate(self.target)
        self.assertEqual(failure.exception.finding["rule"], "client-public-secret-literal")

    def test_public_placeholder_and_url_still_stage_but_env_never_does(self):
        (self.source / "app/main.mjs").write_text('export const VITE_API_KEY="<required>";\nexport const PUBLIC_BASE_URL="https://example.invalid/public";\n', encoding="utf-8")
        self.prepare()
        self.assertEqual(production.validate(self.target)["files"][0]["path"], "app/main.mjs")
        for name in (".env", ".env.example", ".env.production"):
            with patch.object(production, "read_scanned", side_effect=AssertionError("must not read")), self.assertRaises(production.Blocked):
                production.prepare(self.source, self.root / "env-blocked", [name])

    def test_unquoted_and_uri_credentials(self):
        for text in ["password: synthetic-value", "password = synthetic-value", "url = postgres://someone:synthetic-value@localhost/database", "\ufeffpassword: synthetic-value", "\ufeffpassword = synthetic-value"]:
            (self.source / "config.example.json").write_text(text, encoding="utf-8")
            with self.subTest(text=text), self.assertRaises(production.Blocked) as failure:
                self.prepare()
            self.assertNotIn("synthetic-value", str(failure.exception.finding))

    def test_ternary_and_credential_literal_contexts(self):
        path = self.source / "app" / "main.mjs"
        path.write_text("const input = valid ? password : 'invalid-password-input';\n", encoding="utf-8")
        self.prepare()
        for text in [
            "const password = 'SYNTHETIC_ONLY';",
            "password = 'SYNTHETIC_ONLY'",
            "const config = { password: 'SYNTHETIC_ONLY' };",
            '{"password": "SYNTHETIC_ONLY"}',
            "config = {'password': 'SYNTHETIC_ONLY'}",
            "const config = { enabled: true, password: 'SYNTHETIC_ONLY' };",
            "config['password'] = 'SYNTHETIC_ONLY';",
        ]:
            path.write_text(text, encoding="utf-8")
            with self.subTest(text=text), self.assertRaises(production.Blocked):
                production.prepare(self.source, self.root / "blocked-literal", ["app/main.mjs"])

    def test_real_reference_cli_bundle(self):
        source = Path(production.__file__).resolve().parents[1]
        names = ["reference/core.mjs", "reference/crypto.mjs", "reference/login-client.mjs"]
        command = [sys.executable, "-B", str(Path(production.__file__)), "prepare", "--source", str(source), "--target", str(self.target)]
        for name in names:
            command.extend(["--include", name])
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        checked = subprocess.run([sys.executable, "-B", str(Path(production.__file__)), "validate", str(self.target)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stdout)
        self.assertEqual(json.loads(checked.stdout)["files"], 3)
        for name in names:
            self.assertEqual((self.target / name).read_bytes(), (source / name).read_bytes())

    def test_bom_safe_payload_and_cli(self):
        payload = b"\xef\xbb\xbfexport const enabled = true;\n"
        (self.source / "app" / "main.mjs").write_bytes(payload)
        result = subprocess.run([sys.executable, "-B", str(Path(production.__file__)), "prepare", "--source", str(self.source), "--target", str(self.target), "--include", "app/main.mjs"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.target / "app" / "main.mjs").read_bytes(), payload)
        self.assertEqual(production.validate(self.target)["files"][0]["size"], len(payload))

    def test_binary_and_existing_target(self):
        (self.source / "app" / "main.mjs").write_bytes(b"\xff\x00")
        with self.assertRaises(production.Blocked):
            self.prepare()
        self.target.mkdir()
        (self.target / "keep").write_text("keep")
        with self.assertRaises(production.Blocked):
            self.prepare()
        self.assertEqual((self.target / "keep").read_text(), "keep")

    def test_payload_and_extra_directory_tamper(self):
        self.prepare()
        (self.target / ".git").mkdir()
        with self.assertRaises(production.Blocked):
            production.validate(self.target)
        (self.target / ".git").rmdir()
        (self.target / "app" / "main.mjs").write_text("changed")
        with self.assertRaises(production.Blocked):
            production.validate(self.target)

    def test_hardlink_and_source_drift(self):
        os.link(self.source / "app" / "main.mjs", self.source / "alias.mjs")
        with self.assertRaises(production.Blocked):
            self.prepare()
        (self.source / "alias.mjs").unlink()
        actual = production.read_scanned
        def mutating_read(root, name, expected):
            payload = actual(root, name, expected)
            (root / name).write_bytes(payload + b"\n")
            return payload
        with patch.object(production, "read_scanned", side_effect=mutating_read), self.assertRaises(production.Blocked):
            self.prepare()
        self.assertFalse(self.target.exists())

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_windows_junction(self):
        link = self.root / "junction"
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(self.source)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        try:
            with self.assertRaises(production.Blocked):
                production.prepare(link, self.target, self.names)
        finally:
            os.rmdir(link)


if __name__ == "__main__":
    unittest.main()
