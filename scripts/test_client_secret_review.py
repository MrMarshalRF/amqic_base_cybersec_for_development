"""Inert, non-authentic text fixtures with exact expected findings."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import client_secret_review as client


def snapshot(text, path="app/config.js", committed=False):
    return {"format": 1, "files": [{"path": path, "text": text, "committed": committed}]}


def finding(path, rule, severity="high"):
    return {"path": path, "rule": rule, "severity": severity}


class ClientReviewTests(unittest.TestCase):
    def check(self, text, expected, path="app/config.js", committed=False):
        result = client.review(snapshot(text, path, committed))
        self.assertEqual(result["findings"], expected)
        self.assertEqual(result["result_etag"], client.etag({key: value for key, value in result.items() if key != "result_etag"}))
        self.assertNotIn("INERT_NOT_A_CREDENTIAL_5739", json.dumps(result))
        return result

    def test_each_public_prefix_match_and_two_near_matches(self):
        for prefix in client.PREFIXES:
            with self.subTest(prefix=prefix):
                self.check(prefix + 'API_KEY="INERT_NOT_A_CREDENTIAL_5739"',
                           [finding("app/config.js", "client-public-secret-literal")])
                self.check(prefix + 'API_KEY="<set-at-build-time>"', [])
                self.check(prefix + 'BASE_URL="https://example.invalid/public"', [])
        self.check('SERVER_API_KEY="INERT_NOT_A_CREDENTIAL_5739"', [])

    def test_literal_formats(self):
        for text in ('export const VITE_CLIENT_SECRET = "INERT_NOT_A_CREDENTIAL_5739";',
                     '{"NEXT_PUBLIC_ACCESS_TOKEN": "INERT_NOT_A_CREDENTIAL_5739"}',
                     "const config = { NUXT_PUBLIC_AUTH_KEY: 'INERT_NOT_A_CREDENTIAL_5739' };",
                     'REACT_APP_PASSWORD=INERT_NOT_A_CREDENTIAL_5739 # local fixture'):
            self.check(text, [finding("app/config.js", "client-public-secret-literal")])
        for text in ('VITE_API_KEY=process.env.SERVER_API_KEY',
                     'VITE_API_KEY="${SERVER_API_KEY}"',
                     'VITE_API_KEY="your-key-here"',
                     'PRIVATE_API_KEY="INERT_NOT_A_CREDENTIAL_5739"'):
            self.check(text, [])

    def test_committed_environment_match_and_two_nears(self):
        self.check("ENABLED=true", [finding(".env.production", "committed-environment-file")], ".env.production", True)
        self.check("ENABLED=true", [], ".env.production", False)
        self.check("ENABLED=true", [], "config/settings.ini", True)
        self.check('SERVER_TOKEN="<required>"', [], ".env.example", True)

    def test_example_environment_match_and_two_nears(self):
        self.check('SERVER_API_KEY="INERT_NOT_A_CREDENTIAL_5739"',
                   [finding(".env.example", "example-environment-nonplaceholder")], ".env.example", True)
        self.check('SERVER_API_KEY="<required>"', [], ".env.example", True)
        self.check('BASE_URL="https://example.invalid/public"', [], ".env.example", True)

    def test_ignore_omission_match_and_two_nears(self):
        self.check("node_modules/\n", [finding(".gitignore", "environment-ignore-review", "low")], ".gitignore")
        self.check(".env\n.env.*\n", [], ".gitignore")
        self.check("# explicit root rules\n/.env\n/.env.*\n", [], ".gitignore")
        self.check(".env\n.env.*\n!.env.production\n", [finding(".gitignore", "environment-ignore-review", "low")], ".gitignore")

    def test_strict_schema_paths_and_bounds(self):
        invalid = [None, {}, {"format": True, "files": []}, {"format": 1, "files": []}]
        for path in ("../outside", "/outside", "a//b", "a\\b", "a/../b", "C:/absolute", "a\nvalue", "a./b"):
            invalid.append(snapshot("safe", path))
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(client.InvalidReview):
                client.review(document)
        document = snapshot("safe")
        document["files"] *= client.MAX_FILES + 1
        with self.assertRaises(client.InvalidReview):
            client.review(document)
        with self.assertRaises(client.InvalidReview):
            client.review(snapshot("x" * (client.MAX_FILE_BYTES + 1)))
        with patch.object(client, "MAX_TOTAL_BYTES", 3), self.assertRaises(client.InvalidReview):
            client.review(snapshot("four"))
        document = snapshot("safe")
        document["files"].append({"path": "APP/config.js", "text": "", "committed": False})
        with self.assertRaises(client.InvalidReview):
            client.review(document)
        document = snapshot("safe")
        document["files"][0]["committed"] = "false"
        with self.assertRaises(client.InvalidReview):
            client.review(document)

    def test_etag_binding_and_no_file_io_from_logical_paths(self):
        document = snapshot("enabled=true", "outside/logical.txt")
        tag = client.etag(document)
        with patch("builtins.open", side_effect=AssertionError("no file IO")):
            self.assertEqual(client.review(document, tag)["input_etag"], tag)
        document["files"][0]["text"] += "\n"
        with self.assertRaises(client.InvalidReview):
            client.review(document, tag)

    def test_cli_redaction_and_input_guards(self):
        with tempfile.TemporaryDirectory(prefix="amqic-client-review-") as folder:
            path = Path(folder) / "snapshot.json"
            path.write_text(json.dumps(snapshot('PUBLIC_SECRET="INERT_NOT_A_CREDENTIAL_5739"')), encoding="utf-8")
            command = [sys.executable, "-B", str(Path(client.__file__)), str(path)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["findings"], [finding("app/config.js", "client-public-secret-literal")])
            self.assertEqual(result.stderr, "")
            self.assertNotIn("INERT_NOT_A_CREDENTIAL_5739", result.stdout)
            for suffix in (["--unexpected=INERT_NOT_A_CREDENTIAL_5739"], ["--expected-input-etag", '"sha256-wrong"']):
                blocked = subprocess.run(command + suffix, capture_output=True, text=True)
                self.assertEqual(blocked.returncode, 2)
                self.assertEqual(blocked.stderr, "")
                self.assertEqual(json.loads(blocked.stdout), {"status": "blocked", "rule": "invalid-review-input"})
            path.write_text('{"format":1,"format":1,"files":[]}', encoding="utf-8")
            with self.assertRaises(client.InvalidReview):
                client.read_input(path)
            path.write_bytes(b"x" * (client.MAX_INPUT_BYTES + 1))
            with self.assertRaises(client.InvalidReview):
                client.read_input(path)
            path.write_text("{}", encoding="utf-8")
            os.link(path, Path(folder) / "alias.json")
            with self.assertRaises(client.InvalidReview):
                client.read_input(path)


if __name__ == "__main__":
    unittest.main()
