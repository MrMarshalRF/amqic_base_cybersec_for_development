"""Docker harness failure handling, using mocks without a Docker daemon."""
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import tempfile
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import test_nginx as harness
from render import load_paths, render


class HarnessTests(unittest.TestCase):
    @staticmethod
    def opaque_error():
        error = ssl.SSLError(ssl.SSL_ERROR_SSL, "[SSL] unknown error (_ssl.c:1011)")
        error.library = "SSL"
        return error

    @staticmethod
    def alert_output():
        return (b"Verification: OK\nNo ALPN negotiated\nVerify return code: 0 (ok)\n"
                b"123:error:0A000460:SSL routines:ssl3_read_bytes:reason(1120):../ssl/record/rec_layer_s3.c:1600:SSL alert number 120\n")

    def confirm_cli(self, output=None, code=1):
        child = MagicMock()
        child.stdout = io.BytesIO(self.alert_output() if output is None else output)
        child.wait.return_value = code
        child.poll.return_value = code
        with patch.object(harness.shutil, "which", return_value="/reviewed/openssl"), \
                patch.object(harness.subprocess, "Popen", return_value=child) as launch:
            proof = harness.confirm_h2_alert(49152, Path("synthetic/fullchain.pem"))
        return proof, launch, child

    def test_opaque_python_error_requires_independent_proof(self):
        proof, _, _ = self.confirm_cli()
        confirm = MagicMock(return_value=proof)
        result = harness.probe_alpn(MagicMock(side_effect=self.opaque_error()), ["h2"], None, confirm)
        self.assertEqual(result["python_observation"], "opaque_ssl_unknown_error")
        self.assertEqual(result["independent_confirmation"]["alert_number"], 120)
        self.assertNotIn("certificate_verified", result["independent_confirmation"])
        confirm.assert_called_once_with()
        for callback in (None, MagicMock(return_value={}), MagicMock(side_effect=OSError("unavailable"))):
            with self.subTest(callback=callback), self.assertRaises((ssl.SSLError, AssertionError, OSError)):
                harness.probe_alpn(MagicMock(side_effect=self.opaque_error()), ["h2"], None, callback)

    def test_opaque_confirmation_is_not_used_for_other_failures_or_offers(self):
        for offered, expected, error in ((["h2", "http/1.1"], "http/1.1", self.opaque_error()),
                                         (["h2"], None, ssl.SSLError("unrelated"))):
            callback = MagicMock()
            with self.assertRaises(ssl.SSLError):
                harness.probe_alpn(MagicMock(side_effect=error), offered, expected, callback)
            callback.assert_not_called()
        for field, value in (("library", "OTHER"), ("reason", "CERTIFICATE_VERIFY_FAILED"),
                             ("errno", ssl.SSL_ERROR_EOF), ("strerror", "[SSL] unknown error (_ssl.c:1011) suffix")):
            error = self.opaque_error()
            setattr(error, field, value)
            callback = MagicMock()
            with self.subTest(field=field), self.assertRaises(ssl.SSLError):
                harness.probe_alpn(MagicMock(side_effect=error), ["h2"], None, callback)
            callback.assert_not_called()

    def test_known_python_alpn_path_needs_no_cli(self):
        error = ssl.SSLError("known alert")
        error.reason = "TLSV1_ALERT_NO_APPLICATION_PROTOCOL"
        callback = MagicMock(side_effect=AssertionError("CLI must not run"))
        self.assertEqual(harness.probe_alpn(MagicMock(side_effect=error), ["h2"], None, callback)["handshake"],
                         "no_application_protocol")
        callback.assert_not_called()

    def test_cli_confirmation_uses_fixed_verified_loopback_argv_and_bounded_output(self):
        proof, launch, child = self.confirm_cli()
        self.assertEqual(proof["alert_number"], 120)
        self.assertEqual(proof["output_bytes"], len(self.alert_output()))
        self.assertNotIn("output", proof)
        self.assertEqual(launch.call_args.args[0], ["/reviewed/openssl", "s_client", "-connect", "127.0.0.1:49152",
                         "-servername", "kit.example.test", "-verify_hostname", "kit.example.test",
                         "-CAfile", str(Path("synthetic/fullchain.pem")), "-verify_return_error", "-alpn", "h2"])
        self.assertIs(launch.call_args.kwargs["shell"], False)
        child.wait.assert_called_once_with(timeout=5)
        child.kill.assert_not_called()

    def test_cli_confirmation_rejects_incomplete_conflicting_or_oversized_proof(self):
        valid = self.alert_output()
        variants = [b"", valid.replace(b"No ALPN negotiated\n", b""),
                    valid.replace(b"No ALPN negotiated", b"ALPN protocol: h2"),
                    valid.replace(b"120", b"40"), valid.replace(b"reason(1120)", b"unrelated"),
                    valid.replace(b"Verification: OK", b"Verification error: bad certificate"),
                    valid + b"verify error:num=20:unable to get local issuer certificate\n",
                    valid + b"123:error:0A000126:SSL routines:unexpected EOF\n",
                    valid + b"connect:errno=111\n",
                    valid + b"SSL alert number 40\n", b"x" * 65537]
        for output in variants:
            with self.subTest(output=output[:60]), self.assertRaises(AssertionError):
                self.confirm_cli(output)
        with self.assertRaises(AssertionError):
            self.confirm_cli(valid, code=0)

    def test_cli_missing_timeout_and_invalid_port_fail_closed(self):
        with patch.object(harness.shutil, "which", return_value=None), self.assertRaises(AssertionError):
            harness.confirm_h2_alert(49152, Path("synthetic.pem"))
        for port in (0, 65536, True, "49152"):
            with self.subTest(port=port), patch.object(harness.subprocess, "Popen") as launch, self.assertRaises(AssertionError):
                harness.confirm_h2_alert(port, Path("synthetic.pem"))
            launch.assert_not_called()
        child = MagicMock()
        child.stdout = io.BytesIO(self.alert_output())
        child.wait.side_effect = [subprocess.TimeoutExpired("openssl", 5), 1]
        child.poll.return_value = None
        with patch.object(harness.shutil, "which", return_value="/reviewed/openssl"), \
                patch.object(harness.subprocess, "Popen", return_value=child), self.assertRaises(subprocess.TimeoutExpired):
            harness.confirm_h2_alert(49152, Path("synthetic.pem"))
        child.kill.assert_called_once()

    def test_cli_confirmation_rejects_conflicting_or_unknown_verification_diagnostics(self):
        for extra in (b"Verify return code: 20 (unable to get local issuer certificate)\n",
                      b"Verify return code: unknown\n", b"Verify return code: -1 (unknown)\n",
                      b"Verify return code\n", b"verify return code : 20 (bad)\n",
                      b"Verify return code: 0 (ok)\n", b"Verification: FAILED\n",
                      b"Verification: OK\n"):
            with self.subTest(extra=extra), self.assertRaises(AssertionError):
                self.confirm_cli(self.alert_output() + extra)

    def test_cli_output_overflow_kills_owned_process(self):
        child = MagicMock()
        child.stdout = io.BytesIO(b"x" * 65537)
        child.wait.return_value = 1
        child.poll.side_effect = [None, 1]
        with patch.object(harness.shutil, "which", return_value="/reviewed/openssl"), \
                patch.object(harness.subprocess, "Popen", return_value=child), self.assertRaises(AssertionError):
            harness.confirm_h2_alert(49152, Path("synthetic.pem"))
        child.kill.assert_called_once()
    def test_observed_nginx_build_records_version_and_modules(self):
        observed = harness.nginx_build("nginx version: nginx/1.30.7\nconfigure arguments: --with-http_v2_module --with-http_v3_module\n")
        self.assertEqual(observed["version"], "1.30.7")
        self.assertTrue(observed["http_v2_module"])
        self.assertTrue(observed["http_v3_module"])
        self.assertFalse(harness.nginx_build("nginx version: nginx/1.30.7")["http_v3_module"])
        with self.assertRaises(AssertionError):
            harness.nginx_build("unknown binary")

    def test_alpn_rejects_h2_selection_and_accepts_http11(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.selected_alpn_protocol.return_value = "http/1.1"
        connect = MagicMock(return_value=connection)
        result = harness.probe_alpn(connect, ["h2", "http/1.1"], "http/1.1")
        self.assertEqual(result["selected"], "http/1.1")
        connection.sendall.assert_not_called()
        connection.selected_alpn_protocol.return_value = "h2"
        with self.assertRaises(AssertionError):
            harness.probe_alpn(connect, ["h2"], None)
        connection.selected_alpn_protocol.return_value = None
        self.assertIsNone(harness.probe_alpn(connect, ["h2"], None)["selected"])
        connection.__exit__.assert_called()

    def test_alpn_does_not_misclassify_unrelated_tls_failures(self):
        connect = MagicMock(side_effect=ssl.SSLError("unrelated TLS failure"))
        with self.assertRaises(ssl.SSLError):
            harness.probe_alpn(connect, ["h2"], None)
        error = ssl.SSLError("no application protocol")
        error.reason = "TLSV1_ALERT_NO_APPLICATION_PROTOCOL"
        connect.side_effect = error
        self.assertEqual(harness.probe_alpn(connect, ["h2"], None)["handshake"], "no_application_protocol")
        with self.assertRaises(ssl.SSLError):
            harness.probe_alpn(connect, ["h2", "http/1.1"], "http/1.1")

    def test_alpn_accepts_exact_windows_generic_ssl_alert_only_for_h2_only(self):
        for reason in (None, "SSL"):
            error = ssl.SSLError(ssl.SSL_ERROR_SSL,
                                 "[SSL] tlsv1 alert no application protocol (_ssl.c:1028)")
            if reason is not None:
                error.reason = reason
            connect = MagicMock(side_effect=error)
            with self.subTest(reason=reason):
                self.assertEqual(harness.probe_alpn(connect, ["h2"], None)["handshake"], "no_application_protocol")
                for offered, expected in ((["h2", "http/1.1"], "http/1.1"),
                                          (["http/1.1"], None), (["h2", "http/1.1"], None)):
                    with self.assertRaises(ssl.SSLError):
                        harness.probe_alpn(connect, offered, expected)

    def test_alpn_rejects_other_ssl_alerts_and_near_matches(self):
        messages = ["[SSL] tlsv1 alert handshake failure (_ssl.c:1028)",
                    "[SSL] certificate verify failed (_ssl.c:1028)",
                    "[SSL] EOF occurred in violation of protocol (_ssl.c:1028)",
                    "[SSL] tlsv1 alert no application protocol (_ssl.c:1028) extra",
                    "prefix [SSL] tlsv1 alert no application protocol (_ssl.c:1028)"]
        for message in messages:
            error = ssl.SSLError(ssl.SSL_ERROR_SSL, message)
            error.reason = "SSL"
            with self.subTest(message=message), self.assertRaises(ssl.SSLError):
                harness.probe_alpn(MagicMock(side_effect=error), ["h2"], None)
        for number, reason in ((ssl.SSL_ERROR_EOF, "SSL"),
                               (ssl.SSL_ERROR_SSL, "CERTIFICATE_VERIFY_FAILED")):
            error = ssl.SSLError(number, "[SSL] tlsv1 alert no application protocol (_ssl.c:1028)")
            error.reason = reason
            with self.subTest(number=number, reason=reason), self.assertRaises(ssl.SSLError):
                harness.probe_alpn(MagicMock(side_effect=error), ["h2"], None)

    def test_missing_published_ports_are_transient(self):
        for ports in (None, {}, {"80/tcp": []}, {"80/tcp": None}):
            with self.subTest(ports=ports), self.assertRaises(ConnectionRefusedError):
                harness.mapped_port(ports, False)

    def test_port_binding_requires_loopback_and_a_valid_port(self):
        self.assertEqual(harness.mapped_port({"443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49152"}]}, True), 49152)
        with self.assertRaises(ValueError):
            harness.mapped_port({"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49152"}]}, False)
        with self.assertRaises(ConnectionRefusedError):
            harness.mapped_port({"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "0"}]}, False)

    def test_listener_readiness_retries_refusal_and_closes_probes(self):
        http = MagicMock()
        https = MagicMock()
        connect = MagicMock(side_effect=[ConnectionRefusedError(), http, https])
        with patch.object(harness.time, "monotonic", return_value=0), patch.object(harness.time, "sleep") as pause:
            harness.wait_for_listeners(connect)
        self.assertEqual([call.args for call in connect.call_args_list], [(False,), (False,), (True,)])
        self.assertTrue(all(call.kwargs["timeout"] <= 1 for call in connect.call_args_list))
        http.__exit__.assert_called_once()
        https.__exit__.assert_called_once()
        pause.assert_called_once_with(0.05)

    def test_listener_readiness_has_a_deadline(self):
        connect = MagicMock()
        with patch.object(harness.time, "monotonic", side_effect=[0, 1]):
            with self.assertRaises(TimeoutError):
                harness.wait_for_listeners(connect, timeout=1)
        connect.assert_not_called()

    def test_listener_readiness_rejects_late_success(self):
        connect = MagicMock(return_value=MagicMock())
        with patch.object(harness.time, "monotonic", side_effect=[0, 0, 0, 0, 2, 2, 2]):
            with self.assertRaises(TimeoutError):
                harness.wait_for_listeners(connect, timeout=1)
        self.assertEqual(connect.call_count, 2)

    def test_listener_readiness_closes_http_when_tls_is_not_ready(self):
        http = MagicMock()
        connect = MagicMock(side_effect=[http, ConnectionResetError()])
        with patch.object(harness.time, "monotonic", side_effect=[0, 0, 0, 0, 1, 1]):
            with self.assertRaises(TimeoutError):
                harness.wait_for_listeners(connect, timeout=1)
        http.__exit__.assert_called_once()

    def cleanup(self, response):
        state = {"container_id": "synthetic-container", "network_id": "synthetic-network"}
        saved = []
        with patch.object(harness, "docker", side_effect=response) as command:
            harness.cleanup_resources(state, lambda: saved.append(copy.deepcopy(state)))
        self.assertEqual(saved, [state])
        return state, command.call_args_list

    def test_docker_command_has_a_finite_timeout(self):
        with patch.object(harness.subprocess, "check_output", return_value="synthetic\n") as command:
            self.assertEqual(harness.docker("image", "inspect", "synthetic"), "synthetic")
        self.assertEqual(command.call_args.kwargs["timeout"], 30)
        with patch.object(harness.subprocess, "check_output", side_effect=subprocess.TimeoutExpired("synthetic", 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                harness.docker("image", "inspect", "synthetic")

    def test_normal_cleanup_uses_only_the_recorded_resource_ids(self):
        state, calls = self.cleanup(["synthetic logs", "", "", "", ""])
        self.assertEqual([call.args for call in calls], [
            ("logs", "synthetic-container"),
            ("rm", "-f", "synthetic-container"),
            ("ps", "-a", "--no-trunc", "--filter", "id=synthetic-container", "--format", "{{.ID}}"),
            ("network", "rm", "synthetic-network"),
            ("network", "ls", "--no-trunc", "--filter", "id=synthetic-network", "--format", "{{.ID}}"),
        ])
        self.assertFalse(state["cleanup_pending"])
        self.assertEqual(state["cleanup_errors"], [])

    def test_log_failure_does_not_prevent_verified_cleanup(self):
        error = subprocess.TimeoutExpired("synthetic", 30)
        state, calls = self.cleanup([error, "", "", "", ""])
        self.assertEqual(len(calls), 5)
        self.assertTrue(state["container_absent"])
        self.assertTrue(state["network_absent"])
        self.assertFalse(state["cleanup_pending"])
        self.assertEqual(state["cleanup_errors"][0]["operation"], "container-logs")

    def test_failed_removal_preserves_pending_and_still_cleans_network(self):
        error = subprocess.CalledProcessError(1, "synthetic")
        state, calls = self.cleanup(["synthetic logs", error, "synthetic-container", "", ""])
        self.assertEqual(len(calls), 5)
        self.assertFalse(state["container_absent"])
        self.assertTrue(state["network_absent"])
        self.assertTrue(state["cleanup_pending"])

    def test_unknown_absence_never_counts_as_removed(self):
        error = subprocess.TimeoutExpired("synthetic", 30)
        state, _ = self.cleanup(["synthetic logs", "", error, "", ""])
        self.assertFalse(state["container_absent"])
        self.assertTrue(state["cleanup_pending"])

    def test_unknown_creation_is_saved_without_guessing_an_id(self):
        state = {"container_creation": "pending", "requested_container_name": "synthetic-request"}
        saved = []
        with patch.object(harness, "docker") as command:
            harness.cleanup_resources(state, lambda: saved.append(copy.deepcopy(state)))
        command.assert_not_called()
        self.assertTrue(state["cleanup_pending"])
        self.assertEqual(saved, [state])


class RegistryPolicyTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[2]

    def test_protocol_policy_rejects_enabled_protocols_or_advertisement(self):
        config = render("kit.example.test", "192.168.240.2:8080",
                        self.root / "infra/protected-paths.json",
                        self.root / "infra/nginx/nginx.conf.template")
        self.assertEqual(harness.protocol_config(config), {
            "http2": "off", "quic_udp_listeners": False, "alt_svc": "suppressed"})
        self.assertLess(config.index("http2 off;"), config.index("    server {"))
        for changed in (config.replace("http2 off;", "http2 on;"),
                        config.replace("http2 off;", ""),
                        config.replace("listen 443 ssl;", "listen 443 ssl http2;"),
                        config.replace("listen 443 ssl;", "listen 443 quic;"),
                        config.replace("http2 off;", "http2 off; http3 on;"),
                        config.replace("proxy_hide_header Alt-Svc;", ""),
                        config.replace("http2 off;", 'http2 off; add_header Alt-Svc \'h3=":443"\';')):
            with self.subTest(candidate=changed[:80]), self.assertRaises(AssertionError):
                harness.protocol_config(changed)

    def test_actual_rendered_registry_literals_and_boundaries(self):
        paths = load_paths(self.root / "infra/protected-paths.json")
        config = render("kit.example.test", "192.168.240.2:8080",
                        self.root / "infra/protected-paths.json",
                        self.root / "infra/nginx/nginx.conf.template")
        # Exercise rules extracted from the real rendered output, not a second renderer.
        literals = [line.strip()[4:-4] for line in config.split("map $uri $protected_uri {", 1)[1].split("\n    }", 1)[0].splitlines()
                    if line.strip().startswith('"~*^/') and line.strip().endswith('" 1;')
                    and not line.strip().startswith('"~*^/assets/admin/.*')]
        self.assertEqual(len(literals), len(paths))
        rules = [re.compile(pattern, re.I) for pattern in literals]
        for path, rule in zip(paths, rules):
            with self.subTest(path=path):
                for suffix in ("", "/child", ".bak", ";parameter", "~"):
                    self.assertTrue(rule.match(path.upper() + suffix))
                self.assertFalse(rule.match(path + "-public"))
                self.assertFalse(rule.match(path + "x"))
        for path in ("/robots.txt", "/.well-known/security.txt", "/api/v1/status", "/"):
            self.assertFalse(any(rule.match(path) for rule in rules), path)

    def test_admin_map_class_uses_the_existing_server_guard(self):
        config = render("kit.example.test", "192.168.240.2:8080",
                        self.root / "infra/protected-paths.json",
                        self.root / "infra/nginx/nginx.conf.template")
        block = config.split("map $uri $protected_uri {", 1)[1].split("\n    }", 1)[0]
        line, = [line.strip() for line in block.splitlines()
                 if line.strip().startswith('"~*^/assets/admin/.*')]
        # Nginx quoted strings unescape doubled backslashes before PCRE sees them.
        rule = re.compile(line[4:-4].replace("\\\\", "\\"), re.I)
        for path in ("/assets/admin/app.js.map", "/assets/admin/nested/app.css.map",
                     "/ASSETS/ADMIN/APP.JS.MAP", "/assets/admin/app.map/child",
                     "/assets/admin/app.map;download", "/assets/admin/app.map.bak"):
            self.assertTrue(rule.match(path), path)
        for path in ("/assets/admin/app.js", "/assets/admin/nested/app.css",
                     "/assets/admin/app.map-public", "/assets/admin/app.js.mapx",
                     "/assets/administrator/app.map", "/api/v1/status",
                     "/api/v1/admin/content", "/.well-known/security.txt"):
            self.assertFalse(rule.match(path), path)
        self.assertEqual(config.count("if ($protected_uri) { return 418; }"), 2)
        self.assertNotIn("location ^~ /assets/admin/", config)
        lab = harness.add_static_bypass_fixture(config)
        self.assertEqual(lab.count("location ^~ /assets/admin/"), 1)
        self.assertIn("limit_req zone=website_per_ip burst=9 nodelay;", lab)
        self.assertLess(lab.rindex("if ($protected_uri)"), lab.index("location ^~ /assets/admin/"))

    def test_technical_paths_are_canonical_and_raw_traversal_stays_out(self):
        paths = load_paths(self.root / "infra/protected-paths.json")
        expected = {"/api/v1/secrets", "/proc/self/environ",
                    "/jenkins/credentials/store/system/domain/_", "/credentials.js",
                    "/ssl/server.key", "/ssl/localhost.key", "/backend/settings.py",
                    "/config/custom-environment-variables.json", "/config/database.json",
                    "/gc-service.json", "/google-service-account.json", "/google-services.json",
                    "/api/proc/self/environ", "/.dsh", "/prompt-inject.md"}
        self.assertTrue(expected.issubset(paths))
        self.assertEqual(len(paths), 160)
        self.assertNotIn("/assets/admin/*.map", paths)
        self.assertFalse(any(".." in path.split("/") for path in paths))

    def test_registry_rejects_unsafe_values_duplicates_and_bounds(self):
        with tempfile.TemporaryDirectory(prefix="kit-registry-") as folder:
            file = Path(folder) / "paths.json"
            invalid = [[], ["/a"] * 257, ["/Case", "/case"],
                       ["/a/../b"], ["/./a"], ["//a"], ["/a/"], ["relative"],
                       ["/a%2fb"], ["/assets/admin/*.map"], ["/app/api/[...]/route.ts"], ["/a?x=1"],
                       ["/a#fragment"], ["/a\\b"], ["/a\ninclude evil;"],
                       ['/a" 0;'], ["/a|b"], ["/a$b"], ["/nonascii-Г©"], [None]]
            for paths in invalid:
                file.write_text(json.dumps({"schema_version": 1, "paths": paths}))
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    load_paths(file)
            file.write_text(json.dumps({"schema_version": 1, "paths": ["/p" + str(i) for i in range(256)]}))
            self.assertEqual(len(load_paths(file)), 256)
            file.write_text(json.dumps({"schema_version": True, "paths": ["/ok"]}))
            with self.assertRaises(ValueError):
                load_paths(file)

    def test_gitignore_keeps_source_and_public_examples_versionable(self):
        # A standalone disposable fixture; never initialize or modify the source repository.
        parent = Path(tempfile.gettempdir()).resolve()
        fixture = Path(tempfile.mkdtemp(prefix="kit-ignore-", dir=parent)).resolve()
        self.assertEqual(fixture.parent, parent)
        positives = [".env", "nested/.env.production", "nested/.env.worker",
                     "mailgun.env", "nested/resend.env", "huggingface.env",
                     "credentials.json", "nested/credentials.yaml", "envs/staging.env",
                     "k8s/app-secrets.yaml", "k8s/namespace/secrets.yaml",
                     "kubernetes/secret.yaml", "manifests/secret.yml", "manifests/secret.yaml",
                     "helm/secrets/values.yaml", "helm/charts/app/values-secret.yaml",
                     "config/prod.secret.exs", "config/keys.json", "config/secrets.json",
                     "pb_data/data.db", "pb_data/auxiliary.json",
                     "bootstrap/cache/config.php", "storage/framework/cache/config.php",
                     "dump.sql", "private.sql.gz",
                     ".agent-work/task.json", "nested/.agent-work/task.md",
                     "private-evidence/check.md", "api-delegations/task.json",
                     ".dpapi/store.json", "nested/session.dpapi",
                     ".dsh/config.json", "nested/.dsh/settings.json",
                     "prompt-inject.md", "nested/prompt-inject.md"]
        negatives = [".env.example", ".env.prod.example", "nested/.env.worker.example",
                     "env.example", "env.sample", "envs/staging.example", "envs/staging.sample",
                     "terraform.tfvars.example", "schema.sql", "db/schema.rb", "db/seeds.rb",
                     "prisma/schema.prisma", "Jenkinsfile", "Gemfile", "Pipfile.lock",
                     "package-lock.json", "playwright.config.js", "cypress.config.js",
                     "jest.setup.ts", "astro.config.ts", "app.config.js", "app.config.ts",
                     "kustomization.yaml", "k8s/env-configmap.yaml", "helm/values-staging.yaml",
                     ".github/workflows/secrets.yml", ".github/workflows/publish.yml",
                     "docker-compose.yml", "cloudfunctions.yaml", "firebase.config.json",
                     "convex.json", "netlify.toml", "sparkpost.json", "sparkpost.php",
                     "connectionstrings.config", "emailconfig.yml", "mail.conf", "mail.ini",
                     "sendgrid.yml", "ses-config.json", "sentry.properties",
                     "robots.txt", ".well-known/security.txt",
                     "AGENTS.md", "SECURITY.md", "skills/example/SKILL.md",
                     "reference/core.mjs", "release-public-key.pem", "release-public-key.gpg",
                     "app/evidence.json", "app/agent-workflow.mjs",
                     "config.local.toml.example", ".env.production.example",
                     "deploy/compose.yaml", "trust/public.crt", "trust/public.cer",
                     ".dsh-public/config.json", "nested/prompt-inject-public.md",
                     "app/dsh-client.mjs"]
        # Git subprocesses must not inherit a caller's repository/index redirects
        # or machine-global ignore policies. A hostile synthetic parent environment
        # exercises isolation without referencing any real repository or secret.
        sentinel = parent / (fixture.name + "-outside-git")
        self.assertFalse(sentinel.exists())
        caller_config = fixture / "caller-config"
        (caller_config / "git").mkdir(parents=True)
        (caller_config / "git/ignore").write_text("Jenkinsfile\n")
        with patch.dict(os.environ, {"GIT_DIR": str(sentinel),
                                    "XDG_CONFIG_HOME": str(caller_config),
                                    "GIT_WORK_TREE": str(sentinel),
                                    "GIT_INDEX_FILE": str(sentinel / "index"),
                                    "GIT_CONFIG_COUNT": "1",
                                    "GIT_CONFIG_KEY_0": "core.excludesfile",
                                    "GIT_CONFIG_VALUE_0": str(sentinel / "ignore")}):
            git_env = {key: value for key, value in os.environ.items()
                       if not key.startswith("GIT_")}
            git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_CONFIG_SYSTEM": os.devnull})
            try:
                subprocess.run(["git", "-c", "core.excludesFile=" + os.devnull,
                                "init", "--quiet", "--template=", str(fixture)], check=True,
                               capture_output=True, env=git_env, timeout=30)
                shutil.copyfile(self.root / ".gitignore", fixture / ".gitignore")
                for name in positives + negatives:
                    file = fixture / name
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text("synthetic fixture only\n")
                for names, ignored in ((positives, True), (negatives, False)):
                    for name in names:
                        result = subprocess.run(["git", "-c", "core.excludesFile=" + os.devnull,
                                             "check-ignore", "--no-index", "--", name],
                                                cwd=fixture, capture_output=True, text=True, env=git_env, timeout=5)
                        with self.subTest(path=name):
                            self.assertEqual(result.returncode, 0 if ignored else 1, result.stdout + result.stderr)
            finally:
                # Exact newly-created child only; refuse traversal/symlink replacement before recursive cleanup.
                if fixture.resolve().parent != parent or fixture.is_symlink():
                    raise RuntimeError("Unsafe disposable Git fixture cleanup target")
                shutil.rmtree(fixture)
                self.assertFalse(sentinel.exists(), "Inherited Git redirect escaped the fixture")


if __name__ == "__main__":
    unittest.main()
