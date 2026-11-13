"""Validate shipped Compose normalization without creating Docker resources."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


class ComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which("docker")
        if cls.docker is None:
            raise unittest.SkipTest("Docker CLI and Compose are required")
        result = subprocess.run([cls.docker, "compose", "version", "--short"], capture_output=True, timeout=30)
        if result.returncode:
            raise unittest.SkipTest("Docker Compose plugin is required")
        cls.directory = Path(__file__).resolve().parent

    def configure(self, filename, values):
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("COMPOSE_", "APP_", "PYTHON_IMAGE_", "ARTIFACT_", "QUARANTINE_", "UPLOAD_"))
        }
        environment.update(COMPOSE_DISABLE_ENV_FILE="1", COMPOSE_PROJECT_NAME="amqic-config-validation")
        environment.update(values)
        arguments = [self.docker, "compose", "-f", str(self.directory / filename)]
        if filename == "quarantine.compose.yaml":
            arguments.extend(["--profile", "prepare", "--profile", "fetch", "--profile", "inspect"])
        elif filename == "uploads.compose.yaml":
            arguments.extend(["--profile", "prepare"])
        return subprocess.run(arguments + ["config", "--format", "json"],
                              env=environment, capture_output=True, text=True, timeout=30)

    def assert_tmpfs(self, service, size):
        mounts = service["tmpfs"]
        self.assertEqual(len(mounts), 1)
        target, options = mounts[0].split(":", 1)
        self.assertEqual(target, "/tmp")
        self.assertTrue({"rw", "noexec", "nosuid", "nodev", "size=" + size}.issubset(options.split(",")))

    def test_quarantine_has_one_complete_tmpfs_mount_per_service(self):
        result = self.configure("quarantine.compose.yaml", {
            "PYTHON_IMAGE_REPOSITORY": "python", "PYTHON_IMAGE_SHA256": "a" * 64,
            "ARTIFACT_URL": "https://example.invalid/artifact.tar.gz",
            "ARTIFACT_SHA256": "b" * 64, "QUARANTINE_VOLUME": "amqic-validation-not-created",
        })
        self.assertEqual(result.returncode, 0)
        services = json.loads(result.stdout)["services"]
        self.assertEqual(set(services), {"prepare", "fetch", "inspect"})
        for name in ("fetch", "inspect"):
            self.assert_tmpfs(services[name], "8m")
            self.assertTrue(services[name]["read_only"])
            self.assertEqual(services[name]["user"], "65532:65532")
        self.assertEqual(services["inspect"]["network_mode"], "none")

    def test_application_has_one_complete_tmpfs_and_no_published_ports(self):
        result = self.configure("compose.yaml", {
            "APP_IMAGE_REPOSITORY": "example/app", "APP_IMAGE_SHA256": "a" * 64,
            "APP_PRIVATE_IPV4": "10.252.252.2", "APP_PRIVATE_SUBNET": "10.252.252.0/29",
        })
        self.assertEqual(result.returncode, 0)
        service = json.loads(result.stdout)["services"]["app"]
        self.assert_tmpfs(service, "16m")
        self.assertFalse(service.get("ports"))
        self.assertTrue(service["read_only"])
        self.assertEqual(service["user"], "65532:65532")

    def test_required_settings_fail_closed(self):
        for filename in ("compose.yaml", "quarantine.compose.yaml", "uploads.compose.yaml"):
            with self.subTest(filename=filename):
                self.assertNotEqual(self.configure(filename, {}).returncode, 0)

    def test_upload_storage_roles_and_networks_are_separate(self):
        values = {"PYTHON_IMAGE_REPOSITORY": "python", "PYTHON_IMAGE_SHA256": "a" * 64}
        for role in ("INTAKE", "SCANNER", "PROMOTER", "MEDIA"):
            values["UPLOAD_" + role + "_REPOSITORY"] = "example/" + role.lower()
            values["UPLOAD_" + role + "_SHA256"] = "b" * 64
        result = self.configure("uploads.compose.yaml", values)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        services = config["services"]
        self.assertEqual(set(services), {"prepare", "intake", "scanner", "promoter", "media"})
        expected = {
            "intake": {"/quarantine": ("quarantine", False)},
            "scanner": {"/quarantine": ("quarantine", True), "/verdicts": ("verdicts", False)},
            "promoter": {"/quarantine": ("quarantine", True), "/verdicts": ("verdicts", True),
                         "/clean": ("clean", False)},
            "media": {"/clean": ("clean", True)},
        }
        self.assertEqual(set(config["volumes"]), {"quarantine", "verdicts", "clean"})
        self.assertEqual(len({item["name"] for item in config["volumes"].values()}), 3)
        for name, mounts in expected.items():
            service = services[name]
            actual = {item["target"]: (item["source"], item.get("read_only", False))
                      for item in service["volumes"]}
            self.assertEqual(actual, mounts)
            self.assertTrue(all(item["type"] == "volume" for item in service["volumes"]))
            self.assertTrue(all(item["volume"]["nocopy"] for item in service["volumes"]))
            self.assertTrue(service["read_only"])
            self.assertFalse(service.get("ports"))
            self.assertFalse(service.get("privileged"))
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertNotEqual(service["user"].split(":")[0], "0")
            self.assert_tmpfs(service, "16m")
        for name in ("prepare", "scanner", "promoter"):
            self.assertEqual(services[name]["network_mode"], "none")
        self.assertEqual(set(services["intake"]["networks"]), {"upload_ingress"})
        self.assertEqual(set(services["media"]["networks"]), {"media_ingress"})
        self.assertTrue(all(network["internal"] for network in config["networks"].values()))
        self.assertEqual(services["prepare"]["cap_add"], ["CHOWN"])
        self.assertEqual(services["prepare"]["profiles"], ["prepare"])
        self.assertEqual(services["scanner"]["group_add"], ["20001"])
        self.assertEqual(services["promoter"]["group_add"], ["20001", "20002"])
        self.assertEqual(services["media"]["group_add"], ["20003"])


if __name__ == "__main__":
    unittest.main()
