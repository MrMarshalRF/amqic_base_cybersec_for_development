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
            if not key.startswith(("COMPOSE_", "APP_", "PYTHON_IMAGE_", "ARTIFACT_", "QUARANTINE_"))
        }
        environment.update(COMPOSE_DISABLE_ENV_FILE="1", COMPOSE_PROJECT_NAME="amqic-config-validation")
        environment.update(values)
        arguments = [self.docker, "compose", "-f", str(self.directory / filename)]
        if filename == "quarantine.compose.yaml":
            arguments.extend(["--profile", "prepare", "--profile", "fetch", "--profile", "inspect"])
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
        for filename in ("compose.yaml", "quarantine.compose.yaml"):
            with self.subTest(filename=filename):
                self.assertNotEqual(self.configure(filename, {}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
