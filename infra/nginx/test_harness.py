"""Docker harness failure handling, using mocks without a Docker daemon."""
import copy
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import test_nginx as harness


class HarnessTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
