#!/usr/bin/env python3
"""Exercise the templates in a disposable, loopback-only synthetic Docker lab."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import time
import uuid

from render import render

EXPECTED_CSP = (
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; manifest-src 'self'; media-src 'none'; "
    "worker-src 'none'; upgrade-insecure-requests"
)


def docker(*arguments, timeout=30):
    return subprocess.check_output(
        ["docker", *arguments], text=True, stderr=subprocess.STDOUT, timeout=timeout
    ).strip()


def cleanup_resources(state, save):
    errors = []
    container = state.get("container_id")
    network = state.get("network_id")

    def attempt(operation, callback):
        try:
            return callback()
        except (subprocess.SubprocessError, OSError) as error:
            errors.append({"operation": operation, "error": type(error).__name__})
            return None

    if container:
        logs = attempt("container-logs", lambda: docker("logs", container))
        if logs is not None:
            state["logs"] = logs
        attempt("container-remove", lambda: docker("rm", "-f", container))
        observed = attempt("container-absence", lambda: docker(
            "ps", "-a", "--no-trunc", "--filter", f"id={container}", "--format", "{{.ID}}"))
        state["container_absent"] = observed == ""
    if network:
        attempt("network-remove", lambda: docker("network", "rm", network))
        observed = attempt("network-absence", lambda: docker(
            "network", "ls", "--no-trunc", "--filter", f"id={network}", "--format", "{{.ID}}"))
        state["network_absent"] = observed == ""
    state["cleanup_errors"] = errors
    state["cleanup_pending"] = bool(
        (container and not state.get("container_absent"))
        or (network and not state.get("network_absent"))
        or state.get("container_creation") == "pending"
        or state.get("network_creation") == "pending"
    )
    save()


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def mapped_port(ports, secure):
    bindings = ports.get("443/tcp" if secure else "80/tcp") if isinstance(ports, dict) else None
    if not bindings:
        raise ConnectionRefusedError("Synthetic published port is not ready")
    if len(bindings) != 1 or bindings[0].get("HostIp") != "127.0.0.1":
        raise ValueError("Unexpected synthetic port binding")
    port = bindings[0].get("HostPort")
    if not isinstance(port, str) or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ConnectionRefusedError("Synthetic published port is not ready")
    return int(port)


def wait_for_listeners(connect, timeout=30):
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Synthetic nginx listeners did not become ready") from last_error
        try:
            for secure in (False, True):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Synthetic nginx listener readiness deadline")
                with connect(secure, timeout=min(1, remaining)):
                    pass
            if time.monotonic() > deadline:
                raise TimeoutError("Synthetic nginx listener readiness deadline")
            return
        except OSError as error:
            last_error = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.05, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Reviewed local nginx image sha256:...")
    parser.add_argument("--output", type=Path, required=True, help="New directory for synthetic fixtures and report")
    parser.add_argument("--tls-fixture", type=Path, help="Directory with synthetic fullchain.pem and privkey.pem")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        parser.error("Use an exact reviewed local image ID")
    if docker("image", "inspect", args.image, "--format", "{{.Id}}") != args.image:
        parser.error("Image ID mismatch")
    base = args.output.resolve()
    base.mkdir(parents=True, exist_ok=False)
    if args.tls_fixture:
        for name in ("fullchain.pem", "privkey.pem"):
            shutil.copyfile(args.tls_fixture / name, base / name)
    else:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=kit.example.test",
            "-addext", "subjectAltName=DNS:kit.example.test",
            "-keyout", str(base / "privkey.pem"), "-out", str(base / "fullchain.pem"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # These keys are disposable synthetic fixtures, readable by test UID 101.
    # Never pass production key material to this harness.
    for name in ("fullchain.pem", "privkey.pem"):
        (base / name).chmod(0o444)
    here = Path(__file__).resolve().parent
    source_paths = [here / "nginx.conf.template", here / "render.py", here.parent / "protected-paths.json", Path(__file__).resolve(), here.parent / "firewall/addresses.py", here.parent / "firewall/__init__.py"]
    source_hashes = {str(path.relative_to(here.parent)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
    upstream_fixture = '''
    map $arg_upstream_csp $synthetic_upstream_csp {
        default "";
        1 "script-src 'none'";
    }
    server {
        listen 18080;
        add_header Content-Security-Policy $synthetic_upstream_csp always;
        location / { return 200 "synthetic upstream"; }
    }
}
'''
    def make_config(policy=None):
        result = render("kit.example.test", "192.168.240.2:8080", here.parent / "protected-paths.json", here / "nginx.conf.template", policy)
        result = result.replace("192.168.240.2:8080", "127.0.0.1:18080")
        return result.rsplit("}", 1)[0] + upstream_fixture

    config = make_config()
    (base / "nginx.conf").write_text(config, encoding="utf-8")
    (base / "nginx.conf").chmod(0o444)
    state = {
        "purpose": "synthetic nginx regression only", "image": args.image,
        "owner": "this test invocation", "cleanup_owner": "this test invocation",
        "intent": "create and remove one isolated test bridge and loopback-only nginx container",
        "source_sha256": source_hashes,
        "rendered_config_sha256": hashlib.sha256(config.encode("utf-8")).hexdigest(),
        "starts": [], "results": {},
    }
    report = base / "report.json"

    def save():
        report.write_text(json.dumps(state, indent=2), encoding="utf-8")

    network = None
    container = None
    save()
    try:
        state["requested_network_name"] = "kit-nginx-test-" + uuid.uuid4().hex
        state["network_creation"] = "pending"
        save()
        network = docker("network", "create", state["requested_network_name"])
        state["network_id"] = network
        state["network_creation"] = "observed"
        save()
        mounts = []
        for name, target in (("nginx.conf", "/etc/nginx/nginx.conf"), ("fullchain.pem", "/etc/nginx/tls/fullchain.pem"), ("privkey.pem", "/etc/nginx/tls/privkey.pem")):
            mounts += ["--mount", f"type=bind,src={base / name},dst={target},readonly"]
        state["requested_container_name"] = "kit-nginx-test-" + uuid.uuid4().hex
        state["container_creation"] = "pending"
        save()
        container = docker(
            "create", "--name", state["requested_container_name"], "--network", network, "--user", "101:101", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--pids-limit=32", "--memory=128m", "--cpus=0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "-p", "127.0.0.1::80", "-p", "127.0.0.1::443", *mounts,
            "--entrypoint", "nginx", args.image, "-g", "daemon off;",
        )
        state["container_id"] = container
        state["container_creation"] = "observed"
        save()
        context = ssl.create_default_context(cafile=str(base / "fullchain.pem"))

        def start(restart=False):
            docker("restart" if restart else "start", container)
            details = json.loads(docker("inspect", container))[0]
            state["starts"].append({"pid": details["State"]["Pid"], "started_at": details["State"]["StartedAt"]})
            state["ports"] = details["NetworkSettings"]["Ports"]
            save()
            wait_for_listeners(readiness_connect)
            state["starts"][-1]["listeners_ready"] = True
            save()

        def connect(secure, timeout=5):
            port = mapped_port(state["ports"], secure)
            deadline = time.monotonic() + timeout
            connection = socket.create_connection(("127.0.0.1", port), timeout=timeout)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Synthetic nginx connection deadline")
                connection.settimeout(remaining)
                if not secure:
                    return connection
                return context.wrap_socket(connection, server_hostname="kit.example.test")
            except BaseException:
                connection.close()
                raise

        def readiness_connect(secure, timeout):
            deadline = time.monotonic() + timeout
            try:
                details = json.loads(docker("inspect", container, timeout=timeout))[0]
            except subprocess.TimeoutExpired as error:
                raise ConnectionRefusedError("Synthetic container metadata is not ready") from error
            state["ports"] = details["NetworkSettings"]["Ports"]
            state["starts"][-1]["ready_pid"] = details["State"]["Pid"]
            state["starts"][-1]["ready_started_at"] = details["State"]["StartedAt"]
            save()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectionRefusedError("Synthetic metadata deadline")
            return connect(secure, timeout=remaining)

        def burst(paths, secure=True, host="kit.example.test", spoof=False, method="GET", additional_csp=None, request_headers=()):
            connections = []
            try:
                for _ in paths:
                    connections.append(connect(secure))
                begin = time.monotonic()
                for index, (connection, path) in enumerate(zip(connections, paths)):
                    forwarded = f"X-Forwarded-For: 198.51.100.{index + 1}\r\n" if spoof else ""
                    forwarded += "".join(f"{name}: {value}\r\n" for name, value in request_headers)
                    connection.sendall(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{forwarded}Connection: close\r\n\r\n".encode())
                sent_seconds = time.monotonic() - begin
                responses = []
                for connection in connections:
                    parts = []
                    while True:
                        part = connection.recv(4096)
                        if not part:
                            break
                        parts.append(part)
                    responses.append(b"".join(parts).decode("latin1"))
                for response in responses:
                    headers = {}
                    for line in response.split("\r\n\r\n", 1)[0].split("\r\n")[1:]:
                        name, separator, value = line.partition(":")
                        if separator:
                            headers.setdefault(name.lower(), []).append(value.strip())
                    expected_policies = [EXPECTED_CSP]
                    if additional_csp:
                        expected_policies.append(additional_csp)
                    require(sorted(headers.get("content-security-policy", [])) == sorted(expected_policies), "Missing, duplicate or changed CSP")
                    require(headers.get("x-content-type-options") == ["nosniff"], "Missing nosniff")
                    require(headers.get("referrer-policy") == ["no-referrer"], "Missing Referrer-Policy")
                    expected_hsts = ["max-age=31536000"] if secure else None
                    require(headers.get("strict-transport-security") == expected_hsts, "HSTS must occur only on HTTPS")
                state["results"]["security_headers_all_http_responses"] = True
                state["last_burst_send_seconds"] = sent_seconds
                return [int(response.split()[1]) for response in responses], responses, time.monotonic() - begin
            finally:
                for connection in connections:
                    connection.close()

        def check_burst(name, path, expected, secure=True, host="kit.example.test"):
            codes, responses, elapsed = burst([path] * 11, secure=secure, host=host)
            # Concurrent arrival order is arbitrary. The set of admitted requests is exact.
            if codes.count(expected) != 10 or codes.count(429) != 1:
                raise AssertionError((name, codes, elapsed))
            state["results"][name] = {"codes": codes, "seconds": elapsed, "send_seconds": state["last_burst_send_seconds"]}
            save()
            return responses

        start()
        state["syntax"] = docker("exec", container, "nginx", "-t")
        check_burst("website_protected", "/.env?token=QUERY_MARKER_ONLY", 403)
        check_burst("api_protected", "/api/.env?token=QUERY_MARKER_ONLY", 403)
        codes, _, _ = burst(["/api/.env"] * 3, spoof=True)
        require(codes == [429] * 3, ("spoofed XFF", codes))
        state["results"]["spoofed_xff_no_bypass"] = codes
        start(True)
        codes, _, _ = burst(["/", "/api/v1/status"], method="POST")
        require(codes == [403, 403], ("forbidden POST", codes))
        state["results"]["forbidden_methods"] = codes
        codes, _, _ = burst(["/", "/api/v1/status"], method="TRACE")
        require(codes == [405, 405], ("nginx core rejects TRACE", codes))
        state["results"]["core_rejects_trace"] = codes
        start(True)
        check_burst("website_allowed", "/", 200)
        check_burst("api_allowed", "/api/v1/status", 200)
        codes, _, _ = burst(["/mcp", "/api/.env", "/api/unknown"])
        require(codes == [429] * 3, ("shared allowed/denied API/MCP bucket", codes))
        state["results"]["mcp_shares_api_bucket"] = codes
        time.sleep(0.25)
        codes, _, _ = burst(["/"])
        require(codes == [200], ("website refill", codes))
        codes, _, _ = burst(["/api/v1/status"])
        require(codes == [429], ("API refill too early", codes))
        time.sleep(6.1)
        codes, _, _ = burst(["/api/v1/status"])
        require(codes == [200], ("API refill", codes))
        state["results"]["independent_refill"] = True
        start(True)
        responses = check_burst("http_redirect", "/public?x=1", 308, False)
        require(any("Location: https://kit.example.test/public?x=1" in response for response in responses), "Fixed redirect host")
        check_burst("http_api_redirect", "/api/v1/status", 308, False)
        start(True)
        check_burst("unknown_host_limited", "/", 421, host="evil.test")
        start(True)
        check_burst("wrong_port_host_limited", "/", 421, host="kit.example.test:9999")
        start(True)
        check_burst("api_wrong_port_host_limited", "/api/v1/status", 421, host="kit.example.test:9999")
        start(True)
        check_burst("api_default_host_limited", "/api/v1/status", 421, host="evil.test")
        start(True)
        paths = ["/", "/.env"] * 5 + ["/"]
        codes, _, _ = burst(paths)
        require(codes.count(429) == 1, ("mixed website bucket", codes))
        require(all(code == 429 or code == (200 if path == "/" else 403) for path, code in zip(paths, codes)), ("mixed website responses", codes))
        state["results"]["mixed_allowed_denied_website"] = codes
        start(True)
        codes, _, _ = burst(["/"], host="evil.test")
        require(codes == [421], ("unknown Host", codes))
        paths = ["/.ENV", "/%2eenv", "//.env", "/a/../.env", "/.env.backup", "/config.yaml", "/credentials", "/dump.sql", "/a/.kube/config"]
        codes, _, _ = burst(paths)
        require(codes == [403] * len(paths), ("credential variants", codes))
        state["results"]["credential_variants"] = codes
        start(True)
        paths = ["/.git/config", "/graphify-out/report.json", "/graphify-output/report.json", "/AGENTS.md", "/AGENTS.override.md", "/.mcp.json", "/mcp.json", "/plans/tasks.md", "/receipts/x.json"]
        codes, _, _ = burst(paths)
        require(codes == [403] * len(paths), ("internal tooling paths", codes))
        state["results"]["internal_tooling_paths"] = codes
        start(True)
        codes, _, _ = burst(["/apiary", "/mcpx"])
        require(codes == [403, 403], ("anchored website paths", codes))
        codes, _, _ = burst(["/api/v1/status"])
        require(codes == [200], ("independent API bucket", codes))
        state["results"]["anchored_classifier"] = True
        start(True)
        codes, _, _ = burst(["/?upstream_csp=1"], additional_csp="script-src 'none'")
        require(codes == [200], ("preserved upstream CSP", codes))
        state["results"]["stricter_upstream_csp_preserved"] = True
        untrusted = ssl._create_unverified_context()
        port = int(state["ports"]["443/tcp"][0]["HostPort"])
        try:
            with untrusted.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="evil.test"):
                raise AssertionError("Unknown SNI was accepted")
        except ssl.SSLError:
            state["results"]["unknown_sni_rejected"] = True
        logs = docker("logs", container)
        require("QUERY_MARKER_ONLY" not in logs, "Query marker leaked into logs")
        state["results"]["query_marker_absent_from_stdout_and_stderr"] = True
        network_info = json.loads(docker("network", "inspect", network))[0]
        peer = str(ipaddress.IPv4Address(network_info["IPAM"]["Config"][0]["Gateway"]))
        state["whitelist_transport_peer"] = peer
        state["whitelist_configs"] = {}

        def use_policy(name, policy):
            policy_file = base / f"{name}.json"
            policy_file.write_text(json.dumps(policy), encoding="utf-8")
            candidate = make_config(policy_file)
            config_file = base / "nginx.conf"
            config_file.chmod(0o644)
            config_file.write_text(candidate, encoding="utf-8")
            config_file.chmod(0o444)
            state["whitelist_configs"][name] = {
                "policy_sha256": hashlib.sha256(policy_file.read_bytes()).hexdigest(),
                "config_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
            }
            start(True)

        use_policy("peer-allowed", {"schema_version": 1, "mode": "peer", "peer_cidrs": [peer + "/32", "::1/128"]})
        codes, _, _ = burst(["/", "/api/v1/status"])
        require(codes == [200, 200], ("allowed transport peer", codes))
        use_policy("peer-denied", {"schema_version": 1, "mode": "peer", "peer_cidrs": ["198.51.100.1/32", "2001:db8::/64"]})
        codes, _, _ = burst(["/"], secure=False)
        require(codes == [403], ("unlisted peer HTTP must not redirect", codes))
        codes, _, _ = burst(["/"], request_headers=[("X-Forwarded-For", "198.51.100.1")])
        require(codes == [403], ("XFF must not satisfy peer whitelist", codes))
        check_burst("whitelist_denials_are_limited", "/api/v1/status", 403)
        client_policy = {"schema_version": 1, "mode": "trusted-client", "peer_cidrs": [peer + "/32"], "client_cidrs": ["198.51.100.0/24", "2001:db8:1::/64"], "header": "CF-Connecting-IP"}
        use_policy("trusted-client", client_policy)
        invalid_headers = [[], [("CF-Connecting-IP", "invalid")], [("CF-Connecting-IP", "198.51.100.10"), ("CF-Connecting-IP", "198.51.100.11")], [("CF-Connecting-IP", "203.0.113.10")], [("CF-Connecting-IP", "2001:db8:2::10")], [("CF-Connecting-IP", "::ffff:203.0.113.10")], [("X-Forwarded-For", "198.51.100.10")]]
        for headers in invalid_headers:
            codes, _, _ = burst(["/"], request_headers=headers)
            require(codes == [403], ("untrusted client metadata", headers, codes))
        for address in ("198.51.100.10", "2001:db8:1::10"):
            codes, _, _ = burst(["/"], request_headers=[("CF-Connecting-IP", address)])
            require(codes == [200], ("trusted allowed client", address, codes))
        codes, _, _ = burst(["/public"], secure=False, request_headers=[("CF-Connecting-IP", "198.51.100.10")])
        require(codes == [308], ("trusted client HTTP redirect", codes))
        use_policy("untrusted-forwarder", {**client_policy, "peer_cidrs": ["203.0.113.254/32"]})
        codes, _, _ = burst(["/"], request_headers=[("CF-Connecting-IP", "198.51.100.10")])
        require(codes == [403], ("nonpeer cannot supply trusted client", codes))
        use_policy("x-real-ip", {**client_policy, "header": "X-Real-IP"})
        codes, _, _ = burst(["/"], request_headers=[("X-Real-IP", "198.51.100.10")])
        require(codes == [200], ("explicit X-Real-IP mode", codes))
        codes, _, _ = burst(["/"], request_headers=[("CF-Connecting-IP", "198.51.100.10")])
        require(codes == [403], ("unselected header is not trusted", codes))
        state["results"]["peer_and_trusted_client_whitelists"] = True
        state["results"]["ipv6_client_header_policy"] = True
        state["peer_ipv6_transport_runtime"] = "not exercised by loopback IPv4 publisher"
        current_hashes = {str(path.relative_to(here.parent)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
        require(current_hashes == source_hashes, "Source changed during verification")
        state["source_unchanged"] = True
        state["result"] = "passed"
    finally:
        cleanup_resources(state, save)
    if state["cleanup_pending"]:
        raise RuntimeError(f"Test resources require reconciliation; inspect {report}")
    print(f"Passed. Report saved to {report}")


if __name__ == "__main__":
    main()
