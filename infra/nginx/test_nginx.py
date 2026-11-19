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
import threading
import time
import uuid

from render import load_paths, render

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


def nginx_build(version_output):
    """Record observed binary version/modules; no inference of vulnerability clearance."""
    match = re.search(r"nginx version: nginx/(\d+\.\d+\.\d+)", version_output)
    require(match is not None, "Cannot parse observed nginx -V version")
    return {"version": match.group(1), "nginx_V": version_output,
            "http_v2_module": "--with-http_v2_module" in version_output.split(),
            "http_v3_module": "--with-http_v3_module" in version_output.split()}


def protocol_config(config):
    active = "\n".join(line.split("#", 1)[0] for line in config.splitlines())
    require(re.findall(r"\bhttp2\s+([^;]+);", active) == ["off"], "HTTP/2 must be explicitly off")
    listeners = re.findall(r"\blisten\s+([^;]+);", active)
    require(listeners and all(not ({"quic", "udp", "http2"} & set(line.split()))
                              for line in listeners), "Unexpected HTTP/2 or QUIC/UDP listener")
    require(not re.search(r"\bhttp3\s+on\s*;", active), "HTTP/3 enabled")
    require(not re.search(r"\badd_header\s+Alt-Svc\b", active, re.I), "Alt-Svc configured")
    require(re.search(r"\bproxy_hide_header\s+Alt-Svc\s*;", active, re.I), "Upstream Alt-Svc not suppressed")
    return {"http2": "off", "quic_udp_listeners": False, "alt_svc": "suppressed"}


def confirm_h2_alert(port, ca_file):
    """Independent, bounded CLI evidence for one opaque Python/OpenSSL alert only."""
    require(type(port) is int and 1 <= port <= 65535, "Invalid synthetic TLS port")
    executable = shutil.which("openssl")
    require(executable is not None, "OpenSSL confirmation unavailable")
    command = [executable, "s_client", "-connect", f"127.0.0.1:{port}",
               "-servername", "kit.example.test", "-verify_hostname", "kit.example.test",
               "-CAfile", str(ca_file), "-verify_return_error", "-alpn", "h2"]
    # Read at most 64 KiB + one overflow byte, without logging certificates/output.
    output = []
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, shell=False)
    def read_output():
        try:
            output.append(child.stdout.read(65537))
            if len(output[0]) > 65536 and child.poll() is None:
                child.kill()
        except OSError:
            output.append(None)
    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        code = child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        reader.join(timeout=1)
        if not reader.is_alive():
            child.stdout.close()
    require(not reader.is_alive() and len(output) == 1 and output[0] is not None,
            "OpenSSL confirmation output unavailable")
    raw = output[0]
    require(len(raw) <= 65536, "OpenSSL confirmation output exceeded limit")
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
    require(code == 1, "OpenSSL confirmation did not reject h2")
    for marker in (r"^Verification: OK$", r"^Verify return code: 0 \(ok\)$", r"^No ALPN negotiated$"):
        require(re.search(marker, text, re.M), "OpenSSL confirmation lacks expected diagnostic status/ALPN markers")
    lines = [line.strip() for line in text.splitlines()]
    statuses = [line for line in lines if re.match(r"^Verification\b", line, re.I)]
    codes = [line for line in lines if re.match(r"^Verify\s+return\s+code\b", line, re.I)]
    require(statuses == ["Verification: OK"] and codes == ["Verify return code: 0 (ok)"],
            "OpenSSL confirmation contains duplicate, conflicting or unknown verification status")
    alert = r"^[^\r\n]*:error:0A000460:SSL routines:ssl3_read_bytes:(?:reason\(1120\)|tlsv1 alert no application protocol):[^\r\n]*:SSL alert number 120$"
    require(re.search(alert, text, re.M), "OpenSSL confirmation lacks explicit fatal ALPN alert 120")
    require(not re.search(r"ALPN protocol:|verify error:|Verification error:|connect:errno=|Connection refused|SSL alert number (?!120\b)|:error:(?!0A000460:)", text),
            "OpenSSL confirmation contains conflicting failure or protocol")
    return {"method": "openssl_s_client", "alert_number": 120, "selected": None,
            # A fatal pre-certificate alert cannot itself authenticate the peer.
            # Verified Python HTTP/1.1 controls before/after own that evidence.
            "verification_status": "ok", "exit_code": code,
            "output_sha256": hashlib.sha256(raw).hexdigest(), "output_bytes": len(raw)}


def probe_alpn(connect, offered, expected, confirm_opaque=None):
    """Benign TLS negotiation only: never send HTTP/2 frames or stress inputs."""
    try:
        with connect(offered) as connection:
            selected = connection.selected_alpn_protocol()
            require(selected == expected, ("Unexpected ALPN protocol", offered, selected))
            return {"offered": offered, "selected": selected, "handshake": "accepted"}
    except ssl.SSLError as error:
        # A strict server may refuse an h2-only offer instead of negotiating no ALPN.
        reason = getattr(error, "reason", None)
        # Some Windows OpenSSL builds expose this exact alert under generic SSL.
        generic_alert = (reason in (None, "SSL") and error.errno == ssl.SSL_ERROR_SSL
                         and re.fullmatch(r"\[SSL\] tlsv1 alert no application protocol \(_ssl\.c:\d+\)", str(error)) is not None)
        if offered == ["h2"] and expected is None and (reason == "TLSV1_ALERT_NO_APPLICATION_PROTOCOL" or generic_alert):
            return {"offered": offered, "selected": None, "handshake": "no_application_protocol"}
        opaque = (offered == ["h2"] and expected is None and error.errno == ssl.SSL_ERROR_SSL
                  and getattr(error, "library", None) == "SSL" and reason in (None, "SSL")
                  and re.fullmatch(r"\[SSL\] unknown error \(_ssl\.c:\d+\)", str(error)) is not None)
        if opaque and confirm_opaque is not None:
            proof = confirm_opaque()
            require(isinstance(proof, dict) and proof.get("method") == "openssl_s_client"
                    and proof.get("alert_number") == 120 and "selected" in proof and proof["selected"] is None
                    and proof.get("verification_status") == "ok" and proof.get("exit_code") == 1,
                    "Opaque Python TLS error lacks independent confirmation")
            return {"offered": offered, "selected": None, "handshake": "independently_confirmed_alert_120",
                    "python_observation": "opaque_ssl_unknown_error", "independent_confirmation": proof}
        raise


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


def add_static_bypass_fixture(config):
    """Synthetic permissive static owner: never added to the portable template."""
    marker = "        # These exact public routes are examples. Review each new route explicitly."
    require(config.count(marker) == 1, "Synthetic static fixture insertion point changed")
    fixture = """        # Lab-only owner deliberately permits every asset, including map files.
        location ^~ /assets/admin/ {
            limit_req zone=website_per_ip burst=9 nodelay;
            proxy_pass http://127.0.0.1:18080;
        }
"""
    return config.replace(marker, fixture + marker)


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
        # The public proxy must suppress even an upstream HTTP/3 advertisement.
        add_header Alt-Svc 'h3=":443"; ma=60' always;
        location / { return 200 "synthetic upstream"; }
    }
}
'''
    def make_config(policy=None):
        result = render("kit.example.test", "192.168.240.2:8080", here.parent / "protected-paths.json", here / "nginx.conf.template", policy)
        result = result.replace("192.168.240.2:8080", "127.0.0.1:18080")
        return add_static_bypass_fixture(result).rsplit("}", 1)[0] + upstream_fixture

    # Check the portable render before adding the deliberately advertising upstream.
    protocol_policy = protocol_config(render("kit.example.test", "192.168.240.2:8080",
                                            here.parent / "protected-paths.json", here / "nginx.conf.template"))
    config = make_config()
    (base / "nginx.conf").write_text(config, encoding="utf-8")
    (base / "nginx.conf").chmod(0o444)
    state = {
        "purpose": "synthetic nginx regression only", "image": args.image,
        "owner": "this test invocation", "cleanup_owner": "this test invocation",
        "intent": "create and remove one isolated test bridge and loopback-only nginx container",
        "source_sha256": source_hashes,
        "rendered_config_sha256": hashlib.sha256(config.encode("utf-8")).hexdigest(),
        "protocol_policy": protocol_policy,
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

        def connect(secure, timeout=5, alpn=None):
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
                tls_context = context
                if alpn is not None:
                    tls_context = ssl.create_default_context(cafile=str(base / "fullchain.pem"))
                    tls_context.set_alpn_protocols(alpn)
                return tls_context.wrap_socket(connection, server_hostname="kit.example.test")
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

        def burst(paths, secure=True, host="kit.example.test", spoof=False, method="GET", additional_csp=None, request_headers=(), alpn=None):
            connections = []
            try:
                for _ in paths:
                    connection = connect(secure, alpn=alpn)
                    connections.append(connection)
                    if alpn is not None:
                        require(connection.selected_alpn_protocol() == "http/1.1", "HTTP/1.1 ALPN positive control")
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
                    if alpn is not None:
                        require(response.startswith("HTTP/1.1 "), "Unexpected ALPN HTTP response version")
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
                    require("alt-svc" not in headers, "Unexpected Alt-Svc advertisement")
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
        state["nginx_build"] = nginx_build(docker("exec", container, "nginx", "-V"))
        state["syntax"] = docker("exec", container, "nginx", "-t")
        state["results"]["alpn_h2_and_http11"] = probe_alpn(
            lambda offered: connect(True, alpn=offered), ["h2", "http/1.1"], "http/1.1")
        codes, _, _ = burst(["/"], alpn=["h2", "http/1.1"])
        require(codes == [200], ("HTTP/1.1 ALPN allowed root", codes))
        state["results"]["alpn_http11_root_200_with_security_headers"] = True
        state["results"]["alpn_h2_only"] = probe_alpn(
            lambda offered: connect(True, alpn=offered), ["h2"], None,
            confirm_opaque=lambda: confirm_h2_alert(mapped_port(state["ports"], True), base / "fullchain.pem"))
        # Recheck the same live process after the refused offer; no restart can mask failure.
        codes, _, _ = burst(["/"], alpn=["http/1.1"])
        require(codes == [200], ("HTTP/1.1 root after h2 refusal", codes))
        state["results"]["http11_root_after_h2_refusal_200_with_security_headers"] = True
        require(set(state["ports"]) <= {"80/tcp", "443/tcp"}, "Unexpected non-TCP publisher")
        state["results"]["http3_disabled"] = {
            "tcp_only_published_ports": True,
            "quic_listener_configured": False,
            "module_available": state["nginx_build"]["http_v3_module"],
            "udp_handshake": "not_run; no UDP/QUIC listener is configured",
        }
        save()
        start(True)
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
        # All configured literals must return a real denial, never a rate-limit false positive.
        start(True)
        codes, _, _ = burst(["/", "/api/v1/status"])
        require(codes == [200, 200], ("registry positive controls", codes))
        start(True)
        registry_codes = {}
        for path in load_paths(here.parent / "protected-paths.json"):
            # Website requests stay below 10r/s. API/MCP paths get fresh state,
            # since their independent bucket replenishes at only 10r/m.
            if re.match(r"^/(?:api|mcp)(?:/|$)", path, re.I):
                start(True)
            codes, _, _ = burst([path])
            require(codes == [403], ("registry literal denied", path, codes))
            registry_codes[path] = codes[0]
            time.sleep(0.13)
        state["results"]["all_registry_paths_denied"] = registry_codes
        start(True)
        encoded_paths = ["/app/api/%5B...%5D/route.ts", "/app/api/ordinary/route.ts",
                         "/app/api/%255B...%255D/route.ts"]
        codes, _, _ = burst(encoded_paths)
        require(codes == [403] * len(encoded_paths), ("encoded source deny-by-default", codes))
        state["results"]["noncanonical_source_paths_denied"] = dict(zip(encoded_paths, codes))
        # A ^~ owner defeats regex locations; the existing server-level guard must
        # deny maps before selection while ordinary compiled assets still reach upstream.
        start(True)
        assets = ["/assets/admin/app.js", "/assets/admin/app.css",
                  "/assets/admin/nested/app.js", "/assets/admin/nested/app.css",
                  "/assets/admin/app.map-public", "/assets/admin/app.js.mapx",
                  "/assets/admin/app.js?debug=app.js.map"]
        codes, _, _ = burst(assets)
        require(codes == [200] * len(assets), ("legitimate static fixture assets", codes))
        state["results"]["prefixed_static_public_assets"] = dict(zip(assets, codes))
        start(True)
        maps = ["/assets/admin/app.js.map", "/assets/admin/nested/app.css.map",
                "/assets/admin/APP.JS.MAP", "//assets//admin//nested//app.js.map",
                "/assets/admin/app.js.map?download=1", "/assets/admin/app.js%2emap",
                "/assets/admin/app.js%252emap", "/assets/admin/app.js.map;download"]
        codes, _, _ = burst(maps)
        require(codes == [403] * len(maps), ("server guard before prefixed static owner", codes))
        state["results"]["prefixed_static_source_maps_denied"] = dict(zip(maps, codes))
        start(True)
        technical = ["//GOOGLE-SERVICES.JSON", "/%63redentials.js",
                     "/google-service-account.json?download=1"]
        codes, _, _ = burst(technical)
        require(codes == [403] * len(technical), ("technical normalized variants", codes))
        state["results"]["technical_normalized_variants"] = dict(zip(technical, codes))
        start(True)
        traversal = ["/api/w/admins/jobs_u/get_log_file/../../../../proc/self/environ",
                     "/api/proc/self/environ",
                     "/api/w/admins/jobs_u/get_log_file/%2e%2e/%2e%2e/%2e%2e/%2e%2e/proc/self/environ",
                     "/api/w/admins/jobs_u/get_log_file/%252e%252e/%252e%252e/%252e%252e/%252e%252e/proc/self/environ"]
        codes, _, _ = burst(traversal)
        require(codes == [403] * len(traversal), ("raw and normalized traversal denial", codes))
        state["results"]["raw_and_normalized_traversal_denied"] = dict(zip(traversal, codes))
        start(True)
        unchanged = ["/api/v1/status", "/api/v1/admin/content", "/.well-known/security.txt"]
        codes, _, _ = burst(unchanged)
        require(codes == [200, 403, 403], ("unchanged public and default-deny routes", codes))
        state["results"]["unchanged_route_policy"] = dict(zip(unchanged, codes))
        save()
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
