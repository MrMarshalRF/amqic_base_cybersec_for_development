#!/usr/bin/env python3
"""Render an explicit-host, deny-by-default nginx configuration. No activation."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firewall.addresses import parse_cidrs, read_policy, require_disjoint


def load_paths(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or set(data) != {"schema_version", "paths"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1):
        raise ValueError("Unsupported registry schema")
    paths = data["paths"]
    if not isinstance(paths, list) or not paths or len(paths) > 256:
        raise ValueError("Registry must contain 1..256 paths")
    for value in paths:
        if not isinstance(value, str) or not re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", value):
            raise ValueError("Registry paths must be canonical ASCII absolute URI paths")
        if any(part in {".", ".."} for part in value.split("/")):
            raise ValueError("Dot traversal is forbidden")
    if len({value.lower() for value in paths}) != len(paths):
        raise ValueError("Duplicate registry path")
    return sorted(paths, key=str.lower)


def validate_host(host):
    if host != host.lower() or len(host) > 253 or "." not in host:
        raise ValueError("Use a lowercase fully qualified DNS hostname")
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("Invalid DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("IP addresses are forbidden as the canonical host")


def validate_upstream(value):
    address, separator, port = value.partition(":")
    if not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Use an RFC1918 IPv4 address and port")
    ip = ipaddress.IPv4Address(address)
    private_ranges = [ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(ip in network for network in private_ranges):
        raise ValueError("Upstream must be an RFC1918 private IPv4 address")
    return f"{ip}:{int(port)}"


def render_allowlist(path):
    if path is None:
        return "    # Public route policy, no ingress whitelist configured.\n    geo $remote_addr $ingress_allowed { default 1; }"
    data = read_policy(path)
    mode = data.get("mode")
    required = {"schema_version", "mode", "peer_cidrs"}
    if mode == "trusted-client":
        required |= {"client_cidrs", "header"}
    if not isinstance(mode, str) or mode not in {"peer", "trusted-client"} or set(data) != required:
        raise ValueError("Invalid ingress whitelist mode or fields")
    peers = parse_cidrs(data["peer_cidrs"], "peer_cidrs")

    def geo(variable, name, networks):
        entries = "\n".join(f"        {network} 1;" for network in networks)
        return f"    geo {variable} ${name} {{\n        default 0;\n{entries}\n    }}"

    if mode == "peer":
        return geo("$remote_addr", "ingress_allowed", peers)
    headers = {"CF-Connecting-IP": "$http_cf_connecting_ip", "X-Real-IP": "$http_x_real_ip"}
    if not isinstance(data["header"], str) or data["header"] not in headers:
        raise ValueError("Trusted client mode supports only CF-Connecting-IP or X-Real-IP")
    clients = parse_cidrs(data["client_cidrs"], "client_cidrs")
    require_disjoint(peers, clients)
    trusted = "\n".join(f"    set_real_ip_from {network};" for network in peers)
    return "\n".join([
        trusted, f"    real_ip_header {data['header']};", "    real_ip_recursive off;",
        geo("$realip_remote_addr", "ingress_peer_allowed", peers),
        geo("$remote_addr", "ingress_client_allowed", clients),
        f"    map {headers[data['header']]} $ingress_header_valid {{",
        "        default 0;", '        "~^[0-9A-Fa-f:.]+$" 1;', "    }",
        '    map "$ingress_peer_allowed:$ingress_client_allowed:$ingress_header_valid" $ingress_allowed {',
        "        default 0;", '        "1:1:1" 1;', "    }",
    ])


def render(host, upstream, registry, template, allowlist=None):
    paths = load_paths(registry)
    host = validate_host(host)
    upstream = validate_upstream(upstream)
    rules = "\n".join('        "~*^' + re.escape(path) + '(?:$|/|[.;~])" 1;' for path in paths)
    source = Path(template).read_text(encoding="utf-8")
    if source.count("@@HOST@@") == 0 or source.count("@@PROTECTED_RULES@@") != 1 or source.count("@@INGRESS_POLICY@@") != 1:
        raise ValueError("Invalid template markers")
    digest = hashlib.sha256(Path(registry).read_bytes()).hexdigest()
    return ("# Registry SHA-256 " + digest + "\n" + source.replace("@@HOST@@", host)
            .replace("@@PROTECTED_RULES@@", rules).replace("@@UPSTREAM@@", upstream)
            .replace("@@INGRESS_POLICY@@", render_allowlist(allowlist)))


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--upstream", required=True, help="Explicit private IPv4:port of the internal app")
    parser.add_argument("--registry", type=Path, default=here.parent / "protected-paths.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, help="Explicit peer or trusted-client ingress policy JSON")
    args = parser.parse_args()
    result = render(args.host, args.upstream, args.registry, here / "nginx.conf.template", args.allowlist)
    # Exclusive creation preserves the currently accepted configuration on errors.
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(result)


if __name__ == "__main__":
    main()
