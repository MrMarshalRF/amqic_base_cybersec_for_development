#!/usr/bin/env python3
"""Render an ingress-only nftables candidate. Does not execute firewall commands."""
import argparse
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firewall.addresses import parse_cidrs, read_policy


def render(policy_path):
    data = read_policy(policy_path)
    if set(data) != {"schema_version", "ssh_port", "admin_cidrs", "proxy_cidrs"}:
        raise ValueError("Firewall policy requires exactly ssh_port, admin_cidrs and proxy_cidrs")
    port = data["ssh_port"]
    if type(port) is not int or not 1 <= port <= 65535 or port in {80, 443}:
        raise ValueError("ssh_port must be a distinct TCP port in 1..65535")
    administrators = parse_cidrs(data["admin_cidrs"], "admin_cidrs")
    proxies = parse_cidrs(data["proxy_cidrs"], "proxy_cidrs")
    sets = []
    for name, version, networks in (("admin_v4", 4, administrators), ("admin_v6", 6, administrators),
                                    ("proxy_v4", 4, proxies), ("proxy_v6", 6, proxies)):
        addresses = ", ".join(str(network) for network in networks if network.version == version)
        body = f"    set {name} {{\n        type ipv{version}_addr\n        flags interval\n"
        if addresses:
            body += f"        elements = {{ {addresses} }}\n"
        sets.append(body + "    }")
    template = Path(__file__).with_name("nftables.conf.template").read_text(encoding="utf-8")
    if template.count("@@SETS@@") != 1 or template.count("@@SSH_PORT@@") != 2:
        raise ValueError("Invalid firewall template")
    digest = hashlib.sha256(Path(policy_path).read_bytes()).hexdigest()
    return ("# Policy SHA-256 " + digest + "\n" + template.replace("@@SETS@@", "\n".join(sets))
            .replace("@@SSH_PORT@@", str(port)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rendered = render(args.policy)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        output.write(rendered)


if __name__ == "__main__":
    main()
