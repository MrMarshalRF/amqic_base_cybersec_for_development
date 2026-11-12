"""Strict CIDR input shared by firewall and nginx renderers."""
import ipaddress
import json
from pathlib import Path


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate policy field")
        result[key] = value
    return result


def read_policy(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_fields)
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("Expected policy schema_version 1")
    return data


def parse_cidrs(values, label):
    if not isinstance(values, list) or not 1 <= len(values) <= 128:
        raise ValueError(f"{label} must contain 1..128 explicit CIDRs")
    networks = []
    mapped = ipaddress.ip_network("::ffff:0:0/96")
    for value in values:
        if not isinstance(value, str) or value != value.strip() or "/" not in value or "%" in value:
            raise ValueError(f"{label} requires canonical CIDR values")
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen == 0 or network.is_multicast:
            raise ValueError(f"{label} forbids all-address and multicast networks")
        if network.version == 6 and network.overlaps(mapped):
            raise ValueError(f"{label} requires separate IPv4 and IPv6 CIDRs without mapped aliases")
        if network in networks:
            raise ValueError(f"{label} contains duplicate networks")
        networks.append(network)
    # Collapse overlap within each family while preserving the exact permitted union.
    collapsed = [network for version in (4, 6) for network in ipaddress.collapse_addresses(
        item for item in networks if item.version == version
    )]
    if any(network.prefixlen == 0 for network in collapsed):
        raise ValueError(f"{label} may not collectively allow the entire address family")
    return collapsed


def require_disjoint(first, second):
    if any(a.version == b.version and a.overlaps(b) for a in first for b in second):
        raise ValueError("Trusted peers and allowed clients must have disjoint address ranges")
