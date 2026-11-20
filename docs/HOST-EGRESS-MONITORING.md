# Host and container egress monitoring

Use this source-reviewed procedure to review connections initiated by a host or service container. The [application outbound catalog](../enterprise/outbound/README.md) restricts application callers to server-selected endpoint IDs. It is not host egress enforcement: an unexpected process can initiate a connection without using that catalog. This guide does not extend the catalog's narrow IPv4 transport profile or duplicate its DNS and address-pinning implementation.

## Establish the boundary

Start with default-deny egress at the host or container network boundary. Assign an owner to the workload's approved destination classes, such as required package, identity and backup services. Keep the exact destinations, purpose, owner and review date in restricted deployment configuration; open only the required protocols and destinations through reviewed changes. An approved class is not permission to reach every service in that class.

Follow the [infrastructure isolation guidance](INFRASTRUCTURE.md) and use [firewall candidates](../infra/firewall/) only as a packet-filter starting point. The Java [NetworkPolicy example](../enterprise/runtime/helm/templates/networkpolicy.yaml) starts with an empty egress list. Do not add a second shared network merely to obtain Internet access. If a controlled egress proxy is required, restrict both access to the proxy and the destinations it can reach. Define and verify separate target policies for IPv6, proxies and encapsulated tunnels; an IPv4 rule alone does not cover them.

Before activation, the deployment owner must verify the actual routing and enforcement point, required permitted traffic, denied traffic, log delivery and recovery access in the authorized target environment. A generated candidate or an internal container network alone does not establish effective filtering.

## Review decisions

Configure the enforcement point to record denied or unapproved outbound attempts. Retain decision metadata only: time, an opaque workload or asset reference, protocol class such as DNS or HTTPS, destination class or a protected destination hash, and decision (`deny` or `allow`). Treat hashes as correlatable operational data with restricted access and retention. Exclude raw URLs, query strings, tokens, headers and request or response bodies.

For example, a private decision record can describe a documentation timestamp, opaque asset reference, `HTTPS`, `unapproved-external` and `deny`; it needs no hostname or address. Export only the closed [SIEM fields](../enterprise/operations/README.md): category `egress`, action `egress-decision`, signal class `egress-unapproved`, outcome and opaque correlation/case references. Protocol and destination details stay in the restricted source record linked by the case; do not invent extra schema fields. The optional technique mapping is `T1567.004`.

Treat unexpected server-originated connections to webhook-style or public interaction-capture destinations as a high-severity review class. Keep dated class indicators with mandatory expiry in the [operator-private indicator store](INDICATOR-HANDLING.md); do not commit vendor hostnames, addresses or indicator hashes. A match is a lead, not attribution or an automatic ban.

Correlate the decision with a service-account child-shell signal from the [runtime starting profiles](../enterprise/runtime/) and the [multi-source campaign playbook](AUTOMATED-PROBING-DEFENSE.md#multi-source-and-delayed-campaigns). Record the evidence and disposition in the case, optionally using `campaign-note`. A denial shows an attempted connection was denied at the observed point; it does not establish compromise or exclude another route.

## Limits

The allowlist depends on current operator approvals. This guide installs no NSM sensor, DNS firewall or egress collector and establishes no measured detection rate. No packet-capture lab or live egress enforcement is supplied by this increment. The SIEM exporter records operator-authored evidence; it does not collect connection events or detect campaigns.
