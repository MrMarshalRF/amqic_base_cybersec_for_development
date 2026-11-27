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

## Model APIs and interaction capture

Maintain `model-api` as a private, provider-neutral destination class for inference endpoints and gateways. Entitlement belongs to a specific server workload, owner, scope and review/expiry date. An allowed or denied attempt by an unentitled server is a review signal; an entitled workload or approved package mirror is a near match. This server rule does not classify developer workstations or rank providers or countries.

Maintain `interaction-capture` values privately with provenance and expiry. A classified server DNS lookup or connection deserves review; a workstation lookup or an unusual-looking ordinary service subdomain is not enough. Correlate relevant preceding inbound activity using protected linkage references. A classified match does not prove injection or attribution. The [behavior reference](AGENTIC-ATTACK-DETECTION.md) supplies synthetic match/near-match pairs; resolver/proxy collection and classification remain operator integrations.

Record both families through existing `egress` / `egress-decision` / `egress-unapproved` fields. Destination classes and exact indicators stay in the restricted source case. No provider hostname list, resolver sensor or live egress test is shipped.

## Callback and channel review

Follow [command-and-control monitoring](COMMAND-AND-CONTROL-MONITORING.md) for
periodic callback, unusual long-lived session and DNS/web-channel review. Combine
trusted workload lineage and destination authorization with a deployment
baseline. Ordinary TLS, long sessions, random-looking DNS names or regular
health checks alone do not identify a covert channel. Unapproved model use plus
scan-like workstation egress is a review lead, not an extension of the existing
server-only model-API rule or attribution to a product.

Protect collector completeness, clock/key epochs and private session linkage.
Keep actual destinations and any packet/DNS details out of public exports.
Registered maintenance/testing requires externally approved exact scope and
expiry; it does not grant a blanket egress exception. These are manual
correlation procedures, not new evaluator kinds, packet parsers or installed
resolver rules.

## Callback denial and isolated decoys

Default-deny workload egress and reviewed URL-fetch boundaries can prevent an
unnecessary callback, as discussed in the [countermeasure guide](AGENTIC-OFFENSE-DEGRADATION.md).
Confirm resolver routing, proxies, protocol families and the actual enforcing
point. A required resolver or proxy is not permission for arbitrary destinations.
An absent callback is not proof that an injection or execution flaw is fixed;
preserve the root-cause review and legitimate permitted-service checks.

Inert decoys must not initiate callbacks, fetch untrusted destinations or grant
real credentials/data. Keep production services, caches and authenticated flows
outside their response-variation experiments. Correlation with managed-workstation
evidence requires independent collector/owner context; approved inference use
alone cannot justify blocking a workstation. No resolver rule or new egress
enforcement is activated by these procedures.

## Inventory workers, controllers and local models

The [external reconnaissance guide](EXTERNAL-RECON-DEGRADATION.md#govern-your-own-inventory-tooling) covers approved scanner/controller enrollment, inventory-report destinations and unexpected internal breadth or tunnels. Local analysis still needs worker identities, restricted logging and effective egress controls. Use [LLM resilience](LLM-JAILBREAK-RESILIENCE.md) for model-input/output and capability boundaries; a locally hosted model is not evidence that no data can leave.
