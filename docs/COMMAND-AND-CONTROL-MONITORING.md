# Command-and-control behavior monitoring

## TL;DR

Review unexpected outbound behavior using trusted network decisions, resolver/proxy metadata and process context. Correlate independent evidence within a private workload baseline. Periodicity, encryption, a long connection or high DNS entropy alone is insufficient to establish command and control. Missing evidence leaves coverage **unverified**.

## Where it helps

This guide helps an operator investigate possible callback or channel behavior on authorized hosts and service workloads, alongside [host egress controls](HOST-EGRESS-MONITORING.md) and [campaign review](AUTOMATED-PROBING-DEFENSE.md#multi-source-and-delayed-campaigns). It adds operations guidance only: no packet parser, DNS sensor, endpoint collector, executable C2 detector or automatic response is supplied. The existing [offline evaluator](../enterprise/detection/README.md) retains its eight families and does not implement the new review patterns below.

## Establish the observable boundary

Privately inventory workload/asset/account owners, measured process identities, expected parent/child relationships, permitted destination and protocol classes, resolver/proxy paths, long-lived integrations, normal schedules and observed connection lifetimes. An allowed destination class does not authorize all destinations within it. Record deployment role, policy revision, review owner and expiry. Keep exact destinations and engagement details in the [private indicator lifecycle](INDICATOR-HANDLING.md).

Use the actual enforcement point and expected routes, including IPv6, proxies, VPN paths and encapsulation. Verify source completeness and distinguish allowed, denied and merely observed traffic. A denied attempt establishes only denial at that point; it does not prove a successful session or exclude another route. This guide is not an installation recommendation, interception/decryption procedure, offensive channel recipe or permission to probe another system.

## Inventory private evidence

| Source | Private fields needed for review |
| --- | --- |
| Host/network enforcement and flow metadata | Authenticated collector, source record/sequence, event and receipt times, asset/account/workload binding, protocol/destination class, outcome, start/end/duration, bytes/count summaries, routing/enforcement point and policy revision where supported. |
| Resolver | Resolver and client bindings, source event/time, protected destination linkage, request/result class, counts and reviewed length/entropy summaries where supported. Keep raw query names private and minimize their retention. A resolver record alone rarely identifies the initiating process. |
| Proxy or TLS metadata | Proxy/session linkage, approved service class, connection timing, supported handshake/validation metadata and visibility limitations. Keep URLs, names, headers, tokens and content out of exports. TLS metadata does not reveal encrypted application intent. |
| Endpoint/process and integrity | Measured executable identity, process start identity, bounded lineage, workload/account, event time, approved service/rollout reference and independently observed persistence or file-change class. Names or reused PIDs alone are insufficient. |
| Inbound and identity audit | Opaque source/asset/account bindings, authenticated outcome, event time and private case linkage for a preceding probe or identity event. Preserve attempt versus successful effect. |

Authenticate collectors, protect transport/storage and confirm source identities outside agent/client control. Define clock trust, maximum skew, ingestion delay, dropped-event accounting, retention, deduplication and review ownership. Treat missing fields, disabled collection and opaque proxy/NAT linkage as gaps. Do not classify a destination or trust a lineage supplied by a request, model output or the monitored workload itself.

Choose a bounded half-open review window `[since, until)` and event/capacity limits from the same workload role, schedule and time-of-week baseline. Record the source snapshot and policy revision. Order by verified event time with known uncertainty, not arrival order. Correlate only the same authoritative asset/account/workload and compatible protected linkage epoch. A proxy address is not proof of a shared endpoint; ambiguous NAT, shared resolvers, remapping or cross-tenant references cannot establish a campaign. Late events require reconciliation; a full buffer is a reported gap, never silent truncation.

## Review patterns

1. **Repeated unexpected callbacks.** Compare repeat connections with normal scheduled agents, monitoring and update jobs. Review a departure in timing together with an unapproved destination relationship and independently verified unexpected process/lineage. Regularity alone is insufficient; irregular timing does not exclude abuse.
2. **Unexpected persistent session.** Review connection lifetime or bidirectional activity outside the workload baseline together with an unapproved destination/process relationship or a related integrity change. Distinguish an open session from completed commands or data transfer. Approved streaming, remote administration and messaging can remain connected for long periods.
3. **Resolver or web-channel anomaly.** Review unusual DNS size/entropy/rate or web-session behavior only with independent unexpected workload/destination linkage and supporting process or policy evidence. CDNs, telemetry, encrypted DNS and ordinary application identifiers can resemble these patterns. Encryption and DNS appearance do not identify channel purpose; visibility through a proxy, cache or encrypted resolver may be incomplete. No claim of added encryption or tunnel detection follows from ordinary HTTPS/TLS.
4. **Post-probe outbound sequence.** Review a preceding inbound attempt followed by unexpected outbound behavior and independently observed internal discovery or persistence in one approved window. Require exact trusted asset/account linkage and temporal order for each step. Relate to existing campaign evidence without asserting successful exploitation, an implant or causation. An inbound source matching an outbound destination requires a shared protected source/destination mapping; a mere similar timestamp is insufficient.

## Review examples only

These inert scenarios describe expected **human triage**, not executable fixtures, parser behavior or evaluator findings. Times are documentation examples on `2026-11-20`; `a01/u01` and `e01` are opaque private linkage/evidence labels with no real endpoint. Each row assumes authenticated source and clock evidence; missing trust makes the result **unverified**. No traffic is generated.

| Pattern | Match: expected human triage | Near match A | Near match B |
| --- | --- | --- | --- |
| Repeated callbacks | `a01/u01`, `e01` from `00:01Z` to `00:09Z`: repeated unapproved destination relationship plus verified unexpected child process. Investigate owner and process. | `a01/u01`, `e02` in the same window: approved scheduled monitor with matching scope/source/time. Record expected activity. | `a01/u01`, `e03` in the same window: regular connections with no verified destination or process context. Insufficient for this pattern; resolve the context gap. |
| Persistent session | `a02/u02`, `e04` from `00:02Z` to `00:12Z`: lifetime outside its reviewed baseline plus unapproved process/destination linkage. Verify session and related changes. | `a02/u02`, `e05` in the same window: approved streaming or administration session within exact current scope. Record explanation. | `a02/u02`, `e06` at `00:02Z`: denied attempt with no established session. Review the attempt; do not claim persistent connectivity. |
| Resolver/web anomaly | `a03/u03`, `e07` at `00:04Z`: baseline DNS deviation; `e08` at `00:05Z`: independently linked unapproved egress/process. Investigate without inferring content. | `a03/u03`, `e09` at `00:04Z`: approved telemetry/CDN identifiers with expected workload and destination. Record explanation. | `a03/u03`, `e10` at `00:04Z`: encrypted web session or high entropy alone. No C2 conclusion; resolve any independent policy deviation separately. |
| Post-probe sequence | `a04/u04`, `e11` at `00:01Z`: inbound attempt; `e12` at `00:03Z`: unexpected outbound; `e13` at `00:06Z`: linked discovery/persistence evidence. Create a campaign review, keeping effects unconfirmed. | `a04/u04`, `e14` through `e16` in the same window: current owner-registered engagement explains exactly those actions/assets/accounts. Retain evidence and scoped disposition. | `a05/u05`, `e17` at `00:03Z`: outbound on an unrelated asset/account, or outbound predates `e11`. Do not form the proposed ordered sequence. |

## Exceptions and response

An independent owner records approved integrations, maintenance and authorized exercises privately: purpose/contact, exact asset/account/workload/source and destination/action scope, reviewer, `approvedAt`, `expiresAt` and change reference. Require event time in `[approvedAt, expiresAt)` and a still-current approval at review. A workload cannot grant itself an exception. Claimed testing headers, stale registrations and partially matching scope do not suppress review. Preserve findings outside the approval and independent integrity changes; a blanket engagement exclusion is inappropriate.

Confirm the evidence with workload and network owners, preserve the restricted original snapshot and timeline, and assess whether the observed activity completed an effect. Apply separately authorized scoped host/network containment while retaining legitimate recovery access. If identity compromise is supported, use the authorized issuer workflow to revoke/disable/rotate and verify resulting state; a network block does not revoke a credential. Do not connect to a suspected endpoint or run an offensive product to confirm the hypothesis. Reconcile uncertain operations before retrying.

## Export and validation limits

Use existing `egress` / `egress-decision` / `egress-unapproved` for an actual egress decision and `campaign` / `campaign-note` / `campaign-correlation` for the operator's correlated review. Keep complete [SIEM v1 records](../enterprise/operations/README.md) with existing required sequence/time/outcome and opaque `caseRef`. Timing, destination classes, byte summaries, lineage and original event references stay in the restricted case; add no schema field, action or signal enum. Export no raw identity, address, URL, DNS query, packet content, command, credential or provider indicator.

VMs and containers do not establish packet visibility, identity trust or effective egress filtering. Virtual networking, shared host processes, encrypted channels, split DNS and host/container boundaries can hide attribution and flows. The guide does not decrypt traffic, inspect packets or establish deployed coverage or a measured detection/false-positive rate. Target operators must validate supported source semantics, permitted/denied benign workflows, clock and linkage behavior, alert delivery and collection gaps before relying on the review.

The source basis for event selection, audit correlation, inbound/outbound monitoring and traffic baselines is [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf), AU-2, AU-6(3), SI-4(4) and SI-4(13), with SC-7 for boundary protection. These are selected control objectives from the cited revision, not implemented controls, certification or a claim that this guide revalidates the complete current catalog. Framework technique identifiers are omitted from these review patterns.
