# Behavior detection for agentic misuse

This reference supplies offline, bounded structured-event evaluation and operator starting profiles for eight behavior families. A finding is a lead for human investigation, never attribution or an automatic ban. No provider or country is singled out. Class values, observed executable identities, addresses, source linkage keys and exception details belong in the [private indicator lifecycle](INDICATOR-HANDLING.md), not public rules or exports.

Use the [evaluator contract](../enterprise/detection/README.md) for exact fields, trust boundaries, ETags, thresholds and mappings. Deploying a sensor or SIEM adapter is separate target work. Existing [agent protection](AI-AGENT-RUNTIME.md), [host egress](HOST-EGRESS-MONITORING.md), [identity monitoring](IDENTITY-MONITORING.md) and [probing defense](AUTOMATED-PROBING-DEFENSE.md) retain their enforcement and authorization owners.

## Establish a baseline first

An operator first inventories trusted telemetry sources, asset roles, credential owners, model entitlements, source clusters, service identities and legitimate two-way integrations. A reviewed private class record binds provenance, confidence, reviewer, owner, exact asset/account scope and expiry. Expired positives and exceptions stop matching. Scope automation to its credential and expected source; scope maintenance helpers to their service; scope authorized engagements to the actual workload. Keep a change record and a review deadline. Never let the monitored agent author its own exemptions or trust a caller's supplied classification.

Choose a bounded window, capacity and explicit thresholds from normal target behavior, including hour of week, background denial floors and workload-specific API breadth. No universal alert constants are supplied. Capture a coherent normalized snapshot using a trusted clock and pseudonymous key epoch. Evaluate its exact strong ETag. An operator reviews coarse findings alongside protected source records, verifies likely causes, and uses ordinary separately authorized issuer/enforcement workflows if a response is justified. Missing telemetry is a coverage gap, not a clean bill of health.

## Eight starting families

| Family | Telemetry and matching behavior | False positives and near matches |
| --- | --- | --- |
| Agent ancestor starts a security utility | Trusted process creation and bounded ancestor identities; `agent` ancestor plus `security-utility` child yields `agent-tool-spawn`. An approval-disabled ancestor raises severity. Scoped engagement excludes authorized work. | Same utility from a non-agent parent; ordinary build child from an agent. Private measured executable/version identity matters more than a process name. |
| Unentitled server calls a model API | Connection decision plus private `server` workload and provider-neutral `model-api` destination class, without a current workload entitlement; allowed and denied attempts both count. Agent-spawn or callback finding on the same asset/account/window raises severity. | Entitled AI workload; approved non-model destination. Workstations are outside this server rule. SDK/observability calls require classification review. |
| Server uses interaction capture | Server DNS resolution or connection to an unexpired `interaction-capture` member is high severity unless a scoped engagement applies. DNS-normalization uses the protected destination linkage key, never an exported query name. | Workstation lookup; unclassified look-alike name under an ordinary service. Random-looking names alone never establish class membership. |
| Credential velocity and breadth | Group cloud control-plane events by asset, account, credential, source and window; count, distinct service and distinct action thresholds must all be met. Both denied-count and denied-ratio thresholds, or an unexpected source, raise severity. Registered automation suppresses only with that credential's approved source. | IaC/inventory run with registered expected source; high-rate single-action job. A registered credential from an unexpected source still fires. |
| Host or Windows service child and file companion | Parent `service` starts a `shell` or `download` class child, excluding its scoped helper. A service writing a `web-script` object emits a separate integrity companion finding. Trusted normalization verifies web-served directory membership. | Non-service parent; helper approved for this exact service. Backups, maintenance hooks and extensions require reviewed expiry. |
| Probe followed by callback | Same asset/account, denied or technical/protected inbound probe, then outbound destination equal to that inbound opaque source within the batch window. A denied probe raises severity; registered partner destinations are excluded. Event references link the protected inbound and egress records. | Registered two-way partner; inbound source outside the window. Different asset/account, endpoint or reversed temporal order cannot correlate. |
| Rotating sources sweep route classes | Same asset/account/cluster/window, enough distinct low-volume sources and technical/protected route breadth; every source must stay within the per-source maximum. Clustering features are private trusted classifications, never imported indicators. | Public-route crawler fleet; one-route health monitor fleet. Large NAT populations and CDN checks need baseline review. This does not prove coordinated intent. |
| Protected paths | Same asset/account/cluster/window, protected-route denial count above baseline produces a campaign finding. Any non-denied protected hit independently produces a high integrity regression finding, even below burst threshold. Burst severity rises with non-denied or later successful authenticated activity in the same scope. | Steady denied background floor below threshold; isolated denial. No raw request path is exported, and aggregate threat-data reporting stays aggregate. |

The evaluator uses a fixed half-open window and does not maintain rolling state. Callback linkage works only when both records share the private source/destination key epoch. Cloud source breadth does not merge across credentials, accounts or assets. A different source under a credential gets a separate group. The rotating-source detector requires an operator-derived shared cluster; client-supplied headers and fingerprints alone cannot establish that binding.

## Starting profiles and sensor limits

The [agent ancestry template](../enterprise/runtime/profiles/agent-tool-spawn.falco.yaml.template) and [host service template](../enterprise/runtime/profiles/host-service-shell.falco.yaml.template) retain the existing runtime-rule format with private placeholders and minimal event/PID output. The host template checks successful direct children on a non-container host. The ancestry template needs target-supported ancestor semantics and verified measured executable identities. A name list alone is insufficient and must not be represented as strong identity. Resolve authorized scope, owner and expiry privately before activation.

The [Windows profile](../enterprise/runtime/profiles/windows-service-shell.profile.json) specifies trusted parent/child and file-write normalization, not an event subscriber or EDR rule. The pure evaluator is platform-neutral and does not establish Windows coverage. Linux syscall availability, finite ancestry depth, indirect service lineage, process-ID reuse, dropped records, clock skew and sensor tampering remain target verification. File companions require an additional file sensor; no command lines, arguments, environments, private file paths or indicator values belong in exported output.

## Review and compatibility

Every family has a synthetic match and at least two near matches with an exact expected-findings list. Unexpected extra findings fail just as missed findings do. Additional checks reject malformed, oversized, unsafe-prototype and raw-content records, test lifecycle expiry, separate windows/accounts/assets and verify deterministic strong ETags. Run the [local test command](../enterprise/detection/README.md). Static profile checks do not execute the Falco parser or validate any kernel/Windows integration.

Existing SIEM v1 action ownership is preserved. Agent/service process records use runtime/process-exec/host-process; destination records use egress/egress-decision/egress-unapproved; observations use campaign/campaign-note/campaign-correlation. Both web-script and non-denied protected-path integrity observations use **runtime/config-integrity/host-process**, matching the current exporter. No invented administration mapping, new signal enum, identity-state change or undeclared record field is added. A separate trusted adapter must produce complete existing audit records and case references.

The original eight-family increment omitted new framework identifiers. Dated selected mappings for the later operational additions are recorded in [SECURITY.md](../SECURITY.md#directory-c2-and-agent-boundaries-in-v193). No third-party rules, queries, indicators, offensive utilities, payloads or traffic are included. Existing executable fixtures and source-reviewed operating procedures retain distinct evidence scopes; deployed effectiveness and false-positive rates require target validation.

## Related work

The supplied design brief identifies ThreatDefence's [Agentic Attack Detections](https://github.com/ThreatDefence/agentic-attack-detections), pinned there at `cf360e5b2d4ae1584f6af677b3f83a2375dbbb8f`, as context for behavior families and match/near-match testing. That brief describes its rules as experimental and synthetic-data tested. This implementation was written independently from the supplied requirements; no external repository was fetched or executed, and no rule, query, signature, indicator, source code or text was copied. Current external repository, license and validation status were not independently verified in this update. Review the exact source and applicable license before importing any future material; attribution and permission notices must accompany any copied material.

## Multi-stage bursts and persistence follow-on

This section is an operator correlation procedure, not an additional family in
the eight-family evaluator. Define a workload-specific bounded window and a
protected join policy before evaluating events. Relate two or more distinct
signal classes such as probing, a corroborated access anomaly, unapproved
transfer/callback, credential breadth or internal discovery. Repeated events of
one class alone do not satisfy this diversity condition. A denied probe followed
by a denied connection is attempted activity, not proof of an intrusion chain.

Require comparable authenticated clocks, collector provenance and the same
tenant/account scope. Cross-asset joins additionally require a reviewed private
relationship and identity epoch; a shared address, timing, header or opaque
cluster label supplied by the client cannot establish it. Use a half-open window
`[since, until)` and reject events at `until`, uncertain ordering or missing
required identity/collector context from the proposed chain. Retain the coverage
gap for human review rather than treating excluded data as clean.

| Synthetic review example | Expected disposition |
| --- | --- |
| Within one reviewed window, an independently observed access anomaly is followed by an unapproved callback and internal discovery on a privately linked asset in the same tenant. | Create a campaign review with the distinct signals, protected join evidence and observed outcomes. This does not identify a tool or prove every attack stage. |
| Identical timestamps/classes come from different tenants or an unverified asset relation. | Do not join them into one campaign; investigate individual signals under their own scopes. |
| An approved rollout generates a normal service start and inventory traffic, with no corroborated access anomaly or unapproved callback. | Near match for the proposed chain; verify the exact current change scope rather than declaring compromise from speed. |
| The callback precedes the proposed access anomaly, or a required event is exactly at the window end. | Do not assert that ordered chain; preserve separate observations and window/clock limitations. |

Review new services, scheduled tasks or long-lived workload identities occurring
after related probing/callback/credential signals as a separate persistence
lead. Check approved software rollout and identity provisioning before response;
a service creation event alone is not malicious persistence. Directory and
certificate context is in [directory monitoring](DIRECTORY-IDENTITY-MONITORING.md);
callback rhythm and DNS/web-channel evidence is in [C2 monitoring](COMMAND-AND-CONTROL-MONITORING.md).

An engagement exception must be issued outside the monitored agent's authority,
bind owner/reviewer, asset/account, action and target scope, and be valid both
for the event interval and the active evaluation. Use `approvedAt <= eventAt <
expiresAt` with a trusted current clock before expiry. It cannot retroactively
hide prior activity or exempt unrelated identities, scope changes or integrity
failures. Historical approval valid at event time remains investigation context
after expiry; it cannot authorize a current action, renew an expired grant or
erase evidence. Mark authorized exercise findings as reviewed exceptions while keeping
their evidence; never bypass authentication, tenant isolation or independent
tool authorization. The proposed labels above are review vocabulary, not new
accepted kinds or fields in the existing evaluator input schema.

Export only an operator-authored campaign/campaign-note/campaign-correlation
record using existing required fields and an opaque case reference. Evidence of
an integrity change retains runtime/config-integrity ownership. Raw identities,
addresses, prompts and telemetry stay in protected custody.

## Broad-then-deep and managed-workstation context

Use the [countermeasure procedure](AGENTIC-OFFENSE-DEGRADATION.md) to review
route/family breadth followed by focused repetition, including low-rate activity
over longer windows. A cadence, pattern library or single quota denial does not
identify a tool or malicious operator. Confirm the authorization, outcomes and
private linkage described above before relating different signals.

For endpoints you manage, approved model traffic plus independently observed
unexpected technical-route probing, a newly admitted skill/MCP capability or
proxy activity can justify a campaign review. Ordinary approved developer work
is a near match. A remote website does not thereby observe a visitor's local
agent, model provider or proxy; unavailable endpoint evidence remains unknown.
The existing server-only model-API evaluator rule is not widened to workstations
by this guide. These are human correlation procedures, not added detector families.
