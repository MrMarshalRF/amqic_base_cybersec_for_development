# Offline behavior detection reference

`detection.mjs` evaluates bounded synthetic or operator-normalized event records. It imports only the standard-library hash function, performs no network, process, sensor, file or enforcement operations, and never bans a source or revokes a credential. Its results are investigation leads. See [behavior guidance](../../docs/AGENTIC-ATTACK-DETECTION.md) for the eight families and operational limits.

Run the local checks with:

```sh
node --test enterprise/detection/detection.test.mjs
```

## Integration boundary

Call `detectionInputEtag(input)` on a reviewed snapshot, then call `evaluateDetections(input, { expectedEtag })` with that exact tag. Both functions validate the whole input. Missing or stale tags fail with a fixed error; no side effects occur. The returned `inputEtag` identifies accepted input bytes and `etag` identifies the result without its own tag. Tags are quoted SHA-256 over canonical JSON: object keys sorted, array order preserved, no whitespace, with the input/result schema included. Changing any policy field, record or order changes the input tag. Capture one coherent source snapshot before either call; this module does not transact with a live store. Do not use these tags as authorization or as substitutes for source authenticity.

The caller must be a fixed trusted adapter outside agent/client write control. It verifies sensor/source identity, timestamps, process identity and lineage, private class provenance, policy review and clock integrity **before** normalization. There is no signature verification or authenticated log collector here. A caller that fabricates a `server`, `agent`, exemption or trusted-clock record can fabricate results. Never copy classifications, entitlements, cluster references or account/asset bindings directly from request headers, request bodies, model output or arbitrary client claims.

Input is a plain data object with exactly `schema: "amqic.behavior.input.v1"`, `policy` and `events`. Unknown fields, custom prototypes, accessors, symbol fields, sparse arrays, unsafe integers and non-opaque identifiers are rejected. Privacy errors never echo input. Every reference is exactly 32 lowercase hexadecimal characters, generated from operator-private mappings; they are not hashes of low-entropy addresses. Use keyed pseudonymous linkage and stable key epochs privately. Never pass raw addresses, URLs, command lines, payloads, provider names, file paths or credentials.

## Policy contract

The exact `policy` fields are:

| Field | Contract |
| --- | --- |
| `version` | Integer `1`; distinct from the kit release number. |
| `baselineRef`, `clockRef`, `reviewerRef` | Opaque references to a reviewed baseline, trusted clock observation and reviewer. |
| `since`, `until` | Milliseconds, half-open analysis window `[since, until)`, strictly positive duration, at most 24 hours. |
| `trustedNow`, `expiresAt` | Explicit trusted observation time and policy expiry; `until <= trustedNow < expiresAt`. No wall clock is read. |
| `capacity` | Maximum input events, integer 1–2000. Excess input is rejected, never silently truncated. |
| `thresholds` | Exactly `cloudCount`, `cloudServices`, `cloudActions`, `cloudDenied`, `cloudDeniedPermille`, `rotatingSources`, `rotatingRoutes`, `perSourceMax`, `protectedDenied`; count values integer 1–capacity and denied ratio integer 1–1000 per mille. |
| `classes` | At most 4000 operator-private classification/exemption metadata records. No indicator values. |

Thresholds have no operational defaults. Counts are calibrated for this exact window duration, asset role, credential and hour-of-week baseline. The operator splits workloads into appropriately scoped batches; one batch's thresholds apply to its entire window. Cloud count divided by window duration is the velocity baseline; distinct services/actions establish breadth. The denied-count and denied-ratio thresholds must both hold to raise severity for denial behavior; an unexpected source independently raises severity. Neither counts nor ratios are exported. Splitting a real burst across fixed windows can miss it. An operational sliding-window owner must deduplicate overlapping findings using a protected case record; none is installed here.

Each class record has exactly `kind`, `subjectRef`, `bindingRef`, `assetRef`, `accountRef`, `sourceRef`, `reviewerRef`, `ownerRef`, `observedAt`, `expiresAt`, `confidence`. `sourceRef` references private provenance, not an event's network source. `observedAt` is a nonnegative millisecond timestamp no later than trustedNow; expiry is later than observation. Confidence is `low`, `medium` or `high` and is review metadata, not evidence that a class is correct. A class is usable only if observed by event time, unexpired at trustedNow and bound to the event's exact asset/account. Even historical positive classes and exemptions stop matching after expiry until reviewed.

Supported class kinds are `agent`, `approval-disabled`, `security-utility`, `engagement`, `server`, `model-api`, `model-entitlement`, `interaction-capture`, `automation`, `approved-source`, `service`, `shell`, `download`, `helper`, `web-script`, `partner`, `technical-route`, `protected-route`, `crawler`, `health-route`. Private values, executable/version verification, route inventories and source mappings stay outside this repository. `bindingRef` is the exact credential/actor for `approved-source`, and the service actor for `helper`; for every other kind it must be the 32-zero sentinel. This prevents an approved automation source or helper for another credential/service from suppressing an event. Engagements and model entitlements use the workload actor as subject, partners the destination, crawlers the source, and route classes the route object.

## Event contract and output

Each event has exactly `id`, `type`, `at`, `assetRef`, `accountRef`, `actorRef`, `objectRef`, `sourceRef`, `clusterRef`, `actionRef`, `lineageRefs`, `decision`. IDs are unique per snapshot. All references are opaque as above. `lineageRefs` has at most 32 ancestors. `decision` is `allow`, `deny` or `observe`; `type` is `process`, `connect`, `dns`, `cloud`, `inbound`, `file` or `auth`. Timestamps are safe nonnegative milliseconds no later than trustedNow. Events outside the analysis window do not participate.

For processes the actor is the parent/service or executing workload and object is the executable identity; lineage contains ancestors. For connections/DNS the actor is the workload and object the destination. Cloud events use the credential as actor, service as object and API operation class as actionRef. Inbound events use a route class object, protected source reference and trusted cluster. A file event's object is a privately classified script-in-web-directory identity; a trusted normalizer verifies the actual directory and writer. Auth events represent successful authenticated activity only when decision is allow. Actor/source/cluster fields unused by a family still carry opaque sentinel references, never omitted fields.

Results have exactly `schema`, `inputEtag`, `findings`, `etag`. Each finding has `id`, `severity` (`medium` or `high`), `assetRef`, `accountRef`, `category`, `action`, `signalClass`, `eventRefs`. Findings and event references are deterministically ordered. A callback finding links one representative denied probe (latest such probe, or latest technical probe if none denied) and the egress event, keeping evidence size bounded. Full evidence remains in the private snapshot. This is an intermediate result, **not** a directly exportable SIEM record. A trusted adapter must construct an existing v1 audit record with required sequence/time/outcome/opaque case linkage and then use the existing exporter. Do not append `id`, class names, event arrays or new signal enums to the SIEM schema. Mappings use only existing tuples:

| Finding family | Category / action / signal class |
| --- | --- |
| Agent utility, service child | `runtime` / `process-exec` / `host-process` |
| Service web-script write, protected-path regression | `runtime` / `config-integrity` / `host-process` |
| Model API, interaction capture | `egress` / `egress-decision` / `egress-unapproved` |
| Credential velocity, callback, rotating sources, protected denial burst | `campaign` / `campaign-note` / `campaign-correlation` |

The current exporter owns the `config-integrity` → `runtime` mapping. Credential velocity is a campaign observation, not a fabricated identity-state change. Revocation or rotation belongs to the issuer's separately authorized workflow. No schema revision or automatic response is introduced.

## Tested and untested scope

Synthetic exact-findings fixtures cover one match and at least two near matches for every family, plus scope/window separation, policy/class expiry, descriptor/prototype/raw-content denial and ETags. Static profile checks inspect output minimization and starting conditions. No live indicators, external rule imports, third-party traffic, real intrusions, kernel capture, Falco engine validation, Windows sensor integration, detection-effectiveness measurement or false-positive-rate measurement is performed.

The two `.falco.yaml.template` files contain deliberately unresolved private placeholders and require operator adaptation. They are not installable turnkey profiles. Name fields alone do not establish executable identity; match measured identities in a target-supported sensor adapter. Ancestry depth, missing events, clock skew, process-ID reuse, resolver/proxy visibility, protected pseudonym key epochs and cluster quality materially affect results. The Windows JSON file is guidance only. Review target sensor versions and field semantics, then validate benign match/near-match records on target before alerting.
