# Security operations and SIEM export

Use these playbooks with the [enterprise profile](../README.md) and [audit chain](../evidence/README.md#sending-critical-events-to-a-siem). Assign a service owner, an incident lead, and a retention owner. Keep deployment decisions and results in the case or change record. Local fixtures cover the audit export boundary. Monitoring, collector delivery and cloud procedures require verification in the target environment.

## Export a verified audit segment

The offline exporter consumes an array of existing `amqic.audit.v1` entries and a separate trusted binding. The binding contains only `streamRef`, `start` and `end`. Use a unique, opaque 32-character lowercase hex reference for each stream. The start and end checkpoints each contain `sequence` and `hash` from `chain.checkpoint()`. The range starts after the start checkpoint and includes the end checkpoint. A new stream starts at sequence zero with 64 zeroes as its hash. Retrieve the binding and checkpoints from independently controlled storage and authenticate the exact stream. Trust in the checkpoints depends on their custody.

Run both commands against a snapshot of one to 2,000 contiguous entries. Copy the `etag` reported by `describe` into the export command for the reviewed batch. Use fresh output paths and keep the NDJSON and receipt together. A nonzero exit leaves the delivery incomplete.

```sh
node enterprise/operations/siem-cli.mjs describe segment.json trusted-binding.json
node enterprise/operations/siem-cli.mjs export segment.json trusted-binding.json EXPECTED_ETAG > segment.ndjson 2> receipt.json
```

The input ETag is SHA-256 over UTF-8 JSON in fixed field order. It binds both schema identifiers, the stream reference, ordered checkpoints and canonical audit entries. The receipt carries that `inputEtag`, the stream binding and event count. The receipt's `etag` is SHA-256 over the UTF-8 NDJSON, including each terminating newline.

Configure the collector to validate each line using [siem.schema.json](siem.schema.json). The exporter checks hashes, sequence and expected ETag before emitting any record. The schema describes a single record. The fields use enumerated actions, outcomes and categories, opaque references, timestamps and integrity metadata. Assign opaque references server-side and keep their identity mapping restricted. Exclude personal data, account names, credentials, provider assertions, request contents and exception details.

Use `record.event.at` for the event timestamp and retain ingestion time separately. Index `eventId`, `streamRef`, `record.sequence`, `category`, `record.event.outcome` and the opaque correlation reference. For OpenTelemetry, place the canonical record in the body and promote only allowlisted values to attributes. Use the correlation reference as a trace identifier only when verified by your instrumentation. [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)

An `eventId` binds the stream and audit entry hash and stays stable across overlapping exports. Treat repeated IDs as delivery retries. Alert on conflicting hashes for the same stream and sequence. On a collector timeout, reconcile durable acknowledgements before resending the same records. Advance the deployment checkpoint after durable acceptance. Monitor gaps, backlog and ingest failures. Configure authenticated transport, a durable outbox and collector access separately.

## Monitoring and alerting

Establish thresholds from the normal deployment interval, incident priorities and service error budget. Use bounded metric labels such as service, environment, result and reason class. Protect individual investigation identifiers in the restricted audit store.

| Signal | Alert and first check |
| --- | --- |
| Admission unavailable or clock guard refusal | Page on sustained backend failures. Check leadership, fencing, replication, time synchronization and retry backlog. |
| Elevated denials or quota exhaustion | Compare denial and success rates by route class. Review known traffic or deployment changes before deciding on containment. |
| Federation signature, issuer, assertion age or replay rejection | Review sustained changes by trusted provider alias. Check registration, signing key state, time and callback binding. |
| Lease expiry, ambiguous rotation or KMS unwrap failure | Page for production reads failing or a change past its approved window. Check workload identity, key version and old-envelope readability. |
| Audit integrity, gaps or collector rejects | Treat conflicting hashes or unexpected gaps as a security event. Preserve trusted checkpoints and reconcile producer and collector state. |

Exercise each alert with authorized synthetic telemetry. Record query, owner, event time, route, acknowledgement and unresolved gaps. [NIST SP 800-53 Rev. 5 SI-4, AU-6 and AU-9](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## Retention and evidence custody

1. Assign retention by dataset and jurisdiction. Distinguish metrics, sanitized SIEM records, restricted forensic evidence and independently held checkpoints. Confirm agreements and legal holds with the relevant owners.
2. Separate write authority from retention and checkpoint administration. Restrict reads, alert on retention changes and audit retrieval and disposition.
3. Verify archive recovery against the trusted start and end checkpoints. Include replicas, exports and backups in lifecycle reviews. Record the retention decision, scope and approval before disposition.
4. Retain the tested revision, collection window, operator evidence and known gaps with the exact evidence digest. Give the assessor the control scope and applicable operating period. [NIST SP 800-53 Rev. 5 AU-6, AU-9, AU-11 and AU-12](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## Incident response

1. **Triage.** Assign an incident lead and record UTC timestamps, impacted environment, trust boundary and last known good checkpoints. Compare signals to approved changes and known outages.
2. **Preserve.** Collect authorized records, policy revisions and alerts into restricted storage. Record hashes and collection times. Redact any material approved for sharing.
3. **Contain.** Apply the authorized isolation procedure. Review session and workload access and key permissions with the responsible owners. Reconcile pending operations against the authoritative store.
4. **Recover.** Apply the reviewed change or approved rollback, then verify health, tenant and key binding, and audit continuity. Confirm the intended scope before reopening traffic.
5. **Close.** Record remediation, remaining gaps, assigned owners and due dates. Update alerts and exercise assumptions based on the response. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

## Cloud key transition runbook

Record tenant and purpose scope, exact old and candidate key identifiers, workload identity permissions, activation revision and rollback window. Keep promotion and administrative authority separate from workload key use. Before approval, exercise new encryption and old-envelope decryption with synthetic records under the expected permissions. After promotion, verify readers, writers and recorded operation status. Reconcile lost acknowledgements by operation identity and revision before another change.

| Provider | Activation and old-ciphertext check |
| --- | --- |
| AWS KMS | Key-material rotation keeps the logical KMS key ID. When replacing a logical key, verify new writes with the reviewed ARN and preserve old reads with the original ARN and encryption context. Check the recorded rotation or policy revision. [AWS KMS rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html) |
| Google Cloud KMS | Verify the intended primary or approved version. Exercise new encryption and old-ciphertext decryption using the original additional authenticated data. Review re-encryption and backup dependencies before retirement. [Cloud KMS rotation](https://docs.cloud.google.com/kms/docs/key-rotation) |
| Azure Key Vault | Verify the reviewed new version and persist the versioned key identifier with wrapped data. Exercise unwrap using the original version and check dependent services have adopted the new version. [Azure Key Vault rotation](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation) |

Verify backup restore and any remaining dependencies before retirement. Keep an approved rollback revision and an incident plan for compromised keys. Follow the provider's separately authorized procedure and applicable step-up for irreversible changes. Record approvals, observed revisions, reconciliation or rollback outcome and retained-key recovery evidence.

## Local verification

```sh
node --test enterprise/operations/siem.test.mjs
```

Tests cover a non-genesis segment, repeatable event identifiers, stale ETag and tampering rejection, offline CLI output, additive event fields and legacy byte compatibility. Cloud operations, alerting policies, retention enforcement, legal holds and SIEM connectivity are deployment checks.

## Database changes and delayed probing

Follow the [engine patch runbook](../../docs/DATABASE-ENGINE-PATCHING.md) for version/exposure evidence and the [campaign correlation procedure](../../docs/AUTOMATED-PROBING-DEFENSE.md#multi-source-and-delayed-campaigns) for multi-origin/multi-day investigation. The closed schema supports operator-authored runtime, egress, campaign and identity records with opaque references. Writing a record does not detect the underlying behavior: this offline exporter does not collect process events, detect campaigns or activate a listener or sensor.

The following mapping is intended use, not a category/action constraint on existing v1 records. The original six event fields remain required. Optional `caseRef` is exactly 32 lowercase hex characters, `signalClass` is one of the six values below, and `technique` is an ATT&CK identifier in `Tdddd` or `Tdddd.ddd` form. Present optional fields are validated; omit unused fields. Canonical events retain the original field order, followed by present `caseRef`, `signalClass` and `technique` in that order.

| Signal | category | action | signalClass | technique (optional) |
| --- | --- | --- | --- | --- |
| Service-account child shell review | `runtime` | `process-exec` | `host-process` | `T1059.004` |
| SSH trust-file change review | `runtime` | `config-integrity` | `ssh-key-integrity` | `T1098.004` |
| Unapproved host egress review | `egress` | `egress-decision` | `egress-unapproved` | `T1567.004` |
| Indicator match or expiry review | `campaign` | `indicator-review` | `indicator` | omitted |
| Multi-source campaign note | `campaign` | `campaign-note` | `campaign-correlation` | omitted |
| Consent or permission change | `identity` | `consent-change` | `identity-grant` | omitted |
| Service principal or credential change | `identity` | `principal-change` | `identity-grant` | omitted |

Use the [SSH integrity guide](../../docs/SSH-KEY-INTEGRITY.md), [runtime profiles](../runtime/README.md), [host egress guide](../../docs/HOST-EGRESS-MONITORING.md), [indicator handling procedure](../../docs/INDICATOR-HANDLING.md) and [identity monitoring guide](../../docs/IDENTITY-MONITORING.md) for the operator's collection and review responsibilities. Indicator values and their provenance/expiry live in a restricted operator-private store, never in Git or exported event details. Expired or withdrawn indicators must not generate new alerts; matches are human-review enrichment, not attribution or automatic blocking.

Keep raw URLs, command lines, arguments, environment, key material, indicator values and directory display names out of records. All object levels remain closed to extra fields. Host sensors and provider audit logs, authenticated delivery, alert routing, retention and analyst workflows require separate operator integration and target verification; these synthetic tests establish no deployed detection quality.

## Behavior and static-review records

The [behavior reference](../detection/README.md), [agent configuration review](../config-review/README.md) and [client secret review](../../docs/CLIENT-SECRET-EXPOSURE.md) reuse the current v1 schema without adding categories, actions or signal classes. Process reviews map to `runtime` / `process-exec` / `host-process`; egress to `egress` / `egress-decision` / `egress-unapproved`; correlation to `campaign` / `campaign-note` / `campaign-correlation`.

The exporter maps `config-integrity` to category `runtime`, including a blocked static admission reviewed with outcome `deny`; do not label it `administration` or pass new detail fields. A real credential-state change may use `identity` / `principal-change`; a velocity review alone remains a campaign note. Supply the existing trusted actor/tenant/time/case references when constructing an audit event. Review findings are not authorization, raw sensor collection, automatic blocking or issuer revocation.
