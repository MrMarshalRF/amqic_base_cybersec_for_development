# Private indicator handling and expiry

Use indicators as bounded evidence for human review. Keep every value in an operator-private store outside Git and public payloads, including source extracts, fixtures, tickets and chat. The kit does not distribute or refresh a feed and is not a threat-intelligence platform.

## Ingest with provenance

Ingest manually or through a reviewed, authenticated client the adopter already operates. Do not add a scraper, packed FLASH extract or indicator pack to this repository. The [primary guidance in the probing playbook](AUTOMATED-PROBING-DEFENSE.md#primary-guidance-and-standards) links the official FLASH source. Optional commercial or community sources need their own provenance and lawful handling. A screenshot or social-media paraphrase is not an authoritative source.

For each private record retain:

| Field | Operator requirement |
| --- | --- |
| Type and value | Record the type, such as domain, network range, hash, certificate or tool-name token; restrict the value to the private store. |
| Source | Record source name, publication date, source reference and retrieval time. Preserve the source's scope and confidence limits. |
| Time bounds | Record first seen, valid-from and mandatory valid-until, with an explicit time zone. If source expiry is absent, the owner must set a bounded review window before activation. |
| Assessment | Record confidence, reviewer and status: `active`, `expired`, `withdrawn` or `false-positive`. |
| Case | Assign an opaque case reference and retain the review and disposition there. |

For example, a private record may identify a domain-type item by an opaque case reference, source date, retrieval time and a finite validity window. No example value is needed in public documentation. Prefer a hash over a raw value in any restricted record that may leave the store, but treat the hash as sensitive correlation metadata. Public exports contain opaque references and statuses only, not values or their hashes.

## Enforce the lifecycle

1. Validate provenance, scope, time bounds and owner before making an item active. Only active items within their validity window may enrich new alerts. Unknown time or validity must not silently extend the window.
2. Check status and expiry at each use, including queued processing. At valid-until, mark the item `expired` and stop new alerts from that value. A periodic cleanup job alone is insufficient if stale cached items can still alert.
3. Process source withdrawals promptly: mark `withdrawn`, invalidate active copies and queued enrichment, and stop new alerts. Mark a confirmed false positive `false-positive` and remove it from active matching. There is no keep-forever default.
4. Preserve historical cases under the approved retention policy. Do not erase earlier evidence or reinterpret an old match as a new alert. Recheck source and bounds before any reviewed reactivation; never silently renew expiry.

Matches enrich human review, never automatic blocking or attribution to a named group or tool. Tool names, fingerprints and default ports change. Use the [campaign playbook](AUTOMATED-PROBING-DEFENSE.md#multi-source-and-delayed-campaigns) to compare independent evidence and the [host egress guide](HOST-EGRESS-MONITORING.md) for server-originated destination classes.

## Export and retention

Restrict store access and assign a retention owner. Include replicas, caches and exports in withdrawal and expiry handling; avoid leaking source documents or values into reports. Retain private lifecycle status and disposition behind the opaque case reference.

Use [SIEM export](../enterprise/operations/README.md) category `campaign`, action `indicator-review` and signal class `indicator`, with time, outcome and opaque actor, tenant, correlation and case references. The closed schema has no indicator-value or lifecycle-status field: keep the status behind the case reference and do not add undeclared properties. Any public case summary may state the status with an opaque reference only. Expiry review records describe lifecycle work; they must not create fresh indicator-match alerts after expiry or withdrawal.

This is source-reviewed procedure, not an ingest service, scheduled expiry engine, alert connector or tested feed integration. Operators must implement and verify status enforcement, authenticated collection, retention and analyst workflow in their deployment.
