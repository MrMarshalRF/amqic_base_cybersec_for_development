# Directory identity monitoring

## TL;DR

Use this operations guide to review directory, Kerberos, certificate, replication and policy anomalies in an estate you are authorized to monitor. Compare independent audit evidence with a private approved baseline; a deviation is a human investigation lead. Missing or unauthenticated evidence leaves coverage **unverified**, never passed.

## Where it helps

Directory owners can use the guide to connect unusual identity activity with the [campaign review](AGENTIC-ATTACK-DETECTION.md) and [federated/cloud identity procedure](IDENTITY-MONITORING.md). This adds manual directory-monitoring guidance to the web baseline, whose earlier identity scope excluded Active Directory and Kerberos. It adds no Windows collector, directory connector, executable rule, schema field or enforcement action. The offline evaluator still implements eight existing families; it does not evaluate the patterns below.

## Establish applicability and private ownership

Apply only to directories, identity issuers and certificate services actually present in the deployment. Inventory each forest/domain or equivalent trust boundary, tenant, controller, issuing authority, replication partner, privileged group, managed service identity and policy store. Record owner, asset/account linkage, expected clients, allowed operation classes, maintenance windows and approved trust relationships. Do not infer cross-domain trust from similar account names.

Keep exact identities, directory object paths, certificate templates, certificate identifiers, permissions and change tickets in restricted operator storage. Public examples use opaque references. This guide supplies no hardening configuration, credential extraction, ticket or certificate procedure, offensive utility list or testing authorization. Smart-contract exploitation and binary reverse engineering remain outside this baseline.

## Inventory the evidence before correlating

Use the issuer's official audit documentation to select supported logs and permissions for the deployed version. Assign collection and review owners. Record these fields privately, with retention and access controls:

| Source | Private fields needed for review |
| --- | --- |
| Kerberos authentication and ticket service | Issuer/controller identity, source event ID and record sequence, event and receipt times, requesting principal, source asset, service/account reference, request/result class, supported ticket/encryption metadata, failure reason and baseline revision. Do not retain ticket bodies or secrets. |
| Certificate authority | Authority identity, request/event linkage, requester and originating asset, approved template/policy reference, subject/account binding, issuance or denial result, privileged approval and configuration-change references. Exclude private keys and enrollment payloads. |
| Directory access and replication | Controller and collector identities, authenticated requesting principal, source asset, operation/object/permission class, result and expected replication-partner binding. Record which audit policy and object access settings make this source observable. |
| Group, ACL and policy changes | Actor, affected object/group/policy reference, authorized before/after revision, changed permission class, result, administrative source and approved change reference. Preserve before/after detail privately. |
| Enumeration and endpoint activity | Directory read/search operation class and count where observable, actor/source, bounded window, affected object classes, result, measured process identity and lineage if available. Keep query text and process arguments out of exported records. |

Authenticate collectors and protect log transport, storage and access. Verify issuer identity and audit configuration independently of the monitored account or agent. Establish trustworthy UTC clock observations, maximum tolerated skew, ingestion delay, sequence/deduplication rules and dropped-event counters. A timestamp supplied by a client is not a trusted clock. Disabled auditing, unavailable fields, gaps or collector tampering must be recorded as coverage gaps; absence of logged activity does not establish absence of activity.

For Windows sources, audit-policy selection is role-dependent and needs target validation. Directory Service Access also depends on selected-object audit settings; it does not guarantee every enumeration or replication operation is visible. Certificate-service Security auditing needs the CA role and applicable CA/OS settings. Directory template and permission changes need directory change evidence as well; CA request logs alone are insufficient. Microsoft's [audit-policy recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), [Directory Service Access guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-access), [Kerberos service-ticket guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-service-ticket-operations) and [Certification Services guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services) describe these source boundaries. The latter three are previous-version pages; verify field availability and semantics against the deployed OS and issuer.

Choose a finite half-open review window `[since, until)` from the actual workload baseline, with explicit count/capacity limits. Compare like account roles, assets and times of week. Preserve event-time ordering separately from arrival order; late or skewed events cannot establish a causal sequence until reconciled. Join only authoritative asset/account/issuer bindings within a compatible protected pseudonymization epoch. NAT, reused names, shared service accounts and process-ID reuse can make linkage ambiguous. Keep such cases unverified instead of merging them.

## Review patterns

Each pattern requires corroboration and baseline comparison. No universal threshold or automatic malicious classification is supplied.

1. **Ticket or certificate issuance deviation.** Review unusual request volume or service/template breadth together with an unexpected requester/source, changed issuance policy or later independently observed privileged authentication. Separate requests, successful issuance and actual use. A valid signature or issued certificate alone does not prove that the issuance was authorized. Routine renewal, service startup and migrations can explain bursts.
2. **Replication outside the approved relationship.** Review a successful or denied replication-class operation from a principal/source outside the current approved partner and permission baseline. Confirm the operation's semantics in the source audit record and compare recent privilege changes. Legitimate controllers, backup, synchronization and recovery services need explicit baseline entries; a coarse directory-read event alone is insufficient.
3. **Privileged group, ACL or policy change.** Compare a confirmed change with the owner-approved affected objects, actor, administrative source, before/after revision and time. Correlate unexpected widening with subsequent authenticated use when trustworthy linkage exists. Approved rollout and emergency recovery can produce similar events. A failed request does not establish a completed state change.
4. **Unusual account/group enumeration.** Review breadth and rate by actor/source/asset within the chosen window, supported by unexpected privilege context, a new process lineage or a related independent identity change. Inventory, help-desk, access review and synchronization can be broad or frequent. Enumeration alone does not prove credential access or compromise.

## Review examples only

These are inert human-review scenarios, not input fixtures, executable detections or assertions about evaluator output. Times are documentation examples on `2026-11-20`; references are opaque labels for this table only, with no real identities. In every row assume an authenticated collector and valid clock; otherwise the expected result is **unverified**. `a01/u01` denotes one privately linked asset/account, and `e01`, `e02` denote source evidence references. Each pattern has one review match and two near matches.

| Pattern | Match: expected human triage | Near match A | Near match B |
| --- | --- | --- | --- |
| Issuance deviation | `a01/u01`, `e01` at `00:01Z`: issuance breadth outside baseline from unexpected source; `e02` at `00:03Z`: linked privileged authentication. Verify authorization and issuance/use evidence. | `a01/u01`, `e03` at `00:01Z`: owner-approved renewal burst within current source/template/time scope. Record approved explanation. | `a02/u02`, `e04` at `00:03Z`: unrelated authentication after `a01/u01` issuance. Do not form a linked sequence; review issuance on its own evidence. |
| Replication relationship | `a03/u03`, `e05` at `00:04Z`: confirmed replication operation outside the approved principal/source relationship. Verify permissions, outcome and owner. | `a03/u03`, `e06` at `00:04Z`: approved synchronization with current exact scope and expiry. Record expected operation. | `a03/u03`, `e07` at `00:04Z`: ordinary directory read with no verified replication semantics. Do not label it replication. |
| Group/ACL/policy change | `a04/u04`, `e08` at `00:05Z`: confirmed privilege widening with no matching approval; `e09` at `00:07Z`: linked use. Review change and access separately. | `a04/u04`, `e10` at `00:05Z`: approved policy rollout with matching before/after revision and administrative source. Record explanation. | `a04/u04`, `e11` at `00:05Z`: denied modification with unchanged verified state. Review the attempt; do not assert successful widening. |
| Enumeration | `a05/u05`, `e12` at `00:08Z`: atypical read breadth; `e13` at `00:09Z`: independently verified unexpected lineage in the same scope. Investigate both. | `a05/u05`, `e14` at `00:08Z`: registered inventory job within exact approved scope/time. Record expected activity. | `a05/u05`, `e15` at `00:08Z`: isolated normal lookup without breadth or corroboration. Retain ordinary baseline disposition. |

## Exceptions and response

An independent directory owner maintains private approvals with purpose, contact, affected assets/accounts, principal/source, allowed action/object classes, `approvedAt`, `expiresAt`, reviewer and change reference. Evaluate event time within `[approvedAt, expiresAt)` and require the approval to remain current at review. Expired, mismatched, unsigned-off or agent-authored exceptions do not suppress review. A registered engagement never authorizes activity outside its exact scope or suppresses unrelated integrity or trust changes. Preserve the evidence and disposition even when an exception explains it.

Confirm authorization with the identity and asset owners. Preserve original restricted logs, policy revisions, collector/clock observations and a minimal case timeline. Use only separately authorized issuer procedures to revoke or disable credentials/grants, correct permissions, review affected sessions and rotate material. Certificate revocation publication and relying-party behavior require issuer/target verification; a local block alone does not revoke upstream access. Apply scoped host/network containment through the responsible owner, protect legitimate service and recovery access, and reconcile uncertain effects before retrying.

## Export and validation limits

Record an anomaly review using existing `campaign` / `campaign-note` / `campaign-correlation`. Use `identity` / `principal-change` / `identity-grant` only for a real principal/credential change supported by evidence, or `identity` / `consent-change` / `identity-grant` for an actual consent change. Preserve the existing [SIEM v1 contract](../enterprise/operations/README.md), required sequence/time/outcome and opaque `caseRef`. Finer directory semantics remain in the private case. Do not add an action, signal enum or raw directory field.

No raw identities, directory paths, certificate material, URLs, queries, commands or credentials belong in exports. VM or container isolation neither supplies directory visibility nor authenticates host/issuer logs; shared clocks, virtual networking and missing host sensors limit observations. Offline review examples establish no Windows collection, deployed coverage, detection rate or false-positive rate. Validate supported source fields, benign workflows, denied/allowed outcomes, alert delivery and gaps in the operator's authorized environment before operational reliance.
