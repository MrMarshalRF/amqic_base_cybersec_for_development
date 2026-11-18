# Lab evidence and audit records

Use the fixed verification runner to capture the result of a baseline or full local run. The exporter checks the supplied report against the current checksum registry, coverage inventory and source hashes. It exports a compact JSON record and a Markdown view. The projection keeps typed outcomes, UTC run dates, check output digests and recorded skipped subtests. Keep the original reports in access-controlled storage. They may contain diagnostic paths or text that the export omits.

```sh
node scripts/verify.mjs --output /absolute/work/run.json
node enterprise/evidence/cli.mjs export /absolute/repository /absolute/work/run.json /absolute/work/evidence
```

The report and repository must describe the same snapshot. The output parent must exist. Choose a new output directory outside the repository. For all-local reports, retain recorded child reports with their original suffixes beside the parent report. The exporter ignores reported absolute child paths and checks conventional siblings by digest. It rechecks the fixed stage acceptance predicate for each digest-linked child marked passed. The existing Nginx stage has no child report digest in the parent record, so its outcome remains a parent-reported observation. CI and operators should supply reports from trusted runners. Matching source bytes and report hashes establish the binding, while runner trust and control effectiveness require their own review.

## Signing and review

Keep the signing key in an offline store or approved signing service. The Node tool reads only an independently trusted Ed25519 public key and verifies the raw detached signature. For an approved OpenSSL environment, the operator can sign the exact evidence JSON using an existing private key. Use a new signature path. Consult the [OpenSSL pkeyutl signing reference](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/#ed25519-and-ed448-algorithms).

```sh
openssl pkeyutl -sign -rawin -inkey /approved/store/evidence-private.pem -in /absolute/work/evidence/evidence.json -out /absolute/work/evidence/evidence.sig
node enterprise/evidence/cli.mjs verify /absolute/work/evidence/evidence.json /approved/trust/evidence-public.pem /absolute/work/evidence/evidence.sig
```

The signer attests to the JSON bytes. Keep Markdown and other presentation material as derived views. Supply the public key through an independent trust channel. A successful signature check says nothing about execution beyond what the signer reviewed. Retain the report digest, original reports, source revision, signer identity and custody records. The run and export timestamps are observations from their respective clocks. Add an independently trusted timestamp if your process requires one.

## Audit review worksheet

The exported NIST crosswalk supplies evidence leads with the exact scenario status. Read `not_run`, `external_not_run`, `prerequisite_missing` and `source_reviewed` as distinct states. A passed local check covers the associated synthetic fixture for the recorded snapshot. Map it to your actual scope and operating period before using it in an assessment. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

| Review target | Evidence lead | Deployment evidence to collect |
| --- | --- | --- |
| SOC 2 logical access and monitoring | Exact scenario outcomes for identity and tenant boundaries, plus verified audit checkpoints from your deployment | Confirm selected Trust Services Criteria with the auditor. Include access reviews, change records and monitoring across the in-scope period. |
| ISO/IEC 27001:2022 | Scope the access enforcement and logging measures against your risk treatment and Statement of Applicability | Record assignments, approvals, exceptions, review frequency and evidence of operation. |
| PCI DSS v4.0.1 logging and access | Keep the report bindings and checkpoints for candidate access and audit mechanisms | Establish cardholder data environment scope and responsibility. Record applicable requirements, log review and retention evidence in your environment. |

Record the applicable edition and control ID, evidence digest, deployed asset and configuration, owner, operating period, limitations and follow-up actions. Consult the official [AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022), [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) and [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/).

## Sending critical events to a SIEM

`audit.mjs` accepts structured login, access-change, sensitive-read, key-rotation, backup-restore and admin-action events. It requires a canonical UTC timestamp, an outcome and three opaque 128-bit references in lowercase hexadecimal. Generate or pseudonymize those references in the caller and keep the mapping in its access-controlled domain. Never encode user data or secrets in the references. The event API accepts no arbitrary details.

```js
import { createAuditChain, serializeAuditRecord, verifyAuditTrail } from './enterprise/evidence/audit.mjs';

const chain = createAuditChain();
const entry = chain.append({
  at: new Date().toISOString(),
  action: 'login',
  outcome: 'deny',
  correlationId: '1'.repeat(32),
  actorRef: '2'.repeat(32),
  tenantRef: '3'.repeat(32),
});
const line = serializeAuditRecord(entry); // Write as one line to the approved JSON collector.
const checkpoint = chain.checkpoint();    // Store outside the writer's modification boundary.
// The verifier loads trusted start/end checkpoints from that independent store.
verifyAuditTrail([entry], checkpoint);
```

Use a serialized writer per stream and durable coordination between append and checkpoint publication. Provision stream identity, transport authentication, encryption, access, retention and monitoring in the deployment. Store periodic and terminal checkpoints where the event producer cannot rewrite them. Verification with an independently supplied end checkpoint detects event changes, reordering and deletion through that point. Events after the last trusted checkpoint and unrecorded events are outside that assurance. Rotate the stream at 100,000 entries and retain each stream's checkpoint in the independent store. A collector can translate these single-line JSON records into its own schema or an OpenTelemetry log pipeline.

Run the focused synthetic tests with `node --test enterprise/evidence/evidence.test.mjs`.
