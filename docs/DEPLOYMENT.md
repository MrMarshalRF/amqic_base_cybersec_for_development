# Secure production deployment

This runbook starts after an application has passed source preparation and build checks. It applies the release to a specific authorized environment. It does not execute a deployment, authorize changes to an arbitrary server, or provide a universal migration script. Supply the application's real service manager, database, health checks and rollback commands before scheduling the change.

Use [initial deployment](INITIAL-DEPLOYMENT.md) for first-time machine/origin configuration, [VPN access](VPN-TUNNELS.md) for administration, [production preparation](PRODUCTION.md) for source staging, and [GitHub releases](GITHUB-RELEASES.md) for distribution and signed inventories.

## 1. Approve a concrete change

Record the environment, hostname, release tag and immutable commit, final artifact digests, configuration revision, owner, deployment window, expected interruption, data/schema changes and exact rollback. Identify the permitted operator and independent approver where required. Keep release evidence outside the public source tree.

Separate permissions for building, signing and deployment where feasible. A CI job receiving an untrusted pull request must not gain production secrets, a signing key or unrestricted deployment access. Use environment protection and least-privilege short-lived credentials where available. Pin action/tool versions and images; review changes to the pipeline like application code. NIST [SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) is a process reference, not a certification supplied by this runbook.

## 2. Verify the delivered release

Obtain artifacts from the intended repository/release and verify the maintainer identity and signature on the exact registry through the designated trust process. Then verify every payload hash and exact file membership. A matching SHA-256 list alone cannot establish authenticity. Do not execute verification helpers from an untrusted package before establishing trust; use preinstalled trusted tools or a separately reviewed verifier.

Check for unexpected files, links, path traversal, credentials and platform mismatch before unpacking or executing. Inspect archive entries first; extract into a new staging directory outside the active release. Keep file modes and ownership appropriate for the target. The service identity should read its executable/configuration but should not rewrite its own installed code. Runtime writable data and logs belong in separate explicitly managed paths.

For an OCI image, pin the accepted digest rather than a mutable tag, verify available signature/provenance with a trusted policy, review layers for source, keys or mappings, and retain the original digest for rollback. Neither a digest nor a vulnerability scan alone establishes that an image is trustworthy. For binaries, complete [transformations and platform signing](BINARY-OBFUSCATION.md) before final hashing; verify target architecture, loader and runtime dependencies.

If an external web edge is used, follow the [Cloudflare example](CLOUDFLARE-EDGE.md) for proxy/origin TLS, safe cache boundaries and real-client-address handling. Confirm that personal responses cannot be shared from cache and that direct origin access cannot bypass the intended protection.

## 3. Prepare access, configuration and recovery

Establish a tested private administrative path and independent provider/serial recovery. Preserve SSH host-key verification, individual administrator keys, least privilege and the firewall. Confirm the actual proxy/VPN ranges and hostname/certificate expectations rather than copying example addresses.

Deliver production secrets through the application's reviewed secret manager or protected provisioning mechanism. Do not bake them into an image, pass them in process arguments, commit them, or print them into CI logs. Separate development and production identities. Check the service receives only needed credentials and cannot read unrelated secrets. Treat changing credentials or permissions as its own authorized operation.

Save exact current service, proxy and firewall configurations privately. Validate proposed configuration syntax with the actual installed versions before applying it; `nginx -t`, `sshd -t` and a firewall syntax check are useful but do not prove reachability. Avoid opening extra public ports to troubleshoot a missing internal connection.

Where applicable, verify the [malware scanner and shared admission services](SERVICE-PROTECTION.md): current scan databases, quarantine handling, Redis ACL/TLS and failure policy, and gateway bypass denial. Do not make application startup depend on an untested fail-open fallback.

If files can be uploaded, verify the [isolated storage roles](UPLOAD-ISOLATION.md): intake has no main-store mount, the scanner cannot alter inputs, only the promoter writes approved content, and download authorization remains enforced. Storage separation does not replace content identity and race checks.

## 4. Back up and prove recovery before mutation

Create a consistent database backup using the database's own dump/snapshot procedure, plus required persistent files and configuration. The generic file backup helper cannot make a running database consistent. Encrypt and store backups separately with a verified recovery-key path. Record backup identifiers, hashes, retention and a restore result in an isolated target.

Verify the rollback plan against the data schema. Prefer backward-compatible expand/migrate/contract changes: add compatible structures, deploy code that tolerates both versions, backfill with a resumable operation, and remove obsolete structures only in a later separately approved change. Do not assume rolling back an executable reverses a database migration.

Database deletion, backup deletion and other critical/destructive operations require the independent second factor described by this kit, bound to the exact action and arguments. A flag in CI, an AI assertion or a previously accepted OTP is not authorization for a different action. If no trusted verifier is integrated, a human performs that action; automation stops at the prepared plan.

## 5. Stage and test the candidate

Install into a new versioned release directory or select a new accepted image digest without overwriting the active release. Apply least privilege, non-root service identity, minimal capabilities, a read-only code filesystem and bounded resources where compatible. Confirm the process can access only intended data and networks. Do not mount a Docker socket into a public application.

Run the actual candidate with target-compatible configuration in the agreed staging/canary environment. Isolate test data from production, suppress unintended external notifications/payments, and document any real external dependencies needed by the test. Register temporary services, ports and cleanup ownership before launch.

Test startup and readiness, service identity and permissions, database connectivity/schema compatibility, secret retrieval, intended internal upstream routes and graceful shutdown. Distinguish liveness (the process runs), readiness (it can serve requests) and an external functional check. A health endpoint must not disclose credentials, internals or customer data.

## 6. Migrate and switch deliberately

Run only the approved migration on the specified database using the supported migration tool and appropriate locking/transaction handling. Record start/result/version. On timeout or lost output, inspect the authoritative migration state before retrying; do not blindly replay a possibly completed data change.

Use the application's established rollout mechanism: an atomic release pointer with a controlled service restart, rolling deployment, or blue/green upstream switch. Define capacity, connection draining, worker/queue behavior and readiness gates for that mechanism. Validate proxy configuration before reload, retain the last working configuration, and make the candidate ready before directing traffic to it. Do not invent zero-downtime guarantees for a single process.

Start with the agreed canary scope where feasible. Set concrete stop/rollback criteria for error rate, latency, authentication failures, data integrity and resource usage. Do not silently broaden traffic while checks are incomplete.

## 7. Verify from the real request paths

| Check | Required evidence |
| --- | --- |
| Release identity | Running revision/image digest matches the accepted artifact; hashes or signatures still verify. |
| HTTPS and origin | Correct certificate and approved hostname, expected HTTP redirect, direct-IP/invalid-host denial, no accidental public backend/administrative listener. |
| Proxy/VPN boundaries | Fresh permitted connection and fresh denied source/identity; trusted forwarded headers accepted only from configured proxies. |
| Personal-data forms | Direct requests cannot bypass schema/body limits, parameterized storage and safe rendering; denied records stay inaccessible. Container restrictions and private database networking are effective. |
| Authentication | Normal login stages work; missing/expired/replayed credentials, insufficient roles and absent step-up fail. |
| Sensitive files | Representative protected URI probes return the intended denial without exposing contents. Avoid scanning unrelated systems. |
| Limits and headers | Expected rate-limit response, CSP and security headers on normal/error paths; normal shared-IP workload remains usable. |
| Data and dependencies | Compatible reads/writes, migration version, queues/jobs and required outbound dependencies; no unintended side effects. |
| Observability | Useful logs/metrics and alerts reach the intended owner without secrets or sensitive payloads. |
| Recovery | Rollback remains executable and the recent consistent backup can be restored in the tested target. |

Do these checks through both the intended public proxy and private administration path where applicable. Passing a localhost probe does not establish public routing, TLS or origin protection.

## 8. Roll back, close and monitor

If a stop criterion is met, stop traffic expansion and execute the predefined rollback under the same access controls. Verify the prior executable and configuration, then assess schema compatibility. Restore a database only with explicit authority and a plan for writes since the backup; this can lose data and must not be an automatic generic fallback.

After acceptance, record the running version, deployment result, test evidence, backup and rollback references, and responsible owner. Stop/remove only the exact temporary services and disposable resources owned by the deployment task; preserve production data, required reports and retained rollback releases. Do not prune shared Docker resources or remove all older releases indiscriminately.

Monitor for the agreed observation period with an available operator and incident path. Keep the previous release until its retention/compatibility policy allows removal. Publishing release notes or marking a CI job green is not evidence that a production deployment completed successfully.
