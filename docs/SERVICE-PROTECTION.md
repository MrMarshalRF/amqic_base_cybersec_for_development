# Server malware scanning, Redis and request proof of work

These mechanisms address different risks. ClamAV detects some known malicious content; Redis can coordinate short-lived security state across replicas; request proof of work can increase the cost of repeated requests. None replaces application authorization, patching, container isolation, backups, or the signed release process. The patterns below are integration guidance, not a deployed scanner, Redis service or proof-of-work implementation.

## ClamAV on a server

The antivirus project is **ClamAV**. Choose a supported engine and keep its signature database current through the supported update mechanism. Its main components include a single-run scanner (`clamscan`), a scanning daemon (`clamd`), and the database updater (`freshclam`). Use the [official manual](https://docs.clamav.net/) and the configuration reference for the installed version.

### Where scanning helps

- Untrusted uploaded files before they become downloadable, executable or visible to document-processing tools.
- Inbound attachments and integration downloads, using a bounded quarantine workflow.
- Release/dependency artifacts as an additional check after provenance verification and before use.
- Scheduled inspection of selected stored content, with limits that avoid exhausting the production host.

A clean result means that the configured engine/database did not detect a threat within that scan's limits. It does not establish that content is harmless, that a dependency is authentic, or that the server has not been compromised. Encryption, unsupported formats, archive limits, timeouts and scanner errors can leave content uninspected. Keep a distinct `uninspected` result; do not translate every non-detection into approval.

### Quarantine and release flow

1. Accept a bounded upload into a private quarantine area isolated from primary storage, following [UPLOAD-ISOLATION.md](UPLOAD-ISOLATION.md). Enforce upload size and quotas before acceptance. Before extraction, inspect supported archive metadata for declared expansion, file-count, nesting and path/link violations; reject unsupported or indeterminate handling under the application policy. Also enforce actual expansion, counts and deadlines during bounded extraction/scanning because metadata can be false. Generate server-side storage names; do not trust a client path or MIME type.
2. Scan a stable object with a supported engine and current database. Prevent replacement between scanning and use: retain the same immutable object/content identity or check the final bytes again. An approved hash for one file must not approve another file with the same name.
3. Track engine/database version, time, content identity, scan coverage and disposition in protected records. Keep sensitive names and content out of public logs.
4. Release only content that passed the required checks. A timeout, unavailable scanner, limit exceeded, encrypted archive or error follows the application's explicit quarantine/rejection policy. For required malware scanning, do not silently fail open during an outage.
5. On detection, restrict access and notify the responsible operator. Do not automatically delete production files, backups or business records. Quarantine and incident response need their own permissions and recovery plan.

For a single intentionally selected file, a basic Linux command template is:

```sh
clamscan --infected /srv/quarantine/candidate.bin
```

Record the exit status before making a decision: `0` indicates no detection, `1` detection, and `2` an error for this command, as documented in the [upstream clamscan manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in). Those statuses do not remove the need to inspect scan coverage and limits. Avoid scanning the whole filesystem indiscriminately or using automatic removal flags. This command is a template; no malware sample is shipped or executed by this kit.

### Daemon and container boundaries

Prefer a local Unix-domain socket with restricted permissions where the application and scanner arrangement supports it. The clamd TCP protocol does not provide authentication or transport encryption; do not publish port 3310 to the internet. A private container network alone does not authorize every attached container to use the scanner. Keep the scanner reachable only by the intended ingestion service, with resource and concurrency limits. See [clamd usage](https://docs.clamav.net/manual/Usage/Scanning.html).

If content crosses a socket, enforce the daemon's stream limits and the application's upload limits together. A path sent to a daemon refers to the daemon's filesystem, which may differ from the application's container. Prefer a documented streaming/fd-based integration over exposing an entire host filesystem. Treat all scanner responses as protocol data, not commands.

Keep signature updates separate from the constrained application runtime. Allow only the updater's necessary egress and transfer database updates through the supported procedure; do not give a public web container broad internet or host access merely to update signatures. Monitor update failures and database age. The updater and scan daemon still require timely security patches and compatible database/engine versions. [FreshClam documentation](https://docs.clamav.net/manual/Usage/SignatureManagement.html) explains the update path.

For containerized scanning, use a verified pinned image, non-root operation where supported, bounded CPU/memory/PIDs and minimal mounts. Some on-access scanner modes require additional OS integration/privileges: assess those separately instead of granting a scanning container broad host capabilities. Neither a scanner nor a container guarantees containment of a vulnerable file parser.

## Redis as shared security state

Redis can share rate-limit counters, short-lived challenge records, replay markers and queue metadata across application replicas. This avoids a limit that each replica applies independently and can support consistent request admission. Redis is not an encrypted transport between arbitrary containers, a secret manager, or a replacement for durable authorization records.

### Protect the service itself

Use a dedicated private network reachable only by the required backend/gateway services. Do not publish port 6379 on all host interfaces. Preserve host firewall controls and the [container restrictions](INFRASTRUCTURE.md). A Redis container with no published ports may still be reachable from other attached containers; attach only intended consumers.

Configure authentication and least-privilege ACL users per service. Restrict commands and key/channel patterns to each service's actual role. Disable or tightly restrict the default user according to the deployment plan. Do not grant general administration, script loading, filesystem/configuration changes, or access to unrelated namespaces to a request-processing client. Redis logical database numbers are not a security boundary between tenants.

Use TLS with certificate validation when the threat model requires protection from network observers, including across hosts or shared infrastructure. Authentication alone does not encrypt traffic. Keep credentials and TLS private keys in the approved secret store; never place them in image layers, Compose environment examples, URLs, command arguments or logs. Protected mode is a safeguard, not a substitute for authentication, firewalling and TLS. Follow [Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/), [ACLs](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/) and [TLS](https://redis.io/docs/latest/operate/oss_and_stack/management/security/encryption/).

Keep Redis administration separate from application access. Give each workload a narrowly scoped identity, limit client connections and command cost, patch the server and client library, and monitor unexpected administration, namespace access, rejected writes and memory pressure. If queue messages request work, validate their schema and authorize the requested operation in the consumer; never treat a string read from Redis as a shell command.

### Counters, expiry and failure policy

Use atomic operations for check-and-update logic. A separate `GET` followed by `SET`, or `INCR` followed by an expiry operation that can be skipped on failure, can race or leak counters. Use a reviewed transaction or bounded server-side script/function with an exact key contract. Never accept arbitrary scripts, keys or expiry values from untrusted requests.

Bind a rate key to the intended identity and route. Hash or otherwise minimize sensitive identifiers in operational keys where appropriate. Set bounded TTLs and cardinality; an attacker should not be able to allocate unlimited challenge/counter keys. Decide whether limits must apply across all replicas, regions and failover states rather than assuming a local Redis instance is globally authoritative.

Expiry and memory eviction are different. A replay marker evicted before its intended expiry can allow reuse. Separate security-critical state from disposable cache workloads, size it for worst-case traffic, and use an explicit no-eviction/write-failure policy where loss is unacceptable. Handle out-of-memory/write failures by denying the protected operation or using a deliberately designed stricter fallback, not by skipping checks. See [key eviction](https://redis.io/docs/latest/develop/reference/eviction/).

Persistence and replication do not automatically make an acknowledgement durable across every crash or failover. If a Redis restart loses used challenges, previously solved work could be replayed until its acceptance window closes. Either use a durable authoritative store with the required transaction guarantees, or revoke the previous challenge generation and refuse old challenges after state loss. Record this failure behavior and test it. See [persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/) and [replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/).

The reference core in this kit uses its own persistent transaction/replay contracts. This document does not replace them with Redis. For critical operations and external side effects, maintain the durable operation identifier and result record needed for idempotency; a volatile rate counter is not an exactly-once execution guarantee.

## Request proof of work at a gateway

Request proof of work asks a client to perform bounded computation before the server admits selected expensive work. It is a cost-control measure, not proof of a human, identity, consent or entitlement. A well-equipped attacker can parallelize it, outsource it, or still saturate the network. Preserve edge request limits, request-size limits, quotas, CAPTCHA where required, authentication and normal authorization.

Apply the check at the API/MCP gateway **before** the expensive handler. The container itself does not gain isolation from a puzzle. Backend services must reject direct requests that bypass the gateway; use private reachability and authenticated service-to-service access. Do not put signing keys or privileged control sockets into the solver or a public application container.

### Admission pattern

1. Admit only bounded requests for a challenge. Rate-limit issuance independently; cap outstanding challenges, request size and pre-auth CPU/memory work. Validate cheap syntax before creating state.
2. Issue a fresh unpredictable challenge bound to its protocol version, audience/service, intended operation, canonical request digest, short expiry and authenticated subject or session when present. Protect challenge integrity with an authenticated server record or a reviewed server-side authentication mechanism. The client must not be able to choose easier difficulty, extend expiry, or substitute a target operation.
3. The client solves a documented, versioned puzzle with a bounded work budget. Keep effort and latency acceptable for low-powered devices; disclose the computation, allow cancellation, and provide an abuse-resistant accessible alternative when computation is unsuitable. Do not silently run prolonged background computation. Coordinate any extension with the client protocol and UX.
4. The server first rejects malformed, expired, wrong-audience and tampered challenges with bounded work. Verify the solution under the authenticated difficulty and request binding. Do not trust client-supplied timing or a claim that work was completed.
5. Atomically mark the challenge consumed before admitting work. Retain the marker for the complete acceptance window, including permitted clock skew. Concurrent use must not admit two operations. Bound retry semantics to the same request identifier and durable result instead of allowing a token to authorize another request.
6. Apply normal authentication, scope/role checks, quotas and operation-specific step-up. A solved puzzle never skips a login stage, CAPTCHA, TOTP or a required approval in this kit. Execute the admitted operation with its normal least-privilege service identity.

Redis can hold bounded counters and consumption markers if its failure/eviction semantics satisfy the policy above. A valid solution and an atomic Redis write are still separate from a transaction committing a database or external effect. Keep that durable operation boundary in the authoritative service.

### Cost, validation and limits

A typical hash puzzle makes a solution search expensive relative to verification, but effective cost varies greatly by device and algorithm. Choose a reviewed design rather than inventing cryptographic claims from a number of hash bits. Benchmark issuance, verification and solver effort under realistic traffic. Cap difficulty and avoid automatic increases that lock out legitimate clients or turn retries into a feedback loop.

Test expired and replayed challenges, changed request bodies/routes, cross-user use, forged difficulty, concurrent submissions, clock skew, Redis outage/restart/failover, counter eviction and direct backend bypass. Confirm that rejection happens before costly file parsing, model calls or database work. Monitor false rejections and overall origin load; successful puzzle verification alone does not prove denial-of-service resistance.

OWASP's [Denial of Service guidance](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) and [API4 resource-consumption risk](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) support layered resource limits and monitoring. They are not certification of this puzzle pattern. No proof-of-work protocol is implemented or benchmarked in this repository update; production integration needs a reviewed protocol, client compatibility and fault/concurrency tests.

## Operational acceptance

Record the scanner engine/database age and coverage, Redis version/topology/ACL/TLS/eviction/persistence choices, gateway challenge policy, denied bypass paths, outage behavior, load measurements and incident owner. Keep records and recovery credentials outside public source. A detection, scanner outage, lost replay state or excess resource use must have an explicit containment and recovery action.

The guidance adds no live scanner, Redis deployment or gateway to the existing authorization core. Use [secure deployment](DEPLOYMENT.md) for a separately reviewed rollout and [release preparation](GITHUB-RELEASES.md) for the final artifact inventory.
