# Database-engine advisories and patch verification

Review date: 20 November 2026. This is an operations guide for systems you administer. The executable kit laboratory covers PostgreSQL and SQLite references; it does not run Oracle Database, Oracle Text or ORDS, and includes no vulnerability triggers or third-party proof-of-concept code.

## Engine bugs and data isolation are separate boundaries

Parameterized SQL prevents supplied values from becoming query structure. RLS and column grants constrain data access. Neither establishes that the native database engine is free of memory-safety defects reachable through an otherwise permitted session. Keep engines patched even when the application's SQL and grants are narrow.

Inventory every database server, replica, bundled runtime and dormant instance that can return to service. Record distributor, complete package/build, architecture, actual server version, image/platform digest, exposure, service identity and required object-creation rights. Set an exposure-based patch deadline and owner, retain exact vendor findings and document exceptions with expiry. Do not confuse a client-library update with replacing the server binary.

## PostgreSQL CVE-2026-116331

The [PostgreSQL advisory](https://www.postgresql.org/support/security/CVE-2026-116331/) describes type confusion in min/max aggregate optimization that can let an object creator execute code as the database OS user. The [12 November release announcement](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/) lists fixes in 18.7, 17.12, 16.16, 15.20 and 14.25, alongside other security fixes. Take the complete applicable vendor update. PostgreSQL 14.25 was the final release of that branch; migrate to a supported branch rather than treating the final patch as renewed support. [Version policy](https://www.postgresql.org/support/versioning/)

PostgreSQL 10 and later encode the version number as major times 10000 plus minor: 17.12 is `170012`. See [PQserverVersion](https://www.postgresql.org/docs/17/libpq-status.html#LIBPQ-PQSERVERVERSION).

The kit's fixed laboratory profile uses the 17 branch and requires `server_version_num` at least 170012 and below 180000. It records both `SHOW server_version` and the numeric value from the actual isolated server. A different branch requires its own reviewed policy, artifact and compatibility checks; this narrow assertion is not a universal future-version classifier.

A changed image digest does not by itself establish that the old image was vulnerable. Distinct indexes, platform manifests or rebuilds can contain the same PostgreSQL release. Assess exact package metadata and running server observations against vendor findings. The pin refresh and new runtime assertion establish the intended laboratory baseline, not an incident finding about a previous installation.

## Object creation and exposure

Review effective CONNECT, TEMPORARY and schema CREATE rights, including rights inherited from PUBLIC or other roles. Application runtime roles should not own tables, use superuser/BYPASSRLS, change roles or create objects they do not need. The isolated PostgreSQL fixture explicitly revokes unnecessary public database/schema creation rights and tests denied temporary/public-schema object creation while retaining permitted tenant CRUD and replay operations.

If an application needs temporary objects, record that need, isolate the role, test workflows and still apply the engine patch. Privilege reduction is a compensating control, not a workaround that closes the native planner defect. Review [PostgreSQL privileges](https://www.postgresql.org/docs/17/ddl-priv.html) and the exact distributor advisory.

Use private listeners, reviewed pg_hba rules and verified TLS or a protected administrative path. The lab's network-none, Unix-socket-only trust configuration is a synthetic test convenience, not a production authentication recommendation. Never expose database management, publishing or backup interfaces because an application is behind Nginx.

## Optional Oracle Database and ORDS procedure

Oracle is outside the executable lab. For adopters using it, consult the [November 2026 Database CSPU](https://www.oracle.com/security-alerts/cspunov2026.html), its [verbose risk matrices](https://www.oracle.com/security-alerts/cspunov2026verbose.html) and the [October 2026 CPU](https://www.oracle.com/security-alerts/cpuoct2026.html). Obtain exact patch availability and supported upgrade combinations from the vendor channel for your licensed product.

Oracle's CVE-2026-114819 row concerns Oracle Text over Oracle Net, requires Create Session and is not rated remotely exploitable without authentication. The row lists 19.3–19.32, 21.3–21.24 and 23.4.0–23.26.3, with CVSS 9.9. Its takeover wording is not itself a vendor statement that this single CVE is unauthenticated HTTP RCE. A reported chain involving ORDS CVE-2026-91609 is separate researcher analysis and was not reproduced here.

Patch the applicable product set, not just one row: adjacent Oracle Text/RDBMS issues can have wider affected ranges. Inventory Oracle Net and ORDS HTTP exposure independently, restrict them to required trusted paths, and review runtime-account privileges. Do not invent a fixed RU/build or assume that disabling a component is an approved workaround when the vendor has not documented it.

## Rollout and recovery

1. Record every expected instance and its actual artifact/build; identify primary/replica roles and recovery dependencies.
2. Preserve a consistent backup and a tested restore path. Plan availability, migrations, failover/fencing and compatible rollback. Do not roll back to a known vulnerable server to recover service.
3. Obtain authenticated patched artifacts, rebuild images and replace the running instances. Record post-change server versions and artifact identities for every instance, not just the control plane's desired image.
4. Recheck application authorization, RLS, column grants, required objects, connection security and ordinary service behavior using safe fixtures. Do not exercise the CVE to prove a patch.
5. Retain the vendor disposition, times, approvals and sanitized evidence. Unknown or missing observations remain unresolved. Check dormant jobs and templates cannot reintroduce the previous image.

## Monitoring

Monitor unexpected database-account interactive use, new public listeners, privilege/credential changes, unusual service-account children and egress not required by the workload. A process name or a single denied connection is an investigation lead, not attribution. Backup helpers and legitimate extensions can create children; calibrate detections to the actual runtime.

The [closed SIEM schema](../enterprise/operations/README.md) now supports operator-authored `config-integrity` and `process-exec` records with optional opaque references. Do not add arbitrary engine-specific fields or treat an exported record as a detector. Protect detailed evidence separately. A source-reviewed [PostgreSQL child-shell starting rule](../enterprise/runtime/profiles/postgres-shell.falco.yaml) now exists; kernel capture, dropped events and operational alerting remain target verification. It is not deployed database EDR or an Oracle audit collector.

## Standards and evidence scope

Selected [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) relationships are SI-2 flaw remediation, CM-8 inventory, CM-6 configuration, AC-6 least privilege, SC-7 boundaries, SI-4 monitoring and IR-4 response. The local evidence covers fixed PostgreSQL version/privilege assertions and existing synthetic database behavior. Vendor/cloud production rollout, Oracle patching, operational detection and failover remain target-specific verification. These mappings do not establish certification or blanket RCE prevention.
