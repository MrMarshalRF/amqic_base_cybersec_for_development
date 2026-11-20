# Isolated PostgreSQL security verification

Inspect the effect-free plan:

```sh
node lab/database-verify.mjs --plan
node lab/database-verify.mjs --output /absolute/external/new-database-report.json --prepare
```

Node.js 22+, Docker Linux engine and the fixed official image are required:
`docker.io/library/postgres:17.12-bookworm@sha256:837bed18782820fe967067cb5328b02b0d9992c1be9a37ee0c9c492cfc03af3b`.
This immutable index digest was verified through the official Docker Hub
`library/postgres` registry metadata for `17.12-bookworm`. The verifier records the
actual local image identity, `SHOW server_version` and `SHOW server_version_num`,
and accepts only PostgreSQL 17 at numeric version 170012 or later (17.12 minimum).
PostgreSQL 10+ encodes this as major × 10000 + minor: 17.12 is 170012.
The distributed admission lab applies the same version gate and records both values.
The prior digest represented a different artifact identity; a changed digest alone
does not establish that its server was vulnerable or unpatched. Review the
[PostgreSQL security fixes](https://www.postgresql.org/support/security/) and
[17.12 release notes](https://www.postgresql.org/docs/release/17.12/) for patch context.
Only `--prepare` permits pulling this dependency (120-second command timeout).
The whole execution has a 180-second cooperative deadline plus bounded cleanup.
No existing database/container, real accounts, credentials, signing keys or integrations
are used. This is an isolated educational defensive lab, not a live system assessment.

One random-label-owned container runs as UID/GID 999, with read-only root, dropped
capabilities, no-new-privileges, bounded resources and tmpfs database storage. Its
network is `none`; no host ports, host mounts, Docker socket or persistent volume
are supplied. PostgreSQL listens only on the container's `/tmp` Unix socket.
Local trust authentication is a synthetic harness convenience **only**; production
authentication, TLS and secret provisioning are not demonstrated by this lab.

The fixture checks permitted CRUD, denied cross-tenant access, column-level grants,
FORCE RLS on the owner, constrained principal attributes, role-escape/DDL/TRUNCATE
denials, effective database CREATE/TEMPORARY and public-schema CREATE denial,
failed harmless temporary/public table creation by both tenant roles and the replay
service, GUC spoof resistance and parameterized SQL injection data. Roles needing
TEMP require separately reviewed grants and regression checks. These privilege
limits supplement engine patching; they do not fix engine vulnerabilities. Two independent
psql processes race one nonce against the same PostgreSQL primary; exactly one must
commit true. Additional tests cover a later process, committed persistence through
a real PostgreSQL server restart, transaction rollback semantics, stale/future
timestamps, future-window retention, pruning, expired proof rejection and missing/
backward clock guard fail-closed behavior. Clock faults/prune fixtures are created
only by the isolated migration administrator, never exposed to the service role.
Expiration tests seed a synthetic expired row; they do not claim a real 60-second
clock passage or a failover/backup-restore test. No Ed25519 signature verification,
HTTP endpoint, HA/failover, production throughput or external-effect exactly-once
guarantee is established here. See [the database contract](../infra/database/README.md).

Reports and adjacent `.resources.json` ledgers must be new files outside source.
Intent precedes creation; exact observed container ID, PID/start identity and port
metadata precede use. Cleanup reconciles the unique ownership label, validates
container identity, removes only that owned container and verifies absence even on
test failure. Evidence remains external. Failure to verify cleanup reports
`cleanup_pending`; it never implies resources were removed. A timeout is a failure,
not permission to retry an operation with an unknown outcome.
