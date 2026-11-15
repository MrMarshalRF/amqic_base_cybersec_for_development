# Isolated PostgreSQL security verification

Inspect the effect-free plan:

```sh
node lab/database-verify.mjs --plan
node lab/database-verify.mjs --output /absolute/external/new-database-report.json --prepare
```

Node.js 22+, Docker Linux engine and the fixed official image are required:
`docker.io/library/postgres@sha256:40865bc877a289da75963d97d72b59633f639fc5af7a4e856bfa3714cae5b536`.
The digest was observed through Docker Hub's official `library/postgres` tag API
for `17-bookworm`; the verifier records the actual image identity and server version.
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
denials, GUC spoof resistance and parameterized SQL injection data. Two independent
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
