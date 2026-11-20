# PostgreSQL tenant isolation and atomic replay claims

`schema.sql` is a fresh-database reference migration, not an idempotent production
installer. It creates dedicated `tenant_alpha` and `tenant_beta` login principals,
a nonlogin migration owner, and a separate trusted `replay_service` principal.
Production must provision authentication (for example SCRAM over verified TLS),
database CONNECT policy, connection quotas and credentials outside this repository.
No passwords, real keys or real records are included. The fixture targets the
synthetic `postgres` database: it revokes database `CREATE` and `TEMPORARY` from
`PUBLIC`, revokes all public-schema privileges from `PUBLIC`, and explicitly grants
`CONNECT` to the runtime roles. It does not revoke existing public CONNECT.
Production migrations must name their actual database, review inherited/direct
grants and connection policy, and verify effective privileges under each login.
Roles that require temporary tables need a separate reviewed grant and tests.

The lab pins official PostgreSQL `17.12-bookworm` by immutable index digest and
requires PostgreSQL 17 with `server_version_num >= 170012` (17.12 minimum).
PostgreSQL 10+ uses major × 10000 + minor, so 17.12 is 170012.
Both database and distributed labs record the observed server version and numeric
version; a different major family fails this fixed fixture's acceptance.
Consult the [PostgreSQL security fixes](https://www.postgresql.org/support/security/)
and [17.12 release notes](https://www.postgresql.org/docs/release/17.12/) when reviewing
updates. Least-privilege grants and RLS are compensating boundaries, not patches
for database-engine vulnerabilities; synthetic isolation checks do not establish
engine vulnerability clearance.

Use a separate pool authenticated as each tenant principal. Select the pool from
verified server-side identity; never accept a database role from client input.
Do not multiplex untrusted tenants with `SET ROLE`, a session variable or a custom
GUC. The lab administrator uses `SET SESSION AUTHORIZATION` only to test boundaries;
that is not a production authentication design. Ordinary tenant principals have no
memberships, BYPASSRLS, ownership, superuser, role creation or database creation rights.

Both `USING` and `WITH CHECK` bind `tenant_id` to `current_user`; FORCE ROW LEVEL
SECURITY subjects the nonlogin table owner to policies during ordinary queries.
Owners and superusers can still change/disable the policy: protect migration access.
Tenant grants expose only `id`, `tenant_id`, `display_name`. `SELECT *` and selecting
`private_ciphertext` fail; tenants cannot change tenant ownership, DDL or TRUNCATE.
This example intentionally does not give tenant roles any ciphertext access.

Use static identifiers and bound values. For a PostgreSQL driver with `$1` parameters:

```js
const result = await tenantPool.query(
  'SELECT id, tenant_id, display_name FROM app.contacts WHERE id = $1::uuid',
  [validatedContactId]
);
```

The pool must already use the authenticated tenant's principal. Parameterization
does not authorize arbitrary table/column names; choose identifiers from server code.
The SQL fixture also executes an injection string through a prepared parameter.
The private column is a storage boundary, not an encryption implementation; use
the package's authenticated-encryption layer and an external key manager where needed.

## Shared replay store

`replay.consume_nonce(audience, key_id, nonce, issued_at)` is callable only by the
trusted service role. Verify the complete signed request, configured key, audience,
canonical bytes, nonce and timestamp in the application **before** calling it.
The function does not verify Ed25519 or authorize an API action. Never expose a
raw nonce-consumption endpoint. Only privileged migrations register/revoke key IDs;
the fixed registry entry is a synthetic fixture, not a usable signing key.

All API instances must use the same authoritative writable PostgreSQL primary and
registry. The composite unique key makes the claim atomic across connections.
The server accepts timestamps within 30 seconds of its own clock, validates bounded
identifiers/nonce, and retains a nonce until `issued_at + 31 seconds`. Pruning uses
only the database clock after that expiry; no caller clock or TTL controls deletion.
An internal serialized high-water clock guard fails closed on observed backward
clock movement. This deliberately prioritizes safety over throughput: a global lock
serializes claims. Monitor clock corrections and latency. A trusted administrator
must diagnose clock incidents; runtime callers cannot reset the guard.

The service cannot inspect/delete nonce rows, change registration or clock state,
or choose expiry. It can claim registered nonces, so compromise can cause denial
of service: it remains a trusted application principal. Use role-specific quotas
and rate limits. Nonce storage is bounded by accepted request rate and the window,
not by a fixed row quota; invalid floods must be limited before database admission.

**Commit is part of the security boundary.** A true function result is provisional
until the surrounding transaction successfully commits. Rollback also rolls back
the claim. For a database mutation, claim and mutation belong to one transaction;
abort when the claim is false and acknowledge only after commit. For an external
effect, commit a durable outbox/idempotency record with the claim, then deliver with
idempotency. A nonce alone cannot guarantee exactly-once external effects.

Crash recovery must retain committed WAL; failover must not lose acknowledged
claims. Restoring old snapshots or promoting an asynchronously lagging replica can
re-admit old requests. Coordinate failover, fencing and key/window invalidation;
the reference lab does not establish HA or disaster-recovery safety. The clock guard
cannot detect time rollback across a restored database snapshot that loses its state.

Run the isolated verifier described in [the lab guide](../../lab/database.README.md).
