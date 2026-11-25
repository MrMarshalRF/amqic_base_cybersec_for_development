# Database isolation, field encryption and shared replay state

Protect three different boundaries: which rows a caller may access, which columns a query returns, and which service may decrypt a sensitive field. Database encryption at rest protects a stolen disk or backup; it does not authorize SQL queries or prevent an application from returning another customer's plaintext.

Start with the [PostgreSQL example](../infra/database/README.md), the [field-encryption module](../reference/field-encryption.README.md) and the [database laboratory](../lab/database.README.md). Apply these patterns to your own schema and identity system. The examples do not configure a production database or cloud KMS.

## Authenticate before selecting data

Derive the user and tenant from verified server-side authentication. Check current membership, role, requested action and field permissions; never trust a tenant identifier merely because it appears in a URL, JSON body, JWT without signature/audience verification, or a connection setting.

Use a runtime database role that cannot own tables, alter policies, grant itself roles, truncate protected tables or bypass RLS. Keep migration, backup, reporting and application credentials separate. PostgreSQL superusers and `BYPASSRLS` roles bypass RLS even when `FORCE ROW LEVEL SECURITY` is set. `TRUNCATE` is not a row-filtered operation. RLS also does not eliminate inference through unique constraints, timing or aggregate results.

The supplied database example binds rows to the authenticated database principal, with separate tenant roles and no cross-tenant role membership. Keep a separate pool per principal. A shared login allowed to switch into every tenant role can cross that boundary if compromised; it requires a different, explicitly trusted server-side authorization design.

Custom PostgreSQL settings such as `app.tenant_id` are useful transaction context in a trusted server, but are not tenant authentication: a SQL client can set custom settings. A policy that trusts such a setting cannot isolate arbitrary users of the same database login. If adopting that design, restrict access to the trusted backend, set context transaction-locally from verified identity, test commit/rollback and pooled connection reuse, and acknowledge the shared-role SQL-compromise boundary. Never retain tenant context in a session-wide setting across pooled requests.

## Row and column selection

Enable and force RLS on tenant tables. Use both `USING` for visible/existing rows and `WITH CHECK` for the new row values of inserts/updates. Test a request that reads another tenant's ID, changes a row's tenant, inserts an unauthorized tenant, and updates or deletes a cross-tenant row. Successful HTTP authentication alone does not establish these checks.

Select explicit columns. A contact-list endpoint generally needs `id` and `display_name`, not password hashes, factor seeds, encrypted medical details or wrapped keys. Use column grants or a narrowly reviewed interface where practical. `SELECT *`, automatic ORM serialization and mass-assignment updates can expose or overwrite fields that the UI never intended to use.

Bind values using your driver's parameter API. Keep table names, sort expressions and selected column sets in a server-owned allowlist; identifiers cannot be made safe by binding a value parameter. Bound result counts, pagination, statement timeouts and transaction duration. Do not concatenate a requested filter or identifier into SQL.

```javascript
// Driver adapter example; the server has already authorized the requested tenant.
// The pool is bound to that tenant's restricted DB principal, not chosen by SQL input.
const result = await tenantPool.query({
  text: 'SELECT id, display_name FROM app.contacts WHERE id = $1 LIMIT 1',
  values: [validatedContactId]
});
```

Parameterization prevents data from becoming SQL syntax. It does not establish row authorization, protect HTML output or authorize shell execution. Treat returned strings as data at their destination; use context-specific output encoding and avoid passing them into a shell. The [PII input example](../reference/pii-input.mjs) complements these boundaries.

For views, understand whose policies and privileges apply. PostgreSQL 15+ supports `security_invoker` views; owner-executed views and security-definer functions can cross RLS boundaries. Fix function search paths, qualify objects, revoke public execution, and grant only the exact operation needed. Test the actual runtime principal, not only a superuser fixture.

## Encrypt sensitive fields using a KMS boundary

A key management service controls a key-encryption key (KEK). A fresh data-encryption key (DEK) encrypts a field using authenticated encryption; the KMS wraps that DEK. Store the ciphertext, authentication tag, nonce, wrapped DEK, algorithm/schema version and key reference in the database. Do not store a plaintext DEK or the KEK next to the row.

The reference uses AES-256-GCM with a fresh 256-bit DEK and 96-bit random nonce. It binds the expected tenant, table, record, field, purpose and record version to additional authenticated data. Key metadata is authenticated too. Copying a ciphertext into a different row or field must fail, rather than decrypting under a new authorization context.

The application must authorize the row and field before requesting KMS unwrap. The module also requires a trusted authorization callback before use; that callback is not a substitute for correctly authenticated request identity and SQL isolation. Supply expected row identity from the authorized server context, never simply echo identity from an attacker-controlled envelope.

Use an allowlist of immutable KMS key references and the expected encryption context. A database-controlled key ID must not direct the runtime to an arbitrary account, key, endpoint or alternate tenant's key. Prefer workload identity and narrowly scoped KMS permissions over static credentials. Separate key administration from encrypt/decrypt use and audit KMS operations without logging plaintext, tokens, DEKs or confidential search values.

KMS encryption context is authenticated metadata, not a secret channel. Providers may put it in audit logs. Use opaque identifiers and a nonsecret purpose string; do not include names, email addresses, document contents or other PII. The example's local test provider validates crypto contracts only; it is not an HSM or a live cloud KMS.

## Rotation, queries and recovery

New writes can use a new allowed key while old rows remain readable through explicitly permitted historical keys. Rotating a provider's key material does not automatically re-encrypt every database field or delete old wrapped keys. Define a bounded migration: authorize each row, unwrap through its approved old key, encrypt under the new key/context, atomically replace the envelope using a row version, and verify decryption before retiring old access. This reference does not implement an automatic migration service.

Encrypted fields are not ordinary searchable columns. Randomized encryption hides equality but prevents normal plaintext equality/range indexes. If a justified design needs a keyed search token, use a separate purpose-scoped HMAC key, include tenant and field scope, and document equality/frequency leakage and normalization rules. Do not use unsalted hashes of email addresses or phone numbers as confidentiality protection. Keep search permissions separate from decrypt permissions.

Database backups must include ciphertext and required key/version references, while KMS key recovery and deletion protection follow a separate controlled process. Test restore with authorized access to old key versions. Losing the only KEK can make backups unreadable; deleting a key is a destructive operation, not an ordinary rotation step. Apply fresh step-up approval and independent recovery checks.

## Replay protection across instances

**Replay protection is only effective when nonce uniqueness, expiration, and replay-state enforcement remain consistent across instances.** A unique nonce in a process-local map cannot arbitrate two servers. Two replicas performing a read-then-write check can both accept the same request.

After validating the signature, audience, key status, exact method/path/body and timestamp window, consume `(audience, key identity, nonce)` atomically in a shared authoritative write store. Include the key namespace in identity; do not reuse a key ID across different principals accidentally. A unique constraint with `INSERT ... ON CONFLICT DO NOTHING` or an equivalent atomic conditional write must decide acceptance. A cache miss or unavailable store is not authorization.

Keep used nonces until no instance could accept the signed request, including allowed future timestamps and clock tolerance. Expiration and pruning must use the same authoritative time policy as acceptance. A slow instance must not accept an old request after a faster instance has pruned its nonce. Sample the authoritative clock after serialization/locking; reject backward time according to the documented policy. Do not accept caller-supplied `now` as trusted time.

The PostgreSQL example demonstrates a shared primary, constrained nonce consumption and cross-connection arbitration. The existing SQLite examples use a shared file with transactions and a persisted clock guard: suitable for tested same-host connections, not a substitute for a multi-host database service or an SQLite file on an arbitrary network filesystem. Separate `:memory:` stores provide no cross-instance replay protection.

Replicas must use consistent windows, protocol/audience versions, key revocation state and configuration. Read the replay decision from the write primary. Failover, async replication loss, restoring an old backup, deleting replay state, disabling persistence and evicting entries can reopen a replay window. Test these operational scenarios under your actual database topology. Time synchronization remains necessary; a clock guard is not an NTP service.

Nonce consumption also is not durable business idempotency. A retried payment or deletion with a new nonce still needs an action/argument-bound operation ID and durable result handling. A database rollback cannot undo an external effect that already occurred. Separate exactly-once admission, transaction semantics and external-effect reconciliation in the design.

## Deployment and evidence

Keep database and KMS network access private, authenticate server certificates, restrict source workloads and DB roles, and apply resource/statement limits. Plan migrations, RLS policy changes and key grants with rollback and least-privilege checks. Re-run tenant isolation, field projection, authorization-before-decryption, tamper detection and replay races after relevant schema, driver, pool, identity or failover changes.

Use the [database lab](../lab/database.README.md) for actual PostgreSQL tests and `node --test reference/field-encryption.test.mjs` for crypto/provider-contract fixtures. A passing isolated lab validates its exact fixtures; production IAM, KMS policy, TLS, replicas, backups and application authorization require environment-specific verification.

## Primary references

- [PostgreSQL row-security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html): policy evaluation, default deny and bypass limitations.
- [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html) and [CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html): column privileges and invoker views.
- [OWASP Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html) and [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html): database hardening, limited roles and bound values.
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) and [Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html): authenticated encryption and key lifecycle.
- [AWS KMS envelope encryption](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping) and [encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html): a provider example of wrapped DEKs and nonsecret authenticated context.
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final): GCM; [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final): key management; [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final): AC-3/AC-6, SC-12/SC-13/SC-28 and SC-23 control areas.

References describe applicable mechanisms and limits; they are not certification or a complete compliance assessment.

## Engine advisories and object-creation rights

Use [Database-engine patching](DATABASE-ENGINE-PATCHING.md) to inventory and update the actual server binaries, including replicas and dormant images. RLS, narrow columns and parameterized SQL isolate data and query structure; they do not patch native database-engine defects. PostgreSQL CVE-2026-116331 and the separate CVE-2026-6460 require the applicable vendor-fixed server even when application roles are narrow. Follow the patching guide for CVE-2026-6460 C-language extension rebuilds and effective `composite_type_mismatch=error`; reduced object-creation rights do not replace those upgrade conditions.

Review effective database TEMPORARY/CREATE, schema CREATE and CONNECT rights, including PUBLIC and inherited roles. Remove creation rights not required by runtime identities, preserve only needed connections, and test applications that legitimately need temporary objects. These restrictions compensate for exposure and reduce privilege; they are not a documented substitute for an engine fix. The synthetic lab checks the 17.12 minimum and denied creation alongside permitted tenant CRUD/replay.
