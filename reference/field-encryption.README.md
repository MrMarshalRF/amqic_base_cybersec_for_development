# Field envelope encryption reference

`field-encryption.mjs` is a dependency-free Node.js 22/24 reference using built-in AES-256-GCM. Run `node --test reference/field-encryption.test.mjs` from the repository root. Tests use real cryptography and a synthetic in-memory KMS implemented only in the test file. They do not establish a working cloud KMS deployment, IAM configuration, database integration or production readiness.

For each field write, the trusted KMS port generates a fresh random 256-bit data encryption key (DEK). The module encrypts at most 1 MiB with that DEK and a fresh random 96-bit nonce, and stores only ciphertext, its 128-bit authentication tag, the nonce, a wrapped DEK and key metadata. The key encryption key (KEK) stays in the KMS. Distinct field writes require distinct DEKs even for identical plaintext. A compromised application with decrypt permission can still read authorized plaintext.

## Application API

```javascript
import { createFieldEncryption } from './field-encryption.mjs';

const fields = createFieldEncryption({
  kms: trustedKmsPort,
  keyId: configuredCanonicalWriteKeyId,
  allowedKeyIds: configuredCanonicalReadKeyIds,
  authorize: async ({ identity, operation }) => {
    // Trusted application policy checks the current principal, tenant, row,
    // field and operation. Return strictly true only when access is current.
    return trustedFieldPolicy(identity, operation);
  }
});

// Derive these values from the authorized server-side row and schema mapping.
const identity = {
  tenant: authorizedRow.tenant_id,
  table: 'contacts',
  record: authorizedRow.id,
  field: 'private_note',
  purpose: 'contact-service',
  version: authorizedRow.encryption_version
};
const envelope = await fields.encryptField(plaintextBuffer, identity);
// Store JSON.stringify(envelope) through a parameterized database query.
// After a separately authorized row read:
const plaintext = await fields.decryptField(storedEnvelope, identity);
```

Identifiers must all be nonempty strings of at most 256 UTF-16 code units without ASCII control characters. Convert trusted database identifiers to strings explicitly at the schema boundary. The identity has exactly these six own enumerable data properties and an ordinary or null prototype. `version` is the application's immutable encryption identity version, separate from envelope `format` and KMS `keyVersion`. If it represents a mutable row revision, updating that revision requires decrypting under the old trusted identity and encrypting under the new one. Identity is an unambiguous JSON array in fixed order; delimiter concatenation is not used.

Plaintext input and output are `Buffer` values; strings and typed arrays are rejected. The caller controls text encoding and must avoid logging plaintext. `encryptField` accepts an empty buffer. Both methods snapshot caller inputs before awaiting authorization or KMS operations. Caller plaintext and port-owned key buffers are not overwritten. The returned envelope is frozen and can be serialized as JSON. Strict envelope validation rejects unknown fields, accessors, custom prototypes, invalid algorithms/format, malformed or noncanonical standard base64, excessive sizes and disallowed key IDs before unwrap. Enforce transport/JSON body limits before parsing untrusted input; this API does not accept an unlimited serialized document.

The required asynchronous `authorize` callback receives a frozen identity and operation `encrypt` or `decrypt`; only strict `true` permits the KMS call. Omitted callbacks fail construction. Denials and exceptions fail closed. Supply the caller's **trusted expected** identity, never an identity copied from the untrusted envelope/request. Read the row through correctly scoped SQL and database authorization first. This callback is defense in depth, not a substitute for PostgreSQL RLS, user/session authorization or checking field-level permissions. It does not by itself prevent authorization revocation races; applications needing transactionally current authorization must coordinate policy, row access and key access appropriately.

Each operation failure has `FieldEncryptionError`, code `field_encryption_failed` and message `Field encryption operation failed`, with no underlying provider error or plaintext. Map it to a safe transport failure; do not expose detailed provider errors. Invalid startup configuration throws `TypeError`. This reference does not provide constant-time external error handling, admission limits, KMS timeouts/cancellation or audit transport; those belong to the trusted application/port.

## Trusted asynchronous KMS port

Implement these two methods with your selected provider's maintained SDK or protected service:

```text
generateDataKey({ keyId, context })
  -> { keyId, keyVersion, plaintextKey: Buffer(32), wrappedKey: Buffer }
unwrapDataKey({ keyId, keyVersion, wrappedKey: Buffer, context })
  -> plaintextKey: Buffer(32)
```

`generateDataKey` must generate a new cryptographically random 32-byte DEK on every call and wrap it using the requested KEK with the exact authenticated `context`. It must return exactly the four listed data fields. `wrappedKey` must contain 1..16384 bytes. `keyVersion` must be a nonempty control-free string of at most 256 code units identifying the actual KEK version used. Provider-generated key material must never be serialized into application output. Neither method may log raw keys or plaintext. No actual provider client or credentials are included.

`keyId` is a canonical, stable trusted identifier of at most 1024 code units. The configured write ID must also be in the explicit startup allowlist of at most 64 readable IDs. The generated result must return that exact canonical ID. If a provider returns an alias/ARN/resource name in a different form, the trusted adapter must verify its mapping to the configured resource before returning the configured canonical ID. Do not add wildcards, trust aliases from envelopes, or silently expand the read allowlist.

`unwrapDataKey` must enforce the **trusted retained key-version policy** for the allowlisted key ID; the module accepts bounded version metadata and authenticates it, but does not maintain a version allowlist itself. Never interpret envelope IDs/versions as arbitrary URLs, endpoints, projects or credentials. Resolve only configured resources. Use separate runtime identities and minimum grants for writers/readers where the provider permits it. Rate limit and audit operations, bound network timeouts and responses, and fail closed on provider failure. This reference deliberately has no DEK cache. If an application adds one, it needs separate authorization, expiry, revocation and memory-exposure review.

The `context` has exactly `{domain, binding}`. `binding` is SHA-256 of a domain-separated canonical array containing envelope format, configured canonical key ID and full expected identity. Bind this exact context on wrap and unwrap with provider encryption-context/AAD support (or an equivalently authenticated wrapping layer in the trusted adapter). The context avoids raw tenant/record/field values in KMS logs. A deterministic hash is still correlatable and potentially guessable; it is not anonymization. Use nonsecret opaque identifiers and assess the provider's audit metadata rules.

The AES-GCM payload AAD authenticates the protocol domain, format, algorithm, canonical key ID, KEK version, full wrapped DEK and expected identity. Replacing row/tenant/field identity, header, wrapped key, nonce, ciphertext or tag fails authentication. The module does not encrypt metadata, ciphertext length or access patterns. Authentication prevents undetected modification, not replay of an older valid envelope for the same identity. Use trusted monotonic version/state and restore protection where rollback resistance is required.

The port retains ownership of buffers it returns. The module immediately copies DEKs and overwrites its own copies in `finally`; it also clears its copied plaintext input and tentative unauthenticated plaintext. The port is responsible for its retained buffers. JavaScript, V8 and native crypto may make other copies, so complete memory zeroization cannot be guaranteed. Minimize key/plaintext lifetime, disable sensitive dumps/logging and isolate the runtime appropriately.

## Rotation and recovery

Rotate the configured writer to an approved new canonical key/version; retain explicitly authorized old read IDs and KMS versions while old envelopes still exist. Tests cover both retained versions and changed writer IDs. Remove old grants only after migration and recovery verification. Retired/unavailable versions and a provider outage fail closed.

Changing only `wrappedKey`, `keyId` or `keyVersion` in stored JSON is invalid because the payload AAD authenticates them. This reference has **no rewrap-only API** and does not automatically migrate existing data. A migration must read and authorize the old row/identity, decrypt, encrypt with a fresh DEK under the new writer configuration, then conditionally replace the exact old row revision in a transaction. Review migration concurrency, audit, retries, rollback protection and backup/key retention separately; do not log intermediate plaintext. Verify recovery using isolated synthetic/restored test data before retiring keys. Loss of every retained decrypt-capable KMS version makes the corresponding data unrecoverable.
