# One-use account recovery reference

This standalone server-side module implements a cryptographic recovery-token
lifecycle using Node.js built-ins and SQLite. It does **not** reset a password,
change an email address, enroll a factor, revoke a session, send mail, or integrate
with `SecurityCore`. A returned claim establishes one committed local recovery
admission only. It is not a reusable bearer credential or a completed account change.

Run the synthetic tests from the repository root:

```sh
node --experimental-sqlite --test enterprise/recovery/recovery.test.mjs
```

## Trusted identity and operator API

Create `RecoveryStore({ database })` only in trusted host code. Protect its local
database file and its containing directory from untrusted users and agents. All
workers must use the same durable file on reliable local storage; separate
`:memory:` databases do not share state. A network-mounted SQLite file is outside
this reference's tested scope. Do not expose the class or operator methods as
unauthenticated request endpoints.

Bindings are plain data objects containing opaque `tenantId`, `subjectId`, and
integer `securityEpoch`. The host derives these from its current verified account
registry and recovery identity evidence, never from an unverified request's
claimed identity. Identifiers use 1–128 ASCII letters, digits, underscores or
hyphens. Names, addresses and other personal data do not belong in these bindings.

- `registerAccount(binding)` enrolls an account in this separate recovery registry.
  Re-registration is idempotent only at exactly the current epoch; it cannot reset
  or overwrite an existing epoch. This is an operator action, not user provisioning.
- `issue(binding, deliveryAdapter)` accepts exactly one of `password-reset`,
  `email-change`, or `factor-recovery` as `purpose`. `email-change` additionally
  requires `pendingChangeRef`, an opaque reference to a host-owned, already
  verified pending change. Other purposes reject that field. The adapter alone
  receives the raw token. The method returns only `{ issued: true, expires }`.
- `consumeOnce(token, expectedBinding)` requires the exact purpose, tenant,
  subject, pending reference and current epoch. The expected binding is trusted
  host context, not an echo of the token submission. It returns a frozen claim
  with `claimId`, `previousSecurityEpoch`, and the incremented `securityEpoch`.
  That increment and deletion of **all** outstanding recovery tokens for the
  account commit together before returning, preventing a second recovery purpose
  from succeeding at the old epoch.
- `bumpSecurityEpoch(binding)` conditionally increments the current epoch and
  invalidates every pending recovery token. The adopter must invoke equivalent
  invalidation for every password, email and factor change, including changes
  outside recovery. This reference cannot observe changes in another database.
- `close()` closes this connection. Every operation fails closed if the database
  is unavailable. Errors use the fixed `recovery_failed` message without input,
  SQL, path, delivery exception, or token details.

Do not link accounts by matching email addresses. For an email change, the trusted
pending record must bind the existing account, the exact proposed destination,
verification evidence and its own immutable revision. Resolve and conditionally
apply that **same** record in the adopter's transaction/outbox. A reference string
alone proves none of these facts. This module deliberately never accepts an email
address or performs account lookup by address.

## Token, time and resource controls

Tokens contain 32 cryptographically random bytes encoded as 43 canonical base64url
characters. SQLite holds only their SHA-256 verifiers, scoped metadata and expiry;
raw tokens remain transient in the trusted delivery path. No token is returned by
the ordinary issuance response, logged, or placed in a URL by this module. The
delivery and submission adapters must preserve those restrictions, including
redaction in proxies, telemetry, exception capture and browser history.

Default TTL is 600 seconds; configured TTL is limited to 1–900 seconds. Expiration
is strict: `now >= expires` is rejected. SQLite supplies time after `BEGIN IMMEDIATE`
serializes the operation. A persisted high-water mark rejects backward clock
movement across connections and restarts. A trusted test clock requires a distinct
`clockId`; it must never be supplied by request input. Time synchronization and
correct OS time remain operator responsibilities. Restoring an older database can
restore spent tokens and epochs; the clock guard cannot detect restoration of its
own state. Fence old stores and invalidate the recovery incarnation externally
before using a restored store.

One current token per account and purpose limits pending state; reissuance replaces
the previous token for that purpose. The default global outstanding-token cap is
10,000 and can only be configured down to a positive bound of at most 10,000.
Only expired rows are pruned for global capacity reclamation; a full store fails
closed rather than evicting unrelated valid tokens. The account registry is also
bounded (`maxAccounts`, default 10,000, maximum 100,000); accounts are not
automatically deleted. TTL, caps, schema policy version and clock identity are
persisted and must match on every subsequent connection. Changing them needs a
reviewed migration; reconnecting with weaker settings fails.

This module is not an ingress rate limiter. Before issuance and consumption, the
host must impose bounded attempts, issuance frequency, body size, queues and
concurrency using trusted source/account observations and shared admission state.
Use a uniform outward response for unknown and known identities, suppress internal
delivery/capacity distinctions, and assess timing/enumeration resistance in the
actual HTTP handler. A 256-bit token and storage cap do not establish those controls.

## Delivery, fulfillment and failure boundaries

The synchronous reviewed delivery adapter must return strictly `true`. It receives
a frozen `{ token, tenantId, subjectId, securityEpoch, purpose, pendingChangeRef,
expires }` object **after** issuance commits. Its input is secret-bearing. Use a
reviewed protected delivery mechanism and independently verify recovery identity;
token delivery alone does not establish sufficient identity proof for factor
replacement. Async adapters are rejected. An adapter failure revokes only that
exact token verifier where the database remains available; a delivered message,
already begun asynchronous work or an external effect cannot be rolled back.
An unavailable database can prevent revocation. Treat the resulting delivery
outcome as unknown, reconcile it, and never blindly resend or assume nondelivery.
Crash after issuance but before delivery may leave an undelivered token until expiry.

Consumption is a committed one-use reservation, not transactional fulfillment in
another authentication store. The caller must integrate account change, pending
record revision, recovery epoch, and revocation of old sessions/keys/grants/tickets
through one trusted transaction or a durable idempotent outbox protocol. The
reference's random claim ID is not a durable fulfillment ledger: it is returned
once and is not stored here. Crash after consumption or loss of the response burns
the token, with no automatic result replay. The adopter must durably record and
reconcile fulfillment or restart a separately authorized recovery flow; never retry
an external change based only on possession of an old claim. Serialize concurrent
ordinary account changes against the authoritative account revision. Do not mark
access restored until the actual change, new-factor verification where applicable,
epoch synchronization and revocation are confirmed.

No actual authentication integration, email provider, live identity proof,
distributed database, session revocation, failover/backup rollback protection,
production load test or full recovery service is supplied or established here.

## Executable synthetic example

Run this body as an ES module from the repository root, for example with
`node --experimental-sqlite --input-type=module`. It creates no real account,
sends no message and prints no token. Its in-memory delivery port represents only
a synthetic trusted recipient; it must be replaced with a reviewed integration.

```js
import assert from 'node:assert/strict';
import { RecoveryStore } from './enterprise/recovery/recovery.mjs';

const store = new RecoveryStore({ database: ':memory:' });
const account = { tenantId: 'synthetic_tenant', subjectId: 'synthetic_subject', securityEpoch: 1 };
store.registerAccount(account);
const expected = { ...account, purpose: 'password-reset' };
let deliveredToken; // Test-only trusted recipient memory; never log or serialize.
store.issue(expected, ({ token }) => { deliveredToken = token; return true; });
const claim = store.consumeOnce(deliveredToken, expected);
deliveredToken = undefined;
assert.equal(claim.securityEpoch, 2);
assert.equal(claim.purpose, 'password-reset');
// No password was changed. Integrate transactional fulfillment and revocation.
store.close();
```

The tests cover hash-only storage, positive recovery admission, exact context and
pending-reference matching, one-use consumption, cross-purpose invalidation,
operator epoch changes, strict expiry, rollback guard, restart, fixed policy,
capacity, reissuance, malformed inputs, delivery failures and simultaneous worker
connections. They establish these synthetic local properties only.
