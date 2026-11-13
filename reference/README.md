# Executable security core

A standalone example of server-side checks for Node.js 22.14.0. There are no npm dependencies. The `node:sqlite` store is experimental in this Node.js version. Known async core adapters and tool callbacks are rejected during construction. Unexpected Promise results are observed and rejected synchronously, preserving the synchronous contract and preventing unhandled rejection of that result. This does not cancel external effects already initiated by invalid trusted code. The code uses synchronous SQLite transactions and performs the `login → password → CAPTCHA → TOTP → session` sequence on the server. There are no switches for disabling stages.

## Local execution

Run these commands from the `reference` directory.

```powershell
node --experimental-sqlite demo.mjs
node --experimental-sqlite --test core.test.mjs login-client.test.mjs pii-input.test.mjs
```

The demo creates temporary in-memory state, a synthetic user, an Ed25519 key, and one synthetic record. Through the core's public methods, it performs login, separate TOTP confirmation, a signed call to an allowed tool, and a retry with a new nonce. The expected result contains `login="completed"`, `first.removed=1`, `retry.removed=1`, `sameResult=true`. The saved response is returned again; the handler is not executed again. No network server is started.

`fixtures.mjs` contains only test CAPTCHA and factor adapters, a known synthetic password, and a seed from RFC 6238. This file and `demo.mjs` are intended for local learning. For an application, create your own adapters under the contracts below and import `core.mjs` and `crypto.mjs`.

## Files and API

| File | Purpose |
| --- | --- |
| `crypto.mjs` | Restricted JSON serialization, SHA-256, Ed25519, scrypt, and TOTP |
| `core.mjs` | SQLite, login stages, sessions, rate limits, keys, grants, allowed tools |
| `upload-pipeline.mjs`, `clamd-client.mjs` | Working quarantine/promotion and real ClamAV protocol; see [the lab](../docs/REPRODUCIBLE-LAB.md) |
| `admission.mjs` | Standalone bounded PoW, durable replay store and fixed Redis limiter; see [admission](../lab/admission.README.md) |
| `pii-input.mjs`, `pii-input.test.mjs` | Contact-form schema validation and parameterized SQLite storage with injection regression tests; see [web input protection](../docs/WEB-INPUT-PROTECTION.md) |
| `login-client.mjs` | Embeddable headless controller for the login sequence |
| `fixtures.mjs`, `demo.mjs` | Synthetic adapters and an end-to-end example |
| `core.test.mjs`, `race-worker.mjs` | Checks and a concurrency test using separate SQLite connections |
| `login-client.test.mjs` | End-to-end login through the controller, cancellation, stale responses, and transport errors |

Creating the core requires `new SecurityCore({ database, audience, captcha, factors, clock, tools })`. `database` specifies a SQLite file or `:memory:`. Preserving security state across restarts requires a file on reliable local storage. `clock` returns trusted integer Unix time in seconds. System time is used by default. Time moving backward relative to the stored maximum causes the operation to be rejected.

The operator methods `provisionUser`, `registerKey`, `revokeKey`, and `revokeUser` are available only to trusted application code. They must not be exposed directly as HTTP/MCP endpoints. `seedSyntheticRecord` is for the demo. `revokeUser` disables the user, increments the epoch, revokes keys, and deletes their active tickets, sessions, and grants.

Normal login goes through `login(identity, source)`, `password(ticket, password, source)`, `captcha(ticket, proof, source)`, and `secondFactor(ticket, code, source)`. Each stage response contains a new single-use ticket. The successful final stage returns `session` and `expires`. `logout(session)` revokes the session and its grants. Tickets and sessions are stored as SHA-256 verifiers of random 256-bit values. Tickets expire after 180 seconds; sessions after 900 seconds.

Unknown and existing logins receive the same shape of initial response. Invalid passwords are checked through scrypt, including a dummy record for an unknown user. Password hashing uses an independent random salt, `N=32768`, `r=8`, `p=1`, and a 32-byte result. The external handler must return a uniform failure response without internal exception details. Checking the response shape does not prove that all timing side channels have been eliminated.

## Integrating the login form

`LoginClient` from `login-client.mjs` connects to an existing interface without a UI-framework dependency. The constructor accepts `transport` and `onState`. Calling `submit(value)` sends the value for the current stage. `reset()` starts a new attempt and signals cancellation to the previous transport. `state` and `onState(state)` contain only `step`, `busy`, and `error`. The possible stages are `login`, `password`, `captcha`, `totp`, and `authenticated`. Errors use the generic code `request_failed`. State observers are notification callbacks. Their exceptions and rejected promises are contained so that presentation failures cannot leave the controller busy or change its authentication result. A reset performed during a success notification makes that submission return `false`. Passwords, CAPTCHA proofs, TOTP codes, tickets, and sessions are not passed to the render callback.

```javascript
import { LoginClient } from './login-client.mjs';

const login = new LoginClient({
  transport: authenticationHttpAdapter,
  onState: state => updateExistingForm(state)
});

const pending = login.submit(readCurrentFieldValue());
clearSensitiveField();
await pending;
// The new-attempt button calls login.reset().
```

`authenticationHttpAdapter({ step, value, ticket }, { signal })` is an asynchronous adapter for your HTTPS API. It maps the four known `step` values to fixed endpoints in your application, passes `AbortSignal`, uses cookies under the application's rules, and returns validated responses. For the first three stages, the response contract is `{ next: 'password' | 'captcha' | 'totp', ticket }`; only the expected next stage is allowed. For the final stage, the server sets the session through a protected `HttpOnly` cookie, and the adapter returns `{ authenticated: true }`. The raw session token does not enter the client controller. The server adapter calls the corresponding `SecurityCore` method, computes the trusted source itself, and converts the `secondFactor` response into a cookie and safe status.

The controller keeps only the current opaque ticket in a private in-memory field. It does not use localStorage, logging, or password/code storage. The transport and form must also follow these restrictions. Resubmission while a request is pending is rejected. After `reset`, late success and failure responses from the old attempt are ignored. Cancelling the client wait does not undo an already completed server action; server-side logout/revocation is performed through a separate authorized endpoint when needed.

In the existing form, use an identifier field with `autocomplete="username"` for `login`, a password field with `autocomplete="current-password"` for `password`, the selected provider's official widget with server-side verification for `captcha`, and a string field with `inputmode="numeric"` and `autocomplete="one-time-code"` for `totp`. Preserve leading zeros in TOTP codes. Show and submit only the current stage, block resubmission while `busy`, and clear sensitive values after passing them to the transport and when starting a new attempt. The server enforces authorization and mandatory stages.

## Trusted adapters

### CAPTCHA

`captcha.verify({ proof, challenge, source, now })` synchronously returns strictly `true` only after trusted verification of the provider result. `challenge` is the hash of the current server-issued ticket; `source` is the hash of a trusted source identifier. The adapter must check the action, hostname/audience, expiry, challenge binding, and single-use property. Login is rejected if the provider is unavailable.

Most providers operate asynchronously. Perform their network verification in advance in the HTTP adapter, save a short-lived verified receipt in a trusted local layer, and pass a reference to the core. Synchronous `verify` reads and consumes this receipt once, checking the challenge. A browser boolean, arbitrary string, or JSON flag is not a verified receipt. Network calls inside a SQLite transaction are prohibited. If the receipt has already been consumed and the transaction rolls back, the user must complete a new CAPTCHA.

### TOTP enrollment and storage

`factors.assertEnrollment({ id, factorRef })` returns strictly `true` for a user-to-factor binding already verified by the operator process. Before that, enrollment must verify ownership of the new factor and the user's protected identity. `factorRef` is a nonsecret identifier. `factors.secretFor(factorRef)` synchronously returns a `Buffer` of at least 20 bytes from a protected store. The seed is not written to SQLite, responses, logs, or reports.

The core uses six-digit HMAC-SHA1 TOTP with a 30-second period, a ±1 window, and a single persisted last-accepted counter per user. The counter is updated atomically. A code used for login has already been consumed. Wait for the next code for step-up. The same reuse prohibition applies across different sessions of the user.

Seed enrollment/delivery, backup codes, and account recovery are the application's responsibility. Recovery must verify separate trusted evidence, revoke old sessions, keys, grants, and tickets, verify the new factor, and only then restore access. The existing `revokeUser` performs disabling and revocation. The core has no automatic user re-enabling or TOTP bypass. Restoring SQLite from a backup requires an external monotonic epoch/incarnation and revocation of old keys/sessions because the backup may restore previously consumed nonces and counters. The built-in clock guard does not protect against rollback of the store itself.

### Request source and HTTP

The server supplies `source` from trusted transport information. The client cannot choose it through JSON or an unverified `X-Forwarded-For`. Configure trusted proxies and network boundaries. The core stores rate limits by source, identity, and step-up user. The external server must additionally limit total RPS, request size, concurrency of expensive scrypt operations, queues, and memory use. Synchronous scrypt blocks the event loop, so handling load requires a bounded pool and a coordinated SQLite access model.

HTTP integration must provide TLS, exact routing, body limits before reading, uniform external failures, protected cookies with `Secure`, `HttpOnly`, and suitable `SameSite`, CSRF/origin protection, allowlisted CORS, and no tokens/passwords in URLs or logs. Do not store the session token in browser localStorage. Logs contain fixed events and identifiers, without passwords, seeds, CAPTCHA proofs, signatures, session/grant tokens, or full request bodies.

## Signing machine requests

`signRequest(privateKey, { keyId, method, target, audience, timestamp, nonce?, body })` creates an Ed25519 signature. The private key remains with the trusted client; the operator registers the public key. A key supplied in a request is not trusted automatically. `timestamp` is integer Unix time in seconds, `body` is a `Buffer`, and `nonce` is a random single-use identifier. If omitted, the nonce is generated as a random 256-bit value.

The signature covers the protocol domain, key ID, method, exact origin-form target with the original query string, audience, time, nonce, and SHA-256 of the original body bytes. A time skew of ±30 seconds is allowed. A persisted unique index on `(key_id, nonce)` together with `BEGIN IMMEDIATE` prevents concurrent replay acceptance. `verifyRequest(request, scope)` also checks key revocation, user status, and the intersection of key and user scopes. The transport must construct `method`, `target`, and `body` from the request actually received, preserving bytes before parsing and not trusting duplicate values supplied in the body.

The `canonical` serializer defines a restricted JSON format with sorted keys, depth up to 32, safe integers, and ordinary JSON values. The format does not support fractional numbers, `undefined`, sparse arrays, or custom classes. A compatible client must reproduce this format. Tool calls require the original body bytes to match the serialization encoded as UTF-8 exactly. Malformed UTF-8, alternative whitespace, and duplicate fields are rejected.

## Confirming sensitive actions

`stepUp({ session, action, args, operation, code })` issues a 60-second grant after a fresh TOTP code. The grant is bound to the user, specific session, action name, SHA-256 of canonical arguments, and `operation`. For each new logical change, the client creates a unique, stable `operation`, preserving that value and the arguments on retries. After session renewal, the completed operation's result remains available to the same user under the previous `operation` with current successful authorization.

`dispatch(request)` accepts signed `POST /tools/call`. The body contains exactly `action`, `args`, `grant`, `operation`, and `session`. Checks cover the session, allowed tool, argument validation, user and key scopes, nonce, and grant. Grant consumption, the SQL change, and recording the result in `operations` take place in one transaction. A retry with a new nonce and the previous `operation` returns the saved result. Changed action/arguments with the same `operation` are rejected. If the local transaction fails, its SQL changes, grant, and nonce are rolled back.

`tools` is a fixed object created by trusted code at startup. Each descriptor contains `scope`, `stepUp`, `validate(args)`, and `handler({ database, userId }, args)`. The handler synchronously modifies only this SQLite database and returns a serializable result. A Promise is rejected. The integration contract prohibits network calls, shell execution, external files, and changes to other databases inside the handler. External effects require a separate durable outbox/job protocol that handles unknown outcomes. The JavaScript Promise check does not undo a side effect already performed by external code. Independently review a new handler's code before connecting it.

The built-in `records.remove` deletes only a synthetic record belonging to the user. There is no general command executor, arbitrary SQL from requests, or access to real administrative operations.

## MCP boundary and integration readiness

`dispatch` and `listTools` are internal methods of the allowed tool catalog. A complete MCP/JSON-RPC transport, initialization, protocol negotiation, `tools/list`, `tools/call`, OAuth, and HTTP middleware are not implemented in this directory. An MCP adapter must map validated protocol parameters to this core and authorize the transport separately. The custom Ed25519 signature serves the internal machine API. When exposing an MCP HTTP endpoint, follow the current MCP authorization specification.

Concrete integrations still required before adoption include CAPTCHA, protected key and TOTP storage, enrollment/recovery, HTTP/MCP transport, external audit, monitoring, backups, and retention management. The SQLite schema is intended for a new store for this example; migrations for existing product databases are absent. `operations`, rate limits, and expired tickets/sessions/grants require a retention policy. Deleting idempotency records permits replay of an old operation ID, so their retention period must align with the business retry contract. Tests establish the listed local properties and SQLite-connection concurrency; operational load validation and application-specific integration checks are separate work.
