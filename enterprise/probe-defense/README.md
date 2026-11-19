# Defensive request admission and disclosure helpers

This optional Node.js 22/24 standard-library reference limits repetitive requests in an application you operate. It does not identify AI, prove malicious intent, stop every penetration test, or replace authorization, WAF rules, infrastructure limits, replay controls, or incident response. Nothing is activated by importing it. Tests use synthetic data and local temporary databases; no target is probed.

```sh
node --experimental-sqlite --test enterprise/probe-defense/probe-defense.test.mjs
```

## Trusted application integration

Import `createProbeDefense`, `genericDenial`, `createCanaryHandler` and `createSecurityTxt` from `probe-defense.mjs`. Construct one admission instance per application worker with the **same protected local database**, policy, capacity, 32-byte host-protected HMAC key and key version. The key is copied; callers retain responsibility for clearing their supplied buffer. Never commit the key or pass it in chat, CLI arguments, environment or logs. Provision it using your reviewed protected consumer. This module does not load secrets or enforce filesystem permissions.

Example policy shape (tune values to the application):

```js
const policy = {
  version: 'admission_v1',
  routes: {
    read: {
      allowAnonymous: false,
      global: { limit: 1000, windowMs: 60000 },
      source: { limit: 100, windowMs: 60000 },
      tenant: { limit: 200, windowMs: 60000 },
      subject: { limit: 60, windowMs: 60000 },
      session: { limit: 30, windowMs: 60000 }
    }
  }
};
// protectedDatabasePath and protectedKeyBuffer come from reviewed host configuration.
const admission = createProbeDefense({ databasePath: protectedDatabasePath,
  key: protectedKeyBuffer, keyVersion: 'key_v1', policy, maxBuckets: 100000 });
const result = admission.admit({ routeClass: 'read', sourceRef: socketSourceOpaqueRef,
  auth: { tenantRef: verifiedTenantRef, subjectRef: verifiedSubjectRef, sessionRef: verifiedSessionRef } });
if (!result.allowed) {
  const response = result.reason === 'limited'
    ? genericDenial(429, result.retryAfterSeconds) : genericDenial(403);
  // Send only response.status, response.headers and response.body using your HTTP adapter.
} else {
  // Perform the separately authorized operation; admission is not authorization.
}
// On orderly application shutdown:
admission.close();
```

Inputs are a trusted boundary. The server router assigns a canonical route class before admission; unknown classes fail closed. The host derives a stable opaque source reference from the actual socket source or a verified trusted-proxy adapter. Authentication supplies a globally unique canonical opaque tenant reference and canonical subject/session references (1–128 ASCII letters, digits, `_` or `-`). Subject buckets include the tenant; session buckets include the tenant and subject. Reusing a tenant-local subject label across tenants or a subject-local session label across subjects cannot merge their quotas. Preserve those identities across IP changes; do not accept arbitrary new aliases per request. Do not pass raw IPs, URLs, emails or tokens. HTTP headers, user agents, forwarded-IP claims, client JSON and model assertions do not establish these inputs. Authenticated requests require all three identity dimensions. Every route must explicitly configure `allowAnonymous`: `false` rejects `auth: null`; `true` permits it only on deliberately public routes, where global and source limits still apply. Missing/nonboolean flags invalidate the policy. Never downgrade failed authentication to an authenticated route's anonymous budget. Request cost is fixed at one; extra fields, including client-provided cost, are rejected.

Every decision uses `BEGIN IMMEDIATE` on SQLite: check all applicable budgets before incrementing any. A refused request consumes no quota; trusted last-seen time and expired-bucket cleanup may still advance. Each route class has independent global/source/tenant/subject/session fixed windows. IP rotation still meets identity budgets; account rotation still meets source/global budgets. Boundaries permit bursts across adjacent windows; this is not a sliding-window limiter. The returned positive Retry-After covers the latest reset among exceeded budgets.

State survives ordinary reconnects/restarts against the same database. A persisted trusted clock watermark rejects clock rollback. Policy, key bytes/version and capacity are bound at initialization; changing them requires an operator-reviewed cutover, not deleting/resetting state to bypass limits. The database, backups, metadata and application clocks must be protected against rollback/tampering. Restore/failover needs explicit state continuity and clock reconciliation. HMAC bucket IDs reduce direct identity exposure but do not hide activity volume or protect a stolen key. Expired buckets alone are removed; reaching the configured live-bucket cap fails closed without live eviction. SQLite storage/lock errors deny requests; public results contain no SQL, path or identity. Initialize failures throw only a fixed message. Always deny on unavailable results; never silently switch to local in-memory counters.

This is same-host local-file admission. Do not use SQLite on a network filesystem or independently replicated files. Multi-host deployments need one authoritative service that atomically reserves **all** applicable dimensions, synchronized trusted time, policy/key continuity and tested recovery. The [distributed admission reference](../distributed/README.md) covers separate primary-store operation/replay contracts; it is not a drop-in five-dimension adapter. Multiple independent Redis checks do not implement this atomic contract. Admission is not effect idempotency or replay protection; retain the existing operation-bound replay controls separately. The tests demonstrate local concurrent connections, not production failover or distributed performance.

## Uniform ordinary denials and optional inert canary

`genericDenial(403|404|429, retryAfterSeconds?)` preserves the actual HTTP status and uses the same fixed JSON body and `Cache-Control: no-store`. Retry-After is permitted only for 429. Status, timing, routing and headers can still differ; this is not a side-channel elimination claim.

An optional canary is a privately configured **inert route in your own application**. Keep the actual canary registry outside Git; public examples are not secret signals. Its trusted adapter matches the configured route and calls:

```js
const handleCanary = createCanaryHandler({ canaryId: privateOpaqueCanaryId,
  emit: trustedLocalAlertEmitter });
const { response, delivered } = await handleCanary({ sourceRef: socketSourceOpaqueRef });
// HTTP: serialize ONLY response. delivered is a trusted operator diagnostic.
```

The handler returns the ordinary generic 404 after the emitter settles, including when it fails. Delivery is confirmed only when the emitter resolves exactly `true`; `false`, `undefined`, rejection and invalid source references report `delivered: false`. The emitter receives only `type`, opaque `canaryId` and opaque `sourceRef`; no raw IP, path, query, arguments, credentials or request payload. Supply a bounded trusted local emitter and its own retention/access policy; enforce a request deadline in the host. This handler awaits that emitter, so an unbounded sink can stall it and response timing is not guaranteed equivalent. The module provides no network sink, automatic ban, external callback, decoy credential, revenge prompt, tarpit or action against the requester. A hit is a review signal, not proof of malicious intent. Missing delivery needs operator attention; do not expose delivery state over HTTP.

## Generate a conservative security.txt profile

This generator implements a deliberately narrow [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html) profile, not a general RFC validator: one simple `mailto:` contact, UTC second-precision future expiry no more than 365 days ahead, canonical HTTPS `/.well-known/security.txt`, HTTPS policy URL, English preferred language. URI credentials, query/fragment, whitespace and percent escapes are rejected. The function uses explicit trusted `now`, performs no network requests and writes no files.

Run from the repository root to print a synthetic example with a 90-day expiry:

```sh
node --experimental-sqlite --input-type=module -e "import {createSecurityTxt} from './enterprise/probe-defense/probe-defense.mjs'; const now=Math.floor(Date.now()/1000)*1000; console.log(createSecurityTxt({contact:'mailto:security@example.com',expires:new Date(now+90*86400000).toISOString().replace('.000Z','Z'),canonical:'https://example.com/.well-known/security.txt',policy:'https://example.com/security-policy',preferredLanguages:'en',now}));"
```

Use an actual monitored disclosure address and approved policy before publishing. **The existing Nginx configuration denies `/.well-known` paths.** Generation does not publish the file. Publication needs a narrowly reviewed exception for the exact security.txt route, preserving other protected paths, and HTTP target checks for routing, content type, normal/error headers, access/rate behavior, canonical URL and reachable policy/contact. No Nginx exception or deployment is included here.
