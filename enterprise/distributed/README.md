# Distributed admission

Use one authoritative PostgreSQL or Redis primary for each quota domain. Replicas and workers share tenant state through that primary. The two backends implement the same fixed-window contract. Applications choose one backend for a tenant and generation.

## Wire the trusted request boundary

Call the adapter after the application authenticates the caller and authorizes the tenant, resource and action. See the [policy gate](../policy/README.md) and the [database isolation guide](../../docs/DATABASE-SECURITY.md). Use the same trusted authorization context for the actual effect.

```js
import { postgresAdmission, redisAdmission } from './admission.mjs';

// pg Pool.query or a dedicated autocommit pg client
const admit = postgresAdmission(pgPool);
// Alternative: node-redis client connected to the authoritative primary
const admitOnRedis = redisAdmission(redisClient);

const decision = await admit({
  tenant: verifiedTenant,
  generation: activeGeneration,
  policyDigest: verifiedPolicyDigest,
  operationId: durableOperationId,
  bindingDigest: canonicalActionDigest,
  window: originalAdmissionWindow,
  risk: riskDecision
});

if (decision.status !== 'granted') return deny(decision.status);
await applyAuthorizedEffect();
```

Bind the operation ID to the original trusted tenant, generation, policy, window and action in the service. Preserve those components on reconciliation. The request's window is the integer floor of UTC epoch milliseconds divided by the configured window length. Derive the proposed window from a synchronized server clock or a trusted issuance service. The store checks it against its own clock inside atomic admission. A request near a clock or window boundary may be refused with `window_changed`. Issue a new admission intent only for a genuinely new business operation.

Use an opaque ID and a digest of a canonical binding. Keep this binding free of secrets and personal data. Serialize security-relevant policy consistently and pin its SHA-256 at provisioning on every participating worker. Rotate the generation only through an authorized configuration cutover.

## Provision a tenant

Apply [postgres.sql](postgres.sql) to a dedicated schema via the migration role. Insert one row in `amqic_quota.tenant_state` with tenant, generation, policy_digest, window_ms, normal_cap and elevated_cap; state fields have defaults. Grant schema usage, function execution, and the row read and update rights used by the invoker function only to the trusted admission service principal. That principal can write the table directly, so isolate its credential and route writes through the reviewed adapter. Isolate tenant business data from this quota service principal.

Provision Redis key `amqic:quota:v1:<tenant>` through the operator path with **no expiry** and a JSON object such as:

```json
{
  "generation": "deployment_1",
  "policyDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "windowMs": 60000,
  "normal": 100,
  "elevatedCap": 25,
  "lastMs": 0,
  "window": 0,
  "elevated": false,
  "used": 0,
  "operations": {}
}
```

Use a dedicated authenticated TLS connection and a compatible ACL for the fixed script and namespace. Account for the trusted driver's ability to write the backing key. A missing, expired or malformed state fails closed. Provisioning a previously used tenant requires restoration or a fenced, explicitly reviewed cutover. Apply persistence and no-eviction settings and monitor storage availability.

## Concurrency, clock and replay

PostgreSQL serializes each tenant via a row lock and samples `clock_timestamp()` after acquiring it. Use autocommit and a writable primary. A function response inside an outer transaction is provisional until durable commit. Redis samples `TIME` inside one Lua evaluation and makes a single final state write. Each backend records the high-water clock and refuses backwards movement. Synchronize host time and monitor clock steps after failover. A large forward jump can advance a window early, so fence admissions during clock incidents.

The per-tenant budget is bounded to 1,000 accepted operations per window. Elevated risk is sticky within the active window. If the cap falls below usage, subsequent requests are refused. Accepted operations record their bindings for that window. An exact retry returns `duplicate`, a changed binding under the same ID returns `conflict`, and both deny a fresh grant. Prior-window replays fail the window comparison. Rate-limit denials are not persisted per operation because reaching the cap leaves it exhausted until the window ends. A `duplicate` proves an admission reservation exists in the current store, but any business action requires its own durable result reconciliation.

Valid same-window duplicate and conflicting retries still persist the trusted
clock watermark and latch an elevated risk observation. They do not consume
another slot or change the original binding. Later normal-risk requests remain
subject to the reduced cap for that window. Invalid requests, policy mismatches
and stale windows cannot mutate this state. The isolated integration exercise
checks these sequences against both stores.

## Recovery and failover

A timeout or ambiguous response returns `unknown` and yields no grant. Persist and reconcile the original intent. Never switch stores or renew its identifiers or window just to force another allowance. Keep admission separate from durable business fulfillment unless the two are atomically joined within the same authorized storage transaction.

For failover, fence the old writer and stop admission until the new primary has the expected generation, policy, quota ledger and clock state. Verify persistence and replication settings, authenticated routing to the new primary, and the last committed ledger state. Compare the deployment's required recovery point against actual replication acknowledgements. PostgreSQL asynchronous promotion and Redis replication can lose acknowledged writes. Redis WAIT can reduce the loss window but does not guarantee zero data loss or provide fencing. If continuity cannot be established, keep admission closed while reconciling pending effects and arranging a controlled reset. Do not automatically provision state after eviction or restoration from stale backup. Once failover is verified, run an isolated canary to check exact replay denial and budget conservation before reopening traffic.

[PostgreSQL date/time functions](https://www.postgresql.org/docs/current/functions-datetime.html) · [PostgreSQL standby and synchronous replication](https://www.postgresql.org/docs/current/warm-standby.html) · [Redis TIME](https://redis.io/docs/latest/commands/time/) · [Redis WAIT](https://redis.io/docs/latest/commands/wait/)

## Verify

```sh
node --test enterprise/distributed/admission.test.mjs
out=/absolute/new/external/output-directory
expected=$(node enterprise/distributed/integration.mjs --plan "$out" | node -e 'console.log(JSON.parse(require("fs").readFileSync(0,"utf8")).etag)')
node enterprise/distributed/integration.mjs "$out" "$expected"
```

The no-effect plan makes a strong SHA-256 ETag from canonical UTF-8 JSON with recursively sorted keys. It binds the fixture version, output path, the exact script and adapter bytes, and the pinned images. Pass that expected ETag before execution. The report checks source stability and records the accepted input ETag and a separate result ETag calculated over the canonical result without its ETag field.

The integration requires the preinstalled pinned images from the main lab. It uses two isolated synthetic containers with no published ports and no external network. It exercises twelve concurrent requests, verifies that exactly four receive grants, then checks replay, changed binding, generation mismatch, stale window, missing state and backwards-clock denial. It restarts PostgreSQL over an isolated durable volume to verify replay rejection across restart and restarts Redis with persistence disabled to verify missing-state denial. These exercises cover local restart and state loss, not replica promotion, partition fencing or production durability.
