# Enterprise authorization policy and tenant quotas

The same policy compiler validates the JSON in CI and provides the authorization rules used by the service. Each tenant declares a quota and exact allow rules for a method, path, resource kind, data classification and role. Missing rules deny access. The example covers resource operations with a known target. Authentication and request routing belong to the service adapter.

From the repository root:

```sh
node enterprise/policy/policy-cli.mjs --check enterprise/policy/example-policy.json
node --experimental-sqlite --test enterprise/policy/policy.test.mjs
```

A successful validation prints a SHA-256 of normalized policy semantics. Property order, tenant and rule order, and order within a role list produce the same digest. Changing a tenant quota, classification, path or role changes it. Load the CI-reviewed artifact from a trusted source at startup and pin its digest through your deployment configuration. The digest identifies policy content. The distribution mechanism authenticates it. Supply trusted, canonical JSON with unique object keys. Standard JSON.parse keeps the final value when an object repeats a key, so reject duplicate keys in your policy authoring pipeline. Protect the policy directory from concurrent untrusted writes.

## Call the gate at the point of authorization

Pass a request with an exact canonical service route, HTTP method and resource ID. The path grammar accepts root or lowercase ASCII segments. Reject ambiguous, encoded or redirected routes at ingress and use the same route identity in the router and the handler. If a route is parameterized, resolve it to a server-selected policy route and pass the resource ID separately. Use one unambiguous decoding policy throughout.

Wire these server-side adapters:

| Adapter | Contract |
| --- | --- |
| `authenticate(request)` | Verify the session or token and current membership. Return an authenticated tenant and subject with roles from your identity system. Treat tenant and role fields in request headers or bodies as untrusted. |
| `loadResource(context, target)` | Fetch authoritative ownership, kind and classification by tenant and resource ID. Scope the query by the verified tenant and use least-privilege database credentials. Use the request ID only as a lookup value. |
| `assessRisk(binding)` | Return `normal`, `elevated` or `blocked` based on server-observed signals. For example, an internal abuse service may flag a recently alerted tenant as elevated. Unknown values or dependency errors refuse access. The default returns normal. |

```js
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { compilePolicy, createPolicyGate } from './enterprise/policy/policy.mjs';

const policy = compilePolicy(JSON.parse(readFileSync(
  './enterprise/policy/example-policy.json', 'utf8'
)));
const db = new DatabaseSync('/private/data/tenant-quotas.sqlite');
db.exec('PRAGMA busy_timeout = 2000');

const authorize = createPolicyGate({
  policy,
  db,
  authenticate: verifyCurrentSession,
  loadResource: lookupTenantResourceMetadata,
  assessRisk: readInternalRiskSignal
});

const decision = await authorize(request);
if (decision.allowed) {
  // Authorize the actual effect with these exact fields.
  // Recheck ownership and classification inside the protected transaction.
  await runAuthorizedOperation(decision.context, decision.target, decision.resource);
}
```

The functions in the snippet are supplied by the application. Treat the decision as specific to one effect. Use the returned tenant, identity, method, route, resource ID and classification in that effect. Revalidate any change in target or authoritative state between lookup and use. To protect writes, enforce ownership and classification in the same transaction as the mutation. Call the gate again on a new request. Return a uniform external denial for missing, foreign and unauthorized resources so the denial does not reveal which records exist. Keep the internal reason in restricted structured logs. Use the policy digest to correlate the decision with a reviewed configuration.

The application check complements the [tenant-scoped PostgreSQL principals and RLS example](../../infra/database/README.md). Maintain separate tenant database roles or equivalent trusted tenant enforcement. Select the protected tenant's key from server-controlled tenant configuration after authorization. The [field encryption example](../../reference/field-encryption.README.md) binds the expected tenant and field identity into its cryptographic context.

## Quotas and abuse signals

The gate enforces one fixed window per tenant across all allowed routes. SQLite's serialized write transaction checks and updates one tenant row at a time. Connecting processes on the same host must share the same local SQLite database and policy digest. Keep a dedicated connection for the quota module. The SQLite backend needs a different store with equivalent atomic and clock semantics for multi-host use.

Normal requests consume the normal allowance. An elevated signal reduces the allowance for that tenant until its next window. A blocked signal denies the current operation before consuming quota. Other tenants keep their own allowance. If the clock moves backward for a tenant or the quota store fails, the gate denies access. Counts are per operation, so charge the actual operation before invoking it. Separately bound request size, expensive work, aggregate service load and concurrent operations.

A running quota store records the policy digest. Coordinate activation when updating policy. Stop or drain instances on the old policy before using a separate store or migrating the quota state. Carry the current debit or conservatively preserve the existing window to avoid resetting quotas during rollout. Monitor SQLite lock contention and deny cleanly if the store cannot serialize the write. Back up and protect the quota database against unauthorized modification or rollback.

Unauthenticated login traffic needs a separate ingress or identity-provider limiter. Use general login errors, server-side account and source limits, and privacy-preserving telemetry to protect authentication and reduce account enumeration. Supply reputation or behavior signals through a trusted adapter with bounded caching and deadlines, and keep client flags out of risk decisions. The supplied module performs no outbound reputation lookup.

Local tests exercise checked policy loading, exact request binding, cross-tenant denial, quotas across two SQLite connections, tenant isolation, time rollover and clock rollback, invalid risk signals, and fail-closed errors. Use your own deployment to verify authentication, resource ownership, pooled connections, KMS permissions and multi-host quota behavior.
