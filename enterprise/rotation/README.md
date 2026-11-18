# Enterprise credential lifecycle

The rotation controller stages, probes and conditionally activates a credential binding. It returns two fixed status fields that a caller can record without serializing credentials, tenant identifiers, lease references, key references or provider exceptions. Its synthetic adapter tests cover lease replacement and KMS writer rotation.

Run the tests with Node.js 22 or later.

```sh
node --test enterprise/rotation/rotation.test.mjs
```

## Adapter contract

Build one controller per tenant, purpose and canonical key ID where applicable. Derive these from authenticated server context and approved configuration. Resolve provider resources through a fixed server-side allowlist. The permitted adapter runs under a workload identity with narrowly scoped grants.

```js
import { createRotationController } from './enterprise/rotation/rotation.mjs';

const { rotate } = createRotationController({
  kind: 'lease',
  tenant: trustedTenant,
  purpose: 'orders',
  minLeaseMs: 30_000,
  maxLeaseMs: 900_000,
  adapter: approvedAdapter,
});
const outcome = await rotate();
```

| Method | Required behavior |
| --- | --- |
| `read(scope)` | Read the active binding and a durable, non-reusable revision. Return `{revision, active}`. A scope provisioned without an active binding may return `active: null`. Fail closed if a prior ambiguous operation still needs reconciliation. |
| `prepare({scope, operationId})` | Atomically reserve the scope and record the operation intent before requesting the provider effect. Deny admission while another operation for this scope is unresolved. Stage a candidate in protected custody. Bind its ownership to the operation ID, tenant and purpose. Preserve the outcome for reconciliation, including transport loss. Return only the exact binding fields described below. |
| `probe({scope, operationId, candidate})` | Verify the staged candidate inside the protected consumer. Return literal `true` on success. Keep all secret bytes, provider responses and diagnostic exception messages inside the protected consumer. |
| `activate({scope, operationId, candidate, expectedRevision, minRemainingLeaseMs})` | Atomically enforce the scope reservation, exclude other unresolved operations, compare the expected revision and publish exactly the staged binding. Require the ownership marker and sufficient remaining lease time in the promotion transaction. Record committed or definitively rejected state with the binding change. Return literal `true` for committed, `false` for definitive rejection. Preserve an ambiguous result for reconciliation when a reply is lost. |
| `discardPreparedLease({scope, operationId, candidate})` | Atomically mark the exact operation-owned, unpublished lease ineligible for promotion before revocation. Recheck that it was never activated. Return literal `true` after confirmed cleanup. This method applies to lease controllers. |

The adapter is the authority for the durable journal, scope reservation, revision check, transactions, timeouts and recovery. Initial issuance, repeated scheduler ticks and multiple workers must use the same durable scope and revision store. Preserve the reservation while provider or activation state is ambiguous. An operator reconciles ambiguous operations by checking the journal and provider state for that scope before releasing the reservation and resuming the scheduler. Record only redacted results in application logs, SIEM exports or release evidence.

### Short-lived leases

The binding is `{tenant, purpose, ref, expiresAt}`. Use an opaque internal reference tied to the specific issued lease in the adapter's protected store. `expiresAt` is a UTC epoch timestamp in milliseconds based on the TTL the provider actually returned. Keep clocks synchronized. At request admission, use the active binding only while it is current and unexpired. After a successful switch, drain workloads using the prior lease and revoke the exact retired lease after the drain.

An adapter for Vault dynamic database credentials can authenticate with a designated workload identity, resolve the approved database role and request credentials under that role. Keep the credential payload and provider lease ID inside the protected consumer. A Vault renewal extends an existing renewable lease according to the provider's returned TTL. This module replaces leases and bounds the new lifetime. Implement any renewal in a separate provider-owned lifecycle with the same expiry and revocation checks. [Vault lease lifecycle](https://developer.hashicorp.com/vault/docs/concepts/lease)

### Versioned encryption keys

Use `kind: 'key'` and configure a canonical `keyId`. The binding is `{tenant, purpose, keyId, version}`. The adapter checks provider metadata, expected tenant policy, key state and the concrete version used for writes. Map a Google Cloud KMS version or Vault Transit version into this configuration when the platform and authenticated adapter expose that version. AWS KMS automatic rotation retains the same logical key ID and handles key material internally. For that service use native key material rotation, or an independently reviewed migration between configured key resources. [Google Cloud KMS rotation](https://cloud.google.com/kms/docs/key-rotation) · [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) · [AWS KMS rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)

The switch updates the writer binding. Keep approved previous versions readable for extant data and backups. Retire key versions only after verifying migration, recovery and the retention horizon. Integrate the binding with the [field encryption provider and version policy](../../reference/field-encryption.README.md). A failed probe or definitive revision conflict leaves the active binding intact. A lost activation acknowledgement requires reconciliation before further action.

The tests run a synthetic in-memory adapter and check redacted outcomes, concurrent compare-and-set attempts, scope mismatches, lease expiry, rejected or ambiguous provider outcomes and old key retention. Before adopting a provider, exercise the same cases with the actual adapter, durable scope reservation and least-privilege workload identity in an isolated test environment.
