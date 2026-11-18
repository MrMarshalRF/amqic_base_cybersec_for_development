import { randomUUID } from 'node:crypto';

const identifier = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/.test(value);
const timestamp = value => Number.isSafeInteger(value) && value >= 0;
const status = (outcome, retirement = 'none') => Object.freeze({ outcome, retirement });

function record(value, fields) {
  if (value === null || typeof value !== 'object') return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const data = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(data).length !== fields.length ||
      fields.some(field => !Object.hasOwn(data, field) || !data[field].enumerable ||
        !Object.hasOwn(data[field], 'value'))) return null;
  return Object.freeze(Object.fromEntries(fields.map(field => [field, data[field].value])));
}

function exactBinding(value, scope, kind) {
  const fields = kind === 'lease' ? ['tenant', 'purpose', 'ref', 'expiresAt']
    : ['tenant', 'purpose', 'keyId', 'version'];
  const binding = record(value, fields);
  if (!binding || binding.tenant !== scope.tenant || binding.purpose !== scope.purpose) return null;
  if (kind === 'lease' && (!identifier(binding.ref) || !timestamp(binding.expiresAt))) return null;
  if (kind === 'key' && (binding.keyId !== scope.keyId || !identifier(binding.version))) return null;
  return binding;
}

/** Create a rotation controller from server configuration and a trusted provider adapter. */
export function createRotationController({ kind, tenant, purpose, keyId, minLeaseMs = 30_000,
  maxLeaseMs = 900_000, clock = Date.now, adapter }) {
  if (!['lease', 'key'].includes(kind) || !identifier(tenant) || !identifier(purpose) ||
      (kind === 'lease' ? keyId !== undefined : !identifier(keyId)) ||
      !timestamp(minLeaseMs) || !timestamp(maxLeaseMs) || minLeaseMs < 1 ||
      maxLeaseMs < minLeaseMs || typeof clock !== 'function' ||
      !['read', 'prepare', 'probe', 'activate'].every(field => typeof adapter?.[field] === 'function') ||
      (kind === 'lease' && typeof adapter?.discardPreparedLease !== 'function')) {
    throw new TypeError('Invalid rotation configuration');
  }
  const scope = Object.freeze(kind === 'key' ? { tenant, purpose, keyId } : { tenant, purpose });

  function time() {
    const value = clock();
    if (!timestamp(value)) throw new TypeError('Invalid clock');
    return value;
  }

  // The adapter owns authority to discard only this operation's unpublished lease.
  async function discard(operation) {
    if (kind === 'key') return 'candidate_retained';
    try {
      return (await adapter.discardPreparedLease(operation)) === true ? 'candidate_discarded'
        : 'candidate_cleanup_pending';
    } catch {
      return 'candidate_cleanup_pending';
    }
  }

  async function rotate() {
    let prior;
    try {
      const observed = record(await adapter.read(scope), ['revision', 'active']);
      if (!observed || !identifier(observed.revision)) return status('invalid_active_binding');
      const active = observed.active === null ? null : exactBinding(observed.active, scope, kind);
      if (observed.active !== null && !active) return status('invalid_active_binding');
      prior = Object.freeze({ revision: observed.revision, active });
    } catch {
      return status('active_binding_unavailable');
    }

    const operation = Object.freeze({ scope, operationId: randomUUID() });
    let candidate;
    try {
      candidate = exactBinding(await adapter.prepare(operation), scope, kind);
    } catch {
      return status('preparation_unconfirmed', 'reconciliation_required');
    }
    const identity = kind === 'lease' ? 'ref' : 'version';
    if (!candidate || candidate[identity] === prior.active?.[identity]) {
      // A foreign or recycled reference is unsafe even as a cleanup target.
      return status('invalid_candidate_binding', 'reconciliation_required');
    }
    const staged = Object.freeze({ ...operation, candidate });
    try {
      const preparedAt = time();
      if (kind === 'lease' && (candidate.expiresAt - preparedAt < minLeaseMs ||
          candidate.expiresAt - preparedAt > maxLeaseMs)) {
        return status('invalid_lease_lifetime', await discard(staged));
      }
      if ((await adapter.probe(staged)) !== true) return status('probe_failed', await discard(staged));
      const now = time();
      if (now < preparedAt || (kind === 'lease' && candidate.expiresAt - now < minLeaseMs)) {
        return status('candidate_stale', await discard(staged));
      }
    } catch {
      return status('probe_failed', await discard(staged));
    }

    // The adapter performs the exact revision compare-and-set at the durable store.
    // After a lost acknowledgement it must reconcile before reissuing or discarding.
    try {
      const committed = await adapter.activate(Object.freeze({
        ...staged, expectedRevision: prior.revision, minRemainingLeaseMs: kind === 'lease' ? minLeaseMs : 0,
      }));
      if (committed === true) return status('activated', prior.active
        ? (kind === 'lease' ? 'prior_lease_drain' : 'prior_key_retained') : 'none');
      if (committed === false) return status('activation_rejected', await discard(staged));
    } catch {
      return status('activation_unconfirmed', 'reconciliation_required');
    }
    return status('activation_unconfirmed', 'reconciliation_required');
  }
  return Object.freeze({ rotate });
}
