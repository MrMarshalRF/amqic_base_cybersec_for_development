import assert from 'node:assert/strict';
import test from 'node:test';
import { createRotationController } from './rotation.mjs';

const tenant = 'tenant-a';
const purpose = 'orders';
const lease = (ref, expiresAt = 1_500) => ({ tenant, purpose, ref, expiresAt });
const key = version => ({ tenant, purpose, keyId: 'orders-key', version });

function fixture(kind = 'lease', overrides = {}) {
  let active = kind === 'lease' ? lease('old') : key('v1');
  let sequence = 1;
  let clock = 1_000;
  const calls = [];
  const discarded = [];
  const adapter = {
    read: async () => ({ revision: String(sequence), active }),
    prepare: async ({ operationId }) => kind === 'lease' ? lease(operationId) : key('v2'),
    probe: async () => true,
    activate: async ({ expectedRevision, candidate, minRemainingLeaseMs }) => {
      calls.push(candidate);
      if (expectedRevision !== String(sequence) ||
          (kind === 'lease' && candidate.expiresAt - clock < minRemainingLeaseMs)) return false;
      active = candidate;
      sequence++;
      return true;
    },
    discardPreparedLease: async ({ candidate }) => {
      assert.notEqual(candidate.ref, active.ref);
      discarded.push(candidate.ref);
      return true;
    },
    ...overrides,
  };
  const controller = createRotationController({
    kind, tenant, purpose, keyId: kind === 'key' ? 'orders-key' : undefined,
    minLeaseMs: 100, maxLeaseMs: 1_000, clock: () => clock, adapter,
  });
  return { controller, adapter, calls, discarded, active: () => active, advance: n => { clock += n; } };
}

test('lease replacement stages, probes and switches while leaving the former lease to drain', async () => {
  const lab = fixture();
  const events = [];
  const prepare = lab.adapter.prepare;
  const activate = lab.adapter.activate;
  lab.adapter.prepare = async operation => {
    assert.deepEqual(operation.scope, { tenant, purpose });
    events.push('prepare');
    return prepare(operation);
  };
  lab.adapter.probe = async op => {
    assert.equal(op.candidate.ref, op.operationId);
    events.push('probe');
    return true;
  };
  lab.adapter.activate = async op => {
    events.push('activate');
    return activate(op);
  };
  assert.deepEqual(await lab.controller.rotate(), { outcome: 'activated', retirement: 'prior_lease_drain' });
  assert.deepEqual(events, ['prepare', 'probe', 'activate']);
  assert.notEqual(lab.active().ref, 'old');
  assert.deepEqual(lab.discarded, []);
});

test('concurrent attempts use the durable revision to prevent two activations', async () => {
  const lab = fixture();
  const result = await Promise.all([lab.controller.rotate(), lab.controller.rotate()]);
  assert.deepEqual(result.map(x => x.outcome).sort(), ['activated', 'activation_rejected']);
  assert.equal(lab.discarded.length, 1);
  assert.notEqual(lab.discarded[0], lab.active().ref);
});

test('expired, oversized and post-probe stale lease candidates cannot activate', async () => {
  for (const expiry of [1_000, 2_001]) {
    const lab = fixture('lease', { prepare: async () => lease('candidate', expiry) });
    assert.deepEqual(await lab.controller.rotate(), { outcome: 'invalid_lease_lifetime', retirement: 'candidate_discarded' });
    assert.equal(lab.calls.length, 0);
    assert.equal(lab.active().ref, 'old');
  }
  const lab = fixture();
  lab.adapter.probe = async () => { lab.advance(401); return true; };
  assert.deepEqual(await lab.controller.rotate(), { outcome: 'candidate_stale', retirement: 'candidate_discarded' });
  assert.equal(lab.calls.length, 0);
});

test('foreign, recycled and payload-bearing bindings are denied without cleanup effects', async () => {
  const foreign = [
    { ...lease('candidate'), tenant: 'tenant-b' },
    { ...lease('candidate'), purpose: 'payments' },
    lease('old'),
    { ...lease('candidate'), syntheticSecret: 'fixture-secret' },
  ];
  for (const binding of foreign) {
    const lab = fixture('lease', { prepare: async () => binding });
    const result = await lab.controller.rotate();
    assert.deepEqual(result, { outcome: 'invalid_candidate_binding', retirement: 'reconciliation_required' });
    assert.equal(lab.calls.length, 0);
    assert.deepEqual(lab.discarded, []);
    assert.doesNotMatch(JSON.stringify(result), /tenant-a|tenant-b|fixture-secret|candidate"/);
  }
});

test('uncertain outcomes and provider errors return redacted states', async () => {
  const syntheticPayload = 'fixture-provider-error-credential-value';
  const lostAck = fixture();
  const commit = lostAck.adapter.activate;
  lostAck.adapter.activate = async op => {
    await commit(op);
    throw new Error(syntheticPayload);
  };
  const outcome = await lostAck.controller.rotate();
  assert.deepEqual(outcome, { outcome: 'activation_unconfirmed', retirement: 'reconciliation_required' });
  assert.notEqual(lostAck.active().ref, 'old');
  assert.equal(lostAck.discarded.length, 0);
  assert.doesNotMatch(JSON.stringify(outcome), /fixture-provider-error|tenant-a/);

  const lostPrepare = fixture('lease', { prepare: async () => { throw new Error(syntheticPayload); } });
  assert.deepEqual(await lostPrepare.controller.rotate(), {
    outcome: 'preparation_unconfirmed', retirement: 'reconciliation_required',
  });
  assert.equal(lostPrepare.calls.length, 0);

  const failedProbe = fixture('lease', {
    probe: async () => { throw new Error(syntheticPayload); },
    discardPreparedLease: async () => { throw new Error(syntheticPayload); },
  });
  const failure = await failedProbe.controller.rotate();
  assert.deepEqual(failure, { outcome: 'probe_failed', retirement: 'candidate_cleanup_pending' });
  assert.doesNotMatch(JSON.stringify(failure), /fixture-provider-error|tenant-a/);
  assert.equal(failedProbe.active().ref, 'old');
});

test('KMS rotation binds the key and purpose and retains previous versions for existing ciphertext', async () => {
  const lab = fixture('key');
  assert.deepEqual(await lab.controller.rotate(), { outcome: 'activated', retirement: 'prior_key_retained' });
  assert.equal(lab.active().version, 'v2');
  for (const binding of [{ ...key('v2'), keyId: 'other-key' }, { ...key('v2'), purpose: 'another' }, key('v1')]) {
    const rejected = fixture('key', { prepare: async () => binding });
    assert.equal((await rejected.controller.rotate()).outcome, 'invalid_candidate_binding');
    assert.equal(rejected.calls.length, 0);
    assert.equal(rejected.active().version, 'v1');
  }
  const failed = fixture('key', { probe: async () => false });
  assert.deepEqual(await failed.controller.rotate(), { outcome: 'probe_failed', retirement: 'candidate_retained' });
  assert.equal(failed.active().version, 'v1');
});
