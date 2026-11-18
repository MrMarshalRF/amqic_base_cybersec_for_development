import assert from 'node:assert/strict';
import test from 'node:test';
import { postgresAdmission, redisAdmission } from './admission.mjs';

const request = Object.freeze({
  tenant: 'synthetic_tenant', generation: 'deployment_1', policyDigest: 'a'.repeat(64),
  operationId: 'operation_1', bindingDigest: 'b'.repeat(64), window: 123, risk: 'normal'
});

test('PostgreSQL binds the full admission request as parameters', async () => {
  const admit = postgresAdmission({
    query: async (sql, parameters) => {
      assert.equal(sql, 'SELECT amqic_quota.admit($1, $2, $3, $4, $5, $6, $7) AS status');
      assert.deepEqual(parameters, Object.values(request));
      return { rows: [{ status: 'granted' }] };
    }
  });
  assert.deepEqual(await admit(request), { status: 'granted', allowed: true });
});

test('Redis uses one tenant-scoped key and exact operation parameters', async () => {
  const admit = redisAdmission({
    eval: async (script, options) => {
      assert.ok(script.includes("redis.call('TIME')"));
      assert.deepEqual(options, {
        keys: ['amqic:quota:v1:synthetic_tenant'],
        arguments: Object.values(request).slice(1).map(String)
      });
      return 'duplicate';
    }
  });
  assert.deepEqual(await admit(request), { status: 'duplicate', allowed: false });
});

test('Invalid inputs do not reach the backing store', async () => {
  let called = false;
  const admit = redisAdmission({ eval: async () => { called = true; } });
  for (const overrides of [
    { tenant: 'outside:namespace' }, { operationId: '' }, { window: NaN },
    { generation: true }, { policyDigest: 'wrong' }, { bindingDigest: 'wrong' }, { risk: 'other' }
  ]) {
    assert.equal((await admit({ ...request, ...overrides })).status, 'invalid_request');
  }
  assert.equal(called, false);
});

test('A failed, ambiguous or unrecognized response gives no grant', async () => {
  for (const value of ['duplicate', 'conflict', 'clock_rollback', 'rate_limited', 'window_changed', 'invalid_state',
    'unprovisioned', 'policy_mismatch', 'unknown', true, 'GRANTED']) {
    assert.equal((await redisAdmission({ eval: async () => value })(request)).allowed, false);
  }
  const result = await postgresAdmission({ query: async () => { throw Error('private provider message'); } })(request);
  assert.deepEqual(result, { status: 'unknown', allowed: false });
  assert.deepEqual(await postgresAdmission({ query: async () => ({ rows: [{ status: 'granted' }, { status: 'granted' }] }) })(request),
    { status: 'unknown', allowed: false });
});
