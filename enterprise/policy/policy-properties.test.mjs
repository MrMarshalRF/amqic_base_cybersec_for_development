import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { compilePolicy, createPolicyGate } from './policy.mjs';

const example = new URL('./example-policy.json', import.meta.url);
const fixture = () => JSON.parse(readFileSync(example, 'utf8'));
const target = { method: 'GET', path: '/records', resourceId: 'record-1' };

function nextRandom(seed) {
  return () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
}

test('seeded policy permutations preserve the compiled identity', () => {
  const next = nextRandom(0x72656564);
  const expected = compilePolicy(fixture()).digest;
  function shuffle(items) {
    for (let i = items.length - 1; i > 0; i--) {
      const j = next() % (i + 1);
      [items[i], items[j]] = [items[j], items[i]];
    }
  }
  for (let trial = 0; trial < 128; trial++) {
    const policy = fixture();
    shuffle(policy.tenants);
    for (const tenant of policy.tenants) {
      shuffle(tenant.rules);
      tenant.rules.forEach(rule => shuffle(rule.roles));
    }
    assert.equal(compilePolicy(policy).digest, expected);
    policy.tenants[0].rules.push(structuredClone(policy.tenants[0].rules[0]));
    assert.throws(() => compilePolicy(policy), /Duplicate rule key/);
  }
});

test('seeded incomparable input is denied and cannot spend authenticated quota', async t => {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const next = nextRandom(0x636f6e74);
  const gate = createPolicyGate({
    db, policy: compilePolicy(fixture()),
    authenticate: async () => ({ tenant: 'tenant-alpha', subject: 'user-1', roles: ['reader'] }),
    loadResource: async (context, request) => ({
      id: request.resourceId, tenant: context.tenant, kind: 'record', classification: 'internal'
    }),
    clock: () => 60_001,
  });
  for (let trial = 0; trial < 512; trial++) {
    const suffix = next().toString(36);
    const request = trial % 2
      ? { ...target, path: '/unmapped-' + suffix }
      : { ...target, method: 'INVALID-' + suffix };
    assert.equal((await gate(request)).allowed, false, 'seeded case ' + trial);
  }
  const results = await Promise.all(Array.from({ length: 256 }, () => gate(target)));
  assert.equal(results.filter(result => result.allowed).length, 3);
  assert.equal(results.filter(result => result.reason === 'rate_limited').length, 253);
});
