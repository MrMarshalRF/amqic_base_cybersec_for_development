import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { compilePolicy, createPolicyGate } from './policy.mjs';

const example = new URL('./example-policy.json', import.meta.url);
const fixture = () => JSON.parse(readFileSync(example, 'utf8'));
const target = Object.freeze({ method: 'GET', path: '/records', resourceId: 'record-1' });

function options(db, overrides = {}) {
  return {
    db,
    policy: compilePolicy(fixture()),
    authenticate: async () => ({ tenant: 'tenant-alpha', subject: 'user-1', roles: ['reader'] }),
    loadResource: async (context, request) => ({
      id: request.resourceId, tenant: context.tenant, kind: 'record', classification: 'internal'
    }),
    clock: () => 60_001,
    ...overrides
  };
}

test('CI validates the same example policy and canonical identity as the runtime', () => {
  const source = fixture();
  const policy = compilePolicy(source);
  const cli = spawnSync(process.execPath, [fileURLToPath(new URL('./policy-cli.mjs', import.meta.url)),
    '--check', fileURLToPath(example)], { encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stderr);
  assert.deepEqual(JSON.parse(cli.stdout), { valid: true, digest: policy.digest, tenantCount: 2 });

  source.tenants.reverse();
  source.tenants.forEach(tenant => {
    tenant.rules.reverse();
    tenant.rules.forEach(rule => rule.roles.reverse());
  });
  assert.equal(compilePolicy(source).digest, policy.digest);
  source.tenants[0].rules.push(source.tenants[0].rules[0]);
  assert.throws(() => compilePolicy(source), /Duplicate rule key/);
});

test('only an exact path, action, classification and authenticated tenant may consume quota', async t => {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const gate = createPolicyGate(options(db));
  const grant = await gate({ ...target, tenant: 'tenant-beta', roles: ['operator'], risk: 'blocked' });
  assert.equal(grant.allowed, true);
  assert.equal(grant.context.tenant, 'tenant-alpha');
  assert.deepEqual(grant.context.roles, ['reader']);
  assert.ok(Object.isFrozen(grant.context) && Object.isFrozen(grant.target) && Object.isFrozen(grant.resource));
  for (const request of [{ ...target, path: '/records/%2f' }, { ...target, path: '/records/../records' },
    { ...target, path: '/records?scope=all' }, { ...target, method: 'HEAD' }, { ...target, method: 'POST' }]) {
    assert.equal((await gate(request)).allowed, false);
  }
  const crossTenant = createPolicyGate(options(db, { loadResource: async () => ({
    id: target.resourceId, tenant: 'tenant-beta', kind: 'record', classification: 'internal'
  }) }));
  assert.equal((await crossTenant(target)).reason, 'unauthorized');
  const confidential = createPolicyGate(options(db, { loadResource: async context => ({
    id: target.resourceId, tenant: context.tenant, kind: 'record', classification: 'confidential'
  }) }));
  assert.equal((await confidential(target)).reason, 'unauthorized');
  const wrongId = createPolicyGate(options(db, { loadResource: async context => ({
    id: 'record-2', tenant: context.tenant, kind: 'record', classification: 'internal'
  }) }));
  assert.equal((await wrongId(target)).reason, 'unauthorized');
  const noIdentity = createPolicyGate(options(db, { authenticate: async () => null }));
  assert.equal((await noIdentity(target)).reason, 'unauthenticated');
  assert.equal((await gate(target)).allowed, true);
  assert.equal((await gate(target)).allowed, true);
  assert.equal((await gate(target)).reason, 'rate_limited');
});

test('shared quota spans connections, contains noisy tenants and keeps elevated pressure for the window', async t => {
  const root = mkdtempSync(join(tmpdir(), 'enterprise-policy-'));
  const file = join(root, 'quotas.sqlite');
  const db1 = new DatabaseSync(file);
  const db2 = new DatabaseSync(file);
  t.after(() => {
    db2.close();
    db1.close();
    rmSync(root, { recursive: true, maxRetries: 5, retryDelay: 50 });
  });
  let now = 60_001;
  const clock = () => now;
  const gate1 = createPolicyGate(options(db1, { clock }));
  const gate2 = createPolicyGate(options(db2, { clock, assessRisk: () => 'elevated' }));
  assert.equal((await gate1(target)).allowed, true);
  assert.equal((await gate2(target)).reason, 'rate_limited');
  assert.equal((await gate1(target)).reason, 'rate_limited');

  const beta = createPolicyGate(options(db2, { clock, authenticate: async () => ({
    tenant: 'tenant-beta', subject: 'user-2', roles: ['reader']
  }) }));
  assert.equal((await beta(target)).allowed, true);
  now = 120_000;
  assert.equal((await gate1(target)).allowed, true);
  now = 119_999;
  assert.equal((await gate1(target)).reason, 'dependency_error');

  const changed = fixture();
  changed.tenants[0].quota.normal += 1;
  assert.throws(() => createPolicyGate(options(db2, { policy: compilePolicy(changed) })), /digest mismatch/);
});

test('closed risk signals and adapter failures deny without echoing sensitive exceptions', async t => {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  for (const signal of ['blocked', 'unrecognized']) {
    const gate = createPolicyGate(options(db, { assessRisk: () => signal }));
    assert.equal((await gate(target)).reason, 'risk_denied');
  }
  const gate = createPolicyGate(options(db, { loadResource: async () => { throw new Error('private adapter details'); } }));
  const result = await gate(target);
  assert.equal(result.reason, 'dependency_error');
  assert.equal(JSON.stringify(result).includes('private adapter details'), false);
});
