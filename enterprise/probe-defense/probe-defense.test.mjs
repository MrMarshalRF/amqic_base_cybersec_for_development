import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';
import { createProbeDefense, genericDenial, createCanaryHandler, createSecurityTxt } from './probe-defense.mjs';

const key = Buffer.alloc(32, 42); // Synthetic fixture; never use this key in a service.
const request = (sourceRef = 'source_a', suffix = 'a', routeClass = 'read') => ({
  routeClass, sourceRef, auth: { tenantRef: `tenant_${suffix}`, subjectRef: `subject_${suffix}`, sessionRef: `session_${suffix}` }
});
const policy = (dimension, limit = 1) => ({ version: 'v1', routes: Object.fromEntries(['read', 'write'].map(name =>
  [name, { allowAnonymous: false, ...Object.fromEntries(['global', 'source', 'tenant', 'subject', 'session'].map(d => [d, { limit: d === dimension ? limit : 100, windowMs: 10_000 }])) }])) });
function fixture(t, selected = policy('source'), options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'probe-defense-'));
  const config = { databasePath: join(directory, 'quota.sqlite'), key, keyVersion: 'k1', policy: selected, clock: () => 1000, ...options };
  const instances = [];
  const open = (overrides = {}) => { const instance = createProbeDefense({ ...config, ...overrides }); instances.push(instance); return instance; };
  t.after(() => { for (const instance of instances) instance.close(); rmSync(directory, { recursive: true }); });
  return { open, config };
}

for (const dimension of ['global', 'source', 'tenant', 'subject', 'session']) {
  test(`atomic ${dimension} budget denies without spending other budgets`, t => {
    const selected = policy(dimension);
    selected.routes.read.global.limit = dimension === 'global' ? 1 : 2;
    const { open } = fixture(t, selected);
    const guard = open();
    assert.deepEqual(guard.admit(request()), { allowed: true });
    const denied = request();
    if (dimension !== 'source' && dimension !== 'global') denied.sourceRef = 'rotated_source';
    if (dimension === 'source') denied.auth = request('x', 'rotated').auth;
    assert.deepEqual(guard.admit(denied), { allowed: false, reason: 'limited', retryAfterSeconds: 9 });
    if (dimension !== 'global') assert.equal(guard.admit(request('different_source', 'other')).allowed, true);
    assert.equal(guard.admit(request('source_a', 'a', 'write')).allowed, true);
  });
}
test('source rotation cannot bypass subject/session; account rotation cannot bypass source', t => {
  for (const dimension of ['subject', 'session', 'source']) {
    const { open } = fixture(t, policy(dimension));
    const guard = open();
    assert.equal(guard.admit(request()).allowed, true);
    const rotated = dimension === 'source' ? request('source_a', 'b') : request('source_b');
    assert.equal(guard.admit(rotated).reason, 'limited');
  }
});
test('shared connections and reopen preserve atomic limits', t => {
  const { open } = fixture(t, policy('global', 2));
  const a = open(), b = open();
  assert.equal(a.admit(request()).allowed, true);
  assert.equal(b.admit(request('b', 'b')).allowed, true);
  a.close(); b.close();
  assert.equal(open().admit(request('c', 'c')).reason, 'limited');
});
test('concurrent worker connections reserve all dimensions atomically', async t => {
  const { open, config } = fixture(t, policy('global', 3));
  open().close();
  const run = () => new Promise((resolve, reject) => {
    const worker = new Worker(`const {parentPort,workerData}=require('node:worker_threads');
      import(workerData.module).then(({createProbeDefense})=>{
        const guard=createProbeDefense({...workerData.config,key:Buffer.from(workerData.key),clock:()=>1000});
        let count=0; for(let i=0;i<10;i++) count+=Number(guard.admit(workerData.request).allowed);
        guard.close();parentPort.postMessage(count);
      }).catch(error=>{throw error;});`, { eval: true, workerData: {
      module: new URL('./probe-defense.mjs', import.meta.url).href,
      config: { ...config, key: undefined, clock: undefined }, key: [...key], request: request()
    } });
    worker.once('message', resolve); worker.once('error', reject);
    worker.once('exit', code => { if (code) reject(Error('Synthetic worker failed')); });
  });
  const counts = await Promise.all([run(), run()]);
  assert.equal(counts.reduce((sum, count) => sum + count, 0), 3);
});
test('trusted expiry, rollback detection and correct longest exceeded retry', t => {
  let now = 1500;
  const selected = policy('source');
  selected.routes.read.global = { limit: 1, windowMs: 20_000 };
  const { open } = fixture(t, selected, { clock: () => now });
  const guard = open();
  assert.equal(guard.admit(request()).allowed, true);
  assert.equal(guard.admit(request()).retryAfterSeconds, 19);
  now = 1499;
  assert.equal(guard.admit(request()).reason, 'unavailable');
  now = 20_000;
  assert.equal(guard.admit(request()).allowed, true);
});
test('capacity fails closed without live eviction or partial spending', t => {
  let now = 1000;
  const { open } = fixture(t, policy('global'), { maxBuckets: 5, clock: () => now });
  const guard = open();
  assert.equal(guard.admit(request()).allowed, true);
  // New class has five new buckets, while the first class is still live.
  assert.equal(guard.admit(request('b', 'b', 'write')).reason, 'unavailable');
  assert.equal(guard.admit(request()).reason, 'limited');
  now = 10_000;
  assert.equal(guard.admit(request('b', 'b', 'write')).allowed, true);
});
test('configuration/key binding rejects mismatches, copies key and sanitizes failures', t => {
  const copy = Buffer.from(key);
  const { open, config } = fixture(t, policy('global'), { key: copy });
  const guard = open(); copy.fill(0);
  assert.equal(guard.admit(request()).allowed, true);
  for (const override of [{ key: Buffer.alloc(32, 1) }, { keyVersion: 'k2', key }, { policy: policy('session'), key }, { maxBuckets: 99, key }]) {
    assert.throws(() => createProbeDefense({ ...config, ...override }), { message: 'Probe defense initialization unavailable' });
  }
});
test('strict context, policy and SQL failure remain fail closed', t => {
  const { open, config } = fixture(t);
  const guard = open();
  for (const input of [{ ...request(), routeClass: 'unknown' }, { ...request(), cost: 0 },
    { ...request(), auth: {} }, { ...request(), sourceRef: 'raw:192.0.2.1' }]) assert.equal(guard.admit(input).reason, 'invalid_context');
  assert.equal(guard.admit({ ...request(), auth: null }).reason, 'invalid_context');
  const db = new DatabaseSync(config.databasePath);
  db.exec('DROP TABLE probe_buckets'); db.close();
  assert.deepEqual(guard.admit(request()), { allowed: false, reason: 'unavailable' });
  guard.close(); assert.equal(guard.admit(request()).reason, 'unavailable');
  assert.throws(() => createProbeDefense({ ...config, policy: { version: 'v1', routes: {} } }), /initialization unavailable/);
});
test('anonymous requests require explicit public route; schema omissions fail closed', t => {
  const selected = policy('source'); selected.routes.read.allowAnonymous = true;
  const { open, config } = fixture(t, selected);
  assert.equal(open().admit({ ...request(), auth: null }).allowed, true);
  assert.equal(open().admit({ ...request(), auth: null }).reason, 'limited');
  const missing = policy('source'); delete missing.routes.read.allowAnonymous;
  assert.throws(() => createProbeDefense({ ...config, policy: missing }), /initialization unavailable/);
});
test('tenant-scoped subject and subject-scoped session labels cannot collide', t => {
  for (const dimension of ['subject', 'session']) {
    const { open } = fixture(t, policy(dimension));
    const guard = open(); assert.equal(guard.admit(request()).allowed, true);
    const otherTenant = request('b'); otherTenant.auth.tenantRef = 'tenant_b';
    assert.equal(guard.admit(otherTenant).allowed, true);
    assert.equal(guard.admit(request('rotated_source')).reason, 'limited');
    if (dimension === 'session') {
      const otherSubject = request('c'); otherSubject.auth.subjectRef = 'subject_b';
      assert.equal(guard.admit(otherSubject).allowed, true);
    }
  }
});
test('SQL failure after an earlier bucket insert rolls back the entire reservation', t => {
  const { open, config } = fixture(t, policy('global'));
  const guard = open(); const db = new DatabaseSync(config.databasePath);
  db.exec("CREATE TRIGGER fail_insert BEFORE INSERT ON probe_buckets WHEN (SELECT count(*) FROM probe_buckets)>=1 BEGIN SELECT RAISE(ABORT,'synthetic'); END;");
  assert.deepEqual(guard.admit(request()), { allowed: false, reason: 'unavailable' });
  assert.equal(db.prepare('SELECT count(*) AS n FROM probe_buckets').get().n, 0);
  db.exec('DROP TRIGGER fail_insert'); db.close();
  assert.equal(guard.admit(request()).allowed, true);
});
test('denials preserve status and identical safe body', () => {
  const responses = [genericDenial(403), genericDenial(404), genericDenial(429, 5)];
  assert.deepEqual(responses.map(r => r.status), [403, 404, 429]);
  assert.equal(new Set(responses.map(r => r.body)).size, 1);
  assert.equal(responses[2].headers['retry-after'], '5');
  assert.equal(responses[0].headers['cache-control'], 'no-store');
  assert.throws(() => genericDenial(403, 5)); assert.throws(() => genericDenial(429, 0));
});
test('inert canary emits only opaque minimum and hides sink failure from HTTP', async () => {
  let event;
  const handler = createCanaryHandler({ canaryId: 'trap_1', emit: value => { event = value; return true; } });
  const success = await handler({ sourceRef: 'opaque_source', path: '/private?token=secret' });
  assert.deepEqual(event, { type: 'canary_hit', canaryId: 'trap_1', sourceRef: 'opaque_source' });
  assert.equal(success.delivered, true);
  const failed = await createCanaryHandler({ canaryId: 'trap_1', emit: () => { throw Error('private sink'); } })({ sourceRef: 'opaque_source' });
  assert.equal(failed.delivered, false); assert.deepEqual(failed.response, success.response);
  for (const result of [false, undefined]) {
    const unconfirmed = await createCanaryHandler({ canaryId: 'trap_1', emit: () => result })({ sourceRef: 'opaque_source' });
    assert.equal(unconfirmed.delivered, false); assert.deepEqual(unconfirmed.response, success.response);
  }
});
const profile = { contact: 'mailto:security@example.com', expires: '2027-02-01T00:00:00Z',
  canonical: 'https://example.com/.well-known/security.txt', policy: 'https://example.com/security-policy',
  preferredLanguages: 'en', now: Date.parse('2026-11-19T00:00:00Z') };
test('security.txt conservative profile and portable stdout example', () => {
  const value = createSecurityTxt(profile);
  assert.match(value, /^Contact: mailto:security@example.com\n/);
  assert.equal(value.split('\n').length, 6);
  for (const override of [{ contact: 'mailto:a@example.com\r\nX: bad' }, { expires: '2026-11-18T00:00:00Z' },
    { expires: '2028-02-01T00:00:00Z' }, { expires: '2027-02-30T00:00:00Z' },
    { canonical: 'https://example.com/other' }, { canonical: 'https://user@example.com/.well-known/security.txt' },
    { canonical: 'https://example.com/.well-known/security.txt?x=1' }, { policy: 'https://example.com/%0a' },
    { preferredLanguages: 'en\nfr' }]) assert.throws(() => createSecurityTxt({ ...profile, ...override }), /Invalid security.txt profile/);
});
