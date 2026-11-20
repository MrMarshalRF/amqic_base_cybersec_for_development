import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { RecoveryStore } from './recovery.mjs';

const account = Object.freeze({ tenantId: 'tenant_alpha', subjectId: 'subject_one', securityEpoch: 1 });
const binding = (purpose = 'password-reset', extra = {}) => ({ ...account, purpose, ...extra });
const failed = fn => assert.throws(fn, { message: 'recovery_failed' });
function fixture(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'synthetic-recovery-'));
  const database = join(directory, 'state.sqlite');
  const stores = [];
  const open = (policy = {}) => {
    const store = new RecoveryStore({ database, ...options, ...policy });
    stores.push(store);
    return store;
  };
  t.after(() => {
    for (const store of stores) { try { store.close(); } catch { /* already closed */ } }
    // Only synthetic files in this newly created, exclusively owned directory.
    for (const file of readdirSync(directory)) unlinkSync(join(directory, file));
    rmdirSync(directory);
  });
  return { database, open };
}
function issue(store, scope = binding()) {
  let token;
  const result = store.issue(scope, delivery => { token = delivery.token; return true; });
  assert.equal(Object.hasOwn(result, 'token'), false);
  return token;
}

if (!isMainThread && workerData?.recoveryRace) {
  const store = new RecoveryStore({ database: workerData.database });
  parentPort.postMessage('ready');
  Atomics.wait(new Int32Array(workerData.gate), 0, 0);
  let accepted = false;
  try { store.consumeOnce(workerData.token, binding()); accepted = true; } catch { /* generic denial */ }
  store.close();
  parentPort.postMessage({ accepted });
} else {
  test('delivery sees random canonical token; SQLite stores only its hash; one use advances epoch', t => {
    const { open, database } = fixture(t);
    const store = open();
    store.registerAccount(account);
    const token = issue(store);
    assert.match(token, /^[A-Za-z0-9_-]{43}$/);
    const inspect = new DatabaseSync(database);
    const row = inspect.prepare('SELECT * FROM recovery_tokens').get();
    assert.equal(row.verifier, createHash('sha256').update(token).digest('hex'));
    assert.equal(JSON.stringify(row).includes(token), false);
    inspect.close();
    const claim = store.consumeOnce(token, binding());
    assert.equal(claim.securityEpoch, 2);
    assert.equal(claim.previousSecurityEpoch, 1);
    assert.equal(claim.purpose, 'password-reset');
    assert.equal(JSON.stringify(claim).includes(token), false);
    assert.equal(Object.isFrozen(claim), true);
    failed(() => store.consumeOnce(token, binding()));
  });

  test('purpose, tenant, subject, epoch and pending email change reference must match exactly', t => {
    const { open } = fixture(t);
    const store = open();
    store.registerAccount(account);
    const token = issue(store);
    for (const change of [{ tenantId: 'tenant_beta' }, { subjectId: 'subject_two' },
      { securityEpoch: 2 }, { purpose: 'factor-recovery' }]) {
      failed(() => store.consumeOnce(token, binding('password-reset', change)));
    }
    store.consumeOnce(token, binding());
    const email = binding('email-change', { securityEpoch: 2, pendingChangeRef: 'pending_opaque_1' });
    const emailToken = issue(store, email);
    failed(() => store.consumeOnce(emailToken, { ...email, pendingChangeRef: 'pending_opaque_2' }));
    failed(() => issue(store, { ...email, pendingChangeRef: undefined }));
    store.consumeOnce(emailToken, email);
  });

  test('trusted password/email/factor changes invalidate every outstanding purpose', t => {
    for (const reason of ['password', 'email', 'factor']) {
      const { open } = fixture(t);
      const store = open();
      store.registerAccount(account);
      const scopes = [binding(), binding('factor-recovery'), binding('email-change', { pendingChangeRef: 'pending_1' })];
      const tokens = scopes.map(scope => issue(store, scope));
      assert.equal(store.bumpSecurityEpoch(account).securityEpoch, 2, reason);
      tokens.forEach((token, index) => failed(() => store.consumeOnce(token, scopes[index])));
      failed(() => store.registerAccount(account));
    }
  });

  test('successful recovery also invalidates tokens for other purposes', t => {
    const { open } = fixture(t);
    const store = open();
    store.registerAccount(account);
    const password = issue(store);
    const factor = issue(store, binding('factor-recovery'));
    store.consumeOnce(password, binding());
    failed(() => store.consumeOnce(factor, binding('factor-recovery')));
  });

  test('strict expiry and durable clock rollback guard survive restart', t => {
    let now = 1000;
    const { open } = fixture(t, { clock: () => now, clockId: 'synthetic-clock-v1', ttlSeconds: 10 });
    const store = open();
    store.registerAccount(account);
    const token = issue(store);
    now = 1010;
    failed(() => store.consumeOnce(token, binding()));
    now = 1009;
    failed(() => issue(store));
    store.close();
    failed(() => open());
    now = 1010;
    const resumed = open();
    const fresh = issue(resumed);
    resumed.consumeOnce(fresh, binding());
  });

  test('one current token per purpose, bounded store, expiry-only reclaim and account cap', t => {
    let now = 1000;
    const { open } = fixture(t, { clock: () => now, clockId: 'synthetic-clock-v1', ttlSeconds: 10,
      maxOutstanding: 1, maxAccounts: 1 });
    const store = open();
    store.registerAccount(account);
    failed(() => store.registerAccount({ ...account, subjectId: 'subject_two' }));
    const old = issue(store);
    const current = issue(store);
    assert.notEqual(old, current);
    failed(() => store.consumeOnce(old, binding()));
    failed(() => issue(store, binding('factor-recovery')));
    // Capacity rejection rolls back; the existing valid token remains usable.
    store.consumeOnce(current, binding());
    const epochTwo = binding('password-reset', { securityEpoch: 2 });
    const expired = issue(store, epochTwo);
    now = 1010;
    issue(store, binding('factor-recovery', { securityEpoch: 2 }));
    failed(() => store.consumeOnce(expired, epochTwo));
  });

  test('persisted fixed policy refuses weaker/different connections; spent token stays spent', t => {
    const { open } = fixture(t);
    const store = open();
    store.registerAccount(account);
    const token = issue(store);
    store.close();
    const restarted = open();
    restarted.consumeOnce(token, binding());
    restarted.close();
    const again = open();
    failed(() => again.consumeOnce(token, binding()));
    for (const policy of [{ ttlSeconds: 900 }, { maxOutstanding: 5 }, { maxAccounts: 5 }, { clockId: 'other' }]) failed(() => open(policy));
    for (const ttlSeconds of [0, 901, NaN, Infinity]) failed(() => open({ ttlSeconds }));
  });

  test('plain data snapshots, closed purposes and canonical tokens reject injection and mutation', t => {
    const { open } = fixture(t);
    const store = open();
    store.registerAccount(account);
    for (const token of ["' OR 1=1 --", '', 'a'.repeat(100000), 'A'.repeat(42) + 'B', null]) failed(() => store.consumeOnce(token, binding()));
    failed(() => issue(store, binding('unknown-purpose')));
    failed(() => issue(store, binding('password-reset', { tenantId: "' OR 1=1 --" })));
    failed(() => issue(store, { ...binding(), arbitrary: true }));
    let calls = 0;
    const getter = { ...binding() };
    Object.defineProperty(getter, 'subjectId', { get() { calls++; return 'subject_one'; } });
    failed(() => issue(store, getter));
    assert.equal(calls, 0);
    const mutable = binding();
    let token;
    store.issue(mutable, delivery => {
      token = delivery.token;
      mutable.subjectId = 'subject_two';
      assert.equal(Object.isFrozen(delivery), true);
      return true;
    });
    store.consumeOnce(token, binding());
  });

  test('delivery errors and async adapters fail closed without exposing exception text', t => {
    const { open } = fixture(t);
    const store = open();
    store.registerAccount(account);
    let token;
    failed(() => store.issue(binding(), delivery => { token = delivery.token; throw new Error(delivery.token); }));
    failed(() => store.consumeOnce(token, binding()));
    failed(() => store.issue(binding(), delivery => { token = delivery.token; return Promise.resolve(true); }));
    failed(() => store.consumeOnce(token, binding()));
    store.close();
    failed(() => store.consumeOnce(randomBytes(32).toString('base64url'), binding()));
  });

  test('two genuinely concurrent SQLite worker connections admit exactly one claim', async t => {
    const { open, database } = fixture(t);
    const store = open();
    store.registerAccount(account);
    const token = issue(store);
    const gate = new SharedArrayBuffer(4);
    const workers = Array.from({ length: 2 }, () => new Worker(new URL(import.meta.url), {
      workerData: { recoveryRace: true, database, token, gate }
    }));
    const results = workers.map(worker => new Promise((resolve, reject) => {
      worker.on('error', reject);
      worker.on('message', value => { if (value !== 'ready') resolve(value); });
      worker.on('exit', code => { if (code !== 0) reject(new Error('synthetic_worker_failed')); });
    }));
    await Promise.all(workers.map(worker => new Promise(resolve => worker.once('message', resolve))));
    Atomics.store(new Int32Array(gate), 0, 1);
    Atomics.notify(new Int32Array(gate), 0, 2);
    const outcomes = await Promise.all(results);
    await Promise.all(workers.map(worker => worker.threadId === -1 ? undefined : new Promise(resolve => worker.once('exit', resolve))));
    assert.equal(outcomes.filter(result => result.accepted).length, 1);
    failed(() => store.consumeOnce(token, binding()));
  });
}
