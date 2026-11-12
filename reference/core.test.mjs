import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { SecurityCore, AccessDenied, syntheticTools } from './core.mjs';
import { canonical, hash, signRequest, totp } from './crypto.mjs';
import { fixture } from './fixtures.mjs';

function setup(t, options) {
  const f = fixture(options);
  f.provision();
  t.after(() => f.core.close());
  return f;
}

function prepared(f, id = 'record-1', operation = 'operation-1') {
  f.core.seedSyntheticRecord(id, 'user-1');
  const session = f.login();
  f.advance();
  const body = { session, action: 'records.remove', args: { id }, operation };
  body.grant = f.core.stepUp({ ...body, code: f.code() }).grant;
  return body;
}

async function race(database, now, requests, mode) {
  const barrier = new SharedArrayBuffer(4);
  const workers = [];
  try {
    return await Promise.all(requests.map(request => new Promise((resolve, reject) => {
      let finished = false;
      const worker = new Worker(new URL('./race-worker.mjs', import.meta.url), {
        workerData: { database, now, request, barrier, mode }
      });
      workers.push(worker);
      worker.once('error', reject);
      worker.once('exit', code => { if (!finished) reject(new Error('Worker exited without result: ' + code)); });
      worker.on('message', message => {
        if (message === 'ready') {
          if (Atomics.add(new Int32Array(barrier), 0, 1) === requests.length - 1) {
            Atomics.store(new Int32Array(barrier), 0, 3);
            Atomics.notify(new Int32Array(barrier), 0);
          }
        } else { finished = true; resolve(message); }
      });
    })));
  } finally { await Promise.all(workers.map(worker => worker.terminate())); }
}

test('RFC 6238 SHA-1 eight digit reference vectors', () => {
  const key = Buffer.from('12345678901234567890');
  for (const [seconds, expected] of [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]) {
    assert.equal(totp(key, Math.floor(seconds / 30), 8), expected);
  }
});

test('canonical subset rejects undefined, fractional numbers and nonplain objects', () => {
  assert.equal(canonical({ z: [1, true], a: 'x' }), '{"a":"x","z":[1,true]}');
  for (const value of [undefined, 1.1, NaN, new Date(), { x: undefined }]) assert.throws(() => canonical(value));
});

test('every login stage is mandatory, ordered, bound to client and single use', t => {
  const f = setup(t);
  const first = f.core.login('person@example.test', 'client');
  assert.throws(() => f.core.secondFactor(first.ticket, f.code(), 'client'), AccessDenied);
  assert.throws(() => f.core.password(first.ticket, 'synthetic-long-password', 'other-client'), AccessDenied);
  const password = f.core.password(first.ticket, 'synthetic-long-password', 'client');
  assert.equal(password.next, 'captcha');
  assert.throws(() => f.core.password(first.ticket, 'synthetic-long-password', 'client'), AccessDenied);
  assert.throws(() => f.core.secondFactor(password.ticket, f.code(), 'client'), AccessDenied);
  const captcha = f.core.captcha(password.ticket, f.captchaProof(password.ticket), 'client');
  const result = f.core.secondFactor(captcha.ticket, f.code(), 'client');
  assert.match(result.session, /^[A-Za-z0-9_-]{43}$/);
  assert.throws(() => f.core.secondFactor(captcha.ticket, f.code(), 'client'), AccessDenied);
});

test('unknown identities receive the same login shape and generic password denial', t => {
  const f = setup(t);
  const unknown = f.core.login('absent@example.test', 'client');
  const known = f.core.login('person@example.test', 'client');
  assert.deepEqual(Object.keys(unknown), Object.keys(known));
  assert.equal(unknown.next, known.next);
  for (const ticket of [known.ticket, unknown.ticket]) {
    assert.throws(() => f.core.password(ticket, 'wrong-password', 'client'), error => error instanceof AccessDenied && error.message === 'Request denied');
  }
});

test('wrong captcha and expired tickets cannot advance', t => {
  const f = setup(t);
  const first = f.core.login('person@example.test', 'client');
  const next = f.core.password(first.ticket, 'synthetic-long-password', 'client');
  assert.throws(() => f.core.captcha(next.ticket, 'untrusted-string', 'client'), AccessDenied);
  assert.throws(() => f.core.captcha(next.ticket, f.captchaProof(next.ticket), 'client'), AccessDenied);
  const expired = f.core.login('person@example.test', 'client');
  f.advance(180);
  assert.throws(() => f.core.password(expired.ticket, 'synthetic-long-password', 'client'), AccessDenied);
});

test('identity limits survive attempts with different client labels', t => {
  const f = setup(t);
  for (let i = 0; i < 10; i++) f.core.login('person@example.test', 'client-' + i);
  assert.throws(() => f.core.login('person@example.test', 'new-client'), AccessDenied);
  f.advance(60);
  assert.equal(f.core.login('person@example.test', 'new-client').next, 'password');
});

test('used TOTP code cannot be reused for step-up, fresh code succeeds', t => {
  const f = setup(t);
  const session = f.login();
  const input = { session, action: 'records.remove', args: { id: 'one' }, operation: 'one', code: f.code() };
  assert.throws(() => f.core.stepUp(input), AccessDenied);
  f.advance();
  assert.match(f.core.stepUp({ ...input, code: f.code() }).grant, /^[A-Za-z0-9_-]{43}$/);
});

test('Ed25519 binds body, method, exact target, audience, key id, timestamp and nonce', t => {
  const f = setup(t);
  const signed = f.request({ example: true });
  for (const change of [{ body: Buffer.from('{}') }, { method: 'GET' }, { target: '/tools/call?x=1' },
    { audience: 'elsewhere' }, { keyId: 'another' }, { timestamp: signed.timestamp - 1 }, { nonce: 'x'.repeat(43) }]) {
    assert.throws(() => f.core.verifyRequest({ ...signed, ...change }, 'records.remove'), AccessDenied);
  }
  assert.equal(f.core.verifyRequest(signed, 'records.remove').userId, 'user-1');
  assert.throws(() => f.core.verifyRequest(signed, 'records.remove'), AccessDenied);
});

test('wrong signing key, old request, missing scope and revoked key are rejected', t => {
  const f = setup(t);
  const wrong = generateKeyPairSync('ed25519');
  const input = f.request({});
  assert.throws(() => f.core.verifyRequest(signRequest(wrong.privateKey, input), 'records.remove'), AccessDenied);
  assert.throws(() => f.core.verifyRequest(input, 'admin'), AccessDenied);
  f.advance(31);
  assert.throws(() => f.core.verifyRequest(input, 'records.remove'), AccessDenied);
  f.core.revokeKey('example-key');
  assert.throws(() => f.core.verifyRequest(f.request({}), 'records.remove'), AccessDenied);
});

test('sensitive tool operation, idempotent fresh-nonce retry and changed argument rejection', t => {
  const f = setup(t);
  const body = prepared(f);
  const request = f.request(body);
  assert.deepEqual(f.core.dispatch(request), { removed: 1 });
  assert.throws(() => f.core.dispatch(request), AccessDenied);
  assert.deepEqual(f.core.dispatch(f.request(body)), { removed: 1 });
  assert.throws(() => f.core.dispatch(f.request({ ...body, args: { id: 'other' } })), AccessDenied);
  assert.throws(() => f.core.dispatch(f.request({ ...body, operation: 'another' })), AccessDenied);
});

test('idempotency survives a renewed session and invokes handler only once', t => {
  let calls = 0;
  const base = syntheticTools['records.remove'];
  const f = setup(t, { tools: { 'records.remove': { ...base, handler: (context, args) => {
    calls++;
    return base.handler(context, args);
  } } } });
  const body = prepared(f);
  assert.deepEqual(f.core.dispatch(f.request(body)), { removed: 1 });
  f.core.logout(body.session);
  f.advance();
  const session = f.login();
  assert.deepEqual(f.core.dispatch(f.request({ ...body, session })), { removed: 1 });
  assert.equal(calls, 1);
});

test('machine scope cannot exceed current user scopes', t => {
  const f = setup(t);
  f.core.registerKey({ keyId: 'overbroad', userId: 'user-1', publicKey: f.pair.publicKey.export({ type: 'spki', format: 'pem' }), scopes: ['admin'] });
  const input = f.request({});
  const request = signRequest(f.pair.privateKey, { ...input, keyId: 'overbroad' });
  assert.throws(() => f.core.verifyRequest(request, 'admin'), AccessDenied);
});

test('registered key identifiers match the signing grammar', t => {
  const f = setup(t);
  const publicKey = f.pair.publicKey.export({ type: 'spki', format: 'pem' });
  for (const keyId of ['machine@example', '', 'x'.repeat(129), 'bad key']) {
    assert.throws(() => f.core.registerKey({ keyId, userId: 'user-1', publicKey, scopes: ['records.remove'] }), TypeError);
  }
  for (const keyId of ['machine.A_1-9', 'x'.repeat(128)]) {
    f.core.registerKey({ keyId, userId: 'user-1', publicKey, scopes: ['records.remove'] });
    const request = signRequest(f.pair.privateKey, { ...f.request({}), keyId });
    assert.equal(f.core.verifyRequest(request, 'records.remove').userId, 'user-1');
  }
});

test('grant binds action, arguments, session, operation and expiration', t => {
  const f = setup(t);
  const body = prepared(f);
  for (const changed of [{ action: 'unknown-tool' }, { args: { id: 'other' } }, { session: 'x'.repeat(43) },
    { operation: 'other-operation' }, { grant: 'x'.repeat(43) }]) {
    assert.throws(() => f.core.dispatch(f.request({ ...body, ...changed })), AccessDenied);
  }
  f.advance(60);
  assert.throws(() => f.core.dispatch(f.request(body)), AccessDenied);
});

test('session expiration, logout and user revocation reject tool access', t => {
  const f = setup(t);
  const body = prepared(f);
  f.core.logout(body.session);
  assert.throws(() => f.core.dispatch(f.request(body)), AccessDenied);
  f.advance();
  const other = prepared(f, 'record-2', 'operation-2');
  f.advance(900);
  assert.throws(() => f.core.dispatch(f.request(other)), AccessDenied);
  f.core.revokeUser('user-1');
  assert.throws(() => f.core.verifyRequest(f.request({}), 'records.remove'), AccessDenied);
});

test('failed local handler rolls back its SQL effect, grant and nonce for exact retry', t => {
  let fail = true;
  const base = syntheticTools['records.remove'];
  const tools = { 'records.remove': { ...base, handler: (context, args) => {
    const result = base.handler(context, args);
    if (fail) { fail = false; throw new Error('synthetic failure'); }
    return result;
  } } };
  const f = setup(t, { tools });
  const request = f.request(prepared(f));
  assert.throws(() => f.core.dispatch(request), /synthetic failure/);
  assert.deepEqual(f.core.dispatch(request), { removed: 1 });
});

test('file-backed nonce, TOTP counter, session and idempotency persist across restart', t => {
  const directory = mkdtempSync(join(tmpdir(), 'security-reference-'));
  const database = join(directory, 'state.sqlite');
  const f = fixture({ database });
  f.provision();
  const body = prepared(f);
  const usedRequest = f.request(body);
  assert.deepEqual(f.core.dispatch(usedRequest), { removed: 1 });
  f.core.close();
  const restarted = new SecurityCore({ database, audience: 'synthetic-example', tools: syntheticTools, clock: f.now,
    captcha: { verify: () => false }, factors: { assertEnrollment: () => false, secretFor: () => f.secret } });
  try {
    assert.throws(() => restarted.dispatch(usedRequest), AccessDenied);
    assert.deepEqual(restarted.dispatch(f.request(body)), { removed: 1 });
    assert.throws(() => restarted.stepUp({ ...body, operation: 'next', code: f.code() }), AccessDenied);
  } finally { restarted.close(); rmSync(directory, { recursive: true }); }
});

test('clock rollback is rejected', t => {
  const f = setup(t);
  f.advance(-1);
  assert.throws(() => f.core.login('person@example.test', 'client'), AccessDenied);
});

test('two worker connections race one nonce, exactly one succeeds', { timeout: 20000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'security-race-'));
  const database = join(directory, 'state.sqlite');
  const f = fixture({ database });
  f.provision();
  const request = f.request({});
  try {
    assert.deepEqual((await race(database, f.now(), [request, request], 'verify')).sort(), ['accepted', 'denied']);
  } finally {
    f.core.close();
    rmSync(directory, { recursive: true });
  }
});

test('concurrent signed calls consume one grant and share one transactional result', { timeout: 20000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'security-grant-race-'));
  const database = join(directory, 'state.sqlite');
  const f = fixture({ database });
  f.provision();
  try {
    const body = prepared(f);
    const results = await race(database, f.now(), [f.request(body), f.request(body)], 'dispatch');
    assert.deepEqual(results, [{ removed: 1 }, { removed: 1 }]);
  } finally {
    f.core.close();
    rmSync(directory, { recursive: true });
  }
});

test('tool body must be canonical and exactly shaped, unknown tools never execute', t => {
  const f = setup(t);
  const body = prepared(f);
  const request = f.request(body);
  assert.throws(() => f.core.dispatch(signRequest(f.pair.privateKey, { ...request, body: Buffer.from(JSON.stringify(body, null, 2)) })), AccessDenied);
  assert.throws(() => f.core.dispatch(f.request({ ...body, command: 'anything' })), AccessDenied);
  assert.throws(() => f.core.dispatch(f.request({ ...body, action: 'shell' })), AccessDenied);
});

test('canonical tool bodies compare original UTF-8 bytes and preserve Unicode arguments', t => {
  let calls = 0;
  const text = 'Привет 🌍 \ufffd';
  const f = setup(t, { tools: { echo: { scope: 'records.remove', stepUp: false,
    validate: args => typeof args?.text === 'string', handler: (_context, args) => { calls++; return args; } } } });
  const body = { session: f.login(), action: 'echo', args: { text }, operation: 'unicode', grant: null };
  const request = f.request(body);
  const marker = Buffer.from('\ufffd');
  const index = request.body.indexOf(marker);
  const invalid = Buffer.concat([request.body.subarray(0, index), Buffer.from([0xff]), request.body.subarray(index + marker.length)]);
  // UTF-8 replacement decoding produces the same parsed object, but not canonical bytes.
  assert.equal(invalid.toString('utf8'), request.body.toString('utf8'));
  assert.throws(() => f.core.dispatch(signRequest(f.pair.privateKey, { ...request, body: invalid })), AccessDenied);
  assert.equal(calls, 0);
  assert.deepEqual(f.core.dispatch(request), { text });
  assert.equal(calls, 1);
});

test('known async trusted callbacks are rejected before invocation', () => {
  let calls = 0;
  const asyncCallback = async () => { calls++; throw new Error('must not run'); };
  const options = { audience: 'test', captcha: { verify: () => true },
    factors: { assertEnrollment: () => true, secretFor: () => Buffer.alloc(20) } };
  for (const changes of [{ clock: asyncCallback }, { captcha: { verify: asyncCallback } },
    { factors: { ...options.factors, assertEnrollment: asyncCallback } },
    { factors: { ...options.factors, secretFor: asyncCallback } },
    ...['handler', 'validate'].map(key => ({ tools: { echo: { ...syntheticTools['records.remove'], [key]: asyncCallback } } }))]) {
    assert.throws(() => new SecurityCore({ ...options, ...changes }), TypeError);
  }
  assert.equal(calls, 0);
});

test('unexpected rejected handler Promise is observed and local transaction remains retryable', async t => {
  let first = true;
  const base = syntheticTools['records.remove'];
  const f = setup(t, { tools: { 'records.remove': { ...base, handler: (context, args) => {
    const result = base.handler(context, args);
    if (first) { first = false; return Promise.reject(new Error('synthetic async failure')); }
    return result;
  } } } });
  const request = f.request(prepared(f));
  assert.throws(() => f.core.dispatch(request), /Tool handlers must be synchronous/);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.core.dispatch(request), { removed: 1 });
});

test('unexpected rejected adapter Promises fail synchronously without an unhandled rejection', async () => {
  const options = { audience: 'test', captcha: { verify: () => true },
    factors: { assertEnrollment: () => true, secretFor: () => Buffer.alloc(20) } };
  const rejected = () => Promise.reject(new Error('synthetic adapter failure'));
  for (const [changes, invoke] of [
    [{ clock: rejected }, core => core.login('person', 'source')],
    [{ factors: { ...options.factors, assertEnrollment: rejected } }, core => core.provisionUser({
      id: 'user', identity: 'person', password: 'synthetic-long-password', factorRef: 'factor', scopes: [] })]
  ]) {
    const core = new SecurityCore({ ...options, ...changes });
    try { assert.throws(() => invoke(core), /must be synchronous/); }
    finally { core.close(); }
  }
  await new Promise(resolve => setImmediate(resolve));
});
