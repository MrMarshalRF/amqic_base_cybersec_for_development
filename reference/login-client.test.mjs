import test from 'node:test';
import assert from 'node:assert/strict';
import { LoginClient } from './login-client.mjs';
import { fixture } from './fixtures.mjs';

const ticket = 'x'.repeat(43);
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

test('headless client completes the real core sequence with safe state notifications', async () => {
  const f = fixture();
  f.provision();
  const states = [];
  let captchaTicket;
  let session;
  const client = new LoginClient({ onState: state => states.push(state), transport: async ({ step, value, ticket: current }) => {
    if (step === 'login') return f.core.login(value, 'trusted-source');
    if (step === 'password') {
      const result = f.core.password(current, value, 'trusted-source');
      captchaTicket = result.ticket;
      return result;
    }
    if (step === 'captcha') return f.core.captcha(current, value, 'trusted-source');
    session = f.core.secondFactor(current, value, 'trusted-source').session;
    return { authenticated: true };
  } });
  try {
    assert.equal(await client.submit('person@example.test'), true);
    assert.equal(await client.submit('synthetic-long-password'), true);
    assert.equal(await client.submit(f.captchaProof(captchaTicket)), true);
    assert.equal(await client.submit(f.code()), true);
    assert.equal(client.state.step, 'authenticated');
    assert.match(session, /^[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(states.filter(state => !state.busy).map(state => state.step), ['login', 'password', 'captcha', 'totp', 'authenticated']);
    for (const state of states) {
      assert.deepEqual(Object.keys(state).sort(), ['busy', 'error', 'step']);
      assert.ok(Object.isFrozen(state));
    }
    await assert.rejects(client.submit('unexpected'), /Start a new login/);
  } finally { f.core.close(); }
});

test('duplicate submission is rejected before another transport call', async () => {
  const pending = deferred();
  let calls = 0;
  const client = new LoginClient({ onState: () => {}, transport: () => { calls++; return pending.promise; } });
  const first = client.submit('person@example.test');
  await assert.rejects(client.submit('second'), /already in progress/);
  assert.equal(calls, 1);
  pending.resolve({ next: 'password', ticket });
  assert.equal(await first, true);
});

test('synchronous reset from state callback prevents transport invocation', async () => {
  let calls = 0;
  let client;
  client = new LoginClient({ onState: state => { if (state.busy) client.reset(); }, transport: () => {
    calls++;
    return { next: 'password', ticket };
  } });
  assert.equal(await client.submit('identity'), false);
  assert.equal(calls, 0);
  assert.deepEqual(client.state, { step: 'login', busy: false, error: null });
});

test('reset aborts old request and stale success cannot replace a new attempt', async () => {
  const old = deferred();
  let signal;
  let calls = 0;
  const client = new LoginClient({ onState: () => {}, transport: (_request, options) => {
    if (calls++ === 0) { signal = options.signal; return old.promise; }
    return { next: 'password', ticket: 'y'.repeat(43) };
  } });
  const first = client.submit('first');
  client.reset();
  assert.equal(signal.aborted, true);
  assert.equal(await client.submit('second'), true);
  old.resolve({ next: 'password', ticket });
  assert.equal(await first, false);
  assert.deepEqual(client.state, { step: 'password', busy: false, error: null });
});

test('stale rejection cannot reset a later successful attempt', async () => {
  const old = deferred();
  let calls = 0;
  const client = new LoginClient({ onState: () => {}, transport: () => calls++ === 0 ? old.promise : { next: 'password', ticket } });
  const first = client.submit('first');
  client.reset();
  await client.submit('second');
  old.reject(new Error('private diagnostic'));
  assert.equal(await first, false);
  assert.deepEqual(client.state, { step: 'password', busy: false, error: null });
});

test('transport failure and malformed or skipped server stages reset safely', async () => {
  for (const result of [null, {}, { next: 'totp', ticket }, { next: 'password', ticket: 'bad' },
    { next: 'password', ticket, password: 'secret' }, { authenticated: true }]) {
    const client = new LoginClient({ onState: () => {}, transport: async () => result });
    assert.equal(await client.submit('identity'), false);
    assert.deepEqual(client.state, { step: 'login', busy: false, error: 'request_failed' });
  }
  const client = new LoginClient({ onState: () => {}, transport: async () => { throw new Error('private diagnostic'); } });
  assert.equal(await client.submit('identity'), false);
  assert.equal(JSON.stringify(client.state).includes('private'), false);
});

test('failed password clears old ticket before a new login', async () => {
  const seen = [];
  const client = new LoginClient({ onState: () => {}, transport: async request => {
    seen.push({ step: request.step, ticket: request.ticket });
    if (request.step === 'password') throw new Error('denied');
    return { next: 'password', ticket };
  } });
  await client.submit('identity');
  await client.submit('password');
  await client.submit('identity');
  assert.deepEqual(seen, [{ step: 'login', ticket: undefined }, { step: 'password', ticket }, { step: 'login', ticket: undefined }]);
});

test('throwing state observers cannot strand busy or invalidate successful authentication', async () => {
  const seen = [];
  const client = new LoginClient({ onState: () => { throw new Error('synthetic renderer failure'); },
    transport: request => {
      seen.push(request.step);
      const next = { login: 'password', password: 'captcha', captcha: 'totp' }[request.step];
      return next ? { next, ticket } : { authenticated: true };
    } });
  for (const value of ['identity', 'password', 'proof', '123456']) assert.equal(await client.submit(value), true);
  assert.deepEqual(seen, ['login', 'password', 'captcha', 'totp']);
  assert.deepEqual(client.state, { step: 'authenticated', busy: false, error: null });
  client.reset();
  assert.equal(await client.submit('retry'), true);
});

test('observer failures on request error and reset preserve retry and clear the old ticket', async () => {
  const seen = [];
  const client = new LoginClient({ onState: () => { throw new Error('synthetic renderer failure'); },
    transport: request => {
      seen.push({ step: request.step, ticket: request.ticket });
      if (request.step === 'password') throw new Error('synthetic transport failure');
      return { next: 'password', ticket };
    } });
  assert.equal(await client.submit('identity'), true);
  assert.equal(await client.submit('password'), false);
  assert.deepEqual(client.state, { step: 'login', busy: false, error: 'request_failed' });
  client.reset();
  assert.equal(await client.submit('retry'), true);
  assert.equal(seen[2].ticket, undefined);
});

test('rejected async state notifications are observed without delaying transitions', async () => {
  const client = new LoginClient({ onState: async () => { throw new Error('synthetic async renderer failure'); },
    transport: () => ({ next: 'password', ticket }) });
  assert.equal(await client.submit('identity'), true);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(client.state.busy, false);
});

test('reset from a successful state notification makes the completed attempt stale', async () => {
  let client;
  client = new LoginClient({ onState: state => { if (state.step === 'password') client.reset(); },
    transport: () => ({ next: 'password', ticket }) });
  assert.equal(await client.submit('identity'), false);
  assert.deepEqual(client.state, { step: 'login', busy: false, error: null });
});
