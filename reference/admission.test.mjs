import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { Worker } from 'node:worker_threads';
import { createPowGate, SqlitePowStore, solvePow, createRedisRateLimiter } from './admission.mjs';

const request = { subject: 'synthetic-user', audience: 'lab', method: 'POST', path: '/bounded', bodyHash: createHash('sha256').update('body').digest('hex') };
function fixture(store = new SqlitePowStore()) {
  let time = 1000;
  const gate = createPowGate({ secret: Buffer.alloc(32, 7), store, difficulty: 8, ttlSeconds: 30, clock: () => time });
  const token = gate.issue(request);
  const counter = solvePow(token, { difficulty: 8 });
  assert.notEqual(counter, null);
  return { gate, store, token, counter, setTime: n => { time = n; } };
}

test('PoW accepts one bound proof; replay and concurrent submissions fail closed', async () => {
  const f = fixture();
  try {
    const replies = await Promise.all(Array.from({ length: 16 }, () => f.gate.verify({ ...f, request })));
    assert.equal(replies.filter(Boolean).length, 1);
    assert.equal(await f.gate.verify({ ...f, request }), false);
  } finally { f.store.close(); }
});

test('PoW binds subject, audience, method, path and exact body digest', async () => {
  const f = fixture();
  try {
    for (const field of ['subject', 'audience', 'method', 'path', 'bodyHash']) {
      const changed = { ...request, [field]: field === 'bodyHash' ? '0'.repeat(64) : 'changed' };
      assert.equal(await f.gate.verify({ ...f, request: changed }), false, field);
    }
    assert.equal(await f.gate.verify({ ...f, request }), true);
  } finally { f.store.close(); }
});

test('PoW rejects tampered difficulty, expiry, MAC and malformed or excessive counters', async () => {
  const f = fixture();
  try {
    const [payload, mac] = f.token.split('.');
    for (const [index, value] of [[3, 0], [5, 999999]]) {
      const data = JSON.parse(Buffer.from(payload, 'base64url'));
      data[index] = value;
      const token = `${Buffer.from(JSON.stringify(data)).toString('base64url')}.${mac}`;
      assert.equal(await f.gate.verify({ ...f, token, request }), false);
    }
    assert.equal(await f.gate.verify({ ...f, token: `${payload}.${'A'.repeat(43)}`, request }), false);
    for (const counter of ['-1', '01', '4294967296', '1e6', '1'.repeat(1000), 1]) assert.equal(await f.gate.verify({ ...f, counter, request }), false);
    f.setTime(1030);
    assert.equal(await f.gate.verify({ ...f, request }), false);
  } finally { f.store.close(); }
});

test('PoW rejects server clock rollback, invalid policy and store failure', async () => {
  const f = fixture();
  try { f.setTime(999); assert.equal(await f.gate.verify({ ...f, request }), false); } finally { f.store.close(); }
  const bad = fixture({ consume: async () => { throw new Error('unavailable'); } });
  assert.equal(await bad.gate.verify({ ...bad, request }), false);
  assert.throws(() => createPowGate({ secret: Buffer.alloc(31), store: {}, difficulty: 50 }));
  assert.throws(() => solvePow('x', { maxAttempts: 1000001 }));
});

test('PoW rejects future issuance and wrong proof without consuming nonce', async () => {
  const store = new SqlitePowStore();
  try {
    const future = createPowGate({ secret: Buffer.alloc(32, 7), store, difficulty: 8, ttlSeconds: 30, clock: () => 1100 });
    const earlier = createPowGate({ secret: Buffer.alloc(32, 7), store, difficulty: 8, ttlSeconds: 30, clock: () => 1000 });
    const token = future.issue(request), counter = solvePow(token, { difficulty: 8 });
    assert.equal(await earlier.verify({ token, counter, request }), false);
    const f = fixture(store);
    let wrong = '0';
    while (createHash('sha256').update(`amqic-pow-v1\n${f.token}\n${wrong}`).digest()[0] === 0) wrong = String(Number(wrong) + 1);
    assert.equal(await f.gate.verify({ ...f, counter: wrong, request }), false);
    assert.equal(await f.gate.verify({ ...f, request }), true);
  } finally { store.close(); }
});

test('SQLite retains replay and clock guards across independent connections/reopen', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'amqic-admission-'));
  const database = join(dir, 'lab.sqlite');
  const first = new SqlitePowStore(database), second = new SqlitePowStore(database);
  const f = fixture(first);
  try {
    const other = createPowGate({ secret: Buffer.alloc(32, 7), store: second, difficulty: 8, ttlSeconds: 30, clock: () => 1000 });
    const replies = await Promise.all([f.gate.verify({ ...f, request }), other.verify({ ...f, request })]);
    assert.equal(replies.filter(Boolean).length, 1);
  } finally { first.close(); second.close(); }
  const reopened = new SqlitePowStore(database);
  try {
    const other = createPowGate({ secret: Buffer.alloc(32, 7), store: reopened, difficulty: 8, ttlSeconds: 30, clock: () => 1000 });
    assert.equal(await other.verify({ ...f, request }), false);
    assert.equal(await reopened.consume('new', 1040, 999), false);
  } finally { reopened.close(); await rm(dir, { recursive: true, force: true }); }
});

test('SQLite unique consumption arbitrates actual concurrent workers', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'amqic-admission-race-'));
  const database = join(dir, 'lab.sqlite');
  const setup = new SqlitePowStore(database); setup.close();
  const signal = new SharedArrayBuffer(4);
  const workers = Array.from({ length: 4 }, () => new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    (async () => {
      const { SqlitePowStore } = await import(workerData.module);
      const store = new SqlitePowStore(workerData.database);
      parentPort.postMessage('ready');
      Atomics.wait(new Int32Array(workerData.signal), 0, 0);
      try { parentPort.postMessage(await store.consume('same-nonce', 1030, 1000)); }
      finally { store.close(); }
    })().catch(error => { throw error; });
  `, { eval: true, workerData: { database, signal, module: new URL('./admission.mjs', import.meta.url).href } }));
  try {
    await Promise.all(workers.map(worker => new Promise((resolve, reject) => { worker.once('message', resolve); worker.once('error', reject); })));
    const outcomes = workers.map(worker => new Promise((resolve, reject) => { worker.once('message', resolve); worker.once('error', reject); }));
    Atomics.store(new Int32Array(signal), 0, 1); Atomics.notify(new Int32Array(signal), 0);
    assert.equal((await Promise.all(outcomes)).filter(Boolean).length, 1);
  } finally {
    await Promise.all(workers.map(worker => worker.terminate()));
    await rm(dir, { recursive: true, force: true });
  }
});

async function fakeRedis(handler, run) {
  const sockets = new Set();
  const server = net.createServer(socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); handler(socket); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run(server.address().port); } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
}

test('Redis fixed command, bounded response and rate decisions', async () => {
  let seen = '';
  await fakeRedis(socket => socket.once('data', data => { seen = data.toString(); socket.end('*2\r\n:3\r\n:200\r\n'); }), async port => {
    assert.deepEqual(await createRedisRateLimiter({ port, limit: 2 }).check('subject'), { allowed: false, count: 3, retryAfterMs: 200 });
  });
  assert.match(seen, /EVAL/); assert.match(seen, /PEXPIRE/); assert.match(seen, /PTTL/);
  assert.doesNotMatch(seen, /subject/);
});

test('Redis errors, disconnects, missing replies and oversized replies fail closed', async () => {
  assert.throws(() => createRedisRateLimiter());
  for (const reply of ['-ERR denied\r\n', 'x'.repeat(1025), null, '*2\r\n:-1\r\n:10\r\n']) {
    await fakeRedis(socket => socket.once('data', () => { if (reply !== null) socket.write(reply); }), async port => {
      assert.deepEqual(await createRedisRateLimiter({ port, timeoutMs: 25 }).check('subject'), { allowed: false, reason: 'unavailable' });
    });
  }
  assert.throws(() => createRedisRateLimiter({ port: 6379, tlsOptions: { rejectUnauthorized: false } }));
});

test('Redis authenticates before fixed EVAL and parses split replies', async () => {
  await fakeRedis(socket => {
    let stage = 0;
    socket.on('data', data => {
      if (stage++ === 0) { assert.match(data.toString(), /AUTH/); socket.write('+OK\r\n'); }
      else { assert.match(data.toString(), /EVAL/); socket.write('*2\r\n:1\r\n'); setTimeout(() => socket.write(':50\r\n'), 5); }
    });
  }, async port => {
    assert.deepEqual(await createRedisRateLimiter({ port, username: 'synthetic', password: 'synthetic-test-only' }).check('subject'), { allowed: true, count: 1, retryAfterMs: 50 });
  });
});
