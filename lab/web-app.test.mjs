import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLabApp } from './web-app.mjs';

// These verdicts are intentionally synthetic: real ClamAV evidence is separate.
const syntheticScanner = async ({ path }) => ({ status: (await readFile(path)).includes(Buffer.from('SYNTHETIC-INFECTED')) ? 'infected' : 'clean', engine: 'synthetic-test', version: '1' });

async function setup(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'security-web-test-'));
  // This task-owned lifecycle record precedes the ephemeral listener.
  const evidence = join(root, 'listener-lifecycle.json');
  await writeFile(evidence, JSON.stringify({ owner: 'web-app.test', pid: process.pid, state: 'launch-intent', root }));
  let now = 1800000000;
  const app = await createLabApp({ dataRoot: root, scanner: syntheticScanner, clock: () => now, ...options });
  const address = await app.start();
  await writeFile(evidence, JSON.stringify({ owner: 'web-app.test', pid: process.pid, state: 'running', ...address }));
  t.after(async () => {
    await app.close();
    await assert.rejects(fetch(address.origin));
    await rm(root, { recursive: true, force: true });
  });
  const client = () => {
    const jar = new Map(); let csrf;
    const raw = async (path, { method = 'GET', body, headers = {} } = {}) => {
      const response = await fetch(address.origin + path, { method, headers: {
        Cookie: [...jar].map(([key, value]) => `${key}=${value}`).join('; '),
        ...(method === 'POST' ? { Origin: address.origin, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' } : {}), ...headers }, body });
      for (const line of response.headers.getSetCookie()) { const [name, ...value] = line.split(';')[0].split('='); jar.set(name, value.join('=')); }
      return response;
    };
    const post = (path, body, headers) => raw(path, { method: 'POST', body: JSON.stringify(body), headers });
    return { raw, post, jar, csrf: () => csrf,
      async bootstrap() { const response = await raw('/api/bootstrap'); assert.equal(response.status, 200); csrf = (await response.json()).csrf; return response; },
      async login(index = 0) {
        const user = app.fixture.users[index];
        let response = await post('/api/login', { value: user.identity });
        let state = await response.json(); assert.equal(state.next, 'password');
        response = await post('/api/password', { ticket: state.ticket, value: user.password });
        state = await response.json(); assert.equal(state.next, 'captcha');
        response = await post('/api/captcha', { ticket: state.ticket, value: 'synthetic-human' });
        state = await response.json(); assert.equal(state.next, 'totp');
        response = await post('/api/totp', { ticket: state.ticket, value: app.fixture.code(user.id) });
        assert.equal(response.status, 200); assert.deepEqual(await response.json(), { authenticated: true });
        assert.match(response.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
      },
    };
  };
  return { app, address, client, advance: () => { now += 30; } };
}

test('real HTTP enforces all stages, ticket source binding and replay, then logout revokes', async t => {
  const { client } = await setup(t); const alice = client(); const other = client();
  const boot = await alice.bootstrap(); await other.bootstrap();
  assert.match(boot.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  assert.equal((await alice.raw('/api/contacts')).status, 401);
  const ticket = (await (await alice.post('/api/login', { value: 'alice@example.test' })).json()).ticket;
  assert.equal((await alice.post('/api/totp', { ticket, value: '123456' })).status, 401);
  assert.equal((await other.post('/api/password', { ticket, value: 'synthetic-alice-password' })).status, 401);
  const password = await alice.post('/api/password', { ticket, value: 'synthetic-alice-password' });
  assert.equal(password.status, 200);
  assert.equal((await alice.post('/api/password', { ticket, value: 'synthetic-alice-password' })).status, 401);
  await alice.login();
  assert.equal((await alice.post('/api/logout', {})).status, 200);
  assert.equal((await alice.raw('/api/contacts')).status, 401);
});

test('hostile contact data is bound SQL data; ownership claims cannot read or write for another user', async t => {
  const { client } = await setup(t); const alice = client(); const bob = client();
  await alice.bootstrap(); await bob.bootstrap(); await alice.login(); await bob.login(1);
  const payload = { fullName: "O'Connor", email: "x'or'1'='1@example.test", phone: '+12025550123',
    message: "'); DROP TABLE contacts; -- <img src=x onerror=alert(1)>", ownerId: 'lab-bob', userId: 'lab-bob' };
  assert.equal((await alice.post('/api/contacts', payload)).status, 201);
  const rows = await (await alice.raw('/api/contacts')).json();
  assert.equal(rows.contacts.length, 1); assert.equal(rows.contacts[0].message, payload.message);
  assert.equal((await (await bob.raw('/api/contacts')).json()).contacts.length, 0);
  assert.equal((await alice.post('/api/contacts', { ...payload, email: 'not-an-email' })).status, 400);
  assert.equal((await alice.post('/api/contacts', { ...payload, fullName: '<script>' })).status, 400);
});

test('uploads stay unavailable until clean scan; another owner cannot process or download', async t => {
  const { client } = await setup(t); const alice = client(); const bob = client();
  await alice.bootstrap(); await bob.bootstrap(); await alice.login(); await bob.login(1);
  const upload = async bytes => {
    const response = await alice.raw('/api/uploads', { method: 'POST', body: bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Owner-Id': 'lab-bob' } });
    assert.equal(response.status, 201); return (await response.json()).id;
  };
  const id = await upload(Buffer.from('hello synthetic lab'));
  assert.equal((await alice.raw(`/api/uploads/${id}`)).status, 404);
  assert.equal((await bob.post(`/api/uploads/${id}/process`, {})).status, 404);
  assert.equal((await bob.raw(`/api/uploads/${id}`)).status, 404);
  assert.equal((await (await alice.post(`/api/uploads/${id}/process`, {})).json()).status, 'clean');
  const response = await alice.raw(`/api/uploads/${id}`);
  assert.equal(await response.text(), 'hello synthetic lab');
  assert.match(response.headers.get('content-disposition'), /^attachment;/);
  assert.equal(response.headers.get('content-type'), 'application/octet-stream');
  const infected = await upload(Buffer.from('SYNTHETIC-INFECTED'));
  assert.equal((await (await alice.post(`/api/uploads/${infected}/process`, {})).json()).status, 'rejected');
  assert.equal((await alice.raw(`/api/uploads/${infected}`)).status, 404);
});

test('server rejects CSRF, hostile origin/Host, malformed schema/content type and bounded bodies', async t => {
  const { client, address } = await setup(t, { maxJsonBytes: 256, maxUploadBytes: 32 }); const alice = client();
  await alice.bootstrap();
  assert.equal((await alice.post('/api/login', { value: 'alice@example.test' }, { 'X-CSRF-Token': 'wrong' })).status, 403);
  assert.equal((await alice.post('/api/login', { value: 'alice@example.test' }, { Origin: 'https://evil.example' })).status, 403);
  const hostileHost = await new Promise((resolveRequest, reject) => {
    const req = httpRequest(address.origin + '/api/bootstrap', { headers: { Host: 'evil.example' } }, res => {
      res.resume(); res.on('end', () => resolveRequest(res.statusCode));
    });
    req.on('error', reject); req.end();
  });
  assert.equal(hostileHost, 403);
  assert.equal((await alice.raw('/api/bootstrap', { headers: { Origin: 'null' } })).status, 403);
  assert.equal((await alice.post('/api/login', { value: 'alice@example.test', bypass: true })).status, 400);
  assert.equal((await alice.raw('/api/login', { method: 'POST', body: '{' })).status, 400);
  assert.equal((await alice.post('/api/login', { value: 'x' }, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await alice.post('/api/login', { value: 'x'.repeat(300) })).status, 413);
  await alice.login();
  assert.equal((await alice.raw('/api/uploads', { method: 'POST', body: Buffer.alloc(33), headers: { 'Content-Type': 'application/octet-stream' } })).status, 413);
  const response = await alice.raw('/missing');
  assert.equal(response.status, 404); assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});

test('chunked body limit is enforced and delayed-body revocation prevents mutation', async t => {
  const { app, address, client } = await setup(t, { maxJsonBytes: 256 }); const alice = client();
  await alice.bootstrap(); await alice.login();
  const streamed = (path, chunks, onStarted) => new Promise((resolveRequest, reject) => {
    const req = httpRequest(address.origin + path, { method: 'POST', headers: { Origin: address.origin, 'X-CSRF-Token': alice.csrf(), 'Content-Type': 'application/json', Cookie: [...alice.jar].map(([key, value]) => `${key}=${value}`).join('; ') } }, res => {
      res.resume(); res.on('end', () => resolveRequest(res.statusCode));
    });
    req.on('error', reject); req.write(chunks[0]);
    setTimeout(() => { onStarted?.(); for (const chunk of chunks.slice(1)) req.write(chunk); req.end(); }, 30);
  });
  assert.equal(await streamed('/api/contacts', ['{"fullName":"', 'x'.repeat(300), '"}']), 413);
  assert.equal(await streamed('/api/contacts', ['{"fullName":"Alice",', '"email":"alice@example.test"}'], () => app.core.revokeUser('lab-alice')), 401);
});

test('loopback binding and explicit scanner configuration are mandatory; quotas are bounded', async t => {
  const root = await mkdtemp(join(tmpdir(), 'security-web-config-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await assert.rejects(createLabApp({ dataRoot: root }), /clamd/);
  const { app, client } = await setup(t, { requestLimit: 2 });
  await assert.rejects(app.start({ host: '0.0.0.0' }), /loopback/);
  const visitor = client(); await visitor.bootstrap();
  assert.equal((await visitor.raw('/')).status, 200);
  assert.equal((await visitor.raw('/')).status, 429);
});
