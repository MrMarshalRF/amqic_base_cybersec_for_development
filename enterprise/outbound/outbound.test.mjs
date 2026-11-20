import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createOutboundClient, createReturnRouteResolver, isPublicIPv4, OutboundError } from './outbound.mjs';

const endpoint = () => ({ id: 'catalog', hostname: 'catalog.example.com', path: '/public/catalog', maxBytes: 32, timeoutMs: 1000, contentType: 'application/json' });
const publicAnswers = () => [{ address: '93.184.216.34', family: 4 }];
function fixture({ answers = publicAnswers(), resolve, respond, timeoutMs } = {}) {
  let calls = 0, dnsCalls = 0, options, req, res, socket;
  const config = endpoint();
  const originalHost = config.hostname;
  if (timeoutMs) config.timeoutMs = timeoutMs;
  const client = createOutboundClient({ endpoints: [config],
    resolve: resolve ?? (async (name, flags) => { ++dnsCalls; assert.equal(name, originalHost); assert.deepEqual(flags, { all: true, verbatim: true }); return answers; }),
    request: (supplied, callback) => {
      ++calls; options = supplied;
      req = new EventEmitter(); req.destroyed = false;
      req.destroy = () => { req.destroyed = true; };
      socket = { destroyed: false, destroy() { this.destroyed = true; } };
      req.end = () => queueMicrotask(() => {
        req.emit('socket', socket);
        res = new EventEmitter(); res.statusCode = 200; res.complete = true;
        res.headers = { 'content-type': 'application/json', 'content-length': '2' };
        res.destroyed = false; res.destroy = () => { res.destroyed = true; };
        if (respond) respond(res, callback, req);
        else { callback(res); res.emit('data', Buffer.from('{}')); res.emit('end'); }
      });
      return req;
    }
  });
  return { client, config, get calls() { return calls; }, get dnsCalls() { return dnsCalls; }, get options() { return options; }, get req() { return req; }, get res() { return res; }, get socket() { return socket; } };
}
const denied = async (promise, code) => assert.rejects(promise, error => error instanceof OutboundError && error.code === code && error.message === 'Outbound request denied or failed');

test('fixed GET pins checked IPv4 while preserving TLS hostname and direct transport', async () => {
  const f = fixture();
  assert.equal((await f.client.get('catalog')).toString(), '{}');
  const o = f.options;
  assert.equal(o.protocol, 'https:'); assert.equal(o.method, 'GET'); assert.equal(o.port, 443);
  assert.equal(o.hostname, 'catalog.example.com'); assert.equal(o.servername, o.hostname);
  assert.equal(o.path, '/public/catalog'); assert.equal(o.agent, false); assert.equal(o.rejectUnauthorized, true);
  assert.equal(o.family, 4); assert.equal(o.maxHeaderSize, 8192);
  assert.deepEqual(o.headers, { accept: 'application/json', 'accept-encoding': 'identity' });
  // Resolve every operation; lookup never invokes DNS a second time.
  const second = f.client.get('catalog');
  await second; assert.equal(f.dnsCalls, 2);
  const pending = fixture({ respond(res, cb) { cb(res); } });
  const controller = new AbortController(); const operation = pending.client.get('catalog', { signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve));
  pending.options.lookup('catalog.example.com', {}, (error, address, family) => { assert.ifError(error); assert.equal(address, '93.184.216.34'); assert.equal(family, 4); });
  pending.options.lookup('catalog.example.com', { all: true }, (error, addresses) => { assert.ifError(error); assert.deepEqual(addresses, publicAnswers()); });
  pending.options.lookup('other.example.com', {}, error => assert.ok(error));
  controller.abort(); await denied(operation, 'ABORTED');
  assert.ok(pending.req.destroyed && pending.res.destroyed && pending.socket.destroyed);
});

test('conservative special-use IPv4, IPv6, mapped and alternate textual forms denied', () => {
  for (const address of ['0.1.2.3', '10.1.2.3', '100.64.0.1', '100.127.255.255', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.0.0.9', '192.0.2.1', '192.168.1.1', '192.88.99.1', '198.18.0.1', '198.19.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255', '168.63.129.16', '::1', '::ffff:93.184.216.34', '2001:4860:4860::8888', '0177.0.0.1', '2130706433', '0x7f000001']) assert.equal(isPublicIPv4(address), false, address);
  assert.equal(isPublicIPv4('93.184.216.34'), true);
});

test('whole DNS answer list is rejected before any request', async () => {
  for (const answers of [[], null, [{ address: '127.0.0.1', family: 4 }], [...publicAnswers(), { address: '10.0.0.1', family: 4 }], [...publicAnswers(), { address: '::1', family: 6 }], Array(33).fill(publicAnswers()[0])]) {
    const f = fixture({ answers }); await denied(f.client.get('catalog'), 'DESTINATION'); assert.equal(f.calls, 0);
  }
});

test('catalog snapshot, closed caller arguments and no caller URL/headers/body', async () => {
  const f = fixture(); f.config.hostname = 'attacker.example.com'; f.config.path = '/changed';
  await f.client.get('catalog'); assert.equal(f.options.hostname, 'catalog.example.com'); assert.equal(f.options.path, '/public/catalog');
  const initial = f.calls;
  for (const [id, options] of [['https://example.com'], ['__proto__'], ['constructor'], ['catalog', { url: 'https://example.com' }], ['catalog', { headers: {} }], ['catalog', { method: 'POST' }], ['catalog', { body: 'x' }], ['catalog', { signal: {} }]]) await denied(f.client.get(id, options), 'ARGUMENTS');
  assert.equal(f.calls, initial);
});

test('invalid startup destinations and policy values denied', () => {
  for (const hostname of ['0x7f.0.0.1', 'api.example.123']) assert.throws(() => createOutboundClient({ endpoints: [{ ...endpoint(), hostname }] }), TypeError);
  for (const delta of [{ hostname: '127.0.0.1' }, { hostname: 'Catalog.example.com' }, { hostname: '*.example.com' }, { hostname: 'example.com.' }, { hostname: 'éxample.com' }, { hostname: 'example.com:443' }, { path: '//host' }, { path: '/a/../b' }, { path: '/%2e%2e' }, { path: '/a?b' }, { path: '/a#b' }, { maxBytes: 1048577 }, { timeoutMs: 10001 }, { contentType: 'text/html' }, { headers: {} }, { url: 'https://example.com' }, { method: 'GET' }]) assert.throws(() => createOutboundClient({ endpoints: [{ ...endpoint(), ...delta }] }), TypeError);
});

test('DNS timeout and abort prevent late resolver completion from starting request', async () => {
  for (const mode of ['timeout', 'abort']) {
    let release;
    const f = fixture({ timeoutMs: 15, resolve: () => new Promise(resolve => { release = resolve; }) });
    const controller = new AbortController(); const operation = f.client.get('catalog', { signal: controller.signal });
    await new Promise(resolve => setImmediate(resolve));
    if (mode === 'abort') controller.abort();
    await denied(operation, mode === 'abort' ? 'ABORTED' : 'TIMEOUT');
    release(publicAnswers()); await new Promise(resolve => setImmediate(resolve)); assert.equal(f.calls, 0);
  }
  const f = fixture({ resolve: async () => { throw new Error('private DNS diagnostic'); } });
  await denied(f.client.get('catalog'), 'TRANSPORT'); assert.equal(f.calls, 0);
});

test('reject redirects, non200, type, encoding and declared length with resource cleanup', async () => {
  for (const change of [r => r.statusCode = 302, r => r.statusCode = 201, r => r.headers['content-type'] = 'text/html', r => r.headers['content-type'] = ['application/json'], r => r.headers['content-encoding'] = 'gzip', r => r.headers['content-length'] = '33', r => r.headers['content-length'] = '-1']) {
    const f = fixture({ respond(r, cb) { change(r); cb(r); } });
    await denied(f.client.get('catalog'), 'RESPONSE'); assert.ok(f.req.destroyed && f.res.destroyed && f.socket.destroyed); assert.equal(f.calls, 1);
  }
});

test('stream overflow, excessive chunks, truncation and upstream errors deny safely', async () => {
  for (const action of [r => r.emit('data', Buffer.alloc(33)), r => { for (let i = 0; i < 4097; ++i) r.emit('data', Buffer.alloc(0)); }, r => { r.emit('data', Buffer.from('x')); r.emit('end'); }, r => r.emit('aborted'), r => r.emit('error', new Error('sensitive upstream body'))]) {
    const f = fixture({ respond(r, cb) { cb(r); action(r); } });
    await assert.rejects(f.client.get('catalog'), error => error instanceof OutboundError && !error.message.includes('sensitive'));
    assert.ok(f.req.destroyed && f.res.destroyed && f.socket.destroyed);
  }
});

test('deadline bounds headers/body and no retry occurs', async () => {
  for (const respond of [(r, cb) => cb(r), () => {}]) {
    const f = fixture({ timeoutMs: 15, respond }); await denied(f.client.get('catalog'), 'TIMEOUT');
    assert.equal(f.calls, 1); assert.ok(f.req.destroyed && f.socket.destroyed);
  }
});

test('fixed internal return route IDs preserve canonical values, reject URL tricks', () => {
  const routes = [{ id: 'account', path: '/account' }, { id: 'home', path: '/' }];
  const select = createReturnRouteResolver(routes); routes[0].path = '//attacker';
  assert.equal(select('account'), '/account'); assert.equal(select('home'), '/');
  for (const id of ['__proto__', 'constructor', 'https://attacker', '//attacker', '/account', 'account?x', '%61ccount', null, {}]) assert.throws(() => select(id));
  for (const path of ['https://host', '//host', '/\\host', '/a/../account', '/%2f%2fhost', '/%0d%0aLocation', '/a?x', '/a#x', '/a\r\n', '/a.b']) assert.throws(() => createReturnRouteResolver([{ id: 'bad', path }]));
});
