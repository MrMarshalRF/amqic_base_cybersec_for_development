import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecurityCore } from '../reference/core.mjs';
import { hash, totp } from '../reference/crypto.mjs';
import { createContactWriter, InputValidationError } from '../reference/pii-input.mjs';
import { createUploadStore } from '../reference/upload-pipeline.mjs';
import { createClamdScanner } from '../reference/clamd-client.mjs';

const token = () => randomBytes(32).toString('base64url');
const publicRoot = fileURLToPath(new URL('./public/', import.meta.url));
const USERS = Object.freeze([
  { id: 'lab-alice', identity: 'alice@example.test', password: 'synthetic-alice-password', factorRef: 'lab-factor-alice' },
  { id: 'lab-bob', identity: 'bob@example.test', password: 'synthetic-bob-password', factorRef: 'lab-factor-bob' },
]);
const SCOPES = ['contacts.read', 'contacts.write', 'uploads.read', 'uploads.write'];
const fail = status => { const error = new Error('Request denied'); error.status = status; return error; };
// Fetch Standard port blocking (checked 2026-11-20): https://fetch.spec.whatwg.org/#port-blocking
// Keep the synthetic HTTP lab reachable by Fetch clients.
// Port 0 is an allocation request, never a published endpoint.
const fetchBlockedPorts = new Set([
  0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
  87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139,
  143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548,
  554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659,
  4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);
function closeListener(server) {
  return new Promise((resolveClose, reject) => server.close(error => error ? reject(error) : resolveClose()));
}
/** Lab-only allocation seam, exported so forced OS allocations can be tested without opening sockets. */
export async function startLoopbackListener(server, { host = '127.0.0.1', port = 0 } = {}, isClosing = () => false) {
  if (host !== '127.0.0.1' || !Number.isInteger(port) || port < 0 || port > 65535) throw new TypeError('Only one loopback listener allowed');
  if (port && fetchBlockedPorts.has(port)) throw new TypeError('Fetch-blocked lab port');
  for (let attempt = 0; attempt < 8; attempt++) {
    if (isClosing()) throw new Error('Lab startup cancelled');
    await new Promise((resolveStart, reject) => {
      const cleanup = () => { server.removeListener('error', error); server.removeListener('listening', listening); };
      const error = cause => { cleanup(); reject(cause); };
      const listening = () => { cleanup(); resolveStart(); };
      server.once('error', error); server.once('listening', listening);
      try { server.listen(port, host); } catch (cause) { error(cause); }
    });
    const allocated = server.address()?.port;
    if (isClosing() || !Number.isInteger(allocated) || allocated < 1 || allocated > 65535 || fetchBlockedPorts.has(allocated)) {
      await closeListener(server);
      if (isClosing()) throw new Error('Lab startup cancelled');
      if (port) throw new Error('Fetch-compatible lab port unavailable');
      continue;
    }
    return { origin: `http://127.0.0.1:${allocated}`, port: allocated, host };
  }
  throw new Error('Fetch-compatible lab port allocation exhausted');
}
function schema(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      required.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw fail(400);
  return value;
}
function shortString(value, maximum = 256) {
  if (typeof value !== 'string' || value.length > maximum) throw fail(400);
  return value;
}
function equal(a, b) {
  return typeof a === 'string' && typeof b === 'string' && /^[A-Za-z0-9_-]{43}$/.test(a) && a.length === b.length &&
    timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function cookies(header = '') {
  const result = Object.create(null);
  if (header.length > 4096) throw fail(400);
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (!name) continue;
    if (Object.hasOwn(result, name)) throw fail(400);
    result[name] = rest.join('=');
  }
  return result;
}
async function readBody(req, maximum) {
  const length = req.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > maximum)) throw fail(413);
  return new Promise((resolveBody, reject) => {
    const chunks = []; let size = 0;
    function cleanup() { req.removeListener('data', data); req.removeListener('end', end); req.removeListener('error', error); req.removeListener('aborted', aborted); }
    function data(chunk) {
      size += chunk.length;
      if (size > maximum) { cleanup(); req.pause(); reject(fail(413)); } else chunks.push(chunk);
    }
    function end() { cleanup(); resolveBody(Buffer.concat(chunks, size)); }
    function error() { cleanup(); reject(fail(400)); }
    function aborted() { cleanup(); reject(fail(400)); }
    req.on('data', data); req.once('end', end); req.once('error', error); req.once('aborted', aborted);
  });
}

/** Purpose-built synthetic local lab. Explicit scanner injection is for tests only. */
export async function createLabApp({ dataRoot, scanner, clamdHost, clamdPort,
  clock = () => Math.floor(Date.now() / 1000), maxUploadBytes = 1048576,
  maxJsonBytes = 16384, requestLimit = 120, maxBrowsers = 256 } = {}) {
  if (typeof dataRoot !== 'string' || !dataRoot ||
      ![maxUploadBytes, maxJsonBytes, requestLimit, maxBrowsers].every(n => Number.isSafeInteger(n) && n > 0)) {
    throw new TypeError('Explicit private dataRoot and positive limits required');
  }
  const realScanner = !scanner;
  if (!scanner) {
    if (clamdHost !== '127.0.0.1' || !Number.isInteger(clamdPort)) throw new TypeError('Explicit loopback clamd endpoint required');
    scanner = createClamdScanner({ host: clamdHost, port: clamdPort, maxBytes: maxUploadBytes });
  }
  if (typeof scanner !== 'function') throw new TypeError('Scanner required');
  dataRoot = resolve(dataRoot);
  await mkdir(dataRoot, { recursive: true, mode: 0o700 });
  if (realScanner) {
    const probePath = join(dataRoot, `.clamd-probe-${token()}`);
    try {
      await writeFile(probePath, Buffer.alloc(0), { flag: 'wx', mode: 0o600 });
      const result = await scanner({ path: probePath, sha256: hash(Buffer.alloc(0)), size: 0 });
      if (result?.status !== 'clean') throw new Error('Clamd startup check failed');
    } finally { await unlink(probePath).catch(() => {}); }
  }
  const proofs = new Set();
  // Public test seeds, deliberately unrelated to real accounts or protected credentials.
  const seeds = new Map(USERS.map((user, i) => [user.factorRef, Buffer.from(i ? '23456789012345678901' : '12345678901234567890')]));
  const core = new SecurityCore({ database: ':memory:', audience: 'synthetic-loopback-lab', clock,
    captcha: { verify: ({ proof, challenge }) => proofs.delete(challenge + ':' + proof) },
    factors: { assertEnrollment: ({ id, factorRef }) => USERS.some(user => user.id === id && user.factorRef === factorRef),
      secretFor: ref => seeds.get(ref) } });
  let database; let uploads;
  try {
    for (const user of USERS) core.provisionUser({ ...user, scopes: SCOPES });
    database = new DatabaseSync(join(dataRoot, 'contacts.sqlite'));
    database.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL DEFAULT '',
      full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, message TEXT);`);
    uploads = await createUploadStore({ root: join(dataRoot, 'uploads'), scanner, maxBytes: maxUploadBytes });
  } catch (error) { database?.close(); core.close(); throw error; }
  const writeContact = createContactWriter(database);
  const setOwner = database.prepare('UPDATE contacts SET owner_id=? WHERE id=?');
  const listContacts = database.prepare('SELECT id,full_name AS fullName,email,phone,message FROM contacts WHERE owner_id=? ORDER BY id LIMIT 100');
  const browsers = new Map(); const rates = new Map();
  let origin; let closing = false; let starting; let closePromise;
  const sockets = new Set(); const inFlight = new Set();
  const fixture = Object.freeze({ users: USERS,
    code: (userId = USERS[0].id) => {
      const user = USERS.find(item => item.id === userId);
      if (!user) throw new TypeError('Unknown synthetic user');
      return totp(seeds.get(user.factorRef), Math.floor(clock() / 30));
    },
  });
  function expire() {
    const now = clock();
    for (const [id, state] of browsers) if (state.expires <= now) browsers.delete(id);
    for (const [id, state] of rates) if (state.start + 60 <= now) rates.delete(id);
  }
  function quota(address) {
    expire(); const now = clock();
    const state = rates.get(address) ?? { start: now, count: 0 };
    rates.set(address, state);
    if (++state.count > requestLimit) throw fail(429);
  }
  function send(res, status, body, headers = {}) {
    res.writeHead(status, headers); res.end(body);
  }
  function json(res, status, value, headers) {
    send(res, status, JSON.stringify(value), { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  }
  function browser(req, create = false) {
    const jar = cookies(req.headers.cookie);
    let id = jar.lab_browser;
    let state = browsers.get(id);
    if (!state && create) {
      if (browsers.size >= maxBrowsers) throw fail(429);
      id = token(); state = { csrf: token(), expires: clock() + 1800 };
      browsers.set(id, state);
    }
    if (!state || state.expires <= clock()) throw fail(403);
    return { id, state, jar };
  }
  function owner(req, scope) {
    const { jar } = browser(req);
    if (!jar.lab_session) throw fail(401);
    try { return core.authorizeSession(jar.lab_session, scope).userId; } catch { throw fail(401); }
  }
  async function parsed(req) {
    if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '')) throw fail(415);
    const bytes = await readBody(req, maxJsonBytes);
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw fail(400); }
  }
  async function handler(req, res) {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'none'; style-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    try {
      if (closing) throw fail(503);
      if (req.headers.host !== new URL(origin).host) throw fail(403);
      if (req.headers.origin !== undefined && req.headers.origin !== origin) throw fail(403);
      if (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site'])) throw fail(403);
      quota(req.socket.remoteAddress);
      if (!['GET', 'POST'].includes(req.method)) throw fail(405);
      if (!req.url.startsWith('/') || req.url.includes('?') || req.url.includes('#') || req.url.includes('%')) throw fail(404);
      const path = req.url;
      if (req.method === 'GET' && ['/', '/app.js'].includes(path)) {
        const body = await readFile(join(publicRoot, path === '/' ? 'index.html' : 'app.js'));
        return send(res, 200, body, { 'Content-Type': path === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8' });
      }
      if (req.method === 'GET' && path === '/api/bootstrap') {
        const { id, state } = browser(req, true);
        return json(res, 200, { csrf: state.csrf, synthetic: true,
          users: USERS.map(user => ({ identity: user.identity, password: user.password, code: fixture.code(user.id) })),
          captchaAnswer: 'synthetic-human' }, { 'Set-Cookie': `lab_browser=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800` });
      }
      if (req.method === 'POST') {
        if (req.headers.origin !== origin) throw fail(403);
        const { state } = browser(req);
        if (!equal(req.headers['x-csrf-token'], state.csrf)) throw fail(403);
      }
      const loginMethods = { '/api/login': 'login', '/api/password': 'password', '/api/captcha': 'captcha', '/api/totp': 'secondFactor' };
      if (req.method === 'POST' && Object.hasOwn(loginMethods, path)) {
        const input = await parsed(req);
        schema(input, path === '/api/login' ? ['value'] : ['ticket', 'value']);
        shortString(input.value, 512);
        if (path !== '/api/login') shortString(input.ticket, 43);
        const { id, jar } = browser(req);
        let result;
        try {
          if (path === '/api/login') {
            if (jar.lab_session) core.logout(jar.lab_session);
            result = core.login(input.value, id);
          } else if (path === '/api/captcha') {
            // Synthetic provider receipt; the core still enforces stage, binding and one use.
            const proof = token(); const binding = hash(input.ticket) + ':' + proof;
            if (input.value === 'synthetic-human') proofs.add(binding);
            try { result = core.captcha(input.ticket, proof, id); } finally { proofs.delete(binding); }
          } else result = core[loginMethods[path]](input.ticket, input.value, id);
        } catch { throw fail(401); }
        if (path === '/api/totp') return json(res, 200, { authenticated: true },
          { 'Set-Cookie': `lab_session=${result.session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900` });
        return json(res, 200, result);
      }
      if (path === '/api/logout' && req.method === 'POST') {
        schema(await parsed(req), []); const { jar } = browser(req);
        if (jar.lab_session) core.logout(jar.lab_session);
        return json(res, 200, { loggedOut: true }, { 'Set-Cookie': 'lab_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
      }
      if (path === '/api/contacts' && req.method === 'GET') return json(res, 200, { contacts: listContacts.all(owner(req, 'contacts.read')) });
      if (path === '/api/contacts' && req.method === 'POST') {
        owner(req, 'contacts.write'); const input = await parsed(req);
        // Ownership claims never become authority; strip these known untrusted fields.
        schema(input, ['fullName', 'email'], ['phone', 'message', 'ownerId', 'userId']);
        const { ownerId: ignoredOwner, userId: ignoredUser, ...contact } = input;
        const userId = owner(req, 'contacts.write');
        database.exec('BEGIN IMMEDIATE');
        try {
          const result = writeContact(contact);
          setOwner.run(userId, result.lastInsertRowid);
          database.exec('COMMIT');
          return json(res, 201, { id: Number(result.lastInsertRowid) });
        } catch (error) { database.exec('ROLLBACK'); throw error; }
      }
      if (path === '/api/uploads' && req.method === 'POST') {
        owner(req, 'uploads.write');
        if (req.headers['content-type'] !== 'application/octet-stream') throw fail(415);
        const bytes = await readBody(req, maxUploadBytes);
        return json(res, 201, await uploads.stage({ ownerId: owner(req, 'uploads.write'), bytes, mediaType: 'application/octet-stream' }));
      }
      const match = /^\/api\/uploads\/([0-9a-f-]{36})(\/process)?$/.exec(path);
      if (match && match[2] && req.method === 'POST') {
        owner(req, 'uploads.write'); schema(await parsed(req), []);
        const userId = owner(req, 'uploads.write');
        return json(res, 200, await uploads.scanAndPromote({ id: match[1], ownerId: userId }));
      }
      if (match && !match[2] && req.method === 'GET') {
        const file = await uploads.get({ id: match[1], ownerId: owner(req, 'uploads.read') });
        return send(res, 200, file.bytes, { 'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${file.filename}"` });
      }
      throw fail(404);
    } catch (error) {
      const status = error.status ?? (error instanceof InputValidationError ? 400 :
        ['not_found', 'not_available', 'invalid_identity'].includes(error.code) ? 404 : error.code === 'upload_busy' ? 409 : 500);
      if (status === 413) res.setHeader('Connection', 'close');
      if (!res.headersSent && !res.destroyed) json(res, status, { error: status === 500 ? 'request_failed' : 'request_denied' });
      else res.destroy();
    }
  }
  const server = createServer((req, res) => {
    const pending = handler(req, res); inFlight.add(pending);
    pending.finally(() => inFlight.delete(pending));
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.keepAliveTimeout = 1000;
  server.maxHeadersCount = 32;
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('clientError', (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\n\r\n"));
  return {
    core, fixture,
    async start({ host = '127.0.0.1', port = 0 } = {}) {
      if (origin || starting || closing) throw new TypeError('Only one loopback listener allowed');
      starting = startLoopbackListener(server, { host, port }, () => closing);
      try {
        const address = await starting;
        if (closing) throw new Error('Lab startup cancelled');
        origin = address.origin;
        return address;
      } finally { starting = undefined; }
    },
    close() {
      if (closePromise) return closePromise;
      closing = true;
      closePromise = (async () => {
        await starting?.catch(() => {});
        const closed = server.listening ? closeListener(server) : Promise.resolve();
        for (const socket of sockets) socket.destroy();
        await Promise.allSettled([...inFlight]); await closed;
        browsers.clear(); rates.clear(); proofs.clear();
        await uploads.close(); database.close(); core.close();
      })();
      return closePromise;
    },
  };
}

async function main() {
  const args = process.argv.slice(2); const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--data', '--clamd-host', '--clamd-port', '--port'].includes(args[i]) || !args[i + 1]) throw new TypeError('Invalid lab arguments');
    options[args[i]] = args[i + 1];
  }
  const app = await createLabApp({ dataRoot: options['--data'], clamdHost: options['--clamd-host'], clamdPort: Number(options['--clamd-port']) });
  try {
    const address = await app.start({ port: Number(options['--port'] ?? 0) });
    console.log(JSON.stringify({ ...address, pid: process.pid, synthetic: true }));
  } catch (error) { await app.close(); throw error; }
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => app.close().then(() => process.exit(0)));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('Lab startup failed: explicit private data directory and loopback clamd configuration required.'); process.exitCode = 1; });
}
