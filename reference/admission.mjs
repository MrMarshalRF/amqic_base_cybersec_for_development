import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import net from 'node:net';
import tls from 'node:tls';

const digest = value => createHash('sha256').update(value).digest('hex');
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const text = value => typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 512;
const denied = () => { throw new Error('Admission denied'); };
function binding({ subject, audience, method, path, bodyHash }) {
  if (![subject, audience, method, path].every(text) || !/^[a-f0-9]{64}$/.test(bodyHash)) throw new TypeError('Invalid request binding');
  return digest(JSON.stringify([subject, audience, method, path, bodyHash]));
}
function proof(token, counter, bits) {
  const bytes = createHash('sha256').update(`amqic-pow-v1\n${token}\n${counter}`).digest();
  for (let i = 0; i < bits; i++) if ((bytes[i >> 3] & (128 >> (i & 7))) !== 0) return false;
  return true;
}

// Durable only when database is a persistent, protected path shared by all issuers.
export class SqlitePowStore {
  #db;
  constructor(database = ':memory:') {
    this.#db = new DatabaseSync(database);
    this.#db.exec(`PRAGMA busy_timeout=3000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS admission_used (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS admission_clock (id INTEGER PRIMARY KEY CHECK(id=1), seen INTEGER NOT NULL);
      INSERT OR IGNORE INTO admission_clock VALUES(1,0);`);
  }
  async consume(nonce, expires, now) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const { seen } = this.#db.prepare('SELECT seen FROM admission_clock WHERE id=1').get();
      if (now < seen || expires <= now) { this.#db.exec('ROLLBACK'); return false; }
      this.#db.prepare('UPDATE admission_clock SET seen=? WHERE id=1').run(now);
      this.#db.prepare('DELETE FROM admission_used WHERE expires<=?').run(now);
      const result = this.#db.prepare('INSERT OR IGNORE INTO admission_used VALUES(?,?)').run(nonce, expires);
      this.#db.exec('COMMIT');
      return result.changes === 1;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  close() { this.#db.close(); }
}

// The secret, policy, clock and store are trusted server configuration, never HTTP input.
export function createPowGate({ secret, store, difficulty = 12, ttlSeconds = 60, clock = () => Math.floor(Date.now() / 1000) }) {
  if (!Buffer.isBuffer(secret) || secret.length < 32 || !integer(difficulty, 8, 22) ||
      !integer(ttlSeconds, 1, 300) || typeof store?.consume !== 'function' || typeof clock !== 'function') throw new TypeError('Invalid trusted PoW configuration');
  const key = Buffer.from(secret);
  let last = 0;
  const now = () => {
    const n = clock();
    if (!integer(n, 0, Number.MAX_SAFE_INTEGER - 300) || n < last) return denied();
    last = n;
    return n;
  };
  const mac = payload => createHmac('sha256', key).update(`amqic-pow-v1.${payload}`).digest();
  return Object.freeze({
    issue(request) {
      const issued = now();
      const payload = Buffer.from(JSON.stringify([1, randomBytes(24).toString('hex'), binding(request), difficulty, issued, issued + ttlSeconds])).toString('base64url');
      return `${payload}.${mac(payload).toString('base64url')}`;
    },
    async verify({ token, counter, request }) {
      try {
        if (typeof token !== 'string' || token.length > 2048 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token) ||
            typeof counter !== 'string' || !/^(0|[1-9][0-9]{0,9})$/.test(counter) || Number(counter) > 0xffffffff) return false;
        const [payload, signature] = token.split('.');
        const supplied = Buffer.from(signature, 'base64url');
        if (supplied.length !== 32 || !timingSafeEqual(mac(payload), supplied)) return false;
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
        if (!Array.isArray(data) || data.length !== 6) return false;
        const [version, nonce, bound, bits, issued, expires] = data;
        const time = now();
        if (version !== 1 || !/^[a-f0-9]{48}$/.test(nonce) || bound !== binding(request) || bits !== difficulty ||
            !integer(issued, 0, time) || !integer(expires, time + 1, time + 300) || expires - issued !== ttlSeconds ||
            !proof(token, counter, bits)) return false;
        // Atomic shared insertion is mandatory. Store errors fail closed, with no retry.
        return (await store.consume(nonce, expires, now())) === true;
      } catch { return false; }
    },
  });
}

// Explicit synthetic/client work only; never call this on a server request path.
export function solvePow(token, { maxAttempts = 100000, difficulty = 12 } = {}) {
  if (typeof token !== 'string' || token.length > 2048 || !integer(maxAttempts, 1, 1000000) || !integer(difficulty, 8, 22)) throw new TypeError('Invalid bounded solver input');
  for (let counter = 0; counter < maxAttempts; counter++) if (proof(token, String(counter), difficulty)) return String(counter);
  return null;
}

const RATE_SCRIPT = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]); end; local t=redis.call('PTTL',KEYS[1]); if t<0 then return redis.error_reply('missing expiry'); end; return {n,t}";
const encode = args => `*${args.length}\r\n${args.map(arg => { const s = String(arg); return `$${Buffer.byteLength(s)}\r\n${s}\r\n`; }).join('')}`;

// Only fixed AUTH and this fixed EVAL are reachable. No exported command broker.
export function createRedisRateLimiter({ host = '127.0.0.1', port, tlsOptions, username, password, prefix = 'amqic:rate:', limit = 20, windowMs = 60000, timeoutMs = 1000 } = {}) {
  if (!text(host) || !integer(port, 1, 65535) || !integer(limit, 1, 1000000) || !integer(windowMs, 1, 3600000) ||
      !integer(timeoutMs, 1, 10000) || !/^[A-Za-z0-9:_-]{1,80}$/.test(prefix) ||
      (username !== undefined && (!text(username) || password === undefined)) ||
      (password !== undefined && !text(password)) || (tlsOptions !== undefined &&
        (typeof tlsOptions !== 'object' || tlsOptions === null || Object.keys(tlsOptions).some(k => !['ca', 'servername', 'minVersion'].includes(k)) ||
          (tlsOptions.minVersion !== undefined && !['TLSv1.2', 'TLSv1.3'].includes(tlsOptions.minVersion))))) throw new TypeError('Invalid trusted Redis configuration');
  return Object.freeze({
    async check(subject) {
      if (!text(subject)) return { allowed: false, reason: 'invalid' };
      return new Promise(resolve => {
        let settled = false;
        let buffer = '';
        let authenticated = password === undefined;
        const socket = tlsOptions ? tls.connect({ ...tlsOptions, host, port, rejectUnauthorized: true }) : net.createConnection({ host, port });
        const finish = value => { if (!settled) { settled = true; clearTimeout(deadline); socket.destroy(); resolve(value); } };
        const fail = () => finish({ allowed: false, reason: 'unavailable' });
        const deadline = setTimeout(fail, timeoutMs);
        const sendRate = () => socket.write(encode(['EVAL', RATE_SCRIPT, 1, prefix + digest(subject), windowMs]));
        socket.once(tlsOptions ? 'secureConnect' : 'connect', () => {
          if (authenticated) sendRate();
          else socket.write(encode(username === undefined ? ['AUTH', password] : ['AUTH', username, password]));
        });
        socket.on('error', fail);
        socket.on('end', fail);
        socket.on('close', fail);
        socket.on('data', chunk => {
          buffer += chunk.toString('ascii');
          if (buffer.length > 1024) return fail();
          if (!authenticated) {
            if (!buffer.includes('\r\n')) return;
            if (buffer !== '+OK\r\n') return fail();
            buffer = ''; authenticated = true; sendRate(); return;
          }
          if (buffer.startsWith('-')) return fail();
          const match = /^\*2\r\n:([0-9]{1,16})\r\n:([0-9]{1,16})\r\n$/.exec(buffer);
          if (!match) return;
          const count = Number(match[1]), retryAfterMs = Number(match[2]);
          if (!integer(count, 1, Number.MAX_SAFE_INTEGER) || !integer(retryAfterMs, 0, windowMs)) return fail();
          finish({ allowed: count <= limit, count, retryAfterMs });
        });
      });
    },
  });
}
