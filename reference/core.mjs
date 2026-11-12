import { DatabaseSync } from 'node:sqlite';
import { createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import { types } from 'node:util';
import { canonical, hash, opaque, passwordRecord, checkPassword, signedBytes, totp } from './crypto.mjs';

export class AccessDenied extends Error {
  constructor() { super('Request denied'); this.name = 'AccessDenied'; }
}
const deny = () => { throw new AccessDenied(); };
const synchronous = (value, message = 'Trusted adapters must be synchronous') => {
  if (value && typeof value.then === 'function') {
    // Reject the API misuse synchronously, while observing any later rejection.
    // This cannot cancel or roll back work outside this SQLite transaction.
    Promise.resolve(value).catch(() => {});
    throw new TypeError(message);
  }
  return value;
};
const validId = value => typeof value === 'string' && /^[A-Za-z0-9._@-]{1,128}$/.test(value);
const identityKey = value => typeof value === 'string' ? value.trim().toLowerCase() : '';
const tokenHash = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) ? hash(value) : deny();
const checkedList = value => {
  if (!Array.isArray(value) || value.length > 32 || value.some(item => !validId(item))) throw new TypeError('Invalid scopes');
  return [...new Set(value)].sort();
};

// Trusted application code creates this core. It is never deserialized from a request.
export class SecurityCore {
  #db;
  #clock;
  #captcha;
  #factors;
  #audience;
  #dummy;
  #tools;

  constructor({ database = ':memory:', audience, captcha, factors, clock = () => Math.floor(Date.now() / 1000), tools = {} }) {
    if (!audience || typeof audience !== 'string' || typeof captcha?.verify !== 'function' ||
        typeof factors?.assertEnrollment !== 'function' || typeof factors?.secretFor !== 'function') {
      throw new TypeError('Trusted adapters and audience are required');
    }
    if ([clock, captcha.verify, factors.assertEnrollment, factors.secretFor].some(fn =>
      typeof fn !== 'function' || types.isAsyncFunction(fn))) throw new TypeError('Synchronous trusted adapters required');
    this.#clock = clock;
    this.#captcha = captcha;
    this.#factors = factors;
    this.#audience = audience;
    this.#dummy = passwordRecord(opaque());
    this.#tools = new Map();
    for (const [name, definition] of Object.entries(tools)) {
      if (!validId(name) || !validId(definition.scope) || typeof definition.validate !== 'function' ||
          typeof definition.handler !== 'function' || typeof definition.stepUp !== 'boolean' ||
          types.isAsyncFunction(definition.validate) || types.isAsyncFunction(definition.handler)) throw new TypeError('Invalid trusted tool');
      this.#tools.set(name, Object.freeze({ ...definition }));
    }
    this.#db = new DatabaseSync(database);
    this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS clock_guard (id INTEGER PRIMARY KEY CHECK(id=1), observed INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, identity TEXT UNIQUE NOT NULL, salt TEXT NOT NULL,
        digest TEXT NOT NULL, factor_ref TEXT NOT NULL, scopes TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1,
        disabled INTEGER NOT NULL DEFAULT 0, totp_counter INTEGER NOT NULL DEFAULT -1);
      CREATE TABLE IF NOT EXISTS keys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, pem TEXT NOT NULL,
        scopes TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS nonces (key_id TEXT NOT NULL, nonce TEXT NOT NULL, expires INTEGER NOT NULL,
        PRIMARY KEY(key_id, nonce));
      CREATE TABLE IF NOT EXISTS tickets (digest TEXT PRIMARY KEY, user_id TEXT, stage TEXT NOT NULL,
        source TEXT NOT NULL, expires INTEGER NOT NULL, epoch INTEGER);
      CREATE TABLE IF NOT EXISTS sessions (digest TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        expires INTEGER NOT NULL, epoch INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS limits (bucket TEXT PRIMARY KEY, starts INTEGER NOT NULL, count INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS grants (digest TEXT PRIMARY KEY, session TEXT NOT NULL, user_id TEXT NOT NULL,
        action TEXT NOT NULL, args_hash TEXT NOT NULL, operation TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS operations (user_id TEXT NOT NULL, operation TEXT NOT NULL,
        action TEXT NOT NULL, args_hash TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(user_id, operation));
      CREATE TABLE IF NOT EXISTS synthetic_records (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, value TEXT NOT NULL);`);
  }

  close() { this.#db.close(); }

  #transaction(callback) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const now = synchronous(this.#clock());
      if (!Number.isSafeInteger(now) || now < 0) deny();
      const previous = this.#db.prepare('SELECT observed FROM clock_guard WHERE id=1').get();
      if (previous && now < previous.observed) deny();
      this.#db.prepare('INSERT INTO clock_guard VALUES(1,?) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed').run(now);
      const result = synchronous(callback(now), 'Asynchronous transaction forbidden');
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
  }

  #rate(bucket, now, maximum = 10, window = 60) {
    const name = hash(bucket);
    this.#db.prepare(`INSERT INTO limits VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET
      count=CASE WHEN starts+?<=? THEN 1 ELSE count+1 END,
      starts=CASE WHEN starts+?<=? THEN ? ELSE starts END`).run(name, now, window, now, window, now, now);
    if (this.#db.prepare('SELECT count FROM limits WHERE bucket=?').get(name).count > maximum) deny();
  }

  #source(source) {
    if (typeof source !== 'string' || source.length < 1 || source.length > 256) deny();
    return hash(source);
  }

  // Provisioning is an operator-only API. Identity/factor ownership is verified by the adapter.
  provisionUser({ id, identity, password, factorRef, scopes }) {
    const normalized = identityKey(identity);
    if (!validId(id) || !validId(normalized) || !validId(factorRef) || synchronous(this.#factors.assertEnrollment({ id, factorRef })) !== true) {
      throw new TypeError('Verified enrollment required');
    }
    const record = passwordRecord(password);
    const scopeList = checkedList(scopes);
    this.#transaction(() => this.#db.prepare('INSERT INTO users(id,identity,salt,digest,factor_ref,scopes) VALUES(?,?,?,?,?,?)')
      .run(id, normalized, record.salt, record.digest, factorRef, canonical(scopeList)));
  }

  registerKey({ keyId, userId, publicKey, scopes }) {
    if (typeof keyId !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(keyId) || !validId(userId)) throw new TypeError('Invalid identity');
    const key = createPublicKey(publicKey);
    if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 required');
    const pem = key.export({ type: 'spki', format: 'pem' });
    this.#transaction(() => {
      if (!this.#db.prepare('SELECT id FROM users WHERE id=? AND disabled=0').get(userId)) deny();
      this.#db.prepare('INSERT INTO keys(id,user_id,pem,scopes) VALUES(?,?,?,?)').run(keyId, userId, pem, canonical(checkedList(scopes)));
    });
  }

  revokeKey(keyId) {
    this.#transaction(() => this.#db.prepare('UPDATE keys SET revoked=1 WHERE id=?').run(keyId));
  }

  revokeUser(userId) {
    this.#transaction(() => {
      this.#db.prepare('UPDATE users SET epoch=epoch+1,disabled=1 WHERE id=?').run(userId);
      this.#db.prepare('DELETE FROM tickets WHERE user_id=?').run(userId);
      this.#db.prepare('DELETE FROM sessions WHERE user_id=?').run(userId);
      this.#db.prepare('DELETE FROM grants WHERE user_id=?').run(userId);
      this.#db.prepare('UPDATE keys SET revoked=1 WHERE user_id=?').run(userId);
    });
  }

  #issueTicket(user, stage, source, now) {
    const ticket = opaque();
    this.#db.prepare('INSERT INTO tickets VALUES(?,?,?,?,?,?)')
      .run(hash(ticket), user?.id ?? null, stage, source, now + 180, user?.epoch ?? null);
    return { next: stage, ticket };
  }

  login(identity, source) {
    const normalized = identityKey(identity);
    const sourceHash = this.#source(source);
    return this.#transaction(now => {
      this.#rate('login-source:' + sourceHash, now, 30);
      this.#rate('login-identity:' + normalized, now, 10);
      const user = this.#db.prepare('SELECT * FROM users WHERE identity=? AND disabled=0').get(normalized);
      return this.#issueTicket(user, 'password', sourceHash, now);
    });
  }

  #advance(ticket, stage, source, callback) {
    const digest = tokenHash(ticket);
    const sourceHash = this.#source(source);
    const result = this.#transaction(now => {
      this.#rate('stage:' + sourceHash, now, 30);
      const state = this.#db.prepare('SELECT * FROM tickets WHERE digest=?').get(digest);
      if (!state || state.stage !== stage || state.source !== sourceHash || state.expires <= now) return null;
      this.#db.prepare('DELETE FROM tickets WHERE digest=?').run(digest);
      const user = this.#db.prepare('SELECT * FROM users WHERE id=? AND disabled=0').get(state.user_id);
      if (user && user.epoch !== state.epoch) return null;
      return callback(user, now, sourceHash, digest);
    });
    return result ?? deny();
  }

  password(ticket, password, source) {
    return this.#advance(ticket, 'password', source, (user, now, sourceHash) => {
      const matches = checkPassword(password, user ?? this.#dummy);
      if (!user || !matches) return null;
      return this.#issueTicket(user, 'captcha', sourceHash, now);
    });
  }

  captcha(ticket, proof, source) {
    return this.#advance(ticket, 'captcha', source, (user, now, sourceHash, challenge) => {
      if (!user || synchronous(this.#captcha.verify({ proof, challenge, source: sourceHash, now })) !== true) return null;
      return this.#issueTicket(user, 'totp', sourceHash, now);
    });
  }

  #consumeTotp(user, code, now) {
    const secret = synchronous(this.#factors.secretFor(user.factor_ref));
    if (!Buffer.isBuffer(secret) || secret.length < 20 || typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
    const current = Math.floor(now / 30);
    let accepted = -1;
    for (const counter of [current - 1, current, current + 1]) {
      if (counter >= 0 && counter > user.totp_counter && timingSafeEqual(Buffer.from(totp(secret, counter)), Buffer.from(code))) accepted = counter;
    }
    if (accepted < 0) return false;
    return this.#db.prepare('UPDATE users SET totp_counter=? WHERE id=? AND totp_counter<?')
      .run(accepted, user.id, accepted).changes === 1;
  }

  secondFactor(ticket, code, source) {
    return this.#advance(ticket, 'totp', source, (user, now) => {
      if (!user || !this.#consumeTotp(user, code, now)) return null;
      const session = opaque();
      this.#db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(hash(session), user.id, now + 900, user.epoch);
      return { session, expires: now + 900 };
    });
  }

  #session(session, now) {
    const digest = tokenHash(session);
    const user = this.#db.prepare(`SELECT u.*,s.digest AS session_digest FROM users u JOIN sessions s ON s.user_id=u.id
      WHERE s.digest=? AND s.expires>? AND s.epoch=u.epoch AND u.disabled=0`).get(digest, now);
    if (!user) deny();
    return user;
  }

  logout(session) {
    this.#transaction(() => {
      const digest = tokenHash(session);
      this.#db.prepare('DELETE FROM sessions WHERE digest=?').run(digest);
      this.#db.prepare('DELETE FROM grants WHERE session=?').run(digest);
    });
  }

  #tool(action, args, user) {
    const tool = this.#tools.get(action);
    if (!tool || !JSON.parse(user.scopes).includes(tool.scope) || synchronous(tool.validate(args)) !== true) deny();
    return tool;
  }

  stepUp({ session, action, args, operation, code }) {
    if (!validId(operation)) deny();
    return this.#transaction(now => {
      const user = this.#session(session, now);
      this.#rate('stepup:' + user.id, now, 5);
      const tool = this.#tool(action, args, user);
      if (!tool.stepUp || !this.#consumeTotp(user, code, now)) return null;
      const grant = opaque();
      this.#db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?,?)')
        .run(hash(grant), user.session_digest, user.id, action, hash(canonical(args)), operation, now + 60);
      return { grant, expires: now + 60 };
    }) ?? deny();
  }

  #verifyRequest(request, scope, now) {
    let bytes;
    try { bytes = signedBytes(request); } catch { deny(); }
    if (request.audience !== this.#audience || Math.abs(now - request.timestamp) > 30 ||
        typeof request.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(request.signature)) deny();
    const key = this.#db.prepare(`SELECT k.*,u.scopes AS user_scopes FROM keys k JOIN users u ON u.id=k.user_id
      WHERE k.id=? AND k.revoked=0 AND u.disabled=0`).get(request.keyId);
    if (!key || !JSON.parse(key.scopes).includes(scope) || !JSON.parse(key.user_scopes).includes(scope) ||
        !verify(null, bytes, key.pem, Buffer.from(request.signature, 'base64url'))) deny();
    this.#db.prepare('DELETE FROM nonces WHERE expires<?').run(now);
    const inserted = this.#db.prepare('INSERT OR IGNORE INTO nonces VALUES(?,?,?)').run(key.id, request.nonce, now + 61);
    if (inserted.changes !== 1) deny();
    return key.user_id;
  }

  verifyRequest(request, scope) {
    return this.#transaction(now => ({ userId: this.#verifyRequest(request, scope, now) }));
  }

  listTools() {
    return [...this.#tools.entries()].map(([name, tool]) => ({ name, scope: tool.scope, stepUp: tool.stepUp }));
  }

  // A transport-neutral tool call core, intended behind an authenticated MCP adapter.
  dispatch(request) {
    return this.#transaction(now => {
      if (request.method !== 'POST' || request.target !== '/tools/call') deny();
      if (!Buffer.isBuffer(request.body) || request.body.length > 65536) deny();
      let input;
      try { input = JSON.parse(request.body.toString('utf8')); } catch { deny(); }
      if (!input || Array.isArray(input) || Object.keys(input).sort().join(',') !== 'action,args,grant,operation,session' ||
          !Buffer.from(canonical(input), 'utf8').equals(request.body) || !validId(input.operation)) deny();
      const user = this.#session(input.session, now);
      const tool = this.#tool(input.action, input.args, user);
      if (this.#verifyRequest(request, tool.scope, now) !== user.id) deny();
      const argsHash = hash(canonical(input.args));
      const previous = this.#db.prepare('SELECT * FROM operations WHERE user_id=? AND operation=?').get(user.id, input.operation);
      if (previous) {
        if (previous.action !== input.action || previous.args_hash !== argsHash) deny();
        return JSON.parse(previous.result);
      }
      if (tool.stepUp) {
        const grant = this.#db.prepare('SELECT * FROM grants WHERE digest=?').get(tokenHash(input.grant));
        if (!grant || grant.expires <= now || grant.user_id !== user.id || grant.session !== user.session_digest ||
            grant.action !== input.action || grant.args_hash !== argsHash || grant.operation !== input.operation) deny();
        this.#db.prepare('DELETE FROM grants WHERE digest=?').run(grant.digest);
      }
      const result = synchronous(tool.handler({ database: this.#db, userId: user.id }, input.args), 'Tool handlers must be synchronous');
      const encoded = canonical(result);
      this.#db.prepare('INSERT INTO operations VALUES(?,?,?,?,?)').run(user.id, input.operation, input.action, argsHash, encoded);
      return JSON.parse(encoded);
    });
  }

  seedSyntheticRecord(id, ownerId, value = 'synthetic') {
    if (!validId(id) || !validId(ownerId)) throw new TypeError('Invalid fixture');
    this.#transaction(() => this.#db.prepare('INSERT INTO synthetic_records VALUES(?,?,?)').run(id, ownerId, value));
  }
}

export const syntheticTools = Object.freeze({
  'records.remove': {
    scope: 'records.remove', stepUp: true,
    validate: args => args && Object.getPrototypeOf(args) === Object.prototype && Object.keys(args).length === 1 && validId(args.id),
    handler: ({ database, userId }, args) => ({ removed: database.prepare('DELETE FROM synthetic_records WHERE id=? AND owner_id=?').run(args.id, userId).changes })
  }
});
