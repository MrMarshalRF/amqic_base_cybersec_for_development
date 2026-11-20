import { randomBytes, createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const PURPOSES = new Set(['password-reset', 'email-change', 'factor-recovery']);
const OPAQUE = /^[A-Za-z0-9_-]{1,128}$/;
const failure = () => new Error('recovery_failed');
const digest = token => createHash('sha256').update(token, 'ascii').digest('hex');
const integer = (value, max) => Number.isSafeInteger(value) && value >= 1 && value <= max;

// Copy data properties before use; request getters/prototypes are not identity evidence.
function snapshot(input, keys) {
  try {
    if (!input || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) throw failure();
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Reflect.ownKeys(descriptors).some(key => !keys.includes(key))) throw failure();
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor && !Object.hasOwn(descriptor, 'value')) throw failure();
      result[key] = descriptor?.value;
    }
    return result;
  } catch { throw failure(); }
}

function identity(input, recovery = false) {
  const value = snapshot(input, recovery
    ? ['tenantId', 'subjectId', 'securityEpoch', 'purpose', 'pendingChangeRef']
    : ['tenantId', 'subjectId', 'securityEpoch']);
  if (typeof value.tenantId !== 'string' || typeof value.subjectId !== 'string' ||
      !OPAQUE.test(value.tenantId) || !OPAQUE.test(value.subjectId) ||
      !integer(value.securityEpoch, Number.MAX_SAFE_INTEGER - 1)) throw failure();
  if (recovery) {
    if (!PURPOSES.has(value.purpose)) throw failure();
    if (value.purpose === 'email-change') {
      if (typeof value.pendingChangeRef !== 'string' || !OPAQUE.test(value.pendingChangeRef)) throw failure();
    } else if (value.pendingChangeRef !== undefined) throw failure();
    value.pendingChangeRef ??= null;
  }
  return Object.freeze(value);
}

/** Trusted server-side reference. Do not expose operator methods as request endpoints. */
export class RecoveryStore {
  #db;
  #clock;
  #policy;

  constructor({ database, ttlSeconds = 600, maxOutstanding = 10000, maxAccounts = 10000,
    clock, clockId = 'sqlite-unixepoch-v1' } = {}) {
    try {
      if (typeof database !== 'string' || !database || !integer(ttlSeconds, 900) ||
          !integer(maxOutstanding, 10000) || !integer(maxAccounts, 100000) ||
          (clock !== undefined && typeof clock !== 'function') ||
          (clock !== undefined && clockId === 'sqlite-unixepoch-v1') ||
          typeof clockId !== 'string' || !OPAQUE.test(clockId)) throw failure();
      this.#clock = clock;
      this.#policy = Object.freeze({ version: 1, ttlSeconds, maxOutstanding, maxAccounts, clockId });
      this.#db = new DatabaseSync(database);
      this.#db.exec(`PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS recovery_policy (id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL, watermark INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS recovery_accounts (tenant TEXT NOT NULL, subject TEXT NOT NULL, epoch INTEGER NOT NULL, PRIMARY KEY(tenant, subject));
        CREATE TABLE IF NOT EXISTS recovery_tokens (
          verifier TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL,
          purpose TEXT NOT NULL CHECK(purpose IN ('password-reset','email-change','factor-recovery')),
          epoch INTEGER NOT NULL, pending_ref TEXT, expires INTEGER NOT NULL,
          UNIQUE(tenant, subject, purpose), FOREIGN KEY(tenant,subject) REFERENCES recovery_accounts(tenant,subject));
        CREATE INDEX IF NOT EXISTS recovery_expiry ON recovery_tokens(expires);`);
      this.#transaction(() => {
        const policy = JSON.stringify(this.#policy);
        const existing = this.#db.prepare('SELECT policy FROM recovery_policy WHERE id=1').get();
        if (existing && existing.policy !== policy) throw failure();
        if (!existing) this.#db.prepare('INSERT INTO recovery_policy VALUES(1,?,0)').run(policy);
        this.#now();
      });
    } catch {
      try { this.#db?.close(); } catch { /* no diagnostics containing paths */ }
      throw failure();
    }
  }

  #transaction(operation) {
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const result = operation();
      this.#db.exec('COMMIT');
      return result;
    } catch {
      try { this.#db.exec('ROLLBACK'); } catch { /* already closed or not begun */ }
      throw failure();
    }
  }

  #now() {
    const now = this.#clock ? this.#clock() : this.#db.prepare('SELECT unixepoch() AS now').get().now;
    const row = this.#db.prepare('SELECT watermark, policy FROM recovery_policy WHERE id=1').get();
    if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - 901 ||
        !row || row.policy !== JSON.stringify(this.#policy) || now < row.watermark) throw failure();
    this.#db.prepare('UPDATE recovery_policy SET watermark=? WHERE id=1').run(now);
    return now;
  }

  #account(binding) {
    return this.#db.prepare('SELECT epoch FROM recovery_accounts WHERE tenant=? AND subject=?')
      .get(binding.tenantId, binding.subjectId);
  }

  registerAccount(input) {
    const binding = identity(input);
    return this.#transaction(() => {
      this.#now();
      const existing = this.#account(binding);
      if (existing) {
        if (existing.epoch !== binding.securityEpoch) throw failure();
      } else {
        if (this.#db.prepare('SELECT count(*) AS n FROM recovery_accounts').get().n >= this.#policy.maxAccounts) throw failure();
        this.#db.prepare('INSERT INTO recovery_accounts VALUES(?,?,?)')
          .run(binding.tenantId, binding.subjectId, binding.securityEpoch);
      }
      return Object.freeze({ ...binding });
    });
  }

  bumpSecurityEpoch(input) {
    const binding = identity(input);
    return this.#transaction(() => {
      this.#now();
      if (this.#account(binding)?.epoch !== binding.securityEpoch) throw failure();
      const securityEpoch = binding.securityEpoch + 1;
      this.#db.prepare('UPDATE recovery_accounts SET epoch=? WHERE tenant=? AND subject=?')
        .run(securityEpoch, binding.tenantId, binding.subjectId);
      this.#db.prepare('DELETE FROM recovery_tokens WHERE tenant=? AND subject=?').run(binding.tenantId, binding.subjectId);
      return Object.freeze({ ...binding, securityEpoch });
    });
  }

  // Only this trusted delivery port receives the raw secret. Never log its input.
  issue(input, deliver) {
    const binding = identity(input, true);
    if (typeof deliver !== 'function') throw failure();
    const token = randomBytes(32).toString('base64url');
    const verifier = digest(token);
    const expires = this.#transaction(() => {
      const now = this.#now();
      if (this.#account(binding)?.epoch !== binding.securityEpoch) throw failure();
      this.#db.prepare('DELETE FROM recovery_tokens WHERE expires<=?').run(now);
      this.#db.prepare('DELETE FROM recovery_tokens WHERE tenant=? AND subject=? AND purpose=?')
        .run(binding.tenantId, binding.subjectId, binding.purpose);
      if (this.#db.prepare('SELECT count(*) AS n FROM recovery_tokens').get().n >= this.#policy.maxOutstanding) throw failure();
      const expiry = now + this.#policy.ttlSeconds;
      this.#db.prepare('INSERT INTO recovery_tokens VALUES(?,?,?,?,?,?,?)')
        .run(verifier, binding.tenantId, binding.subjectId, binding.purpose, binding.securityEpoch, binding.pendingChangeRef, expiry);
      return expiry;
    });
    try {
      // Network delivery should be prepared by an adopter's durable outbox. This port
      // is synchronous and is outside the SQLite transaction, with no rollback claim.
      const result = deliver(Object.freeze({ token, ...binding, expires }));
      if (result !== true) {
        if (result instanceof Promise) result.catch(() => {});
        throw failure();
      }
    } catch {
      // Exact verifier only: a reentrant/newer issuance must not be revoked.
      this.#transaction(() => this.#db.prepare('DELETE FROM recovery_tokens WHERE verifier=?').run(verifier));
      throw failure();
    }
    return Object.freeze({ issued: true, expires });
  }

  consumeOnce(token, input) {
    const binding = identity(input, true);
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token) ||
        Buffer.from(token, 'base64url').toString('base64url') !== token) throw failure();
    const claim = this.#transaction(() => {
      const now = this.#now();
      const row = this.#db.prepare('SELECT * FROM recovery_tokens WHERE verifier=?').get(digest(token));
      if (!row || row.expires <= now || row.tenant !== binding.tenantId || row.subject !== binding.subjectId ||
          row.purpose !== binding.purpose || row.pending_ref !== binding.pendingChangeRef ||
          row.epoch !== binding.securityEpoch || this.#account(binding)?.epoch !== binding.securityEpoch) return null;
      const securityEpoch = binding.securityEpoch + 1;
      this.#db.prepare('UPDATE recovery_accounts SET epoch=? WHERE tenant=? AND subject=?')
        .run(securityEpoch, binding.tenantId, binding.subjectId);
      this.#db.prepare('DELETE FROM recovery_tokens WHERE tenant=? AND subject=?').run(binding.tenantId, binding.subjectId);
      return Object.freeze({ ...binding, securityEpoch, previousSecurityEpoch: binding.securityEpoch,
        claimId: randomBytes(16).toString('hex') });
    });
    if (!claim) throw failure();
    return claim;
  }

  close() {
    try { this.#db.close(); } catch { throw failure(); }
  }
}
