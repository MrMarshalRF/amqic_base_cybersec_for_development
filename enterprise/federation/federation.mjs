import { createHash, randomBytes } from 'node:crypto';

const DIGEST = /^[a-f0-9]{64}$/;
const HANDLE = /^[A-Za-z0-9_-]{43}$/;
const MAX_SESSION_MS = 900_000;
const ERRORS = new Set(['invalid_request', 'invalid_provider', 'unavailable', 'rejected', 'identity_denied']);

export class FederationError extends Error {
  constructor(code) {
    super(ERRORS.has(code) ? code : 'rejected');
    this.name = 'FederationError';
    this.code = this.message;
  }
}

const reject = code => { throw new FederationError(code); };
const text = (v, limit = 512) => typeof v === 'string' && v.length > 0 && v.length <= limit && !/[\p{C}\s]/u.test(v);
const integer = v => Number.isSafeInteger(v) && v >= 0;
const hash = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const handle = () => randomBytes(32).toString('base64url');

export function callbackUrl(value) {
  if (!text(value) || !value.startsWith('https://')) reject('invalid_provider');
  let url;
  try { url = new URL(value); } catch { reject('invalid_provider'); }
  if (url.href !== value || url.username || url.password || url.search || url.hash) reject('invalid_provider');
  return url;
}

/**
 * SQLite consumer for a single shared file, suitable for same-host workers.
 * A multi-host service supplies its own equivalent atomic challenge store.
 */
export function sqliteChallenges(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS federation_challenge (
    digest TEXT PRIMARY KEY,
    expires INTEGER NOT NULL,
    payload TEXT NOT NULL
  ) STRICT;`);
  const insert = db.prepare('INSERT INTO federation_challenge VALUES (?, ?, ?) ON CONFLICT DO NOTHING');
  const take = db.prepare('DELETE FROM federation_challenge WHERE digest = ? AND expires > ? RETURNING payload');
  const purge = db.prepare('DELETE FROM federation_challenge WHERE expires <= ?');
  return Object.freeze({
    put(key, record) { return insert.run(key, record.expiresAt, JSON.stringify(record)).changes === 1; },
    take(key, now) {
      const row = take.get(key, now);
      return row ? JSON.parse(row.payload) : null;
    },
    purgeExpired(now) {
      if (!integer(now)) reject('invalid_request');
      return purge.run(now).changes;
    },
  });
}

export function createFederation({ providers, challenges, resolveIdentity, clock = Date.now, ttlMs = 300_000 }) {
  if (!Array.isArray(providers) || providers.length === 0 || providers.length > 128 ||
      !integer(ttlMs) || ttlMs < 1000 || ttlMs > 300_000 ||
      typeof challenges?.put !== 'function' || typeof challenges?.take !== 'function' ||
      typeof resolveIdentity !== 'function' || typeof clock !== 'function') reject('invalid_provider');

  const registry = new Map();
  const callbacks = new Set();
  for (const entry of providers) {
    const { tenant, id, revision, adapter, groupRoles, allowProvisioning = false } = entry;
    if (!text(tenant, 128) || !text(id, 128) || !DIGEST.test(revision ?? '') ||
        !adapter || !['oidc', 'saml'].includes(adapter.protocol) ||
        !text(adapter.issuer) || !text(adapter.audience) ||
        typeof adapter.start !== 'function' || typeof adapter.verify !== 'function' ||
        !Array.isArray(groupRoles) || groupRoles.length > 128 || typeof allowProvisioning !== 'boolean') reject('invalid_provider');
    const callback = callbackUrl(adapter.redirectUri).href;
    const key = JSON.stringify([tenant, id]);
    if (registry.has(key) || callbacks.has(callback)) reject('invalid_provider');
    callbacks.add(callback);
    const roles = new Map();
    for (const pair of groupRoles) {
      if (!Array.isArray(pair) || pair.length !== 2 || !text(pair[0]) || !text(pair[1], 64) ||
          roles.has(pair[0])) reject('invalid_provider');
      roles.set(...pair);
    }
    const provider = { tenant, id, revision, adapter: Object.freeze({ ...adapter }), roles, allowProvisioning };
    registry.set(key, provider);
  }

  const now = () => {
    const n = clock();
    if (!integer(n) || n > Number.MAX_SAFE_INTEGER - MAX_SESSION_MS) reject('unavailable');
    return n;
  };
  const providerFor = (tenant, id, browserBinding) => {
    if (!text(tenant, 128) || !text(id, 128) || typeof browserBinding !== 'string' ||
        !HANDLE.test(browserBinding)) reject('invalid_request');
    return registry.get(JSON.stringify([tenant, id])) ?? reject('invalid_request');
  };
  const challengeKey = (p, browserBinding, state) =>
    hash(['amqic/federation-challenge/v1', p.tenant, p.id, p.revision, browserBinding, state]);

  async function start({ tenant, providerId, browserBinding }) {
    const p = providerFor(tenant, providerId, browserBinding);
    const { protocol } = p.adapter;
    const state = handle();
    const issuedAt = now();
    const transaction = Object.freeze({
      state, issuedAt, expiresAt: issuedAt + ttlMs,
      ...(protocol === 'oidc' ? { nonce: handle(), verifier: handle() } : { requestId: '_' + handle() }),
    });
    try {
      // Persist the challenge before returning a redirect. An ambiguous store result denies the flow.
      if (await challenges.put(challengeKey(p, browserBinding, state), transaction) !== true) reject('unavailable');
      const redirect = await p.adapter.start(transaction);
      if (!text(redirect, 8192) || !redirect.startsWith('https://') || now() >= transaction.expiresAt) reject('unavailable');
      return Object.freeze({ redirect });
    } catch {
      reject('unavailable');
    }
  }

  async function complete({ tenant, providerId, browserBinding, redirectUri, state, response }) {
    const p = providerFor(tenant, providerId, browserBinding);
    const adapter = p.adapter;
    if (redirectUri !== adapter.redirectUri || typeof state !== 'string' || !HANDLE.test(state)) reject('invalid_request');

    const started = now();
    let txn;
    try { txn = await challenges.take(challengeKey(p, browserBinding, state), started); }
    catch { reject('unavailable'); }
    if (!txn || txn.state !== state || !integer(txn.issuedAt) || !integer(txn.expiresAt) ||
        txn.issuedAt > started || txn.expiresAt <= started ||
        txn.expiresAt - txn.issuedAt !== ttlMs) reject('rejected');

    let identity;
    try { identity = await adapter.verify(response, txn); } catch { reject('rejected'); }
    const checked = now();
    if (!identity || identity.protocol !== adapter.protocol || identity.issuer !== adapter.issuer ||
        identity.audience !== adapter.audience || !text(identity.subject) || !integer(identity.expiresAt) ||
        checked < started || checked >= Math.min(identity.expiresAt, txn.expiresAt) ||
        !Array.isArray(identity.groups) || identity.groups.length > 128 ||
        identity.groups.some(g => !text(g))) reject('rejected');
    const roles = Object.freeze([...new Set(identity.groups.map(group => p.roles.get(group)).filter(Boolean))].sort());
    if (!roles.length) reject('identity_denied');

    // Provisioning resolves only the canonical, tenant-scoped federated identity key.
    const binding = Object.freeze({
      key: hash(['amqic/federated-subject/v1', tenant, providerId, adapter.issuer, identity.subject]),
      tenant, providerId, issuer: adapter.issuer, subject: identity.subject,
      allowProvisioning: p.allowProvisioning, roles, validUntil: Math.min(identity.expiresAt, txn.expiresAt),
    });
    let resolved;
    try { resolved = await resolveIdentity(binding); } catch { reject('unavailable'); }
    const finalized = now();
    if (resolved?.tenant !== tenant || resolved.enabled !== true || !text(resolved.id, 128) ||
        finalized < checked || finalized >= binding.validUntil) reject('identity_denied');
    const expiresAt = Math.min(finalized + MAX_SESSION_MS, identity.expiresAt);
    return Object.freeze({ tenant, userId: resolved.id, roles, expiresAt });
  }
  return Object.freeze({ start, complete });
}
