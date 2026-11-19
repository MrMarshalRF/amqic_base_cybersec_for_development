import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac } from 'node:crypto';

const dimensions = ['global', 'source', 'tenant', 'subject', 'session'];
const opaque = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const hash = value => createHash('sha256').update(value).digest('hex');
const unavailable = () => ({ allowed: false, reason: 'unavailable' });

function normalizePolicy(policy) {
  if (!exact(policy, ['version', 'routes']) || !opaque(policy.version)
      || !policy.routes || typeof policy.routes !== 'object' || Array.isArray(policy.routes)) throw Error();
  const names = Object.keys(policy.routes).sort();
  if (!integer(names.length, 1, 32)) throw Error();
  const routes = Object.create(null);
  for (const name of names) {
    if (!opaque(name) || !exact(policy.routes[name], ['allowAnonymous', ...dimensions])
        || typeof policy.routes[name].allowAnonymous !== 'boolean') throw Error();
    routes[name] = Object.assign(Object.create(null), { allowAnonymous: policy.routes[name].allowAnonymous });
    for (const dimension of dimensions) {
      const rule = policy.routes[name][dimension];
      if (!exact(rule, ['limit', 'windowMs']) || !integer(rule.limit, 1, 1_000_000)
          || !integer(rule.windowMs, 1000, 86_400_000)) throw Error();
      routes[name][dimension] = { limit: rule.limit, windowMs: rule.windowMs };
    }
  }
  return { version: policy.version, routes };
}

// Caller owns a protected local database directory and trusted clock/key/identity adapters.
// This synchronous same-host reference is deliberately not a distributed quota service.
export function createProbeDefense({ databasePath, key, keyVersion, policy, clock = Date.now, maxBuckets = 100_000 }) {
  let db;
  let secret;
  let normalized;
  try {
    if (typeof databasePath !== 'string' || !databasePath || !Buffer.isBuffer(key) || key.length !== 32
        || !opaque(keyVersion) || typeof clock !== 'function' || !integer(maxBuckets, 5, 1_000_000)) throw Error();
    secret = Buffer.from(key);
    normalized = normalizePolicy(policy);
    const binding = hash(JSON.stringify({ policy: normalized, keyVersion, maxBuckets,
      keyCheck: createHmac('sha256', secret).update('probe-defense-key-check-v1').digest('hex') }));
    db = new DatabaseSync(databasePath);
    db.exec('PRAGMA busy_timeout=1000; BEGIN IMMEDIATE;');
    db.exec('CREATE TABLE IF NOT EXISTS probe_meta (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, last_ms INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS probe_buckets (id TEXT PRIMARY KEY, used INTEGER NOT NULL, expires INTEGER NOT NULL);');
    const meta = db.prepare('SELECT binding FROM probe_meta WHERE id=1').get();
    if (meta && meta.binding !== binding) throw Error();
    if (!meta) db.prepare('INSERT INTO probe_meta VALUES (1, ?, 0)').run(binding);
    db.exec('COMMIT');
  } catch {
    try { db?.exec('ROLLBACK'); } catch { /* no open transaction */ }
    try { db?.close(); } catch { /* already closed */ }
    secret?.fill(0);
    throw new Error('Probe defense initialization unavailable');
  }
  let closed = false;
  return {
    admit(input) {
      if (closed) return unavailable();
      if (!exact(input, ['routeClass', 'sourceRef', 'auth']) || !opaque(input.routeClass)
          || !Object.hasOwn(normalized.routes, input.routeClass) || !opaque(input.sourceRef)
          || !(input.auth === null || (exact(input.auth, ['tenantRef', 'subjectRef', 'sessionRef'])
            && Object.values(input.auth).every(opaque)))
          || (input.auth === null && !normalized.routes[input.routeClass].allowAnonymous)) return { allowed: false, reason: 'invalid_context' };
      try {
        db.exec('BEGIN IMMEDIATE');
        const now = clock();
        const meta = db.prepare('SELECT last_ms FROM probe_meta WHERE id=1').get();
        if (!integer(now, 0, Number.MAX_SAFE_INTEGER - 86_400_000) || !meta || now < meta.last_ms) throw Error();
        db.prepare('UPDATE probe_meta SET last_ms=? WHERE id=1').run(now);
        db.prepare('DELETE FROM probe_buckets WHERE expires<=?').run(now);
        const refs = { global: 'all', source: input.sourceRef,
          ...(input.auth ? { tenant: input.auth.tenantRef,
            subject: [input.auth.tenantRef, input.auth.subjectRef],
            session: [input.auth.tenantRef, input.auth.subjectRef, input.auth.sessionRef] } : {}) };
        const buckets = Object.entries(refs).map(([dimension, ref]) => {
          const rule = normalized.routes[input.routeClass][dimension];
          const window = Math.floor(now / rule.windowMs);
          const id = createHmac('sha256', secret).update(JSON.stringify([input.routeClass, dimension, ref, window])).digest('hex');
          const row = db.prepare('SELECT used FROM probe_buckets WHERE id=?').get(id);
          return { id, used: row?.used ?? 0, exists: !!row, limit: rule.limit, expires: (window + 1) * rule.windowMs };
        });
        const exceeded = buckets.filter(bucket => bucket.used >= bucket.limit);
        if (exceeded.length) {
          db.exec('COMMIT');
          return { allowed: false, reason: 'limited', retryAfterSeconds: Math.max(...exceeded.map(b => Math.ceil((b.expires - now) / 1000))) };
        }
        const count = db.prepare('SELECT count(*) AS n FROM probe_buckets').get().n;
        if (count + buckets.filter(b => !b.exists).length > maxBuckets) {
          db.exec('COMMIT');
          return unavailable();
        }
        const increment = db.prepare('INSERT INTO probe_buckets VALUES (?, 1, ?) ON CONFLICT(id) DO UPDATE SET used=used+1');
        for (const bucket of buckets) increment.run(bucket.id, bucket.expires);
        db.exec('COMMIT');
        return { allowed: true };
      } catch {
        try { db.exec('ROLLBACK'); } catch { /* fail closed */ }
        return unavailable();
      }
    },
    close() {
      if (!closed) { closed = true; secret.fill(0); db.close(); }
    }
  };
}

export function genericDenial(status, retryAfterSeconds) {
  if (![403, 404, 429].includes(status) || (retryAfterSeconds !== undefined
      && (status !== 429 || !integer(retryAfterSeconds, 1, 86_400)))) throw new Error('Invalid denial configuration');
  const headers = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
  if (status === 429 && retryAfterSeconds !== undefined) headers['retry-after'] = String(retryAfterSeconds);
  return { status, headers, body: '{"error":"Request unavailable"}' };
}

export function createCanaryHandler({ canaryId, emit }) {
  if (!opaque(canaryId) || typeof emit !== 'function') throw new Error('Invalid canary configuration');
  return async ({ sourceRef }) => {
    let delivered = false;
    try {
      if (!opaque(sourceRef)) throw Error();
      delivered = await emit(Object.freeze({ type: 'canary_hit', canaryId, sourceRef })) === true;
    } catch { /* Delivery state belongs only to the trusted operator, never the HTTP serializer. */ }
    return { response: genericDenial(404), delivered };
  };
}

function httpsUri(value, canonical = false) {
  if (typeof value !== 'string' || value.length > 2048 || /[\s\\%]/.test(value)) throw Error();
  const uri = new URL(value);
  if (uri.protocol !== 'https:' || uri.username || uri.password || uri.search || uri.hash
      || (canonical && uri.pathname !== '/.well-known/security.txt') || uri.href !== value) throw Error();
  return value;
}

// A conservative RFC 9116 profile, not a general-purpose RFC validator.
export function createSecurityTxt(profile) {
  try {
    if (!exact(profile, ['contact', 'expires', 'canonical', 'policy', 'preferredLanguages', 'now'])) throw Error();
    const { contact, expires, canonical, policy, preferredLanguages, now } = profile;
    if (typeof contact !== 'string' || !/^mailto:[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(contact)
        || contact.length > 320 || preferredLanguages !== 'en'
        || typeof expires !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(expires)
        || !integer(now, 0, Number.MAX_SAFE_INTEGER)) throw Error();
    const expiry = Date.parse(expires);
    if (!Number.isFinite(expiry) || new Date(expiry).toISOString() !== expires.replace('Z', '.000Z')
        || expiry <= now || expiry - now > 365 * 86_400_000) throw Error();
    return `Contact: ${contact}\nExpires: ${expires}\nCanonical: ${httpsUri(canonical, true)}\nPolicy: ${httpsUri(policy)}\nPreferred-Languages: en\n`;
  } catch { throw new Error('Invalid security.txt profile'); }
}
