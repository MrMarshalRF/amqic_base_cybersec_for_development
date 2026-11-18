import { createHash } from 'node:crypto';

const policies = new WeakMap();
const methods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const classifications = new Set(['public', 'internal', 'confidential', 'restricted']);
const token = /^[a-z][a-z0-9_-]{0,63}$/;
const opaqueId = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const route = /^\/(?:[a-z0-9_-]+(?:\/[a-z0-9_-]+)*)?$/;
const riskLevels = new Set(['normal', 'elevated', 'blocked']);

function shape(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    throw new TypeError('Invalid ' + label);
  }
}

function bounded(value, min, max) {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

function matches(pattern, value) {
  return typeof value === 'string' && pattern.test(value);
}

function tuple(...values) {
  return JSON.stringify(values);
}

export function compilePolicy(source) {
  shape(source, ['version', 'tenants'], 'policy');
  if (source.version !== 1 || !Array.isArray(source.tenants) || source.tenants.length < 1 || source.tenants.length > 256) {
    throw new TypeError('Invalid policy version or tenant count');
  }

  const tenants = new Map();
  const normalized = source.tenants.map(tenant => {
    shape(tenant, ['id', 'quota', 'rules'], 'tenant');
    if (!matches(token, tenant.id) || tenants.has(tenant.id)) throw new TypeError('Invalid or duplicate tenant ID');
    shape(tenant.quota, ['windowMs', 'normal', 'elevated'], 'quota');
    const { windowMs, normal, elevated } = tenant.quota;
    if (!bounded(windowMs, 1000, 86_400_000) || !bounded(normal, 1, 1_000_000) ||
        !bounded(elevated, 1, normal)) throw new TypeError('Invalid quota limits');

    if (!Array.isArray(tenant.rules) || tenant.rules.length > 256) throw new TypeError('Invalid rule count');
    const rules = new Map();
    const canonicalRules = tenant.rules.map(rule => {
      shape(rule, ['method', 'path', 'resource', 'classification', 'roles'], 'rule');
      const { method, path, resource, classification, roles } = rule;
      if (!methods.has(method) || !matches(route, path) || path.length > 256 ||
          !matches(token, resource) || !classifications.has(classification) ||
          !Array.isArray(roles) || roles.length < 1 || roles.length > 32 ||
          roles.some(role => !matches(token, role)) || new Set(roles).size !== roles.length) {
        throw new TypeError('Invalid rule fields');
      }
      const key = tuple(method, path, resource, classification);
      if (rules.has(key)) throw new TypeError('Duplicate rule key');
      rules.set(key, new Set(roles));
      return { method, path, resource, classification, roles: [...roles].sort() };
    });
    canonicalRules.sort((a, b) => {
      const first = tuple(a.method, a.path, a.resource, a.classification);
      const second = tuple(b.method, b.path, b.resource, b.classification);
      return first < second ? -1 : first > second ? 1 : 0;
    });
    const quota = Object.freeze({ windowMs, normal, elevated });
    tenants.set(tenant.id, { quota, rules });
    return { id: tenant.id, quota, rules: canonicalRules };
  }).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

  const digest = createHash('sha256').update(JSON.stringify({ version: 1, tenants: normalized })).digest('hex');
  const compiled = Object.freeze({ digest, tenantCount: tenants.size });
  policies.set(compiled, tenants);
  return compiled;
}

function transaction(db, callback) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = callback();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function sqliteQuotas(db, digest, clock) {
  transaction(db, () => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS enterprise_policy_version (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        digest TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS enterprise_tenant_quota (
        tenant TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        elevated INTEGER NOT NULL CHECK (elevated IN (0, 1)),
        count INTEGER NOT NULL CHECK (count >= 0)
      ) STRICT;
    `);
    db.prepare('INSERT INTO enterprise_policy_version VALUES (1, ?) ON CONFLICT DO NOTHING').run(digest);
    if (db.prepare('SELECT digest FROM enterprise_policy_version WHERE singleton = 1').get()?.digest !== digest) {
      throw new Error('Quota store policy digest mismatch');
    }
  });

  const version = db.prepare('SELECT digest FROM enterprise_policy_version WHERE singleton = 1');
  const read = db.prepare('SELECT window_start, last_seen, elevated, count FROM enterprise_tenant_quota WHERE tenant = ?');
  const write = db.prepare(`
    INSERT INTO enterprise_tenant_quota (tenant, window_start, last_seen, elevated, count)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (tenant) DO UPDATE SET
      window_start = excluded.window_start, last_seen = excluded.last_seen,
      elevated = excluded.elevated, count = excluded.count
  `);

  return function consume(tenant, quota, risk) {
    return transaction(db, () => {
      if (version.get()?.digest !== digest) throw new Error('Quota store policy digest mismatch');
      const now = clock();
      if (!bounded(now, 0, Number.MAX_SAFE_INTEGER)) throw new Error('Invalid quota clock');
      const previous = read.get(tenant);
      if (previous && now < previous.last_seen) throw new Error('Quota clock moved backwards');
      const windowStart = now - now % quota.windowMs;
      const current = previous?.window_start === windowStart ? previous : undefined;
      const elevated = risk === 'elevated' || current?.elevated === 1;
      const used = current?.count ?? 0;
      const allowed = used < (elevated ? quota.elevated : quota.normal);
      write.run(tenant, windowStart, now, elevated ? 1 : 0, used + Number(allowed));
      return allowed;
    });
  };
}

/**
 * Create a gate from trusted server-side adapters and a dedicated SQLite connection.
 * Use the same local SQLite file and compiled policy on each same-host connection.
 * Invoke this before each protected operation. Apply granted context at the actual effect.
 */
export function createPolicyGate({ policy, db, authenticate, loadResource, assessRisk = () => 'normal', clock = Date.now }) {
  const tenants = policies.get(policy);
  if (!tenants || [authenticate, loadResource, assessRisk, clock].some(fn => typeof fn !== 'function')) {
    throw new TypeError('Invalid policy gate dependencies');
  }
  const consume = sqliteQuotas(db, policy.digest, clock);
  const deny = reason => Object.freeze({ allowed: false, reason, policyDigest: policy.digest });

  return async function authorize(request) {
    try {
      const target = Object.freeze({ method: request?.method, path: request?.path, resourceId: request?.resourceId });
      if (!methods.has(target.method) || !matches(route, target.path) || target.path.length > 256 ||
          !matches(opaqueId, target.resourceId)) return deny('invalid_target');

      const actor = await authenticate(request);
      if (!matches(token, actor?.tenant) || !matches(opaqueId, actor?.subject) || !Array.isArray(actor.roles) ||
          actor.roles.length < 1 || actor.roles.length > 32) return deny('unauthenticated');
      const roles = [...actor.roles];
      if (roles.some(role => !matches(token, role))) return deny('unauthenticated');
      const context = Object.freeze({ tenant: actor.tenant, subject: actor.subject, roles: Object.freeze(roles) });
      const tenant = tenants.get(context.tenant);
      if (!tenant) return deny('unauthorized');

      const stored = await loadResource(context, target);
      if (!stored || stored.id !== target.resourceId || stored.tenant !== context.tenant ||
          !matches(token, stored.kind) || !classifications.has(stored.classification)) return deny('unauthorized');
      const resource = Object.freeze({ id: stored.id, kind: stored.kind, classification: stored.classification });
      const allowedRoles = tenant.rules.get(tuple(target.method, target.path, resource.kind, resource.classification));
      if (!allowedRoles || !context.roles.some(role => allowedRoles.has(role))) return deny('unauthorized');

      const binding = Object.freeze({ context, target, resource });
      const risk = await assessRisk(binding);
      if (!riskLevels.has(risk) || risk === 'blocked') return deny('risk_denied');
      if (!consume(context.tenant, tenant.quota, risk)) return deny('rate_limited');
      return Object.freeze({ allowed: true, policyDigest: policy.digest, ...binding });
    } catch {
      return deny('dependency_error');
    }
  };
}
