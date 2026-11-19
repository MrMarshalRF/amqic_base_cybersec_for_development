// Transport-neutral reference guard. Trusted host adapters are the security boundary.
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

const compiled = new WeakSet();
const fail = (code) => { throw new Error(code); };
const own = (o, k) => Object.hasOwn(o, k);
const object = (o) => o !== null && typeof o === 'object' && !Array.isArray(o)
  && [Object.prototype, null].includes(Object.getPrototypeOf(o));
function exact(o, keys) {
  if (!object(o) || Object.keys(o).sort().join('|') !== [...keys].sort().join('|')) fail('invalid_shape');
}
const id = (x) => typeof x === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(x);
const integer = (x) => Number.isSafeInteger(x) && x >= 1;
function freeze(x) {
  if (x && typeof x === 'object') { Object.values(x).forEach(freeze); Object.freeze(x); }
  return x;
}
// Only JSON data, never getters, class instances, undefined, symbols or toJSON hooks.
function snapshot(x, depth = 0) {
  if (depth > 12) fail('input_limit');
  if (x === null || typeof x === 'boolean' || typeof x === 'string') {
    if (typeof x === 'string' && x.length > 4096) fail('input_limit');
    return x;
  }
  if (typeof x === 'number' && Number.isSafeInteger(x)) return Object.is(x, -0) ? 0 : x;
  if (!Array.isArray(x) && !object(x)) fail('invalid_json');
  const keys = Reflect.ownKeys(x);
  if (keys.length > 130) fail('input_limit');
  if (keys.some(key => typeof key !== 'string')) fail('invalid_json');
  if (!Array.isArray(x)) keys.sort();
  const result = Array.isArray(x) ? [] : Object.create(null);
  for (const key of keys) {
    if (Array.isArray(x) && key === 'length') continue;
    const d = Object.getOwnPropertyDescriptor(x, key);
    if (typeof key !== 'string' || !d.enumerable || !own(d, 'value') || key === '__proto__') fail('invalid_json');
    if (Array.isArray(x) && !/^(0|[1-9][0-9]*)$/.test(key)) fail('invalid_json');
    result[key] = snapshot(d.value, depth + 1);
  }
  if (Array.isArray(x) && (result.length !== x.length || keys.length !== x.length + 1)) fail('invalid_json');
  return result;
}
function canonical(x) {
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (object(x)) return '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
  return JSON.stringify(x);
}
const digest = (x) => createHash('sha256').update(canonical(x)).digest('hex');
function field(s) {
  if (s.type === 'string' || s.type === 'boolean') {
    exact(s, ['type', 'values']);
    if (!Array.isArray(s.values) || !s.values.length || s.values.length > 64
      || s.values.some(v => typeof v !== s.type || (s.type === 'string' && v.length > 1024))
      || new Set(s.values).size !== s.values.length) fail('invalid_schema');
  } else if (s.type === 'integer') {
    exact(s, ['type', 'min', 'max']);
    if (!Number.isSafeInteger(s.min) || !Number.isSafeInteger(s.max) || s.min > s.max) fail('invalid_schema');
  } else fail('unsupported_schema');
}
function policy(p) {
  exact(p, ['version', 'maxCalls', 'maxLifetimeMs', 'tools']);
  if (p.version !== 1 || !integer(p.maxCalls) || p.maxCalls > 10000
    || !integer(p.maxLifetimeMs) || p.maxLifetimeMs > 86400000 || !object(p.tools)
    || !Object.keys(p.tools).length || Object.keys(p.tools).length > 32) fail('invalid_policy');
  for (const [tool, r] of Object.entries(p.tools)) {
    if (!id(tool)) fail('invalid_tool');
    exact(r, ['args', 'requiresApproval', 'endpointIds']);
    if (!object(r.args) || Object.keys(r.args).length > 32 || typeof r.requiresApproval !== 'boolean'
      || !Array.isArray(r.endpointIds) || r.endpointIds.length > 32
      || r.endpointIds.some(x => !id(x)) || new Set(r.endpointIds).size !== r.endpointIds.length) fail('invalid_rule');
    for (const [name, schema] of Object.entries(r.args)) { if (!id(name)) fail('invalid_argument'); field(schema); }
  }
  return p;
}
function subset(c, b) {
  if (c.maxCalls > b.maxCalls || c.maxLifetimeMs > b.maxLifetimeMs) return false;
  for (const [tool, r] of Object.entries(c.tools)) {
    const base = b.tools[tool];
    if (!base || (base.requiresApproval && !r.requiresApproval)
      || r.endpointIds.some(x => !base.endpointIds.includes(x))
      || Object.keys(r.args).sort().join('|') !== Object.keys(base.args).sort().join('|')) return false;
    for (const [name, s] of Object.entries(r.args)) {
      const t = base.args[name];
      if (s.type !== t.type || (s.type === 'integer' ? s.min < t.min || s.max > t.max : s.values.some(x => !t.values.includes(x)))) return false;
    }
  }
  return true;
}
/** Closed finite/range schema comparison; unsupported input always fails closed. */
export function checkPolicyNarrowing(candidate, boundary) {
  try { return subset(policy(snapshot(candidate)), policy(snapshot(boundary))) ? 'within_boundary' : 'outside_boundary'; }
  catch { return 'unsupported_or_invalid'; }
}
/** The catalog is a trusted host-authored maximum policy, never model supplied. */
export function compilePolicy(input, catalog) {
  const p = policy(snapshot(input)), b = policy(snapshot(catalog));
  if (!subset(p, b)) fail('outside_catalog');
  const value = freeze({ policy: p, catalogDigest: digest(b), policyDigest: digest(p) });
  compiled.add(value);
  return value;
}

/** Keep this object and every adapter inaccessible to the model. */
export function createSession({ compiledPolicy, identity, handlers, approve, audit, now }) {
  if (!compiled.has(compiledPolicy)) fail('uncompiled_policy');
  const who = freeze(snapshot(identity));
  exact(who, ['sessionId', 'tenantId', 'actorId', 'generation']);
  if (Object.values(who).some(x => !id(x))) fail('invalid_identity');
  if (typeof audit !== 'function' || typeof now !== 'function' || typeof approve !== 'function' || !object(handlers)) fail('invalid_adapter');
  const p = compiledPolicy.policy, fixed = Object.create(null);
  for (const tool of Object.keys(p.tools)) {
    const d = Object.getOwnPropertyDescriptor(handlers, tool);
    if (!d || !own(d, 'value') || typeof d.value !== 'function') fail('unknown_handler');
    fixed[tool] = d.value;
  }
  let revoked = false, last = -1, calls = 0;
  const replay = new Set();
  function clock() {
    let t;
    try { t = now(); } catch { revoked = true; fail('clock_failure'); }
    if (!Number.isSafeInteger(t) || t < 0 || t < last) { revoked = true; fail('clock_failure'); }
    last = t; return t;
  }
  const started = clock();
  const expires = started + p.maxLifetimeMs;
  if (!Number.isSafeInteger(expires)) fail('clock_failure');
  function active() { const t = clock(); if (revoked || t >= expires) fail('inactive_session'); return t; }
  async function emit(event) {
    try { if (await audit(freeze(event)) !== true) fail('audit_failure'); }
    catch { revoked = true; fail('audit_failure'); }
  }
  return Object.freeze({
    revoke() { revoked = true; },
    async dispatch(input) {
      // All validation and reservation precede the first asynchronous boundary.
      const r = freeze(snapshot(input));
      exact(r, ['sessionId', 'tenantId', 'actorId', 'generation', 'requestId', 'tool', 'args']);
      if (Object.keys(who).some(k => r[k] !== who[k])) fail('identity_mismatch');
      if (!id(r.requestId) || !id(r.tool) || !own(p.tools, r.tool)) fail('unknown_request');
      const rule = p.tools[r.tool];
      exact(r.args, Object.keys(rule.args));
      for (const [k, s] of Object.entries(rule.args)) {
        const v = r.args[k];
        if (s.type === 'integer' ? !Number.isSafeInteger(v) || v < s.min || v > s.max : !s.values.includes(v)) fail('invalid_arguments');
      }
      active();
      if (replay.has(r.requestId)) fail('replay');
      if (calls >= p.maxCalls) fail('call_budget');
      replay.add(r.requestId); calls++;
      const binding = freeze({ version: 1, identity: who, request: r,
        policyDigest: compiledPolicy.policyDigest, catalogDigest: compiledPolicy.catalogDigest,
        endpointIds: rule.endpointIds, expiresAt: expires });
      const hash = digest(binding);
      await emit({ version: 1, event: 'reserved', sessionId: who.sessionId, requestId: r.requestId, tool: r.tool, digest: hash });
      active();
      if (rule.requiresApproval) {
        let answer;
        try { answer = snapshot(await approve(freeze({ digest: hash, binding }))); }
        catch { fail('approval_failed'); }
        exact(answer, ['digest']);
        if (answer.digest !== hash) fail('approval_mismatch');
      }
      active();
      await emit({ version: 1, event: 'dispatch', sessionId: who.sessionId, requestId: r.requestId, tool: r.tool, digest: hash });
      active();
      // No await between the last active check and invoking the captured handler.
      // Handler failures/unknown results remain consumed: never blindly retry effects.
      return fixed[r.tool](r.args, freeze({ identity: who, requestId: r.requestId, digest: hash, endpointIds: rule.endpointIds }));
    }
  });
}

function publicIPv4(ip) {
  if (isIP(ip) !== 4) return false;
  if (ip === '168.63.129.16') return false; // Azure platform virtual IP; never an outbound application target here.
  const [a, b, c] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 192 && b === 88 && c === 99)
    || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    || (a === 203 && b === 0 && c === 113));
}
/** Offline plan only: no DNS lookup, network call, credential access or token. */
export function checkEgress(input) {
  try {
    const r = snapshot(input);
    exact(r, ['url', 'method', 'endpoint', 'dnsAnswers']);
    exact(r.endpoint, ['id', 'hostname', 'path', 'method', 'credentialRef']);
    const e = r.endpoint;
    if (!id(e.id) || !id(e.credentialRef) || !['GET', 'POST'].includes(e.method) || r.method !== e.method
      || typeof e.hostname !== 'string' || e.hostname.length > 253 || !e.hostname.includes('.')
      || !e.hostname.split('.').every(l => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))
      || !/^[a-z]{2,63}$/.test(e.hostname.split('.').at(-1))
      || isIP(e.hostname) !== 0 || typeof e.path !== 'string'
      || !/^\/(?:[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*)?$/.test(e.path)
      || r.url !== `https://${e.hostname}${e.path}`
      || !Array.isArray(r.dnsAnswers) || !r.dnsAnswers.length || r.dnsAnswers.some(x => typeof x !== 'string' || !publicIPv4(x))) fail('egress_denied');
    return freeze({ status: 'plan_only', endpointId: e.id, hostname: e.hostname, port: 443,
      path: e.path, method: e.method, credentialRef: e.credentialRef, checkedAddresses: r.dnsAnswers });
  } catch { return Object.freeze({ status: 'denied' }); }
}
