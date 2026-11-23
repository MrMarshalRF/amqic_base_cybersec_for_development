import { createHash } from 'node:crypto';

// This is an offline evaluator, not a trust boundary or a telemetry collector.
const REF = /^[a-f0-9]{32}$/;
const KINDS = new Set(['agent', 'approval-disabled', 'security-utility', 'engagement', 'server', 'model-api', 'model-entitlement', 'interaction-capture', 'automation', 'approved-source', 'service', 'shell', 'download', 'helper', 'web-script', 'partner', 'technical-route', 'protected-route', 'crawler', 'health-route']);
const TYPES = new Set(['process', 'connect', 'dns', 'cloud', 'inbound', 'file', 'auth']);
const THRESHOLDS = ['cloudCount', 'cloudServices', 'cloudActions', 'cloudDenied', 'rotatingSources', 'rotatingRoutes', 'perSourceMax', 'protectedDenied'];
const MAPPING = {
  process: ['runtime', 'process-exec', 'host-process'],
  integrity: ['runtime', 'config-integrity', 'host-process'],
  egress: ['egress', 'egress-decision', 'egress-unapproved'],
  campaign: ['campaign', 'campaign-note', 'campaign-correlation'],
};
function invalid() { throw new TypeError('Invalid detection snapshot'); }
function object(value, fields) {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== fields.length || !fields.every(k => Object.hasOwn(descriptors, k) && Object.hasOwn(descriptors[k], 'value'))) invalid();
}
function integer(n, min, max) { if (!Number.isSafeInteger(n) || n < min || n > max) invalid(); }
function ref(s) { if (typeof s !== 'string' || s.length !== 32 || !REF.test(s)) invalid(); }
function list(v, max) {
  if (!Array.isArray(v) || Object.getPrototypeOf(v) !== Array.prototype || v.length > max || Reflect.ownKeys(v).length !== v.length + 1) invalid();
  for (let i = 0; i < v.length; i++) if (!Object.hasOwn(Object.getOwnPropertyDescriptor(v, String(i)) ?? {}, 'value')) invalid();
}
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
function tag(value) { return `"${createHash('sha256').update(canonical(value)).digest('hex')}"`; }
function snapshot(input) {
  object(input, ['schema', 'policy', 'events']);
  if (input.schema !== 'amqic.behavior.input.v1') invalid();
  const p = input.policy;
  object(p, ['version', 'baselineRef', 'clockRef', 'reviewerRef', 'since', 'until', 'trustedNow', 'expiresAt', 'capacity', 'thresholds', 'classes']);
  if (p.version !== 1) invalid();
  for (const k of ['baselineRef', 'clockRef', 'reviewerRef']) ref(p[k]);
  for (const k of ['since', 'until', 'trustedNow', 'expiresAt']) integer(p[k], 0, Number.MAX_SAFE_INTEGER);
  if (p.until <= p.since || p.until - p.since > 86400000 || p.until > p.trustedNow || p.trustedNow >= p.expiresAt) invalid();
  integer(p.capacity, 1, 2000);
  object(p.thresholds, [...THRESHOLDS, 'cloudDeniedPermille']);
  for (const k of THRESHOLDS) integer(p.thresholds[k], 1, p.capacity);
  integer(p.thresholds.cloudDeniedPermille, 1, 1000);
  list(p.classes, 4000);
  for (const c of p.classes) {
    object(c, ['kind', 'subjectRef', 'bindingRef', 'assetRef', 'accountRef', 'sourceRef', 'reviewerRef', 'ownerRef', 'observedAt', 'expiresAt', 'confidence']);
    if (!KINDS.has(c.kind) || !['low', 'medium', 'high'].includes(c.confidence)) invalid();
    for (const k of ['subjectRef', 'bindingRef', 'assetRef', 'accountRef', 'sourceRef', 'reviewerRef', 'ownerRef']) ref(c[k]);
    if (!['approved-source', 'helper'].includes(c.kind) && c.bindingRef !== '0'.repeat(32)) invalid();
    integer(c.observedAt, 0, p.trustedNow); integer(c.expiresAt, c.observedAt + 1, Number.MAX_SAFE_INTEGER);
  }
  list(input.events, p.capacity);
  const ids = new Set();
  for (const e of input.events) {
    object(e, ['id', 'type', 'at', 'assetRef', 'accountRef', 'actorRef', 'objectRef', 'sourceRef', 'clusterRef', 'actionRef', 'lineageRefs', 'decision']);
    if (!TYPES.has(e.type) || !['allow', 'deny', 'observe'].includes(e.decision)) invalid();
    for (const k of ['id', 'assetRef', 'accountRef', 'actorRef', 'objectRef', 'sourceRef', 'clusterRef', 'actionRef']) ref(e[k]);
    if (ids.has(e.id)) invalid(); ids.add(e.id);
    integer(e.at, 0, p.trustedNow); list(e.lineageRefs, 32); e.lineageRefs.forEach(ref);
  }
  // No input object survives into evaluation or output.
  return JSON.parse(canonical(input));
}
export function detectionInputEtag(input) { return tag(snapshot(input)); }

export function evaluateDetections(input, { expectedEtag } = {}) {
  const s = snapshot(input), inputEtag = tag(s), p = s.policy, t = p.thresholds;
  if (expectedEtag !== inputEtag) throw new Error('Detection snapshot ETag mismatch');
  const events = s.events.filter(e => e.at >= p.since && e.at < p.until).sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));
  const classIndex = new Map();
  for (const c of p.classes) if (c.expiresAt > p.trustedNow) {
    const key = [c.kind, c.subjectRef, c.bindingRef, c.assetRef, c.accountRef].join(':');
    // Earliest currently valid observation is enough for this immutable window.
    classIndex.set(key, Math.min(classIndex.get(key) ?? Infinity, c.observedAt));
  }
  const has = (e, kind, subjectRef) => (classIndex.get([kind, subjectRef, ['approved-source', 'helper'].includes(kind) ? e.actorRef : '0'.repeat(32), e.assetRef, e.accountRef].join(':')) ?? Infinity) <= e.at;
  const findings = [];
  const emit = (id, severity, mapping, es) => {
    const [category, action, signalClass] = MAPPING[mapping], e = es[0];
    findings.push({ id, severity, assetRef: e.assetRef, accountRef: e.accountRef, category, action, signalClass, eventRefs: es.map(x => x.id).sort() });
  };
  for (const e of events) {
    if (e.type === 'process' && e.lineageRefs.some(r => has(e, 'agent', r)) && has(e, 'security-utility', e.objectRef) && !has(e, 'engagement', e.actorRef)) emit('agent-tool-spawn', e.lineageRefs.some(r => has(e, 'approval-disabled', r)) ? 'high' : 'medium', 'process', [e]);
    if (e.type === 'connect' && has(e, 'server', e.actorRef) && has(e, 'model-api', e.objectRef) && !has(e, 'model-entitlement', e.actorRef)) emit('server-model-api', 'medium', 'egress', [e]);
    if (['dns', 'connect'].includes(e.type) && has(e, 'server', e.actorRef) && has(e, 'interaction-capture', e.objectRef) && !has(e, 'engagement', e.actorRef)) emit('interaction-capture', 'high', 'egress', [e]);
    if (e.type === 'process' && has(e, 'service', e.actorRef) && ['shell', 'download'].some(k => has(e, k, e.objectRef)) && !has(e, 'helper', e.objectRef)) emit('service-child', 'high', 'process', [e]);
    if (e.type === 'file' && has(e, 'service', e.actorRef) && has(e, 'web-script', e.objectRef) && !has(e, 'helper', e.objectRef)) emit('service-file-write', 'high', 'integrity', [e]);
    if (e.type === 'connect' && !has(e, 'partner', e.objectRef)) {
      const probes = events.filter(x => x.type === 'inbound' && x.assetRef === e.assetRef && x.accountRef === e.accountRef && x.sourceRef === e.objectRef && x.at <= e.at && (x.decision === 'deny' || has(x, 'technical-route', x.objectRef) || has(x, 'protected-route', x.objectRef)));
      if (probes.length) {
        // One representative denied probe (or latest technical probe) bounds
        // output size while preserving the exact protected linkage pair.
        const probe = probes.findLast(x => x.decision === 'deny') ?? probes.at(-1);
        emit('probe-callback', probe.decision === 'deny' ? 'high' : 'medium', 'campaign', [probe, e]);
      }
    }
  }
  function groups(type, keys) {
    const map = new Map();
    for (const e of events.filter(x => x.type === type)) {
      const key = [e.assetRef, e.accountRef, ...keys.map(k => e[k])].join(':');
      if (!map.has(key)) map.set(key, []); map.get(key).push(e);
    }
    return map.values();
  }
  const distinct = (es, key) => new Set(es.map(e => e[key])).size;
  for (const es of groups('cloud', ['actorRef', 'sourceRef'])) {
    const e = es[0];
    const denied = es.filter(x => x.decision === 'deny').length;
    if (es.length >= t.cloudCount && distinct(es, 'objectRef') >= t.cloudServices && distinct(es, 'actionRef') >= t.cloudActions && !(has(e, 'automation', e.actorRef) && has(e, 'approved-source', e.sourceRef))) emit('credential-velocity', (denied >= t.cloudDenied && denied * 1000 >= t.cloudDeniedPermille * es.length) || !has(e, 'approved-source', e.sourceRef) ? 'high' : 'medium', 'campaign', es);
  }
  for (const es of groups('inbound', ['clusterRef'])) {
    const suspicious = es.filter(e => (has(e, 'technical-route', e.objectRef) || has(e, 'protected-route', e.objectRef)) && !has(e, 'crawler', e.sourceRef) && !has(e, 'health-route', e.objectRef));
    const counts = new Map(); suspicious.forEach(e => counts.set(e.sourceRef, (counts.get(e.sourceRef) ?? 0) + 1));
    if (counts.size >= t.rotatingSources && distinct(suspicious, 'objectRef') >= t.rotatingRoutes && [...counts.values()].every(n => n <= t.perSourceMax)) emit('rotating-sources', 'medium', 'campaign', suspicious);
    const protectedHits = es.filter(e => has(e, 'protected-route', e.objectRef));
    const nonDenied = protectedHits.filter(e => e.decision !== 'deny');
    if (nonDenied.length) emit('protected-path-regression', 'high', 'integrity', nonDenied);
    if (protectedHits.filter(e => e.decision === 'deny').length >= t.protectedDenied) {
      const authenticated = events.some(e => e.type === 'auth' && e.decision === 'allow' && e.assetRef === es[0].assetRef && e.accountRef === es[0].accountRef && e.clusterRef === es[0].clusterRef && e.at >= protectedHits[0].at);
      emit('protected-path-burst', nonDenied.length || authenticated ? 'high' : 'medium', 'campaign', protectedHits);
    }
  }
  for (const f of findings) if (f.id === 'server-model-api' && findings.some(x => ['agent-tool-spawn', 'probe-callback'].includes(x.id) && x.assetRef === f.assetRef && x.accountRef === f.accountRef)) f.severity = 'high';
  findings.sort((a, b) => canonical(a).localeCompare(canonical(b)));
  const result = { schema: 'amqic.behavior.result.v1', inputEtag, findings };
  for (const f of findings) { Object.freeze(f.eventRefs); Object.freeze(f); }
  Object.freeze(findings);
  return Object.freeze({ ...result, etag: tag(result) });
}
