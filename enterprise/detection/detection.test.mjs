import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { detectionInputEtag, evaluateDetections } from './detection.mjs';

const r = n => n.toString(16).padStart(32, '0');
const A = r(1), ACCOUNT = r(2), ACTOR = r(3), OBJECT = r(4), SOURCE = r(5), CLUSTER = r(6), ROOT = r(7);
function fixture() {
  return { schema: 'amqic.behavior.input.v1', policy: { version: 1, baselineRef: r(90), clockRef: r(91), reviewerRef: r(92), since: 1000, until: 2000, trustedNow: 2000, expiresAt: 3000, capacity: 100, thresholds: { cloudCount: 3, cloudServices: 3, cloudActions: 3, cloudDenied: 2, cloudDeniedPermille: 500, rotatingSources: 3, rotatingRoutes: 3, perSourceMax: 2, protectedDenied: 3 }, classes: [] }, events: [] };
}
function classify(f, kind, subjectRef, overrides = {}) {
  f.policy.classes.push({ kind, subjectRef, bindingRef: ['approved-source', 'helper'].includes(kind) ? ACTOR : r(0), assetRef: A, accountRef: ACCOUNT, sourceRef: r(93), reviewerRef: r(94), ownerRef: r(95), observedAt: 0, expiresAt: 3000, confidence: 'high', ...overrides });
}
function event(f, type, overrides = {}) {
  const e = { id: r(100 + f.events.length), type, at: 1500, assetRef: A, accountRef: ACCOUNT, actorRef: ACTOR, objectRef: OBJECT, sourceRef: SOURCE, clusterRef: CLUSTER, actionRef: r(8), lineageRefs: [], decision: 'observe', ...overrides };
  f.events.push(e); return e;
}
const mapping = { process: ['runtime', 'process-exec', 'host-process'], integrity: ['runtime', 'config-integrity', 'host-process'], egress: ['egress', 'egress-decision', 'egress-unapproved'], campaign: ['campaign', 'campaign-note', 'campaign-correlation'] };
function expected(id, severity, kind, es) {
  const [category, action, signalClass] = mapping[kind];
  return { id, severity, assetRef: es[0].assetRef, accountRef: es[0].accountRef, category, action, signalClass, eventRefs: es.map(e => e.id).sort() };
}
const run = f => evaluateDetections(f, { expectedEtag: detectionInputEtag(f) });
function exact(f, findings) { assert.deepEqual(run(f).findings, findings); }

test('agent utility: ancestor match, non-agent and ordinary build near matches', () => {
  const f = fixture(); classify(f, 'agent', ROOT); classify(f, 'security-utility', OBJECT);
  const e = event(f, 'process', { lineageRefs: [r(9), ROOT] }); exact(f, [expected('agent-tool-spawn', 'medium', 'process', [e])]);
  e.lineageRefs = [r(9)]; exact(f, []); e.lineageRefs = [ROOT]; e.objectRef = r(10); exact(f, []);
  e.objectRef = OBJECT; classify(f, 'approval-disabled', ROOT); exact(f, [expected('agent-tool-spawn', 'high', 'process', [e])]);
  classify(f, 'engagement', ACTOR); exact(f, []);
});
test('model API: unentitled server match, entitled workload and ordinary destination near matches', () => {
  const f = fixture(); classify(f, 'server', ACTOR); classify(f, 'model-api', OBJECT);
  const e = event(f, 'connect', { decision: 'deny' }); exact(f, [expected('server-model-api', 'medium', 'egress', [e])]);
  classify(f, 'model-entitlement', ACTOR); exact(f, []); f.policy.classes.pop(); e.objectRef = r(9); exact(f, []);
});
test('interaction capture: server DNS match, workstation and unclassified look-alike near matches', () => {
  const f = fixture(); classify(f, 'server', ACTOR); classify(f, 'interaction-capture', OBJECT);
  const e = event(f, 'dns'); exact(f, [expected('interaction-capture', 'high', 'egress', [e])]);
  e.actorRef = r(9); exact(f, []); e.actorRef = ACTOR; e.objectRef = r(9); exact(f, []);
});
function cloudFixture() {
  const f = fixture();
  for (let i = 0; i < 3; i++) event(f, 'cloud', { objectRef: r(20 + i), actionRef: r(30 + i), decision: 'deny' });
  return f;
}
test('cloud: velocity+breadth match, registered automation and single-action near matches', () => {
  const f = cloudFixture(); exact(f, [expected('credential-velocity', 'high', 'campaign', f.events)]);
  classify(f, 'automation', ACTOR); exact(f, [expected('credential-velocity', 'high', 'campaign', f.events)]);
  classify(f, 'approved-source', SOURCE); exact(f, []);
  f.policy.classes[1].bindingRef = r(99); exact(f, [expected('credential-velocity', 'high', 'campaign', f.events)]);
  f.policy.classes = []; f.events.forEach(e => e.actionRef = r(30)); exact(f, []);
});
test('cloud denied ratio affects severity independently of count with an approved non-automation source', () => {
  const f = cloudFixture(); classify(f, 'approved-source', SOURCE);
  f.events[0].decision = 'allow'; f.policy.thresholds.cloudDeniedPermille = 700;
  exact(f, [expected('credential-velocity', 'medium', 'campaign', f.events)]);
  f.policy.thresholds.cloudDeniedPermille = 600;
  exact(f, [expected('credential-velocity', 'high', 'campaign', f.events)]);
});
test('host and Windows service profile semantics: shell/download, non-service/helper near matches; file companion', () => {
  for (const child of ['shell', 'download']) {
    const f = fixture(); classify(f, 'service', ACTOR); classify(f, child, OBJECT);
    const e = event(f, 'process'); exact(f, [expected('service-child', 'high', 'process', [e])]);
    e.actorRef = r(9); exact(f, []); e.actorRef = ACTOR; classify(f, 'helper', OBJECT); exact(f, []);
    f.policy.classes.at(-1).bindingRef = r(99); exact(f, [expected('service-child', 'high', 'process', [e])]);
  }
  const f = fixture(); classify(f, 'service', ACTOR); classify(f, 'web-script', OBJECT);
  const e = event(f, 'file'); exact(f, [expected('service-file-write', 'high', 'integrity', [e])]);
  e.actorRef = r(9); exact(f, []); e.actorRef = ACTOR; e.objectRef = r(9); exact(f, []);
});
test('callback: probe to same opaque endpoint match, partner and outside-window near matches', () => {
  const f = fixture(); const probe = event(f, 'inbound', { at: 1200, decision: 'deny' }); const callback = event(f, 'connect', { objectRef: SOURCE });
  exact(f, [expected('probe-callback', 'high', 'campaign', [probe, callback])]);
  classify(f, 'partner', SOURCE); exact(f, []); f.policy.classes.pop(); probe.at = 999; exact(f, []);
  probe.at = 1600; exact(f, []); probe.at = 1200; callback.objectRef = r(9); exact(f, []);
});
function rotatingFixture() {
  const f = fixture();
  for (let i = 0; i < 3; i++) { classify(f, 'technical-route', r(20 + i)); event(f, 'inbound', { objectRef: r(20 + i), sourceRef: r(30 + i) }); }
  return f;
}
test('rotating sources: technical breadth match, public crawler and health-route fleet near matches', () => {
  const f = rotatingFixture(); exact(f, [expected('rotating-sources', 'medium', 'campaign', f.events)]);
  f.events.forEach(e => classify(f, 'crawler', e.sourceRef)); exact(f, []);
  const health = rotatingFixture(); health.events.forEach(e => { classify(health, 'health-route', e.objectRef); e.objectRef = r(20); }); exact(health, []);
  const publicRoutes = rotatingFixture(); publicRoutes.policy.classes = []; exact(publicRoutes, []);
});
test('protected paths: denial burst + non-denied regression, background floor and single hit near matches', () => {
  const f = fixture(); classify(f, 'protected-route', OBJECT);
  for (let i = 0; i < 3; i++) event(f, 'inbound', { decision: 'deny' });
  const allowed = event(f, 'inbound', { decision: 'allow' });
  // Production ordering is stable by canonical finding representation: action first.
  exact(f, [expected('protected-path-burst', 'high', 'campaign', f.events), expected('protected-path-regression', 'high', 'integrity', [allowed])]);
  f.events = f.events.slice(0, 2); exact(f, []); f.events = f.events.slice(0, 1); exact(f, []);
  f.events[0].decision = 'allow'; exact(f, [expected('protected-path-regression', 'high', 'integrity', f.events)]);
});
test('scope and time separation: cloud credential/source/account/asset and cluster/window', () => {
  for (const field of ['actorRef', 'sourceRef', 'accountRef', 'assetRef']) { const f = cloudFixture(); f.events[2][field] = r(99); exact(f, []); }
  for (const field of ['clusterRef', 'accountRef', 'assetRef']) { const f = rotatingFixture(); f.events[2][field] = r(99); exact(f, []); }
  const f = cloudFixture(); f.events[2].at = 999; exact(f, []);
  const cb = fixture(); event(cb, 'inbound', { decision: 'deny', accountRef: r(99) }); event(cb, 'connect', { objectRef: SOURCE }); exact(cb, []);
});
test('private lifecycle: expired class stops matching, expired exemption stops suppressing', () => {
  const f = fixture(); classify(f, 'server', ACTOR); classify(f, 'model-api', OBJECT); const e = event(f, 'connect');
  f.policy.classes[1].expiresAt = 2000; exact(f, []); f.policy.classes[1].expiresAt = 3000;
  classify(f, 'model-entitlement', ACTOR, { expiresAt: 2000 }); exact(f, [expected('server-model-api', 'medium', 'egress', [e])]);
  f.policy.classes[1].observedAt = 1600; exact(f, []);
});
test('strict bounded privacy boundary rejects unsafe prototypes, accessors, raw payloads and invalid types', () => {
  const mutations = [f => f.extra = 'raw', f => f.events.push({}), f => f.policy.classes.push({}), f => f.policy.capacity = 2001, f => f.policy.until = 999999999, f => f.policy.expiresAt = 2000, f => f.policy.thresholds.cloudCount = 0, f => f.events[0].type = 'unknown', f => f.events[0].objectRef = 'https://synthetic.invalid', f => f.events[0].commandLine = 'omitted', f => f.events[0].at = -1, f => f.events[0].at = 2001, f => f.events[0].lineageRefs = Array(33).fill(ROOT), f => f.events.push({ ...f.events[0] }), f => Object.setPrototypeOf(f.events[0], { inherited: true }), f => Object.defineProperty(f.events[0], 'type', { get() { throw Error('getter executed'); } }), f => f.events[0][Symbol('hidden')] = 1, f => delete f.events[0].id, f => f.events.length = 101];
  for (const mutate of mutations) { const f = fixture(); event(f, 'process'); mutate(f); assert.throws(() => detectionInputEtag(f), /Invalid detection snapshot/); }
  const sparse = fixture(); sparse.events = Array(2); assert.throws(() => detectionInputEtag(sparse), /Invalid/);
});
test('strong ETags bind exact immutable snapshot and deterministic result; stale/missing tag refused', () => {
  const f = fixture(); const inputEtag = detectionInputEtag(f); const first = run(f);
  assert.match(inputEtag, /^"[a-f0-9]{64}"$/); assert.match(first.etag, /^"[a-f0-9]{64}"$/);
  assert.deepEqual(run(f), first); assert.equal(first.inputEtag, inputEtag);
  assert.ok(Object.isFrozen(first)); assert.ok(Object.isFrozen(first.findings));
  assert.throws(() => evaluateDetections(f), /ETag/); f.policy.baselineRef = r(999);
  assert.notEqual(detectionInputEtag(f), inputEtag); assert.throws(() => evaluateDetections(f, { expectedEtag: inputEtag }), /ETag/);
  assert.deepEqual(Object.keys(first).sort(), ['etag', 'findings', 'inputEtag', 'schema']);
});
test('opaque reference boundaries reject line breaks and raw-content fields without echoing values', () => {
  for (const suffix of ['\n', '\r\n', ' ']) {
    const f = fixture(); event(f, 'connect', { objectRef: OBJECT + suffix });
    assert.throws(() => run(f), { message: 'Invalid detection snapshot' });
  }
});
test('model API severity correlates only within same account/asset/window', () => {
  const f = fixture(); classify(f, 'server', ACTOR); classify(f, 'model-api', OBJECT); classify(f, 'agent', ROOT); classify(f, 'security-utility', r(20));
  const model = event(f, 'connect'); const spawn = event(f, 'process', { objectRef: r(20), lineageRefs: [ROOT] });
  exact(f, [expected('server-model-api', 'high', 'egress', [model]), expected('agent-tool-spawn', 'medium', 'process', [spawn])]);
  spawn.at = 999; exact(f, [expected('server-model-api', 'medium', 'egress', [model])]);
});
test('starting profiles remain templates and minimize output', () => {
  for (const name of ['agent-tool-spawn', 'host-service-shell']) {
    const text = readFileSync(new URL(`../runtime/profiles/${name}.falco.yaml.template`, import.meta.url), 'utf8');
    assert.match(text, /OPERATOR_/); assert.match(text, /evt\.rawres >= 0/);
    const output = text.split('\n').find(line => line.startsWith('  output:'));
    assert.ok(output); assert.doesNotMatch(output, /cmdline|args|env|proc\.name|proc\.pname/);
    assert.match(text, /source: syscall/);
  }
  const profile = JSON.parse(readFileSync(new URL('../runtime/profiles/windows-service-shell.profile.json', import.meta.url), 'utf8'));
  assert.equal(profile.status, 'starting-specification-not-deployed');
  assert.deepEqual(profile.outputFields, ['assetRef', 'accountRef', 'eventRef', 'signalId']);
  assert.deepEqual(profile.conditions.childClasses, ['shell', 'download']);
  assert.equal(profile.conditions.parentClass, 'service');
});
