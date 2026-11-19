import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compilePolicy, checkPolicyNarrowing, createSession, checkEgress } from './agent-runtime.mjs';

const identity = { sessionId: 's1', tenantId: 't1', actorId: 'a1', generation: 'g1' };
const boundary = () => ({ version: 1, maxCalls: 3, maxLifetimeMs: 1000, tools: { report: {
  args: { kind: { type: 'string', values: ['summary', 'detail'] }, dry: { type: 'boolean', values: [true] }, limit: { type: 'integer', min: 1, max: 10 } },
  requiresApproval: true, endpointIds: ['reportApi']
} } });
const request = (requestId = 'r1') => ({ ...identity, requestId, tool: 'report', args: { kind: 'summary', dry: true, limit: 2 } });
function fixture(options = {}) {
  let time = 100, effects = 0;
  const events = [], approvals = [];
  const policy = options.policy ?? boundary();
  const session = createSession({ compiledPolicy: compilePolicy(policy, boundary()), identity,
    handlers: { report: (args, context) => { effects++; return { args, context }; } },
    now: () => time,
    audit: e => { events.push(e); return true; },
    approve: b => { approvals.push(b); return { digest: b.digest }; }, ...options.adapters });
  return { session, events, approvals, effects: () => effects, time: v => { time = v; } };
}

test('permitted operation reaches only fixed handler with exact immutable binding and sanitized audit', async () => {
  const f = fixture(), r = request(), result = await f.session.dispatch(r);
  assert.equal(f.effects(), 1);
  assert.deepEqual({ ...result.args }, r.args);
  assert.equal(result.context.digest, f.approvals[0].digest);
  assert.match(result.context.digest, /^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(f.approvals[0].binding.request.args));
  assert.deepEqual(f.events.map(e => e.event), ['reserved', 'dispatch']);
  assert.ok(f.events.every(e => !('args' in e) && !('binding' in e)));
});

test('negative zero is normalized before approval binding, digest and handler execution', async () => {
  async function run(value) {
    const p = boundary(); p.tools.report.args.limit.min = 0;
    let approval;
    const s = createSession({ compiledPolicy: compilePolicy(p, p), identity,
      handlers: { report: (args, context) => ({ value: args.limit, digest: context.digest }) },
      approve: b => { approval = b; return { digest: b.digest }; }, audit: () => true, now: () => 100 });
    const r = request(); r.args.limit = value;
    const result = await s.dispatch(r);
    assert.equal(Object.is(approval.binding.request.args.limit, -0), false);
    assert.equal(Object.is(result.value, -0), false);
    assert.equal(result.value, 0);
    assert.equal(result.digest, approval.digest);
    return result;
  }
  assert.deepEqual(await run(-0), await run(0));
});

test('reordered object fields produce identical approval and handler representation and digest', async () => {
  async function run(args) {
    let approval;
    const p = boundary();
    const s = createSession({ compiledPolicy: compilePolicy(p, p), identity,
      handlers: { report: (value, context) => ({ keys: Object.keys(value), digest: context.digest }) },
      approve: b => { approval = b; return { digest: b.digest }; }, audit: () => true, now: () => 100 });
    const result = await s.dispatch({ ...request(), args });
    assert.deepEqual(Object.keys(approval.binding.request.args), ['dry', 'kind', 'limit']);
    assert.deepEqual(result.keys, ['dry', 'kind', 'limit']);
    return result;
  }
  assert.deepEqual(await run({ kind: 'summary', dry: true, limit: 2 }),
    await run({ limit: 2, kind: 'summary', dry: true }));
});

test('unknown request fields including model approved flag, identity and generation mismatch deny', async () => {
  for (const patch of [{ approved: true }, { tenantId: 'other' }, { actorId: 'other' }, { generation: 'old' }, { sessionId: 'other' }, { tool: 'exec' }]) {
    const f = fixture(); await assert.rejects(f.session.dispatch({ ...request(), ...patch })); assert.equal(f.effects(), 0);
  }
});

test('arguments enforce exact keys, finite strings/booleans and safe bounded integers', async () => {
  for (const patch of [{ extra: true }, { dry: false }, { kind: 'shell' }, { limit: 11 }, { limit: 1.5 }, { limit: Number.MAX_VALUE }]) {
    const f = fixture(), r = request(); Object.assign(r.args, patch);
    await assert.rejects(f.session.dispatch(r)); assert.equal(f.effects(), 0);
  }
  const r = request(); Object.defineProperty(r.args, 'evil', { enumerable: true, get() { throw Error('must not execute'); } });
  await assert.rejects(fixture().session.dispatch(r), /invalid_json/);
});

test('caller mutation while awaiting approval cannot change authorized effect', async () => {
  let release, seen;
  const f = fixture({ adapters: { approve: b => { seen = b; return new Promise(resolve => { release = resolve; }); } } });
  const r = request(), pending = f.session.dispatch(r);
  await new Promise(resolve => setImmediate(resolve));
  r.args.kind = 'detail'; r.args.limit = 9; r.tenantId = 'other';
  release({ digest: seen.digest });
  const result = await pending;
  assert.equal(result.args.kind, 'summary'); assert.equal(result.args.limit, 2);
});

test('approval for another digest, boolean flag or stale request cannot grant authority', async () => {
  for (const answer of [{ digest: 'wrong' }, { approved: true }, true, { digest: 'x', approved: true }]) {
    const f = fixture({ adapters: { approve: () => answer } });
    await assert.rejects(f.session.dispatch(request())); assert.equal(f.effects(), 0);
  }
  let prior;
  const f = fixture({ adapters: { approve: b => { const answer = { digest: prior ?? b.digest }; prior = b.digest; return answer; } } });
  await f.session.dispatch(request()); await assert.rejects(f.session.dispatch(request('r2')), /approval_mismatch/);
  assert.equal(f.effects(), 1);
});

test('concurrent duplicate and budget are reserved before asynchronous approval', async () => {
  let release;
  const p = boundary(); p.maxCalls = 1;
  const f = fixture({ policy: p, adapters: { approve: b => new Promise(resolve => { release = () => resolve({ digest: b.digest }); }) } });
  const pending = f.session.dispatch(request());
  await assert.rejects(f.session.dispatch(request()), /replay/);
  await assert.rejects(f.session.dispatch(request('r2')), /call_budget/);
  await new Promise(resolve => setImmediate(resolve)); release(); await pending;
  assert.equal(f.effects(), 1);
});

test('revocation, expiry and rollback during approval block effects and clock failure latches', async () => {
  for (const action of [f => f.session.revoke(), f => f.time(1100), f => f.time(99)]) {
    let release;
    const f = fixture({ adapters: { approve: b => new Promise(resolve => { release = () => resolve({ digest: b.digest }); }) } });
    const pending = f.session.dispatch(request());
    await new Promise(resolve => setImmediate(resolve)); action(f); release();
    await assert.rejects(pending); assert.equal(f.effects(), 0);
  }
  const f = fixture(); f.time(99); await assert.rejects(f.session.dispatch(request()), /clock_failure/);
  f.time(101); await assert.rejects(f.session.dispatch(request('r2')), /inactive_session/);
});

test('audit failures before approval or immediately before handler fail closed', async () => {
  for (const failedEvent of ['reserved', 'dispatch']) {
    const f = fixture({ adapters: { audit: e => e.event !== failedEvent } });
    await assert.rejects(f.session.dispatch(request()), /audit_failure/); assert.equal(f.effects(), 0);
  }
  const f = fixture({ adapters: { audit: () => { throw Error('sensitive downstream failure'); } } });
  await assert.rejects(f.session.dispatch(request()), /^Error: audit_failure$/);
});

test('post-audit expiry/revocation checks run after each asynchronous boundary', async () => {
  let f;
  f = fixture({ adapters: { audit: async e => { if (e.event === 'dispatch') f.session.revoke(); return true; } } });
  await assert.rejects(f.session.dispatch(request()), /inactive_session/); assert.equal(f.effects(), 0);
});

test('unknown catalog, schema, policy version, handler and forged compiled objects deny', () => {
  const p = boundary(); p.tools.exec = p.tools.report;
  assert.throws(() => compilePolicy(p, boundary()), /outside_catalog/);
  for (const mutate of [p => { p.version = 2; }, p => { p.tools.report.args.kind = { type: 'regex', pattern: '.*' }; }, p => { p.extra = true; }]) {
    const p = boundary(); mutate(p); assert.throws(() => compilePolicy(p, boundary()));
  }
  assert.throws(() => createSession({ compiledPolicy: { policy: boundary() } }), /uncompiled_policy/);
  assert.throws(() => createSession({ compiledPolicy: compilePolicy(boundary(), boundary()), identity, handlers: {}, approve() {}, audit() {}, now: () => 1 }), /unknown_handler/);
});

test('closed narrowing checker distinguishes subset, widening and unsupported syntax', () => {
  const c = boundary(); c.maxCalls = 1; c.maxLifetimeMs = 500; c.tools.report.args.kind.values = ['summary'];
  c.tools.report.args.limit.max = 2; c.tools.report.endpointIds = [];
  assert.equal(checkPolicyNarrowing(c, boundary()), 'within_boundary');
  for (const mutate of [p => { p.maxCalls = 4; }, p => { p.tools.report.requiresApproval = false; }, p => { p.tools.report.endpointIds.push('other'); }, p => { p.tools.report.args.kind.values.push('other'); }, p => { delete p.tools.report.args.dry; }]) {
    const p = boundary(); mutate(p); assert.equal(checkPolicyNarrowing(p, boundary()), 'outside_boundary');
  }
  assert.equal(checkPolicyNarrowing({ version: 5 }, boundary()), 'unsupported_or_invalid');
});

test('trusted policy/handler capture, no-approval tool and failure replay semantics', async () => {
  const catalog = boundary(); catalog.tools.report.requiresApproval = false;
  const selected = structuredClone(catalog), compiled = compilePolicy(selected, catalog);
  selected.tools.report.args.limit.max = 100; catalog.maxCalls = 100;
  let called = 0;
  const handlers = { report: () => { called++; throw Error('synthetic unknown effect'); } };
  const s = createSession({ compiledPolicy: compiled, identity, handlers,
    approve: () => assert.fail('approval unnecessary'), audit: () => true, now: () => 1 });
  handlers.report = () => assert.fail('handler capture changed');
  const invalid = request(); invalid.args.limit = 50;
  await assert.rejects(s.dispatch(invalid), /invalid_arguments/);
  await assert.rejects(s.dispatch(request()), /synthetic unknown effect/);
  await assert.rejects(s.dispatch(request()), /replay/); assert.equal(called, 1);
});

test('clock exceptions/nonfinite time and approval exception deny without handler execution', async () => {
  for (const value of [NaN, Infinity, -1, 1.5]) {
    assert.throws(() => fixture({ adapters: { now: () => value } }), /clock_failure/);
  }
  let bad = false;
  const f = fixture({ adapters: { now: () => { if (bad) throw Error('clock stopped'); return 100; } } });
  bad = true; await assert.rejects(f.session.dispatch(request()), /clock_failure/); assert.equal(f.effects(), 0);
  const a = fixture({ adapters: { approve: () => { throw Error('private service failure'); } } });
  await assert.rejects(a.session.dispatch(request()), /^Error: approval_failed$/); assert.equal(a.effects(), 0);
});

const egress = () => ({ url: 'https://api.example.org/report', method: 'POST', endpoint: {
  id: 'reportApi', hostname: 'api.example.org', path: '/report', method: 'POST', credentialRef: 'reportCredential'
}, dnsAnswers: ['8.8.8.8', '1.1.1.1'] });
test('offline egress returns an immutable plan for exact public IPv4 destination', () => {
  const r = egress(), plan = checkEgress(r); assert.equal(plan.status, 'plan_only');
  assert.equal(plan.credentialRef, 'reportCredential'); assert.equal(plan.port, 443);
  assert.ok(Object.isFrozen(plan.checkedAddresses)); r.dnsAnswers[0] = '127.0.0.1';
  assert.equal(plan.checkedAddresses[0], '8.8.8.8');
});
test('all DNS answers must pass: private, metadata, reserved, ambiguous and IPv6 deny', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.100.100.200', '168.63.129.16', '0.0.0.0', '192.0.0.9', '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255', '::1', '::ffff:8.8.8.8', '8.8.8.08', '2130706433', 'unknown']) {
    const r = egress(); r.dnsAnswers.push(ip); assert.equal(checkEgress(r).status, 'denied', ip);
  }
});
test('URL ambiguity, redirects/query/encoding/userinfo/ports/host changes and malformed plans deny', () => {
  for (const url of ['http://api.example.org/report', 'https://api.example.org:443/report', 'https://api.example.org/report?q=1', 'https://api.example.org/report#x', 'https://user@api.example.org/report', 'https://api.example.org/%72eport', 'https://API.example.org/report', 'https://api.example.org./report', 'https://api.example.org/a/../report', 'https://api.example.org\\report', 'https://api.example.org//report', 'https://other.example.org/report']) {
    const r = egress(); r.url = url; assert.equal(checkEgress(r).status, 'denied', url);
  }
  const r = egress(); r.redirect = true; assert.equal(checkEgress(r).status, 'denied');
  const empty = egress(); empty.dnsAnswers = []; assert.equal(checkEgress(empty).status, 'denied');
  for (const hostname of ['127.1', '0x7f.0.0.1', '2130706433', '127.0.0.1', 'api.example.123']) {
    const r = egress(); r.endpoint.hostname = hostname; r.url = `https://${hostname}/report`;
    assert.equal(checkEgress(r).status, 'denied', hostname);
  }
});
