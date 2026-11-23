import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { RULE_IDS, inputETag, reviewConfiguration } from './config-review.mjs';

const now = 1000;
const safe = () => ({ approvals: 'enabled', shell: 'scoped', hooks: [], mcp: [], artifacts: [] });
const policy = () => ({ owner: 'owner1', scope: 'scope1', review: 'review1', validUntil: 3000,
  ruleActions: Object.fromEntries(RULE_IDS.map(r => [r, 'block'])), exceptions: [] });
const file = (content, kind = 'configuration') => ({ path: 'config/snapshot.json', kind,
  content: typeof content === 'string' ? content : JSON.stringify(content) });
const snapshot = f => ({ profile: 'normalized-agent-config/1', files: [f] });
function run(s, p = policy(), expected) {
  const sj = JSON.stringify(s), pj = JSON.stringify(p);
  return reviewConfiguration(sj, pj, now, expected ?? inputETag(sj, pj, now));
}
const mcp = changes => ({ launcher: 'package', pin: '1.2.3', tokenStorage: 'reference', transport: 'https', ...changes });
const config = change => file({ ...safe(), ...change });
// Synthetic descriptive fixture records: never executable commands or tool invocations.
const fixtures = [
  ['approval-disabled', config({ approvals: 'disabled' }), config({ approvals: 'enabled' })],
  ['shell-unrestricted', config({ shell: 'unrestricted' }), config({ shell: 'scoped' })],
  ['remote-execution', config({ hooks: [{ source: 'remote', execute: true }] }), config({ hooks: [{ source: 'remote', execute: false }] })],
  ['instruction-authority', file('Fixture describes an override of policy.', 'instructions'), file('Fixture describes a reviewed policy.', 'instructions')],
  ['instruction-unicode', file('Fixture\u202e marker', 'instructions'), file('Fixture ordinary marker', 'instructions')],
  ['credential-access', file('Fixture describes read access to credential stores.', 'instructions'), file('Fixture describes a reference to a broker.', 'instructions')],
  ['mcp-unpinned', config({ mcp: [mcp({ pin: 'latest' })] }), config({ mcp: [mcp({ pin: '1.2.3' })] })],
  ['mcp-plaintext', config({ mcp: [mcp({ tokenStorage: 'plaintext' })] }), config({ mcp: [mcp({ tokenStorage: 'reference' })] })],
  ['mcp-http', config({ mcp: [mcp({ transport: 'http' })] }), config({ mcp: [mcp({ transport: 'https' })] })],
  ['artifact-agent-state', config({ artifacts: [{ included: true, class: 'agent-home' }] }), config({ artifacts: [{ included: false, class: 'agent-home' }] })],
];
for (const [ruleId, risky, near] of fixtures) {
  test(`${ruleId}: exact risky, scoped, documentation and exception findings`, () => {
    const finding = { file: risky.path, ruleId, severity: ruleId === 'instruction-unicode' ? 'medium' : 'high', checkState: 'blocked' };
    assert.deepEqual(run(snapshot(risky)).findings, [finding]);
    assert.equal(run(snapshot(risky)).status, 'blocked');
    assert.deepEqual(run(snapshot(near)).findings, []);
    assert.deepEqual(run(snapshot({ ...risky, kind: 'documentation' })).findings, []);
    const p = policy();
    p.exceptions.push({ ruleId, fileSha256: createHash('sha256').update(risky.content).digest('hex'),
      owner: p.owner, scope: p.scope, review: 'exception1', validUntil: 2000 });
    const accepted = run(snapshot(risky), p);
    assert.equal(accepted.status, 'exceptions-present');
    assert.deepEqual(accepted.findings, [{ ...finding, checkState: 'accepted-exception' }]);
    const changed = { ...risky, content: risky.kind === 'configuration' ? `${risky.content} ` : `${risky.content} changed` };
    assert.deepEqual(run(snapshot(changed), p).findings, [finding]);
    p.exceptions[0].validUntil = now;
    assert.equal(run(snapshot(risky), p).status, 'incomplete');
  });
}
test('all classes, deterministic order, review-only policy and exact result tag', () => {
  const s = { profile: 'normalized-agent-config/1', files: fixtures.map(([, f], i) => ({ ...f, path: `fixture${i}.json` })).reverse() };
  const result = run(s);
  assert.deepEqual(result, run(s));
  assert.deepEqual(result.findings.map(f => f.ruleId), RULE_IDS);
  const { resultETag, ...body } = result;
  assert.equal(resultETag, `"sha256-${createHash('sha256').update(JSON.stringify(body)).digest('hex')}"`);
  const p = policy(); p.ruleActions['approval-disabled'] = 'review';
  assert.equal(run(snapshot(fixtures[0][1]), p).status, 'review-required');
});
test('additional risky and near-match forms', () => {
  for (const pin of [null, '*', '^1.2.3', '1.2', '1.2.3+floating', 'v1.2.3', '1.2.3\n'])
    assert.deepEqual(run(snapshot(config({ mcp: [mcp({ pin })] }))).findings.map(f => f.ruleId), ['mcp-unpinned']);
  for (const launcher of ['image', 'package']) {
    const pin = launcher === 'image' ? `sha256:${'a'.repeat(64)}` : '1.2.3-beta.1';
    assert.deepEqual(run(snapshot(config({ mcp: [mcp({ launcher, pin })] }))).findings, []);
  }
  for (const cls of ['transcript', 'worktree'])
    assert.deepEqual(run(snapshot(config({ artifacts: [{ included: true, class: cls }] }))).findings.map(f => f.ruleId), ['artifact-agent-state']);
  for (const content of ['Fixture describes conceal actions from user.', 'Fixture describes skip confirmation.'])
    assert.deepEqual(run(snapshot(file(content, 'instructions'))).findings.map(f => f.ruleId), ['instruction-authority']);
  assert.deepEqual(run(snapshot(file('Fixture describes download then execute.', 'instructions'))).findings.map(f => f.ruleId), ['remote-execution']);
  for (const target of ['SSH material', 'cloud credential files', 'password stores'])
    assert.deepEqual(run(snapshot(file(`Fixture describes read access to ${target}.`, 'instructions'))).findings.map(f => f.ruleId), ['credential-access']);
});
test('malformed, unsupported, bounds, self-waivers and stale snapshots fail closed', () => {
  const mutations = [
    s => { s.profile = 'vendor-format'; }, s => { s.exceptions = []; },
    s => { s.files[0].path = '../private'; }, s => { s.files[0].path = 'https://private.invalid'; },
    s => { s.files[0].path = 'config.json\n'; },
    s => { s.files.push({ ...s.files[0] }); }, s => { s.files[0].kind = 'unknown'; },
    s => { s.files[0].content = '{'; }, s => { s.files[0].content = JSON.stringify({ ...safe(), exception: true }); },
    s => { s.files[0].content = 'x'.repeat(65537); }, s => { s.files = []; },
    s => { s.files = Array.from({ length: 101 }, (_, i) => ({ ...s.files[0], path: `f${i}` })); },
  ];
  for (const mutate of mutations) { const s = snapshot(config({})); mutate(s); assert.equal(run(s).status, 'incomplete'); }
  for (const mutate of [p => { delete p.owner; }, p => { p.owner = 'owner\n'; }, p => { p.validUntil = now; }, p => { p.ruleActions['mcp-http'] = 'ignore'; },
    p => { p.exceptions = [{ ruleId: 'mcp-http', fileSha256: 'a'.repeat(64), owner: 'other', scope: p.scope, review: 'r', validUntil: 2000 }]; }]) {
    const p = policy(); mutate(p); assert.equal(run(snapshot(config({})), p).status, 'incomplete');
  }
  assert.equal(run(snapshot(config({})), policy(), 'wrong').checkState, 'stale-input');
  assert.equal(reviewConfiguration('{', '{}', now, 'wrong').status, 'incomplete');
  assert.equal(reviewConfiguration('x'.repeat(1048577), '{}', now, 'wrong').status, 'incomplete');
  assert.equal(reviewConfiguration('{}', '{}', -1, 'wrong').status, 'incomplete');
  assert.notEqual(inputETag('{}', '{}', now), inputETag('{} ', '{}', now));
  assert.notEqual(inputETag('{}', '{}', now), inputETag('{}', '{} ', now));
  assert.notEqual(inputETag('{}', '{}', now), inputETag('{}', '{}', now + 1));
});
test('duplicate JSON keys reject at every serialized boundary, including escaped aliases', () => {
  const sj = JSON.stringify(snapshot(config({}))), pj = JSON.stringify(policy());
  for (const badSnapshot of [sj.replace('"files":', '"files":[],"files":'), sj.replace('"profile":', '"pro\\u0066ile":"wrong","profile":')])
    assert.equal(reviewConfiguration(badSnapshot, pj, now, inputETag(badSnapshot, pj, now)).status, 'incomplete');
  const badPolicy = pj.replace('"owner":', '"owner":"other","owner":');
  assert.equal(reviewConfiguration(sj, badPolicy, now, inputETag(sj, badPolicy, now)).status, 'incomplete');
  const f = config({}); f.content = f.content.replace('"approvals":', '"approvals":"disabled","approvals":');
  assert.equal(run(snapshot(f)).status, 'incomplete');
});
test('output and exceptions contain no input text or raw parser errors', () => {
  const marker = 'SYNTHETIC_PRIVATE_MARKER';
  for (const f of [file(marker, 'instructions'), file(`{"${marker}":true}`), file(`{${marker}`)]) {
    const result = run(snapshot(f));
    assert.equal(JSON.stringify(result).includes(marker), false);
    assert.deepEqual(Object.keys(result).sort(), ['checkState', 'findings', 'inputETag', 'resultETag', 'schema', 'status']);
  }
});
