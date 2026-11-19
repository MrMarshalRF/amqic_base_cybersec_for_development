import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { assessNginxRollout, rolloutInputEtag, classifyOssRelease } from './nginx-rollout.mjs';

const now = Date.parse('2026-11-19T12:00:00.000Z');
const digest = char => 'sha256:' + char.repeat(64);
const cves = ['CVE-2026-123007', 'CVE-2026-123633'];
const policy = {
  schema: 'amqic-nginx-policy/v1', changeId: 'demo-change', changeStartedAt: '2026-11-19T11:00:00.000Z',
  requiredAdvisories: cves,
  expected: [{ workload: 'edge-replica-1', previousMaster: 'master-old', previousWorkers: ['worker-old'], artifactDigest: digest('a') }],
  vendorFindings: cves.map(cve => ({ vendor: 'nginx', product: 'oss', build: '1.30.7', architecture: 'amd64',
    cve, status: 'fixed', reference: 'https://nginx.org/en/security_advisories.html' })),
};
const observation = {
  workload: 'edge-replica-1', master: 'master-new', startedAt: '2026-11-19T11:10:00.000Z',
  workers: [{ instance: 'worker-new', startedAt: '2026-11-19T11:10:01.000Z' }], previousProcessesAbsent: true,
  vendor: 'nginx', product: 'oss', build: '1.30.7', architecture: 'amd64',
  artifactDigest: digest('a'), evidenceDigest: digest('b'),
  protocols: { http2: false, http3: false, quicUdp: false, alpnHttp1: true },
};
const inventory = { schema: 'amqic-nginx-inventory/v1', changeId: policy.changeId,
  observedAt: '2026-11-19T11:30:00.000Z', observations: [observation] };
const evaluate = (p = policy, i = inventory) => assessNginxRollout(p, i, rolloutInputEtag(p, i), now);

test('accept exact patched artifact and replaced master and workers under protocol policy', () => {
  const result = evaluate();
  assert.equal(result.checkPassed, true);
  assert.equal(result.results[0].outcome, 'accepted');
  const { etag, ...withoutTag } = result;
  assert.equal(rolloutInputEtag(policy, inventory), rolloutInputEtag(structuredClone(policy), structuredClone(inventory)));
  assert.match(etag, /^sha256:[0-9a-f]{64}$/);
  function canonical(value) {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (value && typeof value === 'object') return '{' + Object.keys(value).sort()
      .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
    return JSON.stringify(value);
  }
  assert.equal(etag, 'sha256:' + createHash('sha256').update(canonical(withoutTag)).digest('hex'));
});

test('unknown vendor and partial advisory findings deny even with disabled HTTP2', () => {
  const p = structuredClone(policy);
  p.vendorFindings.pop();
  assert.equal(evaluate(p).results[0].outcome, 'vendor-status-unknown');
  p.vendorFindings[0].status = 'affected';
  p.vendorFindings.push({ ...p.vendorFindings[0], cve: cves[1], status: 'fixed' });
  assert.equal(evaluate(p).results[0].outcome, 'affected');
  const i = structuredClone(inventory);
  i.observations[0].vendor = 'vendor-backport';
  assert.equal(evaluate(policy, i).results[0].outcome, 'vendor-status-unknown');
});

test('old or unproven workers and wrong artifact deny', () => {
  for (const update of [
    { master: 'master-old' }, { previousProcessesAbsent: false },
    { workers: [{ instance: 'worker-old', startedAt: observation.startedAt }] },
    { workers: [{ instance: 'worker-new', startedAt: '2026-11-19T10:00:00.000Z' }] },
  ]) {
    assert.equal(evaluate(policy, { ...inventory, observations: [{ ...observation, ...update }] }).results[0].outcome, 'process-replacement-unverified');
  }
  assert.equal(evaluate(policy, { ...inventory, observations: [{ ...observation, artifactDigest: digest('c') }] }).results[0].outcome, 'artifact-mismatch');
});

test('protocol enablement and missing per-replica observations fail closed', () => {
  for (const field of ['http2', 'http3', 'quicUdp', 'alpnHttp1']) {
    const i = structuredClone(inventory);
    i.observations[0].protocols[field] = !i.observations[0].protocols[field];
    assert.equal(evaluate(policy, i).results[0].outcome, 'protocol-policy-mismatch');
  }
  const p = structuredClone(policy);
  p.expected.push({ ...p.expected[0], workload: 'edge-replica-2', previousMaster: 'old-2', previousWorkers: ['old-worker-2'] });
  assert.equal(evaluate(p).results[1].outcome, 'missing-observation');
});

test('stale, mixed, duplicate and future evidence or ETags reject', () => {
  const stale = structuredClone(inventory);
  stale.observedAt = '2026-11-17T11:30:00.000Z';
  assert.throws(() => evaluate(policy, stale));
  const future = structuredClone(inventory);
  future.observedAt = '2026-11-20T11:30:00.000Z';
  assert.throws(() => evaluate(policy, future));
  const changed = structuredClone(inventory);
  changed.observations[0].artifactDigest = digest('d');
  assert.throws(() => assessNginxRollout(policy, changed, rolloutInputEtag(policy, inventory), now));
  const dup = structuredClone(inventory);
  dup.observations.push(dup.observations[0]);
  assert.throws(() => evaluate(policy, dup));
  const missingCve = structuredClone(policy);
  missingCve.requiredAdvisories = [cves[0]];
  assert.throws(() => evaluate(missingCve));
  const malformedUrl = structuredClone(policy);
  malformedUrl.vendorFindings[0].reference = 'https://[';
  assert.throws(() => evaluate(malformedUrl));
});

test('OSS release helper keeps unsupported families and distributor versions unknown', () => {
  for (const v of ['1.30.7', '1.30.8', '1.31.9']) assert.equal(classifyOssRelease(v), 'advisory-fixed-line');
  for (const v of ['1.30.6', '1.31.8']) assert.equal(classifyOssRelease(v), 'affected-line');
  for (const v of ['1.18.0-6ubuntu14.23', '1.32.0', '1.2.3', '1.30.7+vendor']) assert.equal(classifyOssRelease(v), 'unknown');
});

test('CLI rejects stale expected tag with empty stdout and no source effect', () => {
  const root = mkdtempSync(join(tmpdir(), 'nginx-rollout-'));
  try {
    const p = join(root, 'policy.json');
    const i = join(root, 'inventory.json');
    writeFileSync(p, JSON.stringify(policy));
    writeFileSync(i, JSON.stringify(inventory));
    const cli = fileURLToPath(new URL('./nginx-rollout.mjs', import.meta.url));
    const planned = spawnSync(process.execPath, [cli, '--plan', p, i], { encoding: 'utf8' });
    assert.equal(planned.status, 0);
    assert.equal(JSON.parse(planned.stdout).etag, rolloutInputEtag(policy, inventory));
    const rejected = spawnSync(process.execPath, [cli, '--verify', p, i, digest('e')], { encoding: 'utf8' });
    assert.equal(rejected.status, 2);
    assert.equal(rejected.stdout, '');
  } finally { rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); }
});

test('explicit vendor backport findings are accepted and bounded input rejects oversize', () => {
  const p = structuredClone(policy);
  const i = structuredClone(inventory);
  for (const f of p.vendorFindings) {
    f.vendor = 'demo-distributor';
    f.build = '1.24.0-demo+security1';
    f.reference = 'https://example.invalid/vendor-errata';
  }
  Object.assign(i.observations[0], { vendor: 'demo-distributor', build: '1.24.0-demo+security1' });
  assert.equal(evaluate(p, i).checkPassed, true);
  const folder = mkdtempSync(join(tmpdir(), 'nginx-bounds-'));
  try {
    const big = join(folder, 'oversize.json');
    writeFileSync(big, Buffer.alloc(4 * 1024 * 1024 + 1, 32));
    const cli = fileURLToPath(new URL('./nginx-rollout.mjs', import.meta.url));
    const result = spawnSync(process.execPath, [cli, '--plan', big, big], { encoding: 'utf8' });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
  } finally { rmSync(folder, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); }
});

test('detection profile names the Nginx process parent and bounded direct shell signal', () => {
  const text = readFileSync(new URL('./profiles/nginx-shell.falco.yaml', import.meta.url), 'utf8');
  assert.ok(text.includes('proc.pname = nginx') && text.includes('container.id != host'));
  assert.ok(text.includes('evt.rawres >= 0') && text.includes('source: syscall'));
});
