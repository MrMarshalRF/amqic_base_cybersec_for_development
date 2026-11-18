import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createAuditChain, serializeAuditRecord, verifyAuditTrail } from './audit.mjs';
import { exportEvidence, renderMarkdown, sha256, verifyEvidenceSignature } from './evidence.mjs';

const STARTED = '2026-01-01T00:00:00.000Z';
const FINISHED = '2026-01-01T00:01:00.000Z';
const scenarios = [
  { id: 'staged-authentication', category: 'local', stages: ['baseline'], test_checks: ['node-tests'] },
  { id: 'vpn-example', category: 'source-reviewed', stages: ['baseline'], test_checks: ['coverage-membership'] },
  { id: 'external-cloudflare', category: 'external', stages: [], test_checks: [] },
  { id: 'redis-limiter', category: 'local', stages: ['baseline', 'live-consumers'], test_checks: ['node-tests', 'live-consumers'] },
];
const runner = readFileSync(new URL('../../lab/all-local.mjs', import.meta.url));

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'amqic-evidence-'));
  const root = join(dir, 'repo');
  const subdirs = [root, join(root, 'lab'), join(root, 'verification')];
  const written = new Set();
  for (const name of subdirs) mkdirSync(name);
  function write(name, value) {
    writeFileSync(name, Buffer.isBuffer(value) ? value : JSON.stringify(value));
    written.add(name);
  }
  t.after(() => {
    for (const file of written) unlinkSync(file);
    for (const subdir of subdirs.reverse()) rmdirSync(subdir);
    rmdirSync(dir);
  });
  const names = ['lab/all-local.mjs', 'lab/scenarios.json', 'verification/coverage.json'];
  write(join(root, names[0]), runner);
  write(join(root, names[1]), { schema_version: 1, scenarios });
  write(join(root, names[2]), { schema_version: 1, files: names.map(path => ({ path })) });
  const source = names.map(path => ({ path, sha256: sha256(readFileSync(join(root, path))) }));
  const registry = Buffer.from(source.map(row => row.sha256 + '  ' + row.path).join('\n') + '\n');
  write(join(root, 'SHA256SUMS'), registry);
  const digest = sha256(JSON.stringify(source));
  const basis = {
    schema_version: 1,
    started_at: STARTED,
    finished_at: FINISHED,
    source_files: source,
    source_digest: digest,
  };
  const stability = {
    id: 'source-stability', status: 'passed', final_source_digest: digest, full_payload_unchanged: true,
  };
  const path = join(dir, 'ci.json');
  return { root, path, write, registry, basis, stability };
}

test('baseline projection verifies bytes, retains gaps and strips arbitrary diagnostics', t => {
  const { root, path, write, registry, basis, stability } = fixture(t);
  const report = {
    ...basis, status: 'incomplete', complete: false, integrity_registry_sha256: sha256(registry),
    checks: [
      { id: 'node-tests', status: 'passed', skipped_subtests: 2, reason: 'private customer details' },
      { id: 'coverage-membership', status: 'passed' },
      { id: 'sha256-registry', status: 'passed' },
      { id: 'live-consumers', status: 'not_run', reason: 'private path /home/operator' },
      stability,
    ],
  };
  write(path, report);
  const bundle = exportEvidence(root, path);
  assert.equal(bundle.inputReport.sha256, sha256(readFileSync(path)));
  assert.deepEqual(bundle.scenarios.map(row => row.status), ['passed', 'source_reviewed', 'external_not_run', 'not_run']);
  assert.equal(bundle.checks[0].skippedSubtests, 2);
  assert.match(renderMarkdown(bundle), /external_not_run/);
  assert.doesNotMatch(JSON.stringify(bundle) + renderMarkdown(bundle), /private|\/home\/operator/);
  write(path, { ...report, source_digest: '0'.repeat(64) });
  assert.throws(() => exportEvidence(root, path), /source inventory/);
  write(path, report);
  write(join(root, 'lab/scenarios.json'), {});
  assert.throws(() => exportEvidence(root, path), /file hash/);
});

test('all-local export checks linked child bytes and refuses a passing parent over a failed child', t => {
  const { root, path, write, basis, stability } = fixture(t);
  const baselineChild = { status: 'failed', schema_version: 1 };
  const child = Buffer.from(JSON.stringify(baselineChild));
  write(path + '.baseline.json', child);
  const report = {
    ...basis, mode: 'all-local', status: 'failed', local_accepted: false, production_verified: false, exit_code: 1,
    checks: [
      { id: 'baseline', status: 'passed', report_sha256: sha256(child), report_file: '/a/private/remote/path' },
      { id: 'live-consumers', status: 'failed', report_sha256: null },
      stability,
    ],
    scenarios: scenarios.map(item => ({ ...item, status: ({
      'staged-authentication': 'passed', 'vpn-example': 'source_reviewed', 'external-cloudflare': 'external_not_run',
      'redis-limiter': 'failed',
    })[item.id] })),
  };
  write(path, report);
  assert.throws(() => exportEvidence(root, path), /Child report does not satisfy/);
  write(path + '.baseline.json', {});
  assert.throws(() => exportEvidence(root, path), /Child report hash mismatch/);
});

test('detached signatures bind exact bytes and the independently supplied Ed25519 key', () => {
  const bytes = Buffer.from('{"schema":"amqic.evidence.v1"}\n');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const signature = sign(null, bytes, privateKey);
  assert.equal(verifyEvidenceSignature(bytes, Buffer.from(pem), signature), true);
  assert.equal(verifyEvidenceSignature(Buffer.concat([bytes, Buffer.from('\n')]), Buffer.from(pem), signature), false);
  assert.equal(verifyEvidenceSignature(bytes, Buffer.from(other), signature), false);
  assert.equal(verifyEvidenceSignature(bytes, Buffer.from(pem), signature.subarray(1)), false);
});

function event(action = 'login', outcome = 'allow') {
  return {
    at: STARTED,
    action,
    outcome,
    correlationId: 'a'.repeat(32),
    actorRef: 'b'.repeat(32),
    tenantRef: 'c'.repeat(32),
  };
}

test('audit checkpoint detects tampering, truncation and order changes across resume', () => {
  const initial = createAuditChain();
  const first = initial.append(event());
  const start = initial.checkpoint();
  const resumed = createAuditChain(start);
  const second = resumed.append(event('sensitive-read', 'deny'));
  const end = resumed.checkpoint();
  assert.equal(verifyAuditTrail([first, second], end), true);
  assert.equal(verifyAuditTrail([second], end, start), true);
  assert.equal(verifyAuditTrail([first], end), false);
  assert.equal(verifyAuditTrail([second, first], end), false);
  assert.equal(verifyAuditTrail([first, { ...second, event: { ...second.event, outcome: 'allow' } }], end), false);
  assert.equal(JSON.parse(serializeAuditRecord(second)).event.correlationId, first.event.correlationId);
  assert.throws(() => serializeAuditRecord({ ...second, hash: '0'.repeat(64) }), /Invalid audit entry/);
  assert.throws(() => resumed.append({ ...event(), payload: 'password' }), /Invalid structured audit event/);
  assert.throws(() => resumed.append({ ...event(), at: '2026-01-01' }), /Invalid structured audit event/);
});
