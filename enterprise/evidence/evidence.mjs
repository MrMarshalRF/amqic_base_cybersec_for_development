import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { acceptStage } from '../../lab/all-local.mjs';

const MAX_FILE = 32 * 1024 * 1024;
const HEX = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9-]{0,79}$/;
const STATUSES = new Set(['passed', 'failed', 'not_run', 'external_not_run', 'prerequisite_missing', 'source_reviewed']);
const EXCLUDED = new Set(['SHA256SUMS', 'SHA256SUMS.sig', 'verification/v1.2.0-report.json']);
const CHECKS = new Set([
  'registry', 'coverage-membership', 'sha256-registry', 'source-stability', 'node-runtime',
  'python-runtime', 'node-syntax', 'node-tests', 'core-demo', 'operations', 'production',
  'versions', 'quarantine', 'nginx-harness', 'firewall-render', 'terminal',
  'compose-runtime', 'compose', 'baseline', 'live-consumers', 'nginx-runtime',
  'infra-runtime', 'cache-runtime', 'upload-isolation-runtime', 'database-runtime',
  'terminal-coverage',
]);
const CHILD_SUFFIX = new Map([
  ['baseline', '.baseline.json'], ['live-consumers', '.integration.json'],
  ['infra-runtime', '.infra.json'], ['cache-runtime', '.cache.json'],
  ['upload-isolation-runtime', '.upload.json'], ['database-runtime', '.database.json'],
]);
const MAPPING = [
  { scenario: 'staged-authentication', nist: ['IA-2'], topic: 'authentication' },
  { scenario: 'database-row-and-column-isolation', nist: ['AC-3', 'AC-6'], topic: 'access enforcement' },
  { scenario: 'billing-offer-eligibility', nist: ['AC-3', 'SI-10'], topic: 'business authorization' },
  { scenario: 'pow-replay', nist: ['SC-23'], topic: 'session authenticity' },
  { scenario: 'release-provenance', nist: ['SI-7'], topic: 'integrity checking' },
  { scenario: 'enterprise-policy', nist: ['AC-3', 'SC-5'], topic: 'tenant policy and admission budgets' },
  { scenario: 'enterprise-evidence', nist: ['AU-9', 'AU-12'], topic: 'audit record generation and integrity' },
  { scenario: 'enterprise-supply', nist: ['SI-7'], topic: 'release artifact integrity' },
  { scenario: 'enterprise-secrets', nist: ['IA-5', 'SC-12'], topic: 'credential and key management' },
  { scenario: 'enterprise-runtime', nist: ['CM-6', 'SI-2'], topic: 'hardening and flaw remediation' },
];

export const sha256 = data => createHash('sha256').update(data).digest('hex');

function requireValid(ok, message) {
  if (!ok) throw new Error(message);
}

export function readBoundedFile(path, limit = MAX_FILE) {
  const initial = lstatSync(path);
  requireValid(initial.isFile() && !initial.isSymbolicLink(), 'Expected regular evidence input');
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd);
    requireValid(opened.isFile() && opened.ino === initial.ino && opened.dev === initial.dev &&
      opened.size <= limit, 'Input exceeds bound or changed');
    const bytes = Buffer.alloc(opened.size + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (count === 0) break;
      used += count;
    }
    const after = fstatSync(fd);
    requireValid(used === opened.size && after.mtimeMs === opened.mtimeMs && after.size === opened.size,
      'Input changed while reading');
    return bytes.subarray(0, used);
  } finally {
    closeSync(fd);
  }
}

function publicFile(root, name) {
  const parts = name.split('/');
  requireValid(parts.length <= 32 && parts.every(part =>
    /^[a-zA-Z0-9_.-]{1,160}$/.test(part) && part !== '.' && part !== '..' && !part.endsWith('.')),
  'Invalid public inventory path');
  let path = root;
  for (const part of parts.slice(0, -1)) {
    path = join(path, part);
    const stat = lstatSync(path);
    requireValid(stat.isDirectory() && !stat.isSymbolicLink(), 'Invalid inventory directory');
  }
  return readBoundedFile(join(path, parts.at(-1)));
}

function snapshot(root) {
  const registry = publicFile(root, 'SHA256SUMS');
  const names = new Map();
  for (const line of registry.toString('utf8').trimEnd().split(/\r?\n/)) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    requireValid(match && !names.has(match[2]) && !['SHA256SUMS', 'SHA256SUMS.sig'].includes(match[2]),
      'Invalid checksum registry');
    names.set(match[2], match[1]);
  }
  requireValid(names.size > 0 && names.size <= 4096, 'Invalid inventory size');
  const used = new Map();
  for (const path of [...names.keys()].sort()) {
    const bytes = publicFile(root, path);
    const hash = sha256(bytes);
    requireValid(hash === names.get(path), 'Current file hash differs from registry');
    if (path === 'lab/scenarios.json' || path === 'verification/coverage.json') used.set(path, bytes);
  }
  const coverage = JSON.parse(used.get('verification/coverage.json'));
  requireValid(coverage.schema_version === 1 && Array.isArray(coverage.files) &&
    JSON.stringify(coverage.files.map(row => row.path).sort()) === JSON.stringify([...names.keys()].sort()),
  'Coverage inventory mismatch');
  const catalog = JSON.parse(used.get('lab/scenarios.json'));
  requireValid(catalog.schema_version === 1 && Array.isArray(catalog.scenarios) && catalog.scenarios.length <= 256,
    'Invalid scenario catalog');
  const scenarios = new Map();
  for (const item of catalog.scenarios) {
    requireValid(ID.test(item.id) && !scenarios.has(item.id) &&
      ['local', 'source-reviewed', 'external'].includes(item.category) &&
      Array.isArray(item.stages) && item.stages.every(stage => CHECKS.has(stage)) &&
      Array.isArray(item.test_checks) && item.test_checks.every(check => typeof check === 'string' && check.length < 100) &&
      (item.category === 'external' || (item.stages.length && item.test_checks.length)),
    'Invalid catalog scenario');
    scenarios.set(item.id, item);
  }
  const files = [...names.keys()].sort().filter(path => !EXCLUDED.has(path))
    .map(path => ({ path, sha256: names.get(path) }));
  return { files, sourceDigest: sha256(JSON.stringify(files)), registryDigest: sha256(registry), scenarios };
}

function utc(value) {
  requireValid(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value, 'Invalid report timestamp');
  return value;
}

function projectChecks(input) {
  requireValid(Array.isArray(input) && input.length > 0 && input.length <= 128, 'Invalid check list');
  const output = new Map();
  for (const item of input) {
    const id = item.id;
    const known = CHECKS.has(id) || (typeof id === 'string' && /^prepare-(clamav|redis|nginx|node-tool-base|python-tool-base|upload-python|postgres|infra-tools)$/.test(id));
    requireValid(known && STATUSES.has(item.status) && !output.has(id), 'Unexpected, invalid or duplicate check');
    const projected = { id, status: item.status };
    if (item.output_sha256 !== undefined) {
      requireValid(typeof item.output_sha256 === 'string' && HEX.test(item.output_sha256), 'Invalid check digest');
      projected.outputSha256 = item.output_sha256;
    }
    if (item.skipped_subtests !== undefined) {
      requireValid(Number.isSafeInteger(item.skipped_subtests) && item.skipped_subtests >= 0 &&
        item.skipped_subtests <= 100000, 'Invalid skipped count');
      projected.skippedSubtests = item.skipped_subtests;
    }
    output.set(id, projected);
  }
  return output;
}

function projectRun(report, current, allLocal) {
  requireValid(report.schema_version === 1 &&
    report.source_digest === current.sourceDigest &&
    Array.isArray(report.source_files) && report.source_files.length === current.files.length &&
    report.source_files.every((entry, i) => entry.path === current.files[i].path &&
      entry.sha256 === current.files[i].sha256), 'Report does not match current source inventory');
  const startedAt = utc(report.started_at);
  const finishedAt = utc(report.finished_at);
  requireValid(startedAt <= finishedAt, 'Report interval reversed');
  const checks = projectChecks(report.checks);
  const stable = checks.get('source-stability')?.status === 'passed';
  if (stable) {
    const stability = report.checks.find(item => item.id === 'source-stability');
    requireValid(stability.final_source_digest === current.sourceDigest &&
      stability.full_payload_unchanged === true, 'Invalid source stability observation');
  }
  const failed = [...checks.values()].some(item => item.status === 'failed');
  if (allLocal) {
    const incomplete = [...checks.values()].some(item => item.status === 'prerequisite_missing');
    const expected = failed ? 'failed' : incomplete ? 'prerequisite_missing' : 'local_accepted';
    requireValid(report.status === expected && report.local_accepted === (expected === 'local_accepted') &&
      report.production_verified === false && report.exit_code === (failed ? 1 : incomplete ? 2 : 0) &&
      (expected !== 'local_accepted' || (stable && ['baseline', 'live-consumers', 'nginx-runtime', 'infra-runtime',
        'cache-runtime', 'upload-isolation-runtime', 'database-runtime', 'terminal-coverage'].every(
        id => checks.get(id)?.status === 'passed'))), 'Inconsistent all-local status');
  } else {
    const expected = failed ? 'failed' : [...checks.values()].some(item => item.status === 'not_run') ? 'incomplete' : 'passed';
    requireValid(report.status === expected && report.complete === (expected === 'passed') &&
      report.integrity_registry_sha256 === current.registryDigest &&
      (failed || (stable && checks.get('sha256-registry')?.status === 'passed' &&
        checks.get('node-tests')?.status === 'passed')), 'Inconsistent baseline status or registry');
  }
  return { startedAt, finishedAt, checks, stable };
}

function scenarioRows(report, current, allLocal, checks, stable) {
  const reported = new Map();
  if (allLocal) {
    requireValid(Array.isArray(report.scenarios) && report.scenarios.length === current.scenarios.size,
      'Unexpected scenario membership');
    for (const row of report.scenarios) {
      const expected = current.scenarios.get(row.id);
      requireValid(expected && !reported.has(row.id) && row.category === expected.category &&
        JSON.stringify(row.stages) === JSON.stringify(expected.stages), 'Unexpected scenario metadata');
      reported.set(row.id, row.status);
    }
  }
  return [...current.scenarios.values()].map(item => {
    let status = 'not_run';
    if (item.category === 'external') status = 'external_not_run';
    else if (allLocal) {
      const statusList = item.stages.map(stage => checks.get(stage)?.status);
      if (report.prerequisites?.some(entry => entry.status === 'missing')) status = 'prerequisite_missing';
      else if (stable && statusList.every(state => state === 'passed')) {
        status = item.category === 'source-reviewed' ? 'source_reviewed' : 'passed';
      } else status = 'failed';
    } else if (item.stages.length === 1 && item.stages[0] === 'baseline') {
      const states = item.test_checks.map(id => checks.get(id)?.status);
      if (states.includes('failed')) status = 'failed';
      else if (stable && states.every(state => state === 'passed')) {
        status = item.category === 'source-reviewed' ? 'source_reviewed' : 'passed';
      }
    }
    requireValid(!allLocal || reported.get(item.id) === status, 'Unexpected scenario outcome');
    return { id: item.id, category: item.category, status };
  });
}

export function exportEvidence(repository, reportFile) {
  const root = realpathSync(repository);
  const reportPath = resolve(reportFile);
  const raw = readBoundedFile(reportPath);
  const report = JSON.parse(raw);
  const allLocal = report.mode === 'all-local';
  requireValid(allLocal || report.mode === undefined, 'Unsupported report mode');
  const current = snapshot(root);
  const { startedAt, finishedAt, checks, stable } = projectRun(report, current, allLocal);
  const artifacts = [];
  let baselineChecks;
  if (allLocal) {
    const importedRunner = readBoundedFile(fileURLToPath(new URL('../../lab/all-local.mjs', import.meta.url)));
    requireValid(current.files.some(entry => entry.path === 'lab/all-local.mjs' &&
      entry.sha256 === sha256(importedRunner)), 'Current runner differs from exporter validation rules');
    for (const check of report.checks) {
      if (check.report_sha256 == null) {
        requireValid(!(CHILD_SUFFIX.has(check.id) && check.status === 'passed'), 'Missing expected child digest');
        continue;
      }
      const suffix = CHILD_SUFFIX.get(check.id);
      requireValid(suffix && typeof check.report_sha256 === 'string' && HEX.test(check.report_sha256),
        'Unexpected child digest');
      // Read conventional siblings; input report_file strings may be remote runner paths.
      const bytes = readBoundedFile(reportPath + suffix);
      requireValid(sha256(bytes) === check.report_sha256, 'Child report hash mismatch');
      const child = JSON.parse(bytes);
      if (check.status === 'passed') {
        requireValid(acceptStage(check.id, child), 'Child report does not satisfy stage acceptance rules');
      }
      artifacts.push({ stage: check.id, sha256: check.report_sha256, accepted: check.status === 'passed' });
      if (check.id === 'baseline') {
        baselineChecks = [...projectRun(child, current, false).checks.values()];
      }
    }
  }
  const scenarios = scenarioRows(report, current, allLocal, checks, stable);
  const statusByScenario = new Map(scenarios.map(item => [item.id, item.status]));
  return {
    schema: 'amqic.evidence.v1',
    mode: allLocal ? 'all-local' : 'baseline',
    scope: 'synthetic-lab',
    reportStatus: report.status,
    startedAt,
    finishedAt,
    exportedAt: new Date().toISOString(),
    source: { sha256: current.sourceDigest, files: current.files.length },
    inputReport: { sha256: sha256(raw), bytes: raw.length },
    ...(allLocal ? {} : { integrityRegistrySha256: current.registryDigest }),
    checks: [...checks.values()],
    ...(baselineChecks ? { baselineChecks } : {}),
    scenarios,
    artifacts,
    mapping: MAPPING.filter(item => statusByScenario.has(item.scenario)).map(item =>
      ({ ...item, status: statusByScenario.get(item.scenario) })),
    scopeLimit: 'Synthetic execution evidence. Deployment operation, assessment and certification are outside its scope.',
  };
}

export function renderMarkdown(bundle) {
  const counts = bundle.scenarios.reduce((totals, item) => {
    totals[item.status] = (totals[item.status] ?? 0) + 1;
    return totals;
  }, {});
  const lines = [
    '# Laboratory evidence', '',
    'Scope includes synthetic execution. Retain the exact JSON as the evidence record.', '',
    `- Run mode and result — \`${bundle.mode}\` / \`${bundle.reportStatus}\``,
    `- Run began ${bundle.startedAt} and ended ${bundle.finishedAt}.`,
    `- Source SHA-256 — \`${bundle.source.sha256}\``,
    `- Input report SHA-256 — \`${bundle.inputReport.sha256}\``,
    ...Object.entries(counts).map(([status, count]) => `- \`${status}\` has ${count} scenarios.`),
    '', '## Scenario results', '', '| Scenario | Classification | Result |', '| --- | --- | --- |',
    ...bundle.scenarios.map(item => `| ${item.id} | ${item.category} | ${item.status} |`),
    '', '## NIST SP 800-53 Rev. 5 evidence leads', '',
    '| Scenario | Topic | Controls | Lab result |', '| --- | --- | --- | --- |',
    ...bundle.mapping.map(item => `| ${item.scenario} | ${item.topic} | ${item.nist.join(', ')} | ${item.status} |`),
    '', bundle.scopeLimit, '',
  ];
  return lines.join('\n');
}

export function verifyEvidenceSignature(bundleBytes, publicPem, signature) {
  if (!Buffer.isBuffer(bundleBytes) || bundleBytes.length > MAX_FILE ||
    !Buffer.isBuffer(publicPem) || publicPem.length > 4096 ||
    !Buffer.isBuffer(signature) || signature.length !== 64) return false;
  const text = publicPem.toString('ascii');
  if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(text)) return false;
  try {
    const key = createPublicKey(publicPem);
    if (key.asymmetricKeyType !== 'ed25519' || !verify(null, bundleBytes, key, signature)) return false;
    return JSON.parse(bundleBytes).schema === 'amqic.evidence.v1';
  } catch {
    return false;
  }
}
