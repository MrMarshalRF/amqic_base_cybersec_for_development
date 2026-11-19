import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DAY = 86_400_000;
const CVES = ['CVE-2026-123007', 'CVE-2026-123633'];
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:+~-]{0,127}$/.test(value);
const hash = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;

function requireValid(condition) {
  if (!condition) throw new Error('Nginx rollout inputs failed validation.');
}
function exact(value, fields) {
  return plain(value) && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
}
function list(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= 4096;
}
function time(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)) return NaN;
  const parsed = new Date(value);
  return Number.isFinite(+parsed) && parsed.toISOString() === value ? +parsed : NaN;
}
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (plain(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  requireValid(value === null || ['string', 'boolean'].includes(typeof value) || (typeof value === 'number' && Number.isSafeInteger(value)));
  return JSON.stringify(value);
}
const etag = value => 'sha256:' + createHash('sha256').update(canonical(value)).digest('hex');
const key = value => JSON.stringify([value.vendor, value.product, value.build, value.architecture]);

// This helper recognizes only the OSS release lines in the dated advisory.
// Distributor backports, Plus and forks require their own explicit finding.
export function classifyOssRelease(version) {
  if (typeof version !== 'string') return 'unknown';
  const match = /^1\.(30|31)\.(0|[1-9][0-9]{0,5})$/.exec(version);
  if (!match) return 'unknown';
  return Number(match[2]) >= (match[1] === '30' ? 7 : 9) ? 'advisory-fixed-line' : 'affected-line';
}

export function rolloutInputEtag(policy, inventory) {
  return etag({ schema: 'amqic-nginx-rollout-input/v1', policy, inventory });
}

export function assessNginxRollout(policy, inventory, expectedEtag, now = Date.now()) {
  const inputEtag = rolloutInputEtag(policy, inventory);
  requireValid(hash(expectedEtag) && inputEtag === expectedEtag);
  requireValid(exact(policy, ['schema', 'changeId', 'changeStartedAt', 'requiredAdvisories', 'expected', 'vendorFindings']) &&
    policy.schema === 'amqic-nginx-policy/v1' && id(policy.changeId) && Number.isFinite(time(policy.changeStartedAt)) &&
    list(policy.requiredAdvisories) && policy.requiredAdvisories.every(cve => /^CVE-\d{4}-\d{4,}$/.test(cve)) &&
    new Set(policy.requiredAdvisories).size === policy.requiredAdvisories.length &&
    CVES.every(cve => policy.requiredAdvisories.includes(cve)) && list(policy.expected) && list(policy.vendorFindings));
  requireValid(exact(inventory, ['schema', 'changeId', 'observedAt', 'observations']) &&
    inventory.schema === 'amqic-nginx-inventory/v1' && inventory.changeId === policy.changeId &&
    Number.isSafeInteger(now) && Number.isFinite(time(inventory.observedAt)) &&
    time(inventory.observedAt) >= time(policy.changeStartedAt) &&
    time(inventory.observedAt) <= now && now - time(inventory.observedAt) <= DAY && list(inventory.observations));
  const findings = new Map();
  for (const finding of policy.vendorFindings) {
    requireValid(exact(finding, ['vendor', 'product', 'build', 'architecture', 'cve', 'status', 'reference']) &&
      [finding.vendor, finding.product, finding.build, finding.architecture].every(id) &&
      policy.requiredAdvisories.includes(finding.cve) && ['fixed', 'not-affected', 'affected'].includes(finding.status) &&
      typeof finding.reference === 'string' && finding.reference.length <= 512 && URL.canParse(finding.reference) &&
      /^https:\/\/[^@\s/?#\\]+(?:\/[^\s?#\\]*)?$/.test(finding.reference));
    const identity = key(finding) + ':' + finding.cve;
    requireValid(!findings.has(identity));
    findings.set(identity, finding);
  }
  const expected = new Map();
  const oldProcesses = new Set();
  for (const target of policy.expected) {
    requireValid(exact(target, ['workload', 'previousMaster', 'previousWorkers', 'artifactDigest']) &&
      id(target.workload) && id(target.previousMaster) && list(target.previousWorkers) &&
      target.previousWorkers.every(id) && hash(target.artifactDigest) && !expected.has(target.workload));
    for (const process of [target.previousMaster, ...target.previousWorkers]) {
      requireValid(!oldProcesses.has(process));
      oldProcesses.add(process);
    }
    expected.set(target.workload, target);
  }
  const observed = new Map();
  const currentProcesses = new Set();
  for (const row of inventory.observations) {
    requireValid(exact(row, ['workload', 'master', 'startedAt', 'workers', 'previousProcessesAbsent',
      'vendor', 'product', 'build', 'architecture', 'artifactDigest', 'evidenceDigest', 'protocols']) &&
      expected.has(row.workload) && !observed.has(row.workload) && id(row.master) &&
      [row.vendor, row.product, row.build, row.architecture].every(id) &&
      hash(row.artifactDigest) && hash(row.evidenceDigest) &&
      typeof row.previousProcessesAbsent === 'boolean' && Number.isFinite(time(row.startedAt)) &&
      time(row.startedAt) <= time(inventory.observedAt) && list(row.workers) &&
      exact(row.protocols, ['http2', 'http3', 'quicUdp', 'alpnHttp1']) &&
      Object.values(row.protocols).every(value => typeof value === 'boolean'));
    for (const process of [row.master, ...row.workers.map(worker => worker?.instance)]) {
      requireValid(id(process) && !currentProcesses.has(process));
      currentProcesses.add(process);
    }
    for (const worker of row.workers) {
      requireValid(exact(worker, ['instance', 'startedAt']) && Number.isFinite(time(worker.startedAt)) &&
        time(worker.startedAt) <= time(inventory.observedAt));
    }
    observed.set(row.workload, row);
  }
  const results = [];
  for (const [workload, target] of expected) {
    const row = observed.get(workload);
    if (!row) {
      results.push({ workload, outcome: 'missing-observation' });
      continue;
    }
    let outcome = 'accepted';
    const processes = [row.master, ...row.workers.map(worker => worker.instance)];
    if (row.artifactDigest !== target.artifactDigest) outcome = 'artifact-mismatch';
    else if (!row.previousProcessesAbsent || processes.some(process => oldProcesses.has(process)) ||
      [row.startedAt, ...row.workers.map(worker => worker.startedAt)].some(stamp => time(stamp) < time(policy.changeStartedAt))) outcome = 'process-replacement-unverified';
    else if (row.protocols.http2 || row.protocols.http3 || row.protocols.quicUdp || !row.protocols.alpnHttp1) outcome = 'protocol-policy-mismatch';
    const dispositions = policy.requiredAdvisories.map(cve => findings.get(key(row) + ':' + cve));
    if (outcome === 'accepted' && dispositions.some(finding => !finding)) outcome = 'vendor-status-unknown';
    if (outcome === 'accepted' && dispositions.some(finding => finding.status === 'affected')) outcome = 'affected';
    results.push({ workload, outcome, evidenceDigest: row.evidenceDigest });
  }
  const report = { schema: 'amqic-nginx-rollout-report/v1', inputEtag, changeId: policy.changeId,
    observedAt: inventory.observedAt, checkPassed: results.every(row => row.outcome === 'accepted'), results };
  return { ...report, etag: etag(report) };
}

function readJson(path) {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const info = fstatSync(descriptor);
    requireValid(info.isFile() && info.size <= 4 * 1024 * 1024);
    const buffer = Buffer.alloc(4 * 1024 * 1024 + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(descriptor, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    const after = fstatSync(descriptor);
    requireValid(used <= 4 * 1024 * 1024 && used === info.size &&
      info.dev === after.dev && info.ino === after.ino &&
      info.size === after.size && info.mtimeMs === after.mtimeMs);
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, used)));
  } finally { closeSync(descriptor); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [, , mode, policyPath, inventoryPath, expected] = process.argv;
    requireValid((mode === '--plan' && process.argv.length === 5) || (mode === '--verify' && process.argv.length === 6));
    const policy = readJson(policyPath);
    const inventory = readJson(inventoryPath);
    const report = mode === '--plan' ? { schema: 'amqic-nginx-rollout-plan/v1', etag: rolloutInputEtag(policy, inventory) }
      : assessNginxRollout(policy, inventory, expected);
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.checkPassed === false ? 1 : 0;
  } catch {
    console.error('Nginx rollout inputs or expected ETag failed validation.');
    process.exitCode = 2;
  }
}
