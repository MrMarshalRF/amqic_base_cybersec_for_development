import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_ROWS = 4096;
const MAX_INPUT = 4 * 1024 * 1024;

function matches(value, pattern) {
  return typeof value === 'string' && pattern.test(value);
}

function exact(value, names) {
  return value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
}

const identifier = value => matches(value, /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/);
const build = value => matches(value, /^[A-Za-z0-9][A-Za-z0-9_.+:%~-]{0,127}$/);
const digest = value => matches(value, /^sha256:[0-9a-f]{64}$/);
const httpsUrl = value => typeof value === 'string' && value.length <= 512 &&
  URL.canParse(value) && /^https:\/\/[^@\s/?#\\]+(?:\/[^\s?#\\]*)?$/.test(value);

function timestamp(value) {
  if (!matches(value, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/)) return NaN;
  const parsed = new Date(value);
  return Number.isFinite(+parsed) && parsed.toISOString() === value ? +parsed : NaN;
}

function array(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= MAX_ROWS;
}

export function assessJavaRollout(policy, inventory, now = Date.now()) {
  const observedAt = timestamp(inventory?.observedAt);
  if (!exact(policy, ['schema', 'advisory', 'changeId', 'changeStartedAt', 'expected', 'vendorFindings']) ||
      policy.schema !== 'amqic-java-policy/v1' || !matches(policy.advisory, /^CVE-\d{4}-\d{4,}$/) ||
      !identifier(policy.changeId) || !Number.isFinite(timestamp(policy.changeStartedAt)) ||
      !array(policy.expected) || !array(policy.vendorFindings) ||
      !exact(inventory, ['schema', 'changeId', 'observedAt', 'observations']) ||
      inventory.schema !== 'amqic-java-inventory/v1' || inventory.changeId !== policy.changeId ||
      !array(inventory.observations) || !Number.isFinite(observedAt) || !Number.isFinite(now) ||
      observedAt < timestamp(policy.changeStartedAt) || observedAt > now ||
      now - observedAt > 24 * 60 * 60 * 1000) {
    throw new Error('Invalid rollout inputs');
  }

  const tuple = value => JSON.stringify([value.vendor, value.package, value.build, value.architecture]);
  const findings = new Map();
  for (const entry of policy.vendorFindings) {
    if (!exact(entry, ['vendor', 'package', 'build', 'architecture', 'status', 'reference']) ||
        !identifier(entry.vendor) || !identifier(entry.package) || !build(entry.build) ||
        !identifier(entry.architecture) || !['fixed', 'not-affected', 'affected'].includes(entry.status) ||
        !httpsUrl(entry.reference) || findings.has(tuple(entry))) {
      throw new Error('Invalid or duplicate vendor finding');
    }
    findings.set(tuple(entry), entry);
  }

  const expected = new Map();
  const previousInstances = new Set();
  for (const row of policy.expected) {
    if (!exact(row, ['workload', 'previousInstance', 'artifactDigest']) ||
        !identifier(row.workload) || !identifier(row.previousInstance) || !digest(row.artifactDigest) ||
        expected.has(row.workload) || previousInstances.has(row.previousInstance)) {
      throw new Error('Invalid or duplicate expected workload');
    }
    expected.set(row.workload, row);
    previousInstances.add(row.previousInstance);
  }

  const observations = new Map();
  const instances = new Set();
  for (const row of inventory.observations) {
    if (!exact(row, ['workload', 'instance', 'startedAt', 'vendor', 'package', 'build', 'architecture',
      'artifactDigest', 'evidenceDigest']) ||
        !identifier(row.workload) || !identifier(row.instance) || !Number.isFinite(timestamp(row.startedAt)) ||
        timestamp(row.startedAt) > timestamp(inventory.observedAt) ||
        !identifier(row.vendor) || !identifier(row.package) || !build(row.build) ||
        !identifier(row.architecture) || !digest(row.artifactDigest) || !digest(row.evidenceDigest) ||
        !expected.has(row.workload) || observations.has(row.workload) || instances.has(row.instance)) {
      throw new Error('Invalid, unexplained or duplicate runtime observation');
    }
    observations.set(row.workload, row);
    instances.add(row.instance);
  }

  const results = [];
  for (const [id, target] of expected) {
    const observed = observations.get(id);
    if (!observed) {
      results.push({ workload: id, outcome: 'missing-observation' });
      continue;
    }
    const finding = findings.get(tuple(observed));
    let outcome = 'accepted';
    if (observed.artifactDigest !== target.artifactDigest) outcome = 'artifact-mismatch';
    else if (previousInstances.has(observed.instance) ||
             timestamp(observed.startedAt) < timestamp(policy.changeStartedAt)) outcome = 'restart-unverified';
    else if (!finding) outcome = 'vendor-status-unknown';
    else if (finding.status === 'affected') outcome = 'affected';
    results.push({
      workload: id, outcome, vendorStatus: finding?.status ?? 'unknown',
      reference: finding?.reference ?? null, evidenceDigest: observed.evidenceDigest,
    });
  }
  return {
    schema: 'amqic-java-rollout-report/v1',
    advisory: policy.advisory,
    changeId: policy.changeId,
    observedAt: inventory.observedAt,
    checkPassed: results.every(row => row.outcome === 'accepted'),
    results,
  };
}

function readJson(path) {
  const file = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    if (!fstatSync(file).isFile()) throw new Error('Expected a regular file');
    const buffer = Buffer.alloc(MAX_INPUT + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(file, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > MAX_INPUT) throw new Error('Input too large');
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length)));
  } finally {
    closeSync(file);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) {
    console.error('Usage: node java-inventory.mjs POLICY.json INVENTORY.json');
    process.exitCode = 2;
  } else {
    try {
      const report = assessJavaRollout(readJson(process.argv[2]), readJson(process.argv[3]));
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = report.checkPassed ? 0 : 1;
    } catch {
      console.error('Runtime rollout inputs failed validation.');
      process.exitCode = 2;
    }
  }
}
