import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuditChain, serializeAuditRecord, verifyAuditTrail } from '../evidence/audit.mjs';
import { describeSiemBatch, exportSiemBatch } from './siem.mjs';

function fixture() {
  const chain = createAuditChain();
  const event = {
    at: '2026-11-18T12:00:00.000Z', action: 'login', outcome: 'deny',
    correlationId: 'a'.repeat(32), actorRef: 'b'.repeat(32), tenantRef: 'c'.repeat(32),
  };
  chain.append({ ...event, outcome: 'allow' });
  const start = chain.checkpoint();
  const entries = [chain.append(event), chain.append({ ...event, action: 'key-rotation', outcome: 'allow' })];
  return { entries, binding: { streamRef: 'd'.repeat(32), start, end: chain.checkpoint() } };
}

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

// Exercise every assertion used by this schema without adding a validator dependency.
function satisfies(value, schema) {
  if (Object.hasOwn(schema, 'const') && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.oneOf && schema.oneOf.filter(branch => satisfies(value, branch)).length !== 1) return false;
  if (typeof value === 'string' && (value.length < (schema.minLength ?? 0) ||
      value.length > (schema.maxLength ?? Infinity))) return false;
  if (schema.type === 'object') {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    if (schema.required.some(key => !Object.hasOwn(value, key))) return false;
    return Object.keys(value).every(key => Object.hasOwn(schema.properties, key)
      ? satisfies(value[key], schema.properties[key]) : schema.additionalProperties !== false);
  }
  if (schema.type === 'string') {
    if (typeof value !== 'string' || value.length < (schema.minLength ?? 0) ||
        value.length > (schema.maxLength ?? Infinity)) return false;
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) return false;
    if (schema.format === 'date-time' && (!Number.isFinite(Date.parse(value)) ||
        new Date(value).toISOString() !== value)) return false;
  }
  if (schema.type === 'integer' && (!Number.isSafeInteger(value) ||
      value < schema.minimum || value > schema.maximum)) return false;
  return true;
}

const schema = JSON.parse(readFileSync(new URL('./siem.schema.json', import.meta.url)));
const signals = [
  ['runtime', 'process-exec', 'host-process', 'T1059.004'],
  ['runtime', 'config-integrity', 'ssh-key-integrity', 'T1098.004'],
  ['egress', 'egress-decision', 'egress-unapproved', 'T1567.004'],
  ['campaign', 'indicator-review', 'indicator'],
  ['campaign', 'campaign-note', 'campaign-correlation'],
  ['identity', 'consent-change', 'identity-grant'],
  ['identity', 'principal-change', 'identity-grant'],
];

function single(event) {
  const chain = createAuditChain();
  const start = chain.checkpoint();
  const entries = [chain.append(event)];
  const binding = { streamRef: 'd'.repeat(32), start, end: chain.checkpoint() };
  const descriptor = describeSiemBatch(entries, binding);
  const exported = exportSiemBatch(entries, binding, descriptor.etag);
  return { entries, binding, descriptor, exported, line: JSON.parse(exported.ndjson) };
}

test('all new signals traverse the real audit/export seam with optionals present or absent', () => {
  const base = fixture().entries[0].event;
  for (const [category, action, signalClass, technique] of signals) {
    for (const optional of [{}, { caseRef: 'e'.repeat(32), signalClass, technique: technique ?? 'T1059' }]) {
      const result = single({ ...base, action, ...optional });
      assert.equal(result.line.category, category);
      assert.equal(satisfies(result.line, schema), true, action);
      assert.equal(verifyAuditTrail(result.entries, result.binding.end), true);
      assert.deepEqual(JSON.parse(serializeAuditRecord(result.entries[0])), result.entries[0]);
      assert.deepEqual(Object.keys(result.line.record.event), [...Object.keys(base), ...Object.keys(optional)]);
      assert.doesNotMatch(JSON.stringify(result.line), /https?:\/\/|commandLine|arguments|environment|displayName|indicatorValue/);
      // Caller property order cannot change hashes, ETags or exported bytes.
      assert.deepEqual(single(Object.fromEntries(Object.entries({ ...base, action, ...optional }).reverse())), result);
    }
  }
  for (const optional of [{ caseRef: 'e'.repeat(32) }, { signalClass: 'indicator' }, { technique: 'T1059' }]) {
    assert.equal(satisfies(single({ ...base, ...optional }).line, schema), true);
  }
});

test('schema rejects unknown enums and extra keys at every record level without coupling old enums', () => {
  const line = single(fixture().entries[0].event).line;
  for (const category of schema.properties.category.enum) {
    assert.equal(satisfies({ ...line, category }, schema), true, 'category/action are independent');
  }
  const reject = edit => { const copy = structuredClone(line); edit(copy); assert.equal(satisfies(copy, schema), false); };
  reject(row => row.category = 'unknown');
  reject(row => row.record.event.action = 'unknown');
  reject(row => row.extra = 'synthetic');
  reject(row => row.record.extra = 'synthetic');
  for (const key of ['url', 'commandLine', 'args', 'env', 'key', 'indicatorValue', 'displayName']) {
    reject(row => row.record.event[key] = 'synthetic');
    assert.throws(() => single({ ...line.record.event, [key]: 'synthetic' }), /Invalid structured audit event/);
  }
  assert.throws(() => single({ ...line.record.event, action: 'unknown' }), /Invalid structured audit event/);
  assert.throws(() => describeSiemBatch([{ ...line.record, extra: 'synthetic' }], {
    streamRef: line.streamRef, start: { sequence: 0, hash: '0'.repeat(64) },
    end: { sequence: 1, hash: line.record.hash },
  }), /Invalid audit entry/);
});

test('optional values remain closed, typed and bounded in schema and executable projection', () => {
  const base = fixture().entries[0].event;
  const techniqueSchema = schema.properties.record.properties.event.properties.technique;
  assert.equal(techniqueSchema.pattern, '^T[0-9]{4}(\\.[0-9]{3})?$');
  assert.deepEqual(techniqueSchema.oneOf, [{ minLength: 5, maxLength: 5 }, { minLength: 9, maxLength: 9 }]);
  for (const [key, invalid] of [
    ['caseRef', ['', 'a'.repeat(31), 'a'.repeat(33), 'A'.repeat(32), 'g'.repeat(32), 'a'.repeat(32) + '\n', null, 1]],
    ['signalClass', ['', 'unknown', 'Host-process', null, 1]],
    ['technique', ['', 't1059', 'T105', 'T10590', 'T1059x004', 'T1059.04', 'T1059.0004', 'xT1059', 'T1059x',
      'T1059\n', 'T1059\r\n', 'T1059.004\n', 'T1059.004\r\n', null, 1]],
  ]) {
    for (const value of invalid) {
      const event = { ...base, [key]: value };
      assert.equal(satisfies(event, schema.properties.record.properties.event), false, `${key}: ${value}`);
      assert.throws(() => single(event), /Invalid structured audit event/);
    }
    assert.throws(() => single({ ...base, [key]: undefined }), /Invalid structured audit event/);
  }
  for (const key of Object.keys(base)) {
    const missing = { ...base }; delete missing[key];
    assert.throws(() => single(missing), /Invalid structured audit event/);
  }
});

test('legacy audit hashes, input tags and complete NDJSON bytes stay unchanged', () => {
  const result = single(fixture().entries[0].event);
  assert.equal(result.entries[0].hash, '1fb787c89564aefa815eab4bca20daf42f3ea99ed461c183e0e69ad8279cc5b6');
  assert.equal(result.descriptor.etag, '543f3ee714951f02a95a1a760379f7f0a7d150bf629cb543e73e92e645ea8a40');
  assert.equal(result.exported.receipt.etag, '516594c615607bea35e4396b0bf4787697775579cbd57fada00e485a3d956b44');
  assert.equal(hash(result.exported.ndjson), result.exported.receipt.etag);
  assert.equal(satisfies(result.line, schema), true);
  for (const action of ['login', 'access-change', 'sensitive-read', 'key-rotation', 'backup-restore', 'admin-action']) {
    assert.equal(satisfies(single({ ...result.entries[0].event, action }).line, schema), true);
  }
});

test('validated suffix produces stable one-line records with a tagged receipt', () => {
  const { entries, binding } = fixture();
  const descriptor = describeSiemBatch(entries, binding);
  const first = exportSiemBatch(entries, binding, descriptor.etag);
  const reordered = JSON.parse(JSON.stringify(entries).replace(
    '"schema":"amqic.audit.v1","sequence":2', '"sequence":2,"schema":"amqic.audit.v1"'));
  assert.deepEqual(exportSiemBatch(reordered, binding, descriptor.etag), first);
  assert.equal(first.receipt.inputEtag, descriptor.etag);
  assert.equal(first.receipt.etag, hash(first.ndjson));
  assert.equal(first.receipt.eventCount, 2);
  const lines = first.ndjson.trimEnd().split('\n').map(JSON.parse);
  const schema = JSON.parse(readFileSync(new URL('./siem.schema.json', import.meta.url)));
  assert.deepEqual(lines.map(line => line.record), entries);
  assert.deepEqual(lines.map(line => line.category), ['authentication', 'key-management']);
  assert.equal(new Set(lines.map(line => line.eventId)).size, 2);
  for (const line of lines) {
    assert.deepEqual(Object.keys(line).sort(), [...schema.required].sort());
    assert.equal(line.schema, schema.properties.schema.const);
    assert.match(line.eventId, new RegExp(schema.properties.eventId.pattern));
  }

  const suffixBinding = { ...binding, start: { sequence: entries[0].sequence, hash: entries[0].hash } };
  const suffix = exportSiemBatch(entries.slice(1), suffixBinding,
    describeSiemBatch(entries.slice(1), suffixBinding).etag);
  assert.equal(JSON.parse(suffix.ndjson).eventId, lines[1].eventId, 'same event across batch boundaries');
  assert.notEqual(suffix.receipt.inputEtag, descriptor.etag);
});

test('reject stale tags, altered content, mixed sequences and unknown event fields', () => {
  const { entries, binding } = fixture();
  const tag = describeSiemBatch(entries, binding).etag;
  assert.throws(() => exportSiemBatch(entries, binding));
  assert.throws(() => exportSiemBatch(entries, { ...binding, streamRef: 'e'.repeat(32) }, tag));
  assert.throws(() => describeSiemBatch(entries, { ...binding, end: { ...binding.end, hash: 'e'.repeat(64) } }));
  assert.throws(() => describeSiemBatch(entries.slice(1), binding));
  assert.throws(() => describeSiemBatch(entries.toReversed(), binding));
  const modify = edit => { const copy = structuredClone(entries); edit(copy[0]); return copy; };
  assert.throws(() => describeSiemBatch(modify(row => row.event.outcome = 'allow'), binding));
  assert.throws(() => describeSiemBatch(modify(row => row.event.token = 'synthetic'), binding));
  assert.throws(() => describeSiemBatch(modify(row => row.event.action = 'arbitrary'), binding));
});

test('offline CLI emits receipt for accepted export and zero stdout for stale input', () => {
  const { entries, binding } = fixture();
  const dir = mkdtempSync(join(tmpdir(), 'amqic-siem-'));
  const input = join(dir, 'input.json');
  const scope = join(dir, 'scope.json');
  const cli = fileURLToPath(new URL('./siem-cli.mjs', import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf-8', timeout: 10000 });
  try {
    writeFileSync(input, JSON.stringify(entries));
    writeFileSync(scope, JSON.stringify(binding));
    const plan = run('describe', input, scope);
    assert.equal(plan.status, 0, plan.stderr);
    const { etag } = JSON.parse(plan.stdout);
    const result = run('export', input, scope, etag);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stderr).etag, hash(result.stdout));
    writeFileSync(scope, JSON.stringify({ ...binding, streamRef: 'e'.repeat(32) }));
    const denied = run('export', input, scope, etag);
    assert.equal(denied.status, 2);
    assert.equal(denied.stdout, '');
    assert.equal(denied.stderr, 'SIEM batch rejected or output failed.\n');
  } finally {
    unlinkSync(input);
    unlinkSync(scope);
    rmdirSync(dir);
  }
});
