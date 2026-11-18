import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuditChain } from '../evidence/audit.mjs';
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
