import { serializeAuditRecord, verifyAuditTrail } from '../evidence/audit.mjs';
import { sha256 } from '../evidence/evidence.mjs';

const GENESIS = '0'.repeat(64);
const HEX = /^[a-f0-9]{64}$/;
const REF = /^[a-f0-9]{32}$/;
const MAX_EVENTS = 2000;
const MAX_SEQUENCE = 100000;
const INPUT_SCHEMA = 'amqic.siem.input.v1';
const RECORD_SCHEMA = 'amqic.siem.record.v1';
const categories = new Map([
  ['login', 'authentication'],
  ['access-change', 'authorization'],
  ['sensitive-read', 'data-access'],
  ['key-rotation', 'key-management'],
  ['backup-restore', 'recovery'],
  ['admin-action', 'administration'],
]);

function exactFields(value, names) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
}

function descriptor(value) {
  if (!exactFields(value, ['streamRef', 'start', 'end']) ||
      typeof value.streamRef !== 'string' || !REF.test(value.streamRef)) {
    throw new Error('Invalid trusted stream binding');
  }
  const checkpoints = [value.start, value.end].map(item => {
    if (!exactFields(item, ['sequence', 'hash']) || !Number.isSafeInteger(item.sequence) ||
        item.sequence < 0 || item.sequence > MAX_SEQUENCE || typeof item.hash !== 'string' ||
        !HEX.test(item.hash) || (item.sequence === 0) !== (item.hash === GENESIS)) {
      throw new Error('Invalid trusted checkpoint');
    }
    return { sequence: item.sequence, hash: item.hash };
  });
  return { streamRef: value.streamRef, start: checkpoints[0], end: checkpoints[1] };
}

function snapshot(entries, trustedBinding) {
  const scope = descriptor(trustedBinding);
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_EVENTS ||
      entries.length !== scope.end.sequence - scope.start.sequence) {
    throw new Error('Invalid audit range');
  }
  // Canonical copies keep validation and export on the same bytes.
  const records = Array.from(entries, entry => JSON.parse(serializeAuditRecord(entry)));
  if (!verifyAuditTrail(records, scope.end, scope.start)) {
    throw new Error('Audit trail does not match trusted checkpoints');
  }
  const bytes = JSON.stringify({ schema: INPUT_SCHEMA, output: RECORD_SCHEMA, ...scope, records });
  return { scope, records, etag: sha256(bytes) };
}

export function describeSiemBatch(entries, trustedBinding) {
  const { scope, records, etag } = snapshot(entries, trustedBinding);
  return { schema: INPUT_SCHEMA, output: RECORD_SCHEMA, ...scope, eventCount: records.length, etag };
}

export function exportSiemBatch(entries, trustedBinding, expectedEtag) {
  const { scope, records, etag: inputEtag } = snapshot(entries, trustedBinding);
  if (typeof expectedEtag !== 'string' || !HEX.test(expectedEtag) || expectedEtag !== inputEtag) {
    throw new Error('SIEM batch ETag mismatch');
  }
  const ndjson = records.map(record => JSON.stringify({
    schema: RECORD_SCHEMA,
    streamRef: scope.streamRef,
    eventId: sha256(JSON.stringify([RECORD_SCHEMA, scope.streamRef, record.hash])),
    category: categories.get(record.event.action),
    record,
  }) + '\n').join('');
  return {
    ndjson,
    receipt: {
      schema: 'amqic.siem.receipt.v1', ...scope, eventCount: records.length,
      inputEtag, etag: sha256(ndjson),
    },
  };
}
