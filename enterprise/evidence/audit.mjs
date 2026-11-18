import { createHash } from 'node:crypto';

const GENESIS = '0'.repeat(64);
const HEX = /^[a-f0-9]{64}$/;
const REF = /^[a-f0-9]{32}$/;
const MAX_EVENTS = 100000;
const actions = new Set(['login', 'access-change', 'sensitive-read', 'key-rotation', 'backup-restore', 'admin-action']);
const outcomes = new Set(['allow', 'deny', 'error']);
const fields = ['at', 'action', 'outcome', 'correlationId', 'actorRef', 'tenantRef'];

function exactFields(value, names) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
}

function project(event) {
  if (!exactFields(event, fields) || typeof event.at !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(event.at) ||
      !Number.isFinite(Date.parse(event.at)) || new Date(event.at).toISOString() !== event.at ||
      !actions.has(event.action) || !outcomes.has(event.outcome) ||
      ![event.correlationId, event.actorRef, event.tenantRef].every(value => typeof value === 'string' && REF.test(value))) {
    throw new Error('Invalid structured audit event');
  }
  return Object.fromEntries(fields.map(field => [field, event[field]]));
}

function entryFor(sequence, previous, event) {
  const body = { schema: 'amqic.audit.v1', sequence, previous, event: project(event) };
  const hash = createHash('sha256').update(JSON.stringify(body)).digest('hex');
  return { ...body, hash };
}

function validCheckpoint(value) {
  return exactFields(value, ['sequence', 'hash']) && Number.isSafeInteger(value.sequence) &&
    value.sequence >= 0 && value.sequence <= MAX_EVENTS && typeof value.hash === 'string' &&
    HEX.test(value.hash) && (value.sequence === 0 ? value.hash === GENESIS : value.hash !== GENESIS);
}

// Use the last independently trusted checkpoint when resuming a stream.
export function createAuditChain(checkpoint = { sequence: 0, hash: GENESIS }) {
  if (!validCheckpoint(checkpoint)) throw new Error('Invalid audit checkpoint');
  let { sequence, hash } = checkpoint;
  return {
    append(event) {
      if (sequence >= MAX_EVENTS) throw new Error('Audit stream requires rotation');
      const entry = entryFor(sequence + 1, hash, event);
      sequence = entry.sequence;
      hash = entry.hash;
      return entry;
    },
    checkpoint() {
      return { sequence, hash };
    },
  };
}

export function verifyAuditTrail(entries, trustedEnd, trustedStart = { sequence: 0, hash: GENESIS }) {
  if (!validCheckpoint(trustedStart) || !validCheckpoint(trustedEnd) || !Array.isArray(entries) ||
      entries.length !== trustedEnd.sequence - trustedStart.sequence || entries.length > MAX_EVENTS) return false;
  const chain = createAuditChain(trustedStart);
  try {
    for (const entry of entries) {
      if (!exactFields(entry, ['schema', 'sequence', 'previous', 'event', 'hash'])) return false;
      const expected = chain.append(entry.event);
      if (entry.schema !== expected.schema || entry.sequence !== expected.sequence ||
          entry.previous !== expected.previous || entry.hash !== expected.hash) return false;
    }
    return chain.checkpoint().hash === trustedEnd.hash;
  } catch {
    return false;
  }
}

// The audit entry itself is the single-line SIEM JSON record.
export function serializeAuditRecord(entry) {
  if (!exactFields(entry, ['schema', 'sequence', 'previous', 'event', 'hash']) ||
      !Number.isSafeInteger(entry.sequence) || entry.sequence < 1 || entry.sequence > MAX_EVENTS ||
      typeof entry.previous !== 'string' || !HEX.test(entry.previous)) throw new Error('Invalid audit entry');
  const expected = entryFor(entry.sequence, entry.previous, entry.event);
  if (entry.schema !== expected.schema || entry.hash !== expected.hash) throw new Error('Invalid audit entry');
  return JSON.stringify(expected) + '\n';
}
