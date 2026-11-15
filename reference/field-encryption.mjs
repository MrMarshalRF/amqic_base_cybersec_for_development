import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const MAX_FIELD_BYTES = 1024 * 1024;
const MAX_WRAPPED_BYTES = 16 * 1024;
const IDENTITY_FIELDS = ['tenant', 'table', 'record', 'field', 'purpose', 'version'];
const ENVELOPE_FIELDS = ['format', 'algorithm', 'keyId', 'keyVersion', 'wrappedKey', 'iv', 'ciphertext', 'tag'];
const DOMAIN = 'amqic-field-envelope';

export class FieldEncryptionError extends Error {
  constructor() {
    super('Field encryption operation failed');
    this.name = 'FieldEncryptionError';
    this.code = 'field_encryption_failed';
  }
}

// Reject accessors, custom prototypes, symbols and unexpected metadata before reading it.
function record(value, fields) {
  if (!value || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new Error();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some(k => !fields.includes(k))) throw new Error();
  const copy = {};
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw new Error();
    copy[key] = descriptor.value;
  }
  return copy;
}

function text(value, max = 256) {
  if (typeof value !== 'string' || !value.length || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error();
  return value;
}

function identitySnapshot(input) {
  const result = record(input, IDENTITY_FIELDS);
  for (const key of IDENTITY_FIELDS) text(result[key]);
  return Object.freeze(result);
}

function binary(value, max, exact) {
  if (!Buffer.isBuffer(value) || value.length > max || (exact !== undefined && value.length !== exact)) throw new Error();
  return Buffer.from(value);
}

function decode(value, max, exact) {
  // Check encoded size before allocating. Only canonical standard base64 is accepted.
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4 || value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) throw new Error();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > max || (exact !== undefined && bytes.length !== exact) || bytes.toString('base64') !== value) throw new Error();
  return bytes;
}

function identityTuple(identity) { return IDENTITY_FIELDS.map(k => identity[k]); }
function kmsContext(identity, keyId) {
  // Context is authenticated but may enter provider audit logs. Do not send raw row/PII values.
  return Object.freeze({ domain: DOMAIN, binding: createHash('sha256').update(JSON.stringify([DOMAIN, 1, keyId, identityTuple(identity)])).digest('hex') });
}
function payloadAAD(identity, envelope) {
  return Buffer.from(JSON.stringify([DOMAIN, envelope.format, envelope.algorithm, envelope.keyId,
    envelope.keyVersion, envelope.wrappedKey, identityTuple(identity)]));
}

/** Trusted startup dependencies only. See field-encryption.README.md for the KMS port contract. */
export function createFieldEncryption({ kms, keyId, allowedKeyIds, authorize } = {}) {
  let generate, unwrap, allowed;
  try {
    text(keyId, 1024);
    if (!Array.isArray(allowedKeyIds) || !allowedKeyIds.length || allowedKeyIds.length > 64 || typeof authorize !== 'function') throw new Error();
    allowed = new Set(allowedKeyIds.map(id => text(id, 1024)));
    if (!allowed.has(keyId) || !kms || typeof kms.generateDataKey !== 'function' || typeof kms.unwrapDataKey !== 'function') throw new Error();
    generate = kms.generateDataKey.bind(kms);
    unwrap = kms.unwrapDataKey.bind(kms);
  } catch { throw new TypeError('Invalid field encryption configuration'); }

  return Object.freeze({
    async encryptField(plaintext, expectedIdentity) {
      let data, dek;
      try {
        const identity = identitySnapshot(expectedIdentity);
        data = binary(plaintext, MAX_FIELD_BYTES);
        if (await authorize(Object.freeze({ identity, operation: 'encrypt' })) !== true) throw new Error();
        const result = record(await generate(Object.freeze({ keyId, context: kmsContext(identity, keyId) })),
          ['keyId', 'keyVersion', 'plaintextKey', 'wrappedKey']);
        // Copy immediately so cleanup never overwrites buffers retained by the trusted port.
        dek = binary(result.plaintextKey, 32, 32);
        if (text(result.keyId, 1024) !== keyId) throw new Error();
        const keyVersion = text(result.keyVersion);
        const wrapped = binary(result.wrappedKey, MAX_WRAPPED_BYTES);
        if (!wrapped.length) throw new Error();
        const envelope = { format: 1, algorithm: 'AES-256-GCM', keyId, keyVersion,
          wrappedKey: wrapped.toString('base64'), iv: randomBytes(12).toString('base64') };
        const cipher = createCipheriv('aes-256-gcm', dek, Buffer.from(envelope.iv, 'base64'), { authTagLength: 16 });
        cipher.setAAD(payloadAAD(identity, envelope));
        envelope.ciphertext = Buffer.concat([cipher.update(data), cipher.final()]).toString('base64');
        envelope.tag = cipher.getAuthTag().toString('base64');
        return Object.freeze(envelope);
      } catch { throw new FieldEncryptionError(); }
      finally { dek?.fill(0); data?.fill(0); }
    },

    async decryptField(input, expectedIdentity) {
      let dek, tentative;
      try {
        const identity = identitySnapshot(expectedIdentity);
        const envelope = record(input, ENVELOPE_FIELDS);
        if (envelope.format !== 1 || envelope.algorithm !== 'AES-256-GCM' || !allowed.has(text(envelope.keyId, 1024))) throw new Error();
        text(envelope.keyVersion);
        const wrappedKey = decode(envelope.wrappedKey, MAX_WRAPPED_BYTES);
        if (!wrappedKey.length) throw new Error();
        const iv = decode(envelope.iv, 12, 12);
        const ciphertext = decode(envelope.ciphertext, MAX_FIELD_BYTES);
        const tag = decode(envelope.tag, 16, 16);
        if (await authorize(Object.freeze({ identity, operation: 'decrypt' })) !== true) throw new Error();
        dek = binary(await unwrap(Object.freeze({ keyId: envelope.keyId, keyVersion: envelope.keyVersion,
          wrappedKey, context: kmsContext(identity, envelope.keyId) })), 32, 32);
        const decipher = createDecipheriv('aes-256-gcm', dek, iv, { authTagLength: 16 });
        decipher.setAAD(payloadAAD(identity, envelope));
        decipher.setAuthTag(tag);
        tentative = decipher.update(ciphertext);
        const final = decipher.final();
        return Buffer.concat([tentative, final]);
      } catch { throw new FieldEncryptionError(); }
      finally { dek?.fill(0); tentative?.fill(0); }
    }
  });
}
