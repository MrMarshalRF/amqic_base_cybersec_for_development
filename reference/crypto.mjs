import { createHash, createHmac, randomBytes, scryptSync, sign, timingSafeEqual } from 'node:crypto';

export function canonical(value) {
  return encode(value, 0);
}

function encode(value, depth) {
  if (depth > 32) throw new TypeError('Canonical nesting limit exceeded');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + Array.from(value, item => encode(item, depth + 1)).join(',') + ']';
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + encode(value[key], depth + 1)).join(',') + '}';
  }
  throw new TypeError('Unsupported canonical value');
}

export const hash = value => createHash('sha256').update(value).digest('hex');
export const opaque = () => randomBytes(32).toString('base64url');

export function passwordRecord(password) {
  if (typeof password !== 'string' || Buffer.byteLength(password) < 12 || Buffer.byteLength(password) > 1024) {
    throw new TypeError('Password must contain 12 to 1024 UTF-8 bytes');
  }
  const salt = randomBytes(16).toString('hex');
  const digest = scryptSync(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString('hex');
  return { salt, digest };
}

export function checkPassword(password, record) {
  const valid = typeof password === 'string' && Buffer.byteLength(password) <= 1024;
  const input = valid ? password : 'invalid-password-input';
  const actual = scryptSync(input, record.salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return timingSafeEqual(actual, Buffer.from(record.digest, 'hex')) && valid;
}

export function totp(secret, counter, digits = 6, algorithm = 'sha1') {
  if (!Buffer.isBuffer(secret) || secret.length < 20 || !Number.isSafeInteger(counter) || counter < 0 || ![6, 8].includes(digits)) {
    throw new TypeError('Invalid TOTP parameters');
  }
  const moving = Buffer.alloc(8);
  moving.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(algorithm, secret).update(moving).digest();
  const offset = digest[digest.length - 1] & 15;
  const number = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(number % (10 ** digits)).padStart(digits, '0');
}

export function signedBytes(request) {
  const { keyId, method, target, audience, timestamp, nonce, body } = request;
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(keyId) || !/^[A-Z]{1,16}$/.test(method) ||
      typeof target !== 'string' || !/^\/[\x21-\x7e]*$/.test(target) || /[#\\]/.test(target) ||
      typeof audience !== 'string' || audience.length < 1 || audience.length > 256 ||
      !Number.isSafeInteger(timestamp) || !/^[A-Za-z0-9_-]{32,128}$/.test(nonce) ||
      !Buffer.isBuffer(body) || body.length > 65536) throw new TypeError('Invalid signed request');
  return Buffer.from(canonical({ protocol: 'defensive-request-v1', keyId, method, target, audience,
    timestamp, nonce, bodyHash: hash(body) }));
}

export function signRequest(privateKey, input) {
  const request = { ...input, nonce: input.nonce ?? opaque() };
  request.signature = sign(null, signedBytes(request), privateKey).toString('base64url');
  return request;
}
