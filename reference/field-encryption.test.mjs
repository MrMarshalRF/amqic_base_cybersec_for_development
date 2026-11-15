import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { createFieldEncryption, FieldEncryptionError, MAX_FIELD_BYTES } from './field-encryption.mjs';

const identity = () => ({ tenant: 'tenant-a', table: 'contacts', record: 'row-7', field: 'private_note', purpose: 'contact-service', version: '1' });

// Synthetic, in-memory KMS for these tests ONLY. No production adapter or network.
function mockKms() {
  const keys = new Map([['kms/key-a:v1', randomBytes(32)], ['kms/key-a:v2', randomBytes(32)], ['kms/key-b:v1', randomBytes(32)]]);
  const state = { generates: 0, unwraps: 0, version: 'v1', returnedKeys: [] };
  const aad = (id, version, context) => Buffer.from(JSON.stringify([id, version, context.domain, context.binding]));
  return Object.assign(state, {
    async generateDataKey({ keyId, context }) {
      state.generates++;
      const plaintextKey = randomBytes(32);
      state.returnedKeys.push(plaintextKey);
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keys.get(`${keyId}:${state.version}`), iv);
      cipher.setAAD(aad(keyId, state.version, context));
      const encrypted = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
      return { keyId, keyVersion: state.version, plaintextKey, wrappedKey: Buffer.concat([iv, cipher.getAuthTag(), encrypted]) };
    },
    async unwrapDataKey({ keyId, keyVersion, wrappedKey, context }) {
      state.unwraps++;
      const key = keys.get(`${keyId}:${keyVersion}`);
      if (!key) throw new Error('Unretained key version');
      const decipher = createDecipheriv('aes-256-gcm', key, wrappedKey.subarray(0, 12));
      decipher.setAAD(aad(keyId, keyVersion, context));
      decipher.setAuthTag(wrappedKey.subarray(12, 28));
      const plaintextKey = Buffer.concat([decipher.update(wrappedKey.subarray(28)), decipher.final()]);
      state.returnedKeys.push(plaintextKey);
      return plaintextKey;
    }
  });
}
function setup(overrides = {}) {
  const kms = overrides.kms ?? mockKms();
  return { kms, service: createFieldEncryption({ kms, keyId: 'kms/key-a', allowedKeyIds: ['kms/key-a'], authorize: async () => true, ...overrides }) };
}
const fail = async operation => assert.rejects(operation, error => error instanceof FieldEncryptionError && error.code === 'field_encryption_failed' && error.message === 'Field encryption operation failed' && error.cause === undefined);
const mutateBase64 = value => { const bytes = Buffer.from(value, 'base64'); bytes[0] ^= 1; return bytes.toString('base64'); };

test('binary and empty plaintext round trip; only envelope metadata is serialized', async () => {
  const { service } = setup();
  for (const plain of [Buffer.from('sensitive synthetic private note'), Buffer.alloc(0), Buffer.from([0, 255, 127, 0])]) {
    const envelope = await service.encryptField(plain, identity());
    assert.deepEqual(await service.decryptField(JSON.parse(JSON.stringify(envelope)), identity()), plain);
    if (plain.length > 4) assert.equal(JSON.stringify(envelope).includes(plain.toString()), false);
    assert.equal(Object.hasOwn(envelope, 'plaintextKey'), false);
    assert.equal(Object.hasOwn(envelope, 'identity'), false);
  }
});

test('concurrent writes use fresh DEKs, nonces and ciphertext for the same value', async () => {
  const { service } = setup();
  const envelopes = await Promise.all(Array.from({ length: 32 }, () => service.encryptField(Buffer.from('same'), identity())));
  for (const field of ['iv', 'wrappedKey', 'ciphertext']) assert.equal(new Set(envelopes.map(e => e[field])).size, 32);
});

test('explicit retained old key ID and version work after writer rotation', async () => {
  const kms = mockKms();
  const old = setup({ kms }).service;
  const previous = await old.encryptField(Buffer.from('old'), identity());
  kms.version = 'v2';
  const secondVersion = await old.encryptField(Buffer.from('new version'), identity());
  assert.deepEqual(await old.decryptField(previous, identity()), Buffer.from('old'));
  assert.deepEqual(await old.decryptField(secondVersion, identity()), Buffer.from('new version'));
  kms.version = 'v1';
  const rotated = setup({ kms, keyId: 'kms/key-b', allowedKeyIds: ['kms/key-a', 'kms/key-b'] }).service;
  assert.deepEqual(await rotated.decryptField(previous, identity()), Buffer.from('old'));
  const next = await rotated.encryptField(Buffer.from('new key'), identity());
  await fail(() => old.decryptField(next, identity()));
  assert.equal(kms.unwraps, 3, 'disallowed new key rejected before KMS');
});

for (const field of ['tenant', 'table', 'record', 'field', 'purpose', 'version']) {
  test(`trusted expected ${field} is authenticated`, async () => {
    const { service } = setup();
    const envelope = await service.encryptField(Buffer.from('private'), identity());
    await fail(() => service.decryptField(envelope, { ...identity(), [field]: 'different' }));
  });
}
for (const field of ['iv', 'ciphertext', 'tag', 'wrappedKey']) {
  test(`${field} tampering fails closed`, async () => {
    const { service } = setup();
    const envelope = await service.encryptField(Buffer.from('private'), identity());
    await fail(() => service.decryptField({ ...envelope, [field]: mutateBase64(envelope[field]) }, identity()));
  });
}
test('header substitutions fail even when a trusted port returns the same DEK', async () => {
  const dek = randomBytes(32);
  const { service } = setup({ allowedKeyIds: ['kms/key-a', 'kms/key-b'], kms: {
    async generateDataKey({ keyId }) { return { keyId, keyVersion: 'v1', plaintextKey: dek, wrappedKey: Buffer.from('synthetic') }; },
    async unwrapDataKey() { return dek; }
  } });
  const envelope = await service.encryptField(Buffer.from('private'), identity());
  for (const change of [{ keyId: 'kms/key-b' }, { keyVersion: 'v2' }, { wrappedKey: Buffer.from('other').toString('base64') }]) {
    await fail(() => service.decryptField({ ...envelope, ...change }, identity()));
  }
});

test('invalid schema and bounded canonical base64 rejected before unwrap', async () => {
  const { service, kms } = setup();
  const envelope = await service.encryptField(Buffer.from('private'), identity());
  const accessor = { ...envelope };
  Object.defineProperty(accessor, 'keyId', { enumerable: true, get() { throw new Error('getter must not run'); } });
  const candidates = [accessor, Object.assign(Object.create({}), envelope), { ...envelope, extra: true }, { ...envelope, [Symbol('extra')]: true },
    { ...envelope, format: 2 }, { ...envelope, algorithm: 'AES-128-GCM' }, { ...envelope, keyId: 'kms/unapproved' },
    { ...envelope, keyVersion: '' }, { ...envelope, keyVersion: 'v'.repeat(257) },
    { ...envelope, iv: 'AB==' }, { ...envelope, iv: envelope.iv + '\n' }, { ...envelope, tag: 'AAAA' },
    { ...envelope, wrappedKey: '' }, { ...envelope, wrappedKey: 'A'.repeat(22000) },
    { ...envelope, ciphertext: 'A'.repeat(Math.ceil(MAX_FIELD_BYTES / 3) * 4 + 4) }];
  for (const candidate of candidates) await fail(() => service.decryptField(candidate, identity()));
  assert.equal(kms.unwraps, 0);
});

test('authorization denial, non-boolean permission and exceptions never reach KMS', async () => {
  const base = setup();
  const envelope = await base.service.encryptField(Buffer.from('private'), identity());
  for (const authorize of [async () => false, async () => undefined, async () => 'true', async () => { throw new Error('secret provider details'); }]) {
    const { service, kms } = setup({ authorize });
    await fail(() => service.encryptField(Buffer.from('private'), identity()));
    await fail(() => service.decryptField(envelope, identity()));
    assert.equal(kms.generates + kms.unwraps, 0);
  }
  assert.throws(() => setup({ authorize: undefined }), TypeError);
});

test('wrong DEKs, unavailable KMS and unretained versions return the same safe error', async () => {
  const base = setup();
  const envelope = await base.service.encryptField(Buffer.from('private'), identity());
  for (const unwrapDataKey of [async () => { throw new Error('sensitive provider details'); }, async () => randomBytes(32), async () => randomBytes(31), async () => 'not binary']) {
    const { service } = setup({ kms: { generateDataKey: base.kms.generateDataKey, unwrapDataKey } });
    await fail(() => service.decryptField(envelope, identity()));
  }
  await fail(() => base.service.decryptField({ ...envelope, keyVersion: 'retired' }, identity()));
  const { service } = setup({ kms: { async generateDataKey() { throw new Error('outage'); }, async unwrapDataKey() {} } });
  await fail(() => service.encryptField(Buffer.from('private'), identity()));
});

test('provider-generated aliases and malformed key metadata are rejected', async () => {
  for (const change of [{ keyId: 'alias/key-a' }, { plaintextKey: randomBytes(31) }, { plaintextKey: new Uint8Array(32) }, { wrappedKey: Buffer.alloc(0) }, { wrappedKey: Buffer.alloc(16385) }, { keyVersion: '' }]) {
    const kms = mockKms();
    const original = kms.generateDataKey;
    kms.generateDataKey = async args => ({ ...await original(args), ...change });
    const { service } = setup({ kms });
    await fail(() => service.encryptField(Buffer.from('private'), identity()));
  }
});

test('identity and plaintext snapshots survive mutation during awaited authorization', async () => {
  let release;
  let observed;
  const barrier = new Promise(resolve => { release = resolve; });
  const { service } = setup({ authorize: async request => { observed = request; if (request.operation === 'encrypt') await barrier; return true; } });
  const row = identity();
  const plain = Buffer.from('original');
  const pending = service.encryptField(plain, row);
  row.tenant = 'attacker';
  plain.fill(0);
  assert.equal(Object.isFrozen(observed.identity), true);
  assert.equal(observed.identity.tenant, 'tenant-a');
  release();
  const envelope = await pending;
  assert.deepEqual(await service.decryptField(envelope, identity()), Buffer.from('original'));
  assert.deepEqual(plain, Buffer.alloc(8));
});

test('envelope snapshot survives mutation during authorization wait', async () => {
  const base = setup();
  const envelope = { ...await base.service.encryptField(Buffer.from('private'), identity()) };
  let release;
  const barrier = new Promise(resolve => { release = resolve; });
  const { service } = setup({ kms: base.kms, authorize: async () => { await barrier; return true; } });
  const row = identity();
  const pending = service.decryptField(envelope, row);
  envelope.keyId = 'attacker'; envelope.keyVersion = 'attacker'; envelope.ciphertext = '';
  row.record = 'other';
  release();
  assert.deepEqual(await pending, Buffer.from('private'));
});

test('envelope and expected identity snapshots also survive a deferred KMS unwrap', async () => {
  const kms = mockKms();
  const { service: writer } = setup({ kms });
  const envelope = { ...await writer.encryptField(Buffer.from('private'), identity()) };
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  const original = kms.unwrapDataKey;
  kms.unwrapDataKey = async args => { entered(); await barrier; return original(args); };
  const { service } = setup({ kms });
  const row = identity();
  const pending = service.decryptField(envelope, row);
  await started;
  envelope.wrappedKey = ''; envelope.tag = ''; envelope.keyVersion = 'different';
  row.tenant = 'different';
  release();
  assert.deepEqual(await pending, Buffer.from('private'));
});

test('port-owned keys and caller plaintext remain untouched; context omits raw identity', async () => {
  const kms = mockKms();
  const generate = kms.generateDataKey;
  let captured;
  kms.generateDataKey = async args => { captured = args; return generate(args); };
  const { service } = setup({ kms });
  const plain = Buffer.from('private');
  const envelope = await service.encryptField(plain, identity());
  const keyBefore = Buffer.from(kms.returnedKeys[0]);
  await service.decryptField(envelope, identity());
  assert.deepEqual(plain, Buffer.from('private'));
  assert.deepEqual(kms.returnedKeys[0], keyBefore);
  assert.notDeepEqual(keyBefore, Buffer.alloc(32));
  assert.equal(captured.context.binding.length, 64);
  assert.equal(JSON.stringify(captured.context).includes('tenant-a'), false);
  assert.equal(JSON.stringify(captured.context).includes('row-7'), false);
});

test('input limits and startup key policy fail closed', async () => {
  const { service, kms } = setup();
  await fail(() => service.encryptField('implicit strings rejected', identity()));
  await fail(() => service.encryptField(Buffer.alloc(MAX_FIELD_BYTES + 1), identity()));
  await fail(() => service.encryptField(Buffer.from('x'), { ...identity(), extra: true }));
  assert.equal(kms.generates, 0);
  assert.throws(() => setup({ allowedKeyIds: ['kms/key-b'] }), TypeError);
  assert.throws(() => setup({ allowedKeyIds: [] }), TypeError);
  const maximum = Buffer.alloc(MAX_FIELD_BYTES, 42);
  assert.deepEqual(await service.decryptField(await service.encryptField(maximum, identity()), identity()), maximum);
});
