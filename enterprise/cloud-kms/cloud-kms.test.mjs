import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import test from 'node:test';
import { createFieldEncryption } from '../../reference/field-encryption.mjs';
import { createAwsKmsPort, createAzureKmsPort, createGcpKmsPort } from './cloud-kms.mjs';

const awsA = 'arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000001';
const awsB = 'arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000002';
const gcpKey = 'projects/demo-project/locations/global/keyRings/demo/cryptoKeys/field';
const azureVersion = 'https://demo.managedhsm.azure.net/keys/field/00000000000000000000000000000001';
const keyId = 'tenant-a-fields';
const context = Object.freeze({ domain: 'amqic-field-envelope', binding: 'a'.repeat(64) });
const differentContext = Object.freeze({ ...context, binding: 'b'.repeat(64) });
const keys = resource => [{ keyId, keyVersion: 'epoch-1', resource, write: true }];
const genericFailure = { name: 'CloudKmsError', code: 'cloud_kms_failed', message: 'Cloud KMS operation failed' };

class GenerateDataKeyCommand {
  constructor(input) { this.input = input; }
}

class DecryptCommand {
  constructor(input) { this.input = input; }
}

// A synthetic wrapping service with real AEAD, so AAD mismatch tests depend on authentication.
function fakeCipher() {
  const kek = randomBytes(32);
  const wrap = (key, aad) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, iv);
    cipher.setAAD(aad);
    const result = Buffer.concat([cipher.update(key), cipher.final()]);
    return { iv, authenticationTag: cipher.getAuthTag(), result };
  };
  const unwrap = (wrapped, aad) => {
    const cipher = createDecipheriv('aes-256-gcm', kek, wrapped.iv);
    cipher.setAAD(aad);
    cipher.setAuthTag(wrapped.authenticationTag);
    return Buffer.concat([cipher.update(wrapped.result), cipher.final()]);
  };
  return { wrap, unwrap };
}

function packed({ iv, authenticationTag, result }) {
  return Buffer.concat([iv, authenticationTag, result]);
}

function unpacked(value) {
  return { iv: value.subarray(0, 12), authenticationTag: value.subarray(12, 28), result: value.subarray(28) };
}

test('AWS uses official command shapes, exact ARN and encryption context across a field round trip', async () => {
  const cipher = fakeCipher();
  const contexts = [];
  const plaintextBuffers = [];
  const makePort = (records) => createAwsKmsPort({
    keys: records, GenerateDataKeyCommand, DecryptCommand,
    client: {
      async send(command, options) {
        assert.ok(options.abortSignal instanceof AbortSignal);
        const input = command.input;
        assert.ok([awsA, awsB].includes(input.KeyId));
        assert.equal(input.EncryptionContext.amqic_domain, 'amqic-cloud-kms-wrap/v1');
        assert.match(input.EncryptionContext.amqic_binding, /^[a-f0-9]{64}$/u);
        assert.deepEqual(Object.keys(input.EncryptionContext).sort(), ['amqic_binding', 'amqic_domain']);
        const aad = Buffer.from(JSON.stringify([input.KeyId, input.EncryptionContext]));
        contexts.push(input.EncryptionContext.amqic_binding);
        if (command instanceof GenerateDataKeyCommand) {
          assert.equal(input.KeySpec, 'AES_256');
          const Plaintext = randomBytes(32);
          plaintextBuffers.push(Plaintext);
          return { KeyId: input.KeyId, Plaintext, CiphertextBlob: packed(cipher.wrap(Plaintext, aad)) };
        }
        assert.ok(command instanceof DecryptCommand);
        assert.equal(input.EncryptionAlgorithm, 'SYMMETRIC_DEFAULT');
        const Plaintext = cipher.unwrap(unpacked(input.CiphertextBlob), aad);
        plaintextBuffers.push(Plaintext);
        return { KeyId: input.KeyId, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', Plaintext };
      },
    },
  });
  const identity = { tenant: 'synthetic tenant', table: 't', record: 'r', field: 'f', purpose: 'test', version: '1' };
  const open = kms => createFieldEncryption({ kms, keyId, allowedKeyIds: [keyId], authorize: async () => true });
  const first = open(makePort(keys(awsA)));
  const encrypted = await first.encryptField(Buffer.from('synthetic'), identity);
  assert.equal(encrypted.keyVersion, 'epoch-1');
  const latest = open(makePort([
    { ...keys(awsA)[0], write: false },
    { keyId, keyVersion: 'epoch-2', resource: awsB, write: true },
  ]));
  assert.equal((await latest.decryptField(encrypted, identity)).toString(), 'synthetic');
  assert.equal(contexts[0], contexts[1]);
  const followUp = await latest.encryptField(Buffer.from('new'), identity);
  assert.equal(followUp.keyVersion, 'epoch-2');
  assert.notEqual(contexts[0], contexts[2]);
  await assert.rejects(latest.decryptField(encrypted, { ...identity, tenant: 'other' }), { code: 'field_encryption_failed' });
  const retired = open(makePort([{ keyId, keyVersion: 'epoch-2', resource: awsB, write: true }]));
  const previousCalls = contexts.length;
  await assert.rejects(retired.decryptField(encrypted, identity), { code: 'field_encryption_failed' });
  assert.equal(contexts.length, previousCalls);
  assert.ok(plaintextBuffers.every(bytes => bytes.every(x => x === 0)));
});

test('invalid resources and mismatched AWS results fail closed without relaying provider error details', async () => {
  let calls = 0;
  const policy = {
    keys: keys(awsA), GenerateDataKeyCommand, DecryptCommand,
    client: { async send() { calls++; throw new Error('synthetic-sensitive-diagnostic'); } },
  };
  assert.throws(() => createAwsKmsPort({ ...policy, keys: keys(awsA.replace('key/', 'alias/')) }), TypeError);
  assert.throws(() => createAwsKmsPort({ ...policy, keys: [...keys(awsA), ...keys(awsB)] }), TypeError);
  const port = createAwsKmsPort(policy);
  await assert.rejects(port.generateDataKey({ keyId: 'cross-tenant', context }), genericFailure);
  await assert.rejects(port.generateDataKey({ keyId, context: { ...context, binding: 'unbounded' } }), genericFailure);
  await assert.rejects(port.unwrapDataKey({ keyId, keyVersion: 'retired', wrappedKey: Buffer.alloc(32), context }), genericFailure);
  assert.equal(calls, 0);
  await assert.rejects(port.generateDataKey({ keyId, context }), genericFailure);
  assert.equal(calls, 1);
  const Plaintext = Buffer.alloc(32, 1);
  const wrong = createAwsKmsPort({
    ...policy, client: { async send() { return { Plaintext, KeyId: awsB, CiphertextBlob: Buffer.alloc(32) }; } },
  });
  await assert.rejects(wrong.generateDataKey({ keyId, context }), genericFailure);
  assert.ok(Plaintext.every(x => x === 0));
});

const crcTable = Array.from({ length: 256 }, (_, n) => {
  for (let bit = 0; bit < 8; bit++) n = n & 1 ? 0x82f63b78 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
const checksum = bytes => ({
  value: (bytes.reduce((crc, b) => crcTable[(crc ^ b) & 255] ^ (crc >>> 8), -1) ^ -1) >>> 0,
});

test('GCP pins the encrypt version and verifies CRC32C and provider-bound AAD', async () => {
  assert.equal(checksum(Buffer.from('123456789')).value, 0xe3069283);
  const cipher = fakeCipher();
  const version = `${gcpKey}/cryptoKeyVersions/7`;
  let serverName = version;
  let corrupt = false;
  let requestPlaintext;
  const client = {
    async encrypt(input, options) {
      assert.equal(input.name, version);
      assert.equal(options.timeout, 5000);
      assert.deepEqual(input.plaintextCrc32c, checksum(input.plaintext));
      assert.deepEqual(input.additionalAuthenticatedDataCrc32c, checksum(input.additionalAuthenticatedData));
      requestPlaintext = input.plaintext;
      const ciphertext = packed(cipher.wrap(input.plaintext, input.additionalAuthenticatedData));
      return [{
        name: serverName, ciphertext, ciphertextCrc32c: checksum(ciphertext),
        verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true,
      }];
    },
    async decrypt(input) {
      assert.equal(input.name, gcpKey);
      assert.deepEqual(input.ciphertextCrc32c, checksum(input.ciphertext));
      assert.deepEqual(input.additionalAuthenticatedDataCrc32c, checksum(input.additionalAuthenticatedData));
      const plaintext = cipher.unwrap(unpacked(input.ciphertext), input.additionalAuthenticatedData);
      const plaintextCrc32c = checksum(plaintext);
      if (corrupt) plaintextCrc32c.value ^= 1;
      return [{ plaintext, plaintextCrc32c }];
    },
  };
  const port = createGcpKmsPort({ keys: keys(version), client });
  const { wrappedKey, plaintextKey, keyVersion } = await port.generateDataKey({ keyId, context });
  assert.ok(requestPlaintext.every(x => x === 0), 'adapter clears its generated DEK after wrapping');
  assert.deepEqual(await port.unwrapDataKey({ keyId, keyVersion, wrappedKey, context }), plaintextKey);
  await assert.rejects(port.unwrapDataKey({ keyId, keyVersion, wrappedKey, context: differentContext }), genericFailure);
  corrupt = true;
  await assert.rejects(port.unwrapDataKey({ keyId, keyVersion, wrappedKey, context }), genericFailure);
  serverName = `${gcpKey}/cryptoKeyVersions/8`;
  await assert.rejects(port.generateDataKey({ keyId, context }), genericFailure);
  plaintextKey.fill(0);
});

test('Azure Managed HSM A256GCM uses the versioned key and native AAD with a bounded envelope', async () => {
  const cipher = fakeCipher();
  const credential = Object.freeze({ synthetic: true });
  let keyEcho = azureVersion;
  let decryptCalls = 0;
  let responsePlaintext;
  class CryptographyClient {
    constructor(id, supplied) {
      assert.equal(id, azureVersion);
      assert.equal(supplied, credential);
    }
    async encrypt(input, { abortSignal }) {
      assert.equal(input.algorithm, 'A256GCM');
      assert.ok(abortSignal instanceof AbortSignal);
      assert.equal(input.additionalAuthenticatedData.length, 32);
      return { keyID: keyEcho, algorithm: input.algorithm, ...cipher.wrap(input.plaintext, input.additionalAuthenticatedData) };
    }
    async decrypt(input) {
      decryptCalls++;
      const { ciphertext, iv, authenticationTag, additionalAuthenticatedData, algorithm } = input;
      responsePlaintext = cipher.unwrap({ iv, authenticationTag, result: ciphertext }, additionalAuthenticatedData);
      return { keyID: keyEcho, algorithm, result: responsePlaintext };
    }
  }
  assert.throws(() => createAzureKmsPort({ keys: keys(azureVersion.split('/').slice(0, -1).join('/')),
    CryptographyClient, credential }), TypeError);
  const port = createAzureKmsPort({ keys: keys(azureVersion), CryptographyClient, credential });
  const { wrappedKey, plaintextKey, keyVersion } = await port.generateDataKey({ keyId, context });
  assert.equal(wrappedKey.length, 60);
  assert.deepEqual(await port.unwrapDataKey({ keyId, keyVersion, wrappedKey, context }), plaintextKey);
  assert.ok(responsePlaintext.every(x => x === 0));
  await assert.rejects(port.unwrapDataKey({ keyId, keyVersion, wrappedKey: wrappedKey.subarray(1), context }), genericFailure);
  assert.equal(decryptCalls, 1);
  await assert.rejects(port.unwrapDataKey({ keyId, keyVersion, wrappedKey, context: differentContext }), genericFailure);
  keyEcho = azureVersion.replace(/1$/u, '2');
  await assert.rejects(port.unwrapDataKey({ keyId, keyVersion, wrappedKey, context }), genericFailure);
  assert.ok(responsePlaintext.every(x => x === 0));
  plaintextKey.fill(0);
});
