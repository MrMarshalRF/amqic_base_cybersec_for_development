import { createHash, randomBytes } from 'node:crypto';

const DEK_BYTES = 32;
const MAX_WRAPPED_BYTES = 16 * 1024;
const FIELD_DOMAIN = 'amqic-field-envelope';
const WRAP_DOMAIN = 'amqic-cloud-kms-wrap/v1';
const AWS_ARN = /^arn:aws(?:-[a-z0-9]+)*:kms:[a-z0-9-]+:[0-9]{12}:key\/(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$/u;
const GCP_VERSION = /^projects\/[a-z0-9-]+\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[1-9][0-9]*$/u;
const AZURE_VERSION = /^https:\/\/[a-z0-9-]+\.managedhsm\.azure\.net\/keys\/[A-Za-z0-9-]+\/[a-f0-9]{32}$/u;

class CloudKmsError extends Error {
  constructor() {
    super('Cloud KMS operation failed');
    this.name = 'CloudKmsError';
    this.code = 'cloud_kms_failed';
  }
}

function requireThat(condition) {
  if (!condition) throw new CloudKmsError();
}

function isText(value, limit) {
  return typeof value === 'string' && value.length > 0 && value.length <= limit &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function copyBytes(value, min, max = min) {
  requireThat(value instanceof Uint8Array && value.length >= min && value.length <= max);
  return Buffer.from(value);
}

function takePlaintext(value) {
  try { return copyBytes(value, DEK_BYTES); }
  finally { if (value instanceof Uint8Array) value.fill(0); }
}

function usePlaintext(value, verify) {
  try {
    verify();
    return copyBytes(value, DEK_BYTES);
  } finally {
    if (value instanceof Uint8Array) value.fill(0);
  }
}

function providerBinding(provider, entry, context) {
  requireThat(context?.domain === FIELD_DOMAIN && typeof context.binding === 'string' &&
    /^[a-f0-9]{64}$/u.test(context.binding));
  return createHash('sha256').update(JSON.stringify([
    WRAP_DOMAIN, provider, entry.keyId, entry.keyVersion, entry.resource, context.binding,
  ])).digest();
}

function createPort(provider, keys, resourcePattern, bind, timeoutMs) {
  const aliases = new Map();
  try {
    requireThat(Array.isArray(keys) && keys.length > 0 && keys.length <= 64);
    requireThat(Number.isInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 60_000);
    for (const value of keys) {
      const { keyId, keyVersion, resource, write = false } = value;
      requireThat(isText(keyId, 1024) && isText(keyVersion, 256) && isText(resource, 1024) &&
        resourcePattern.test(resource) && typeof write === 'boolean');
      const alias = aliases.get(keyId) ?? { versions: new Map(), writer: null };
      requireThat(!alias.versions.has(keyVersion) && !(write && alias.writer));
      const entry = Object.freeze({ keyId, keyVersion, resource });
      const target = { entry, ...bind(resource, timeoutMs) };
      alias.versions.set(keyVersion, target);
      if (write) alias.writer = target;
      aliases.set(keyId, alias);
    }
  } catch { throw new TypeError('Invalid cloud KMS configuration'); }

  return Object.freeze({
    async generateDataKey({ keyId, context } = {}) {
      let plaintextKey;
      try {
        const target = aliases.get(keyId)?.writer;
        requireThat(target);
        const binding = providerBinding(provider, target.entry, context);
        const generated = await target.generate(binding);
        plaintextKey = takePlaintext(generated.plaintextKey);
        return { keyId, keyVersion: target.entry.keyVersion, plaintextKey,
          wrappedKey: copyBytes(generated.wrappedKey, 1, MAX_WRAPPED_BYTES) };
      } catch {
        plaintextKey?.fill(0);
        throw new CloudKmsError();
      }
    },
    async unwrapDataKey({ keyId, keyVersion, wrappedKey, context } = {}) {
      try {
        const target = aliases.get(keyId)?.versions.get(keyVersion);
        requireThat(target);
        const binding = providerBinding(provider, target.entry, context);
        const wrapped = copyBytes(wrappedKey, 1, MAX_WRAPPED_BYTES);
        return takePlaintext(await target.unwrap(binding, wrapped));
      } catch { throw new CloudKmsError(); }
    },
  });
}

/** Inject a configured @aws-sdk/client-kms client and its two official commands. */
export function createAwsKmsPort({ keys, client, GenerateDataKeyCommand, DecryptCommand, timeoutMs = 5000 }) {
  return createPort('aws-kms', keys, AWS_ARN, (resource, timeout) => {
    const send = client.send.bind(client);
    requireThat(typeof GenerateDataKeyCommand === 'function' && typeof DecryptCommand === 'function');
    const context = binding => ({ amqic_domain: WRAP_DOMAIN, amqic_binding: binding.toString('hex') });
    const run = command => send(command, { abortSignal: AbortSignal.timeout(timeout) });
    return {
      async generate(binding) {
        const result = await run(new GenerateDataKeyCommand({
          KeyId: resource, KeySpec: 'AES_256', EncryptionContext: context(binding),
        }));
        const plaintextKey = usePlaintext(result?.Plaintext, () => {
          requireThat(result?.KeyId === resource);
          copyBytes(result.CiphertextBlob, 1, MAX_WRAPPED_BYTES);
        });
        return { plaintextKey, wrappedKey: result.CiphertextBlob };
      },
      async unwrap(binding, wrapped) {
        const result = await run(new DecryptCommand({
          KeyId: resource, CiphertextBlob: wrapped,
          EncryptionAlgorithm: 'SYMMETRIC_DEFAULT', EncryptionContext: context(binding),
        }));
        return usePlaintext(result?.Plaintext, () =>
          requireThat(result?.KeyId === resource && result.EncryptionAlgorithm === 'SYMMETRIC_DEFAULT'));
      },
    };
  }, timeoutMs);
}

// Castagnoli checksum. This checks the provider transport and is separate from cryptographic AAD.
function crc32c(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function matchesCrc(value, bytes) {
  const checksum = value?.value;
  return checksum !== null && checksum !== undefined && String(checksum) === String(crc32c(bytes));
}

/** Inject a configured @google-cloud/kms KeyManagementServiceClient (gRPC binary results). */
export function createGcpKmsPort({ keys, client, timeoutMs = 5000 }) {
  return createPort('gcp-kms', keys, GCP_VERSION, (version, timeout) => {
    const encrypt = client.encrypt.bind(client);
    const decrypt = client.decrypt.bind(client);
    const key = version.slice(0, version.lastIndexOf('/cryptoKeyVersions/'));
    const aad = binding => ({
      additionalAuthenticatedData: binding,
      additionalAuthenticatedDataCrc32c: { value: crc32c(binding) },
    });
    return {
      async generate(binding) {
        const secret = randomBytes(DEK_BYTES);
        try {
          const [result] = await encrypt({
            name: version, plaintext: secret, plaintextCrc32c: { value: crc32c(secret) }, ...aad(binding),
          }, { timeout });
          const wrappedKey = copyBytes(result?.ciphertext, 1, MAX_WRAPPED_BYTES);
          requireThat(result.name === version && result.verifiedPlaintextCrc32c === true &&
            result.verifiedAdditionalAuthenticatedDataCrc32c === true && matchesCrc(result.ciphertextCrc32c, wrappedKey));
          return { plaintextKey: Buffer.from(secret), wrappedKey };
        } finally { secret.fill(0); }
      },
      async unwrap(binding, wrapped) {
        const [result] = await decrypt({
          name: key, ciphertext: wrapped, ciphertextCrc32c: { value: crc32c(wrapped) }, ...aad(binding),
        }, { timeout });
        return usePlaintext(result?.plaintext, () =>
          requireThat(result?.plaintext instanceof Uint8Array && result.plaintext.length === DEK_BYTES &&
            matchesCrc(result.plaintextCrc32c, result.plaintext)));
      },
    };
  }, timeoutMs);
}

/** Inject @azure/keyvault-keys CryptographyClient and a workload TokenCredential. */
export function createAzureKmsPort({ keys, CryptographyClient, credential, timeoutMs = 5000 }) {
  return createPort('azure-managed-hsm', keys, AZURE_VERSION, (resource, timeout) => {
    const client = new CryptographyClient(resource, credential);
    const encrypt = client.encrypt.bind(client);
    const decrypt = client.decrypt.bind(client);
    const algorithm = 'A256GCM';
    return {
      async generate(binding) {
        const secret = randomBytes(DEK_BYTES);
        try {
          const result = await encrypt({
            algorithm, plaintext: secret, additionalAuthenticatedData: binding,
          }, { abortSignal: AbortSignal.timeout(timeout) });
          requireThat(result?.keyID === resource && result.algorithm === algorithm);
          const wrappedKey = Buffer.concat([
            copyBytes(result.iv, 12), copyBytes(result.authenticationTag, 16), copyBytes(result.result, DEK_BYTES),
          ]);
          return { plaintextKey: Buffer.from(secret), wrappedKey };
        } finally { secret.fill(0); }
      },
      async unwrap(binding, wrapped) {
        requireThat(wrapped.length === 12 + 16 + DEK_BYTES);
        const result = await decrypt({
          algorithm, iv: wrapped.subarray(0, 12), authenticationTag: wrapped.subarray(12, 28),
          ciphertext: wrapped.subarray(28), additionalAuthenticatedData: binding,
        }, { abortSignal: AbortSignal.timeout(timeout) });
        return usePlaintext(result?.result, () =>
          requireThat(result?.keyID === resource && result.algorithm === algorithm));
      },
    };
  }, timeoutMs);
}
