import { constants, lstatSync, openSync, fstatSync, readSync, closeSync, readdirSync } from 'node:fs';
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const sha256Pattern = /^[a-f0-9]{64}$/;
const commitPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const decoder = new TextDecoder('utf-8', { fatal: true });
const maxFileBytes = 64 * 1024 * 1024;
const maxTotalBytes = 512 * 1024 * 1024;
const maxEntries = 20_000;
const sourceExclusions = new Set(['SHA256SUMS', 'SHA256SUMS.sig']);

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function validPath(path) {
  return typeof path === 'string' && path.length > 0 && path.length <= 512 && path.split('/').every(
    part => /^[a-zA-Z0-9._+@-]{1,128}$/.test(part) && !part.endsWith('.') &&
      !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part),
  );
}

function readPlain(path, limit = maxFileBytes) {
  const original = lstatSync(path);
  requireThat(original.isFile() && original.nlink === 1 && original.size <= limit, 'Expected a bounded plain file.');
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const start = fstatSync(fd);
    requireThat(start.isFile() && start.nlink === 1 && start.dev === original.dev &&
      start.ino === original.ino && start.size <= limit, 'File changed before reading.');
    const bytes = Buffer.allocUnsafe(start.size);
    for (let offset = 0; offset < bytes.length;) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      requireThat(count > 0, 'File shortened during reading.');
      offset += count;
    }
    const end = fstatSync(fd);
    requireThat(bytes.length === end.size &&
      start.mtimeMs === end.mtimeMs && start.ctimeMs === end.ctimeMs, 'File changed during reading.');
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function isText(bytes) {
  try {
    return !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/u.test(decoder.decode(bytes));
  } catch {
    return false;
  }
}

function walk(root, sourceMode, visit) {
  requireThat(lstatSync(root).isDirectory(), 'Expected a plain payload directory.');
  const seen = new Set();
  let entries = 0;
  let size = 0;
  function scan(directory, prefix) {
    for (const name of readdirSync(directory).sort()) {
      const path = prefix ? prefix + '/' + name : name;
      const file = join(directory, name);
      const info = lstatSync(file);
      if (sourceMode && path === '.git' && (info.isDirectory() || info.isFile())) continue;
      requireThat(validPath(path) && !seen.has(path.toLowerCase()) && ++entries <= maxEntries,
        'Invalid or duplicate payload path, or entry limit exceeded.');
      seen.add(path.toLowerCase());
      if (info.isDirectory()) {
        requireThat(!sourceMode || !sourceExclusions.has(path), 'Registry path must be a file.');
        scan(file, path);
      } else if (sourceMode && sourceExclusions.has(path)) {
        requireThat(info.isFile() && info.nlink === 1, 'Registry path must be a plain file.');
      } else {
        const bytes = readPlain(file);
        size += bytes.length;
        requireThat(size <= maxTotalBytes, 'Payload size limit exceeded.');
        visit(path, bytes);
      }
    }
  }
  scan(root, '');
}

export function checkSha256(root) {
  const registry = decoder.decode(readPlain(join(root, 'SHA256SUMS'), 16 * 1024 * 1024));
  const lines = registry.replace(/\r?\n$/, '').split(/\r?\n/);
  const expected = new Map();
  for (const line of lines) {
    const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(line);
    requireThat(match && validPath(match[2]) && !expected.has(match[2]), 'Malformed or duplicate checksum entry.');
    expected.set(match[2], match[1]);
  }
  let files = 0;
  walk(root, true, (path, bytes) => {
    requireThat(expected.get(path) === sha256(bytes), 'Unexpected file or checksum mismatch.');
    expected.delete(path);
    files++;
  });
  requireThat(expected.size === 0, 'Checksum registry lists missing files.');
  return { status: 'verified', files };
}

function readPolicy(policy) {
  requireThat(record(policy) && Object.keys(policy).length === 2 && policy.schemaVersion === 1 &&
    record(policy.binaries), 'Invalid binary policy.');
  const pins = Object.entries(policy.binaries);
  requireThat(pins.length <= maxEntries && pins.every(([path, hash]) => validPath(path) &&
    typeof hash === 'string' && sha256Pattern.test(hash)), 'Invalid binary policy entry.');
  return new Map(pins.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
}

export function inventory(root, policy, sourceCommit) {
  requireThat(typeof sourceCommit === 'string' && commitPattern.test(sourceCommit), 'Expected a full source commit identifier.');
  const binaries = readPolicy(policy);
  const policySha256 = sha256(encode({ schemaVersion: 1, binaries: Object.fromEntries(binaries) }));
  const files = [];
  walk(root, false, (path, bytes) => {
    const digest = sha256(bytes);
    const text = isText(bytes);
    if (!text || binaries.has(path)) {
      requireThat(binaries.get(path) === digest, 'Unexpected binary or binary pin mismatch.');
      binaries.delete(path);
    }
    files.push({ path, size: bytes.length, sha256: digest, format: text ? 'utf8-text' : 'binary' });
  });
  requireThat(files.length && binaries.size === 0, 'Empty payload or missing file from binary policy.');
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { schemaVersion: 1, kind: 'amqic.release-subject', sourceCommit, policySha256, files };
}

export function checkInventory(root, policy, manifest, sourceCommit) {
  const expected = encode(inventory(root, policy, sourceCommit));
  requireThat(Buffer.isBuffer(manifest) && expected.equals(manifest), 'Release inventory does not match the expected subject.');
  return { status: 'matched', inventorySha256: sha256(expected) };
}

export function verifyInventory(root, policy, manifest, signature, trustedPublicPem, sourceCommit) {
  requireThat(Buffer.isBuffer(manifest) && Buffer.isBuffer(signature) && signature.length === 64 &&
    /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(trustedPublicPem),
  'Expected an Ed25519 public key and a raw detached signature.');
  const publicKey = createPublicKey(trustedPublicPem);
  requireThat(publicKey.asymmetricKeyType === 'ed25519' && verifySignature(null, manifest, publicKey, signature),
    'Detached inventory signature failed.');
  return { ...checkInventory(root, policy, manifest, sourceCommit), status: 'verified' };
}

function componentField(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 &&
    !/[\u0000-\u001F\u007F-\u009F]/u.test(value);
}

function bom(components, scope, sourceHash) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      lifecycles: [{ phase: 'pre-build' }],
      properties: [
        { name: 'amqic:inventory:scope', value: scope },
        { name: 'amqic:inventory:input-sha256', value: sourceHash },
      ],
    },
    components,
    compositions: [{ aggregate: 'incomplete' }],
  };
}

function parseIntegrity(value) {
  requireThat(typeof value === 'string' && value.length <= 1024, 'Missing or invalid package integrity.');
  const sizes = { sha256: 32, sha384: 48, sha512: 64 };
  const integrity = new Map();
  for (const token of value.split(/ +/)) {
    const match = /^(sha(?:256|384|512))-([a-zA-Z0-9+/]+={0,2})$/.exec(token);
    requireThat(match && !integrity.has(match[1]), 'Invalid or ambiguous package integrity.');
    const bytes = Buffer.from(match[2], 'base64');
    requireThat(bytes.length === sizes[match[1]] && bytes.toString('base64') === match[2], 'Invalid package integrity encoding.');
    integrity.set(match[1], bytes);
  }
  return integrity;
}

function lockedPackages(bytes) {
  const lock = JSON.parse(decoder.decode(bytes));
  requireThat(record(lock) && [2, 3].includes(lock.lockfileVersion) && record(lock.packages), 'Expected npm lockfile v2 or v3.');
  const entries = Object.entries(lock.packages).filter(([path]) => path).sort();
  requireThat(entries.length <= maxEntries, 'Too many locked packages.');
  return entries.map(([path, value]) => {
    const suffix = /(?:^|\/)node_modules\/((?:@[\w.-]+\/)?[\w.-]+)$/.exec(path);
    const name = value?.name ?? suffix?.[1];
    requireThat(validPath(path) && suffix && record(value) && !value.link && !value.inBundle &&
      typeof name === 'string' && /^(?:@[\w.-]+\/)?[\w.-]+$/.test(name) &&
      componentField(name) && componentField(value.version), 'Unsupported npm lock entry.');
    return { path, name, version: value.version, integrity: parseIntegrity(value.integrity) };
  });
}

export function npmSbom(lockBytes) {
  const components = lockedPackages(lockBytes).map(entry => ({
    type: 'library', name: entry.name, version: entry.version, 'bom-ref': entry.path,
    properties: [...entry.integrity].map(([algorithm, bytes]) => ({
      name: 'amqic:npm:archive-integrity', value: algorithm + '-' + bytes.toString('base64'),
    })),
  }));
  return bom(components, 'declared-npm-lock-entries-with-archive-integrity', sha256(lockBytes));
}

export function declaredSbom(input) {
  const items = JSON.parse(decoder.decode(input));
  requireThat(Array.isArray(items) && items.length <= maxEntries, 'Expected a bounded array of components.');
  const supported = new Set(['application', 'library', 'framework', 'operating-system', 'container', 'platform', 'file']);
  const seen = new Set();
  const components = items.map(item => {
    requireThat(record(item) && Object.keys(item).length === 3 && supported.has(item.type) &&
      componentField(item.name) && componentField(item.version), 'Invalid declared component.');
    const id = sha256(encode([item.type, item.name, item.version]));
    requireThat(!seen.has(id), 'Duplicate declared component.');
    seen.add(id);
    return { type: item.type, name: item.name, version: item.version, 'bom-ref': 'declared:' + id };
  });
  components.sort((a, b) => a['bom-ref'] < b['bom-ref'] ? -1 : a['bom-ref'] > b['bom-ref'] ? 1 : 0);
  return bom(components, 'manually-declared-components', sha256(input));
}

export function checkDependency(archiveBytes, lockBytes, packagePath) {
  const entry = lockedPackages(lockBytes).find(x => x.path === packagePath);
  requireThat(entry, 'Package absent from the npm lock.');
  // When several hashes are present, require every supplied digest to match.
  for (const [algorithm, bytes] of entry.integrity) {
    requireThat(createHash(algorithm).update(archiveBytes).digest().equals(bytes), 'Locked package archive integrity mismatch.');
  }
  return { status: 'verified', archiveSha256: sha256(archiveBytes) };
}

function cli(args) {
  const [command, ...values] = args;
  const count = { 'check-sha256': 1, inventory: 3, check: 4, verify: 6, sbom: 1, 'sbom-components': 1, 'check-dependency': 3 };
  requireThat(Object.hasOwn(count, command) && values.length === count[command], 'Invalid command or argument count. See enterprise/supply/README.md.');
  if (command === 'check-sha256') return checkSha256(values[0]);
  if (command === 'sbom') return npmSbom(readPlain(values[0]));
  if (command === 'sbom-components') return declaredSbom(readPlain(values[0]));
  if (command === 'check-dependency') return checkDependency(readPlain(values[0]), readPlain(values[1]), values[2]);
  const policy = JSON.parse(decoder.decode(readPlain(values[1], 4 * 1024 * 1024)));
  if (command === 'inventory') return inventory(values[0], policy, values[2]);
  if (command === 'check') return checkInventory(values[0], policy, readPlain(values[2]), values[3]);
  return verifyInventory(values[0], policy, readPlain(values[2]), readPlain(values[3], 64),
    decoder.decode(readPlain(values[4], 4096)), values[5]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.stdout.write(encode(cli(process.argv.slice(2))));
  } catch {
    process.stderr.write('Supply-chain check rejected its inputs. See enterprise/supply/README.md.\n');
    process.exitCode = 1;
  }
}
