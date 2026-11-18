import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkSha256, inventory, checkInventory, verifyInventory, npmSbom, declaredSbom, checkDependency } from './supply.mjs';

const source = 'a'.repeat(40);
const hash = value => createHash('sha256').update(value).digest('hex');
const bytes = data => Buffer.from(JSON.stringify(data));
const manifestBytes = data => Buffer.from(JSON.stringify(data, null, 2) + '\n');
const noBinaries = { schemaVersion: 1, binaries: {} };

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'amqic-supply-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test('checks exact checksum membership and rejects changed, missing, duplicate and unexpected paths', t => {
  const root = fixture(t);
  const file = join(root, 'a.txt');
  const registry = join(root, 'SHA256SUMS');
  const line = hash('abc') + '  a.txt\n';
  writeFileSync(file, 'abc');
  writeFileSync(registry, line);
  mkdirSync(join(root, '.git'));
  assert.deepEqual(checkSha256(root), { status: 'verified', files: 1 });
  writeFileSync(file, 'changed');
  assert.throws(() => checkSha256(root), /checksum mismatch/);
  writeFileSync(file, 'abc');
  writeFileSync(join(root, 'extra.txt'), 'x');
  assert.throws(() => checkSha256(root), /Unexpected file/);
  rmSync(join(root, 'extra.txt'));
  writeFileSync(registry, line + line);
  assert.throws(() => checkSha256(root), /duplicate/);
  writeFileSync(registry, line);
  rmSync(file);
  assert.throws(() => checkSha256(root), /missing files/);
});

test('staged binary permissions bind exact bytes and paths', t => {
  const root = fixture(t);
  const executable = Buffer.from([0, 255, 0, 1]);
  const filename = join(root, 'approved.bin');
  writeFileSync(filename, executable);
  writeFileSync(join(root, 'notes.txt'), 'hello\n');
  assert.throws(() => inventory(root, noBinaries, source), /Unexpected binary/);
  const policy = { schemaVersion: 1, binaries: { 'approved.bin': hash(executable) } };
  const observed = inventory(root, policy, source);
  assert.deepEqual(observed.files.map(item => item.format), ['binary', 'utf8-text']);
  writeFileSync(filename, Buffer.from([0, 1]));
  assert.throws(() => inventory(root, policy, source), /pin mismatch/);
  rmSync(filename);
  assert.throws(() => inventory(root, policy, source), /missing file/);
  assert.throws(() => inventory(root, { schemaVersion: 1, binaries: { '../a': hash(executable) } }, source), /Invalid binary policy/);
});

test('rejects linked members and reserved file names', t => {
  const root = fixture(t);
  writeFileSync(join(root, 'source.txt'), 'hello');
  linkSync(join(root, 'source.txt'), join(root, 'link.txt'));
  assert.throws(() => inventory(root, noBinaries, source), /plain file/);
  rmSync(join(root, 'link.txt'));
  if (process.platform !== 'win32') {
    symlinkSync(join(root, 'source.txt'), join(root, 'link.txt'));
    assert.throws(() => inventory(root, noBinaries, source), /plain file/);
    rmSync(join(root, 'link.txt'));
    writeFileSync(join(root, 'NUL.txt'), 'fake');
    assert.throws(() => inventory(root, noBinaries, source), /Invalid or duplicate payload path/);
  }
});

test('detached signature binds inventory, trusted key, source, policy and payload', t => {
  const root = fixture(t);
  writeFileSync(join(root, 'content.txt'), 'hello');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const manifest = manifestBytes(inventory(root, noBinaries, source));
  const signature = sign(null, manifest, privateKey);
  assert.equal(checkInventory(root, noBinaries, manifest, source).status, 'matched');
  assert.equal(verifyInventory(root, noBinaries, manifest, signature, pem, source).status, 'verified');
  const wrong = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => verifyInventory(root, noBinaries, manifest, signature, wrong, source), /signature failed/);
  assert.throws(() => verifyInventory(root, noBinaries, manifest, signature, pem, 'b'.repeat(40)), /does not match/);
  assert.throws(() => verifyInventory(root, noBinaries, Buffer.concat([manifest, Buffer.from(' ')]), signature, pem, source), /signature failed/);
  assert.throws(() => verifyInventory(root, noBinaries, manifest, signature.subarray(1), pem, source), /raw detached/);
  const newPolicy = { schemaVersion: 1, binaries: { 'content.txt': hash('hello') } };
  assert.throws(() => verifyInventory(root, newPolicy, manifest, signature, pem, source), /does not match/);
  writeFileSync(join(root, 'content.txt'), 'tampered');
  assert.throws(() => verifyInventory(root, noBinaries, manifest, signature, pem, source), /does not match/);
});

test('creates a bounded CycloneDX lock inventory and verifies dependency archive digests', () => {
  const archive = Buffer.from('synthetic dependency tarball bytes');
  const integrity = 'sha512-' + createHash('sha512').update(archive).digest('base64');
  const lock = bytes({ lockfileVersion: 3, packages: {
    '': { name: 'fixture' },
    'node_modules/a': { version: '1.0.0', integrity, resolved: 'https://invalid.example/hidden.tgz' },
    'node_modules/a/node_modules/@scope/b': { version: '2.0.0', integrity },
  } });
  const bom = npmSbom(lock);
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.6');
  assert.equal(bom.compositions[0].aggregate, 'incomplete');
  assert.deepEqual(bom.components.map(x => x.name), ['a', '@scope/b']);
  assert.equal(new Set(bom.components.map(x => x['bom-ref'])).size, 2);
  assert.equal(JSON.stringify(bom).includes('hidden.tgz'), false);
  assert.equal(checkDependency(archive, lock, 'node_modules/a').status, 'verified');
  assert.throws(() => checkDependency(Buffer.from('wrong'), lock, 'node_modules/a'), /integrity mismatch/);
  assert.throws(() => checkDependency(archive, lock, 'node_modules/nonexistent'), /absent/);
  assert.throws(() => npmSbom(bytes({ lockfileVersion: 3, packages: { 'node_modules/a': { link: true } } })), /Unsupported/);
  assert.throws(() => npmSbom(bytes({ lockfileVersion: 3, packages: { 'node_modules/a': { version: '1' } } })), /Missing/);
  assert.throws(() => npmSbom(bytes({ lockfileVersion: 1, packages: {} })), /v2 or v3/);
});

test('distinguishes declared components and disallows duplicate identities', () => {
  const runtime = { type: 'platform', name: 'Node.js', version: '22' };
  const bom = declaredSbom(bytes([runtime]));
  assert.equal(bom.components[0].version, '22');
  assert.equal(bom.compositions[0].aggregate, 'incomplete');
  assert.throws(() => declaredSbom(bytes([runtime, runtime])), /Duplicate/);
});
