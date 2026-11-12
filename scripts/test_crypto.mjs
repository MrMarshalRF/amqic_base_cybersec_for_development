// All passwords and payloads below are synthetic public test fixtures.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { encryptBytes, transform } from './archive_crypto.mjs';

const directory = mkdtempSync(join(tmpdir(), 'amqic-crypto-test-'));
const scripts = dirname(fileURLToPath(import.meta.url));
const password = Buffer.from('public synthetic fixture password');
let checks = 0;
try {
  const original = join(directory, 'original');
  const encrypted = join(directory, 'encrypted');
  const restored = join(directory, 'restored');
  writeFileSync(original, Buffer.from('Synthetic\0payload\n'));
  await transform('encrypt', original, encrypted, password);
  await transform('decrypt', encrypted, restored, password);
  assert.deepEqual(readFileSync(restored), readFileSync(original)); checks++;
  await assert.rejects(transform('decrypt', encrypted, restored, password)); checks++;
  await assert.rejects(transform('decrypt', encrypted, join(directory, 'wrong'), Buffer.from('wrong')));
  assert.equal(existsSync(join(directory, 'wrong')), false); checks++;
  const bytes = readFileSync(encrypted);
  for (const offset of [0, 12, 30, 40, bytes.length - 1]) {
    const modified = Buffer.from(bytes);
    modified[offset] ^= 1;
    const corrupt = join(directory, `corrupt-${offset}`);
    const output = `${corrupt}.plain`;
    writeFileSync(corrupt, modified);
    await assert.rejects(transform('decrypt', corrupt, output, password));
    assert.equal(existsSync(output), false); checks++;
  }
  for (const length of [0, 10, bytes.length - 1]) {
    const truncated = join(directory, `short-${length}`);
    writeFileSync(truncated, bytes.subarray(0, length));
    await assert.rejects(transform('decrypt', truncated, `${truncated}.plain`, password));
    assert.equal(existsSync(`${truncated}.plain`), false); checks++;
  }
  const direct = join(directory, 'direct');
  writeFileSync(direct, encryptBytes(Buffer.from('synthetic credential'), password));
  await transform('decrypt', direct, `${direct}.plain`, password);
  assert.equal(readFileSync(`${direct}.plain`, 'utf8'), 'synthetic credential'); checks++;
  assert.notDeepEqual(encryptBytes(Buffer.from('same'), password), encryptBytes(Buffer.from('same'), password)); checks++;
  for (const [file, args] of [
    ['archive_crypto.mjs', ['encrypt', original, join(directory, 'cli')]],
    ['protected_input.mjs', []],
    ['secure_backup.mjs', ['create', directory, join(directory, 'backup'), 'original']],
  ]) {
    const result = spawnSync(process.execPath, [join(scripts, file), ...args], { encoding: 'utf8', input: '' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /refused/); checks++;
  }
  console.log(JSON.stringify({ status: 'passed', checks }));
} finally {
  password.fill(0);
  rmSync(directory, { recursive: true, force: false });
}
