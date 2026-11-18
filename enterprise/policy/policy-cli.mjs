import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { compilePolicy } from './policy.mjs';

const MAX_BYTES = 1024 * 1024;
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

function readPolicy(path) {
  const expected = lstatSync(path, { bigint: true });
  if (!expected.isFile()) throw new Error('Expected a regular policy file');
  const handle = openSync(path, OPEN_FLAGS);
  try {
    const observed = fstatSync(handle, { bigint: true });
    if (!observed.isFile() || observed.ino !== expected.ino || observed.dev !== expected.dev ||
        observed.size > BigInt(MAX_BYTES)) throw new Error('Policy file changed or exceeds the size limit');

    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = readSync(handle, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    const final = fstatSync(handle, { bigint: true });
    if (length > MAX_BYTES || BigInt(length) !== observed.size || final.size !== observed.size ||
        final.mtimeNs !== observed.mtimeNs || final.ctimeNs !== observed.ctimeNs) {
      throw new Error('Policy file changed or exceeds the size limit');
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length)));
  } finally {
    closeSync(handle);
  }
}

if (process.argv.length !== 4 || process.argv[2] !== '--check') {
  console.error('Usage: node enterprise/policy/policy-cli.mjs --check POLICY.json');
  process.exitCode = 2;
} else {
  try {
    const policy = compilePolicy(readPolicy(process.argv[3]));
    console.log(JSON.stringify({ valid: true, digest: policy.digest, tenantCount: policy.tenantCount }));
  } catch {
    console.error('Policy validation failed.');
    process.exitCode = 1;
  }
}
