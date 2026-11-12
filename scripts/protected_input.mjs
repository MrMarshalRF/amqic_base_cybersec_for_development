#!/usr/bin/env node
import { closeSync, constants, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { userInfo } from 'node:os';
import { dirname, join, parse, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { confirmedPassword, encryptBytes, hiddenPassword } from './archive_crypto.mjs';

async function main() {
  if (process.argv.length !== 2 || process.platform !== 'linux' || !process.stdin.isTTY || !process.stdout.isTTY) throw Error('human Linux terminal required');
  const home = userInfo().homedir;
  const store = join(home, '.local', 'share', 'amqic-protected-input');
  const project = realpathSync(join(dirname(fileURLToPath(import.meta.url)), '..'));
  if (store === project || store.startsWith(project + sep) || project.startsWith(store + sep)) throw Error('store and project must be disjoint');
  let current = parse(store).root;
  for (const part of store.slice(current.length).split('/')) {
    current = join(current, part);
    try { mkdirSync(current, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const info = lstatSync(current);
    if (!info.isDirectory() || info.isSymbolicLink()) throw Error('unsafe store path');
  }
  const info = lstatSync(store);
  if (info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) throw Error('private store required');
  const destination = resolve(store, 'credential.amqic');
  try {
    lstatSync(destination);
    throw Error('credential already exists');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  process.stdout.write('Encrypted credential enrollment. No application consumer is installed.\n');
  const secret = await hiddenPassword('Credential: ');
  let password;
  try {
    if (!secret.length) throw Error('empty credential');
    password = await confirmedPassword('Separate storage passphrase (at least 16 characters): ');
    const payload = encryptBytes(secret, password);
    const temporary = join(store, `.input-${randomBytes(16).toString('hex')}.partial`);
    const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    try {
      writeFileSync(descriptor, payload);
      fsyncSync(descriptor);
      linkSync(temporary, destination);
    } finally {
      closeSync(descriptor);
      unlinkSync(temporary);
    }
    process.stdout.write('{"status":"encrypted_input_recorded","consumer":"not_configured","execution_authority":false}\n');
  } finally {
    secret.fill(0);
    password?.fill(0);
  }
}

main().catch(() => {
  process.stderr.write('{"status":"refused_or_incomplete","execution_authority":false}\n');
  process.exitCode = 1;
});
