#!/usr/bin/env node
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { confirmedPassword, hiddenPassword, transform } from './archive_crypto.mjs';

const backupScript = join(dirname(fileURLToPath(import.meta.url)), 'backup.py');

function runBackup(args) {
  const result = spawnSync('python3', [backupScript, ...args], { encoding: 'utf8', maxBuffer: 1024 * 1024 });
  if (result.status !== 0) throw Error('backup stage failed');
}

async function main() {
  const [mode, source, output, ...includes] = process.argv.slice(2);
  if (process.platform !== 'linux' || !process.stdin.isTTY || !process.stdout.isTTY || !['create', 'restore'].includes(mode) || !source || !output || (mode === 'create' && !includes.length) || (mode === 'restore' && includes.length)) throw Error('human Linux terminal and exact arguments required');
  const destination = join(realpathSync(dirname(resolve(output))), basename(output));
  if (mode === 'create') {
    const root = realpathSync(source);
    if (destination === root || destination.startsWith(root + sep)) throw Error('archive must be outside source');
  }
  const password = mode === 'create' ? await confirmedPassword() : await hiddenPassword('Archive password: ');
  const temporary = mkdtempSync(join(realpathSync(tmpdir()), 'amqic-backup-'));
  try {
    const plain = join(temporary, 'payload.tar.gz');
    if (mode === 'create') {
      runBackup(['create', '--root', resolve(source), '--output', plain, '--allow-plaintext', ...includes.flatMap(item => ['--include', item])]);
      await transform('encrypt', plain, destination, password);
      const check = join(temporary, 'readback.tar.gz');
      await transform('decrypt', destination, check, password);
      runBackup(['verify', check]);
    } else {
      await transform('decrypt', resolve(source), plain, password);
      runBackup(['restore', plain, '--target', destination]);
    }
    process.stdout.write(JSON.stringify({ status: 'verified', operation: mode, encryption: 'AES-256-GCM' }) + '\n');
  } finally {
    password.fill(0);
    // Only this freshly created private directory belongs to this invocation.
    rmSync(temporary, { recursive: true, force: false });
  }
}

main().catch(() => {
  process.stderr.write('{"status":"refused_or_failed","detail":"preserve persistent archives; inspect private restore staging if present"}\n');
  process.exitCode = 1;
});
