import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const shell = process.platform === 'win32'
  ? ['C:/Program Files/Git/bin/sh.exe', 'C:/Program Files (x86)/Git/bin/sh.exe'].find(existsSync)
  : '/bin/sh';
const run = (...args) => spawnSync(shell, ['lab/run.sh', ...args], {
  cwd: root, encoding: 'utf8', timeout: 30000, windowsHide: true,
});

test('POSIX wrapper help and plan do not prepare services', { skip: !shell && 'POSIX shell unavailable on this host' }, () => {
  assert.equal(run('--help').status, 0);
  const result = run('--plan');
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.status, 'plan');
  assert.equal(plan.effect_free, true);
  assert.deepEqual(plan.checks, []);
});

test('POSIX wrapper rejects malformed flags before preparation', { skip: !shell && 'POSIX shell unavailable on this host' }, () => {
  for (const args of [['--output'], ['--output', ''], ['--output', 'relative.json'],
    ['--unknown'], ['--plan', '--no-prepare'], ['--plan', '--output', '/tmp/test.json']]) {
    const result = run(...args);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout, '');
  }
});
