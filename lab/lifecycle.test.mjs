import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../', import.meta.url));
function run(script, args) {
  return spawnSync(process.execPath, ['--experimental-sqlite', script, ...args], {
    cwd: source, encoding: 'utf8', timeout: 15000, windowsHide: true,
    env: { ...process.env, LAB_CLAMD_HOST: '127.0.0.1', LAB_CLAMD_PORT: '1' },
  });
}
test('lab refuses relative paths and source-tree reports before starting resources', () => {
  for (const args of [['--verify', '--output', 'relative.json'],
    ['--verify', '--output', join(source, 'lab', 'must-not-exist.json')]]) {
    const result = run('lab/run-lab.mjs', args);
    assert.notEqual(result.status, 0);
    assert.equal(existsSync(join(source, 'lab', 'must-not-exist.json')), false);
  }
  const result = run('lab/live-verify.mjs', ['--output', join(source, 'lab', 'must-not-exist.json')]);
  assert.notEqual(result.status, 0);
  assert.equal(existsSync(join(source, 'lab', 'must-not-exist.json')), false);
});
test('lab preserves an existing report instead of overwriting evidence', t => {
  const directory = mkdtempSync(join(tmpdir(), 'lab-evidence-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const output = join(directory, 'result.json');
  writeFileSync(output, 'existing-evidence');
  for (const script of ['lab/run-lab.mjs', 'lab/live-verify.mjs']) {
    const args = script.includes('run-lab') ? ['--verify', '--output', output] : ['--output', output];
    assert.notEqual(run(script, args).status, 0);
    assert.equal(readFileSync(output, 'utf8'), 'existing-evidence');
  }
});
