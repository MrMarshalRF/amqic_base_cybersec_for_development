import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { EventEmitter } from 'node:events';

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

// Execute the actual private startup helpers without importing the executable lab
// entry (which would create resources). Unique named boundaries fail on drift.
const liveSource = readFileSync(join(source, 'lab/live-verify.mjs'), 'utf8');
const startBoundary = 'async function waitFor(';
const endBoundary = '\nasync function browserPath(';
assert.equal(liveSource.split(startBoundary).length, 2);
assert.equal(liveSource.split(endBoundary).length, 2);
const startupHelpers = liveSource.slice(liveSource.indexOf(startBoundary), liveSource.indexOf(endBoundary));

test('browser startup has a separate fixed deadline; assertion waits retain their deadline', () => {
  assert.match(startupHelpers, /async function waitFor\(check, timeout = 15000\)/);
  assert.match(startupHelpers, /diagnostics, timeout = 45000\)/);
  assert.match(liveSource, /await browserStartup\(child, profile, root, report.browser_startup\)/);
});

for (const mode of ['ready', 'slow', 'partial', 'timeout', 'signal', 'exit', 'spawn', 'cancel', 'invalid', 'unreadable']) {
  test('browser startup: ' + mode + ', bounded diagnostics and post-startup privacy', async () => {
    let now = 0, reads = 0;
    const child = new EventEmitter();
    child.exitCode = null; child.signalCode = null; child.stderr = new EventEmitter();
    const context = vm.createContext({ Buffer, Date: { now: () => now }, cancelled: false,
      join: (...parts) => parts.join('/'),
      readFile: async () => {
        reads++;
        if (mode === 'invalid') return '65536\n/devtools/browser/synthetic';
        if (mode === 'unreadable') throw Object.assign(Error('private path'), { code: 'EACCES' });
        if (mode === 'partial' && reads < 4) return ['', '23', '23456\n/devtools/bro'][reads - 1];
        if (mode === 'ready' || mode === 'partial' || (mode === 'slow' && reads >= 4)) return '23456\n/devtools/browser/synthetic';
        throw Object.assign(Error('missing'), { code: 'ENOENT' });
      },
      delay: async () => {
        now += 100;
        if (mode === 'signal') child.signalCode = 'SIGTERM';
        if (mode === 'exit') child.exitCode = 9;
        if (mode === 'spawn') child.emit('error', Error('/private/root/internal'));
        if (mode === 'cancel') context.cancelled = true;
        child.stderr.emit('data', Buffer.from('x'.repeat(9000) + '/private/root/browser /private/root'));
      }
    });
    vm.runInContext(startupHelpers + '\nthis.startup = browserStartup;', context);
    const diagnostics = {};
    const pending = context.startup(child, '/private/root/browser', '/private/root', diagnostics,
      mode === 'slow' || mode === 'partial' ? 500 : 250);
    child.stderr.emit('data', Buffer.from('/private/root/browser first'));
    if (['ready', 'slow', 'partial'].includes(mode)) {
      assert.equal(await pending, 23456);
      if (mode !== 'ready') assert.equal(diagnostics.elapsed_ms, 300);
      assert.equal(diagnostics.phase, 'devtools-ready');
    } else {
      const expected = { timeout: /timed out/, signal: /exited before readiness/, exit: /exited before readiness/,
        spawn: /spawn failed/, cancel: /cancelled/, invalid: /port invalid/, unreadable: /file unreadable/ };
      await assert.rejects(pending, expected[mode]);
      assert.equal(diagnostics.phase, 'devtools-startup-failed');
    }
    if (mode === 'signal') assert.equal(diagnostics.signal, 'SIGTERM');
    if (mode === 'exit') assert.equal(diagnostics.exit_code, 9);
    assert.ok(Buffer.byteLength(diagnostics.stderr) <= 8192);
    assert.ok(!diagnostics.stderr.includes('/private/root'));
    const retained = diagnostics.stderr;
    child.stderr.emit('data', Buffer.from('LOGIN_SECRET_NEVER_RETAIN'));
    assert.equal(diagnostics.stderr, retained);
    assert.ok(!diagnostics.stderr.includes('LOGIN_SECRET'));
  });
}

test('browser version observation rejects failed HTTP and malformed identity', async () => {
  const first = "  report.browser_startup.phase = 'version-request';";
  const last = '  report.browser = version.Browser;';
  assert.equal(liveSource.split(first).length, 2);
  assert.equal(liveSource.split(last).length, 2);
  const observe = liveSource.slice(liveSource.indexOf(first), liveSource.indexOf(last) + last.length);
  for (const [ok, identity, permitted] of [[false, 'Chrome/Synthetic', false], [true, '', false], [true, null, false], [true, 'Chrome/Synthetic', true]]) {
    const report = { browser_startup: {} };
    const context = vm.createContext({ assert, report, debugPort: 23456,
      AbortSignal: { timeout: ms => { assert.equal(ms, 15000); return 'synthetic-signal'; } },
      fetch: async (url, options) => {
        assert.equal(url, 'http://127.0.0.1:23456/json/version');
        assert.equal(options.signal, 'synthetic-signal');
        return { ok, json: async () => ({ Browser: identity }) };
      } });
    const pending = vm.runInContext('(async () => {' + observe + '})()', context);
    if (permitted) { await pending; assert.equal(report.browser, identity); assert.equal(report.browser_startup.phase, 'version-ready'); }
    else { await assert.rejects(pending); assert.equal(report.browser_startup.phase, 'version-request'); }
  }
});
