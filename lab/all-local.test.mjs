import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { acceptStage } from './all-local.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
function cli(...args) {
  const child = spawnSync(process.execPath, ['scripts/verify.mjs', ...args], { cwd: root, encoding: 'utf8', env: { ...process.env, PATH: '' } });
  return { ...child, report: JSON.parse(child.stdout) };
}
test('plan needs no executable dependencies and starts no lab', () => {
  const result = cli('--plan');
  assert.equal(result.status, 0);
  assert.equal(result.report.effect_free, true);
  assert.equal(result.report.status, 'plan');
  assert.deepEqual(result.report.checks, []);
  assert.ok(result.report.scenarios.some(scenario => scenario.category === 'external'));
  assert.deepEqual(result.report.stages.map(stage => stage.id), ['baseline', 'live-consumers', 'nginx-runtime', 'infra-runtime', 'cache-runtime', 'upload-isolation-runtime']);
});
test('invalid metadata fails before prerequisites or effects', () => {
  for (const args of [['--all', '--output', 'relative.json'], ['--all', '--command', 'anything'], ['--plan', '--prepare'], ['--plan', '--output', 'anything.json'], ['--all', '--plan'], ['--all', '--all']]) {
    const result = cli(...args);
    assert.equal(result.status, 1);
    assert.equal(result.report.status, 'invalid_request');
    assert.deepEqual(result.report.prerequisites, []);
    assert.deepEqual(result.report.checks, []);
  }
});
test('exit-zero shaped reports cannot omit actual checks or cleanup', () => {
  for (const stage of ['baseline', 'live-consumers', 'nginx-runtime', 'infra-runtime', 'cache-runtime', 'upload-isolation-runtime', 'unknown']) {
    for (const report of [null, {}, { status: 'passed' }, { status: 'unknown', complete: true, checks: [] }, { ok: true, cleanup: { ok: true, failures: [] }, checks: {} }]) {
      assert.equal(!!acceptStage(stage, report), false, stage);
    }
  }
  const checks = ['public_fingerprinted_asset_cache_hit', 'client_isolation', 'origin_private_or_set_cookie_not_stored', 'source_stable_and_anonymous_cache_unpoisoned'].map(id => ({ id, status: 'passed' }));
  const valid = { schema_version: 1, status: 'passed', complete: true, checks, cleanup: { containers_absent: true, network_absent: true, verified_by_successful_listing: true } };
  assert.equal(acceptStage('cache-runtime', valid), true);
  assert.equal(acceptStage('cache-runtime', { ...valid, cleanup: { ...valid.cleanup, network_absent: false } }), false);
  assert.equal(acceptStage('cache-runtime', { ...valid, checks: checks.slice(1) }), false);
  assert.equal(acceptStage('cache-runtime', { ...valid, checks: [...checks, { id: 'extra', status: 'not_run' }] }), false);
  assert.equal(acceptStage('cache-runtime', { ...valid, status: 'foreign' }), false);
  const upload = { schema_version: 1, status: 'passed', complete: true, ok: true, checks: ['compose_contract', 'runtime_prepare', 'runtime_intake', 'runtime_scanner', 'runtime_promoter', 'runtime_media', 'source_stable'].map(id => ({ id, status: 'passed', ok: true })), cleanup: { ok: true, containers_absent: true, volumes_absent: true, verified_by_successful_listing: true } };
  assert.equal(acceptStage('upload-isolation-runtime', upload), true);
  assert.equal(acceptStage('upload-isolation-runtime', { ...upload, checks: upload.checks.filter(check => check.id !== 'runtime_scanner') }), false);
  assert.equal(acceptStage('upload-isolation-runtime', { ...upload, cleanup: { ...upload.cleanup, volumes_absent: false } }), false);
});
