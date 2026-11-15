import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  assert.deepEqual(result.report.stages.map(stage => stage.id), ['baseline', 'live-consumers', 'nginx-runtime', 'infra-runtime', 'cache-runtime', 'upload-isolation-runtime', 'database-runtime']);
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

test('existing baseline diagnostics are preserved before preparation', t => {
  const directory = mkdtempSync(join(tmpdir(), 'ci-evidence-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const output = join(directory, 'report.json');
  const log = output + '.baseline.json.versions.log';
  writeFileSync(log, 'previous diagnostic');
  const result = cli('--all', '--prepare', '--output', output);
  assert.equal(result.status, 1);
  assert.equal(result.report.status, 'invalid_request');
  assert.deepEqual(result.report.prerequisites, []);
  assert.equal(readFileSync(log, 'utf8'), 'previous diagnostic');
});
test('exit-zero shaped reports cannot omit actual checks or cleanup', () => {
  for (const stage of ['baseline', 'live-consumers', 'nginx-runtime', 'infra-runtime', 'cache-runtime', 'upload-isolation-runtime', 'database-runtime', 'unknown']) {
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

test('database stage requires real tenant, replay and cleanup checks', () => {
  const ids = ['tenant_rls_column_grants_crud_and_parameterized_injection', 'actual_principal_login_boundary',
    'service_no_direct_store_or_registration_or_clock_access', 'invalid_timestamp_and_unknown_key_fail_closed',
    'two_independent_connections_exactly_one_claim', 'separate_process_replay_denied',
    'transaction_rollback_does_not_pretend_durable_claim', 'committed_nonce_survives_server_restart',
    'future_window_retention_and_expired_proof_after_prune', 'clock_rollback_and_missing_guard_fail_closed', 'owned_sources_unchanged'];
  const valid = { schema_version: 1, status: 'passed', complete: true,
    checks: ids.map(id => ({ id, status: 'passed' })),
    cleanup: { status: 'passed', containers_absent: true, no_persistent_volume_or_network_created: true } };
  assert.equal(acceptStage('database-runtime', valid), true);
  for (const id of ids) assert.equal(acceptStage('database-runtime', { ...valid,
    checks: valid.checks.filter(check => check.id !== id) }), false, id);
  assert.equal(acceptStage('database-runtime', { ...valid, complete: false }), false);
  assert.equal(acceptStage('database-runtime', { ...valid, cleanup: { ...valid.cleanup, containers_absent: false } }), false);
  assert.equal(acceptStage('database-runtime', { ...valid, checks: [...valid.checks, { id: 'unverified', status: 'not_run' }] }), false);
});
