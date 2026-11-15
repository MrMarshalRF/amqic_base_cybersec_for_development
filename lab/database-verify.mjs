import assert from 'node:assert/strict';
import { spawnSync, execFile } from 'node:child_process';
import { readFileSync, writeFileSync, realpathSync, existsSync } from 'node:fs';
import { dirname, resolve, relative, isAbsolute, sep, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

export const DATABASE_IMAGE = 'docker.io/library/postgres@sha256:40865bc877a289da75963d97d72b59633f639fc5af7a4e856bfa3714cae5b536';
const root = realpathSync(fileURLToPath(new URL('..', import.meta.url)));
const argv = process.argv.slice(2);
const prepare = argv.includes('--prepare');
const args = argv.filter(a => a !== '--prepare');
if (args.length === 1 && args[0] === '--plan') {
  console.log(JSON.stringify({ image: DATABASE_IMAGE, prerequisites: ['Node.js 22+', 'Docker Linux engine', 'fixed image present; --prepare permits bounded pull'],
    effects: 'one synthetic network-none container, no host ports/mounts, memory-only database; exact ownership cleanup', maxRunSeconds: 180 }));
  process.exit(0);
}
if (args.length !== 2 || args[0] !== '--output' || !isAbsolute(args[1])) throw new Error('Use --plan or --output ABSOLUTE_EXTERNAL_NEW.json [--prepare]');
const output = resolve(args[1]);
const outside = relative(root, realpathSync(dirname(output)));
if (!(outside === '..' || outside.startsWith('..' + sep) || isAbsolute(outside))) throw new Error('Output must be outside source');
const ledger = output + '.resources.json';
if (existsSync(output) || existsSync(ledger)) throw new Error('Output must be new');
const paths = ['infra/database/schema.sql', 'infra/database/test_rls.sql', 'infra/database/README.md', 'lab/database-verify.mjs', 'lab/database.README.md'];
const hashes = () => paths.map(path => ({ path, sha256: createHash('sha256').update(readFileSync(join(root, path))).digest('hex') }));
const git = (...a) => { const p = spawnSync('git', a, { cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true }); return p.status === 0 ? p.stdout.trim() : 'unknown'; };
const token = randomBytes(10).toString('hex');
const label = 'amqic.database.owner=' + token;
const state = { schema_version: 1, task: 'synthetic-postgresql-security', cleanupOwner: 'database-verify', token,
  phase: 'intent', primaryEnvironment: 'none; no existing database used', disposable: 'one labeled network-none container and tmpfs only', containers: [] };
const save = () => writeFileSync(ledger, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
writeFileSync(ledger, JSON.stringify(state, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
const report = { schema_version: 1, status: 'failed', complete: false, scope: 'isolated synthetic PostgreSQL RLS and shared replay', image: DATABASE_IMAGE,
  source_files: hashes(), git_before: { head: git('rev-parse', 'HEAD'), status: git('status', '--short') }, checks: [], cleanup: {} };
const started = Date.now();
let cancelled = false;
process.on('message', message => { if (message?.type === 'cancel') cancelled = true; });
function docker(a, { input, timeout = 15000, allow = false, cleanup = false } = {}) {
  if (!cleanup && (cancelled || Date.now() - started > 180000)) throw new Error('Lab cancelled or deadline exceeded');
  const p = spawnSync('docker', a, { input, encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  if (p.error || (!allow && p.status !== 0)) throw new Error(`Docker ${a[0]} failed: ${(p.error?.message || p.stderr || '').slice(-1200)}`);
  return { code: p.status, stdout: p.stdout.trim(), stderr: p.stderr.trim() };
}
let id;
const sql = (statement, user = 'postgres', allow = false) => docker(['exec', '-i', id, 'psql', '-X', '-h', '/tmp', '-U', user, '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1'], { input: statement, allow });
const consume = (nonce, time = 'clock_timestamp()') => `SELECT replay.consume_nonce('synthetic-api','synthetic-key-1','${nonce}',${time});`;
const check = (name, fn) => { fn(); report.checks.push({ id: name, status: 'passed' }); };
try {
  const found = docker(['image', 'inspect', DATABASE_IMAGE], { allow: true });
  if (found.code !== 0) {
    if (!prepare) throw new Error('Pinned image absent; use --prepare for this fixed dependency');
    state.phase = 'preparing_fixed_image'; save();
    docker(['pull', DATABASE_IMAGE], { timeout: 120000 });
  }
  report.image_id = JSON.parse(docker(['image', 'inspect', DATABASE_IMAGE]).stdout)[0].Id;
  state.phase = 'create_intent'; state.name = 'amqic-database-' + token; state.createAttempted = true; state.createOutcomeUnknown = true; save();
  // Fixed bootstrap, no client-controlled shell content; trust exists ONLY in this socket-only synthetic container.
  const bootstrap = 'initdb -D /var/lib/postgresql/data --auth=trust >/tmp/init.log && pg_ctl -D /var/lib/postgresql/data -l /tmp/postgres.log -o "-c listen_addresses= -k /tmp" -w start && exec sleep infinity';
  id = docker(['create', '--name', state.name, '--label', label, '--network', 'none', '--read-only', '--user', '999:999',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '256m', '--cpus', '1', '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777',
    '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=128m,uid=999,gid=999,mode=0700',
    '--entrypoint', '/bin/sh', DATABASE_IMAGE, '-c', bootstrap], { timeout: 60000 }).stdout;
  assert.match(id, /^[a-f0-9]{64}$/); state.containers.push({ id }); state.createOutcomeUnknown = false; save();
  docker(['start', id], { timeout: 30000 });
  const observed = JSON.parse(docker(['inspect', id]).stdout)[0];
  Object.assign(state.containers[0], { pid: observed.State.Pid, startedAt: observed.State.StartedAt, ports: observed.NetworkSettings.Ports }); save();
  assert.equal(observed.Config.Labels['amqic.database.owner'], token);
  assert.equal(observed.HostConfig.NetworkMode, 'none'); assert.equal(observed.HostConfig.Privileged, false);
  assert.equal(Object.keys(observed.HostConfig.PortBindings || {}).length, 0);
  assert.ok(observed.Mounts.every(m => m.Type === 'tmpfs'));
  let ready = false;
  for (let n = 0; n < 30; n++) { if (docker(['exec', id, 'pg_isready', '-h', '/tmp', '-U', 'postgres'], { allow: true }).code === 0) { ready = true; break; } await delay(200); }
  assert.ok(ready, 'PostgreSQL readiness'); state.phase = 'running'; save();
  report.postgres_version = sql('SHOW server_version;').stdout;
  sql(readFileSync(join(root, paths[0]), 'utf8'));
  check('tenant_rls_column_grants_crud_and_parameterized_injection', () => assert.match(sql(readFileSync(join(root, paths[1]), 'utf8')).stdout, /rls_checks_passed/));
  check('actual_principal_login_boundary', () => {
    assert.equal(sql('SELECT current_user;', 'tenant_alpha').stdout, 'tenant_alpha');
    assert.notEqual(sql('SET ROLE tenant_beta;', 'tenant_alpha', true).code, 0);
    assert.notEqual(sql('SELECT * FROM app.contacts;', 'tenant_alpha', true).code, 0);
  });
  check('service_no_direct_store_or_registration_or_clock_access', () => {
    for (const s of ['DELETE FROM replay.used_nonces;', 'UPDATE replay.clock_guard SET high_water=clock_timestamp();',
      "INSERT INTO replay.allowed_keys VALUES ('x','y');", 'SET ROLE app_owner;']) assert.notEqual(sql(s, 'replay_service', true).code, 0);
  });
  check('invalid_timestamp_and_unknown_key_fail_closed', () => {
    assert.equal(sql(consume('a'.repeat(22), "clock_timestamp()-interval '31 seconds'"), 'replay_service').stdout, 'f');
    assert.equal(sql(consume('b'.repeat(22), "clock_timestamp()+interval '31 seconds'"), 'replay_service').stdout, 'f');
    assert.equal(sql("SELECT replay.consume_nonce('unknown','synthetic-key-1',repeat('a',22),clock_timestamp());", 'replay_service').stdout, 'f');
    assert.equal(sql(consume('!bad'), 'replay_service').stdout, 'f');
    assert.equal(sql(consume('z'.repeat(129)), 'replay_service').stdout, 'f');
    assert.equal(sql("SELECT replay.consume_nonce(repeat('x',129),'synthetic-key-1',repeat('a',22),clock_timestamp());", 'replay_service').stdout, 'f');
  });
  // Two real independent psql processes share the primary. Both must finish; exactly one wins.
  const concurrent = () => new Promise((resolvePromise, reject) => {
    const statement = consume('c'.repeat(22));
    execFile('docker', ['exec', id, 'psql', '-X', '-h', '/tmp', '-U', 'replay_service', '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement],
      { timeout: 15000, windowsHide: true }, (error, stdout) => error ? reject(error) : resolvePromise(stdout.trim()));
  });
  const claims = await Promise.all([concurrent(), concurrent()]);
  assert.deepEqual(claims.sort(), ['f', 't']); report.checks.push({ id: 'two_independent_connections_exactly_one_claim', status: 'passed', claims });
  check('separate_process_replay_denied', () => assert.equal(sql(consume('c'.repeat(22)), 'replay_service').stdout, 'f'));
  check('transaction_rollback_does_not_pretend_durable_claim', () => {
    assert.match(sql('BEGIN;' + consume('d'.repeat(22)) + 'ROLLBACK;', 'replay_service').stdout, /t/);
    assert.equal(sql(consume('d'.repeat(22)), 'replay_service').stdout, 't');
  });
  // PostgreSQL server restart (container and tmpfs remain); committed claim must survive.
  docker(['exec', id, 'pg_ctl', '-D', '/var/lib/postgresql/data', '-l', '/tmp/postgres.log', '-o', '-c listen_addresses= -k /tmp', '-m', 'fast', '-w', 'restart']);
  check('committed_nonce_survives_server_restart', () => assert.equal(sql(consume('c'.repeat(22)), 'replay_service').stdout, 'f'));
  check('future_window_retention_and_expired_proof_after_prune', () => {
    assert.equal(sql(consume('e'.repeat(22), "clock_timestamp()+interval '29 seconds'"), 'replay_service').stdout, 't');
    assert.equal(sql("SELECT expires_at > clock_timestamp()+interval '58 seconds' FROM replay.used_nonces WHERE nonce=repeat('e',22);").stdout, 't');
    sql("INSERT INTO replay.used_nonces VALUES('synthetic-api','synthetic-key-1',repeat('f',22),clock_timestamp()-interval '1 second');");
    assert.equal(sql(consume('g'.repeat(22)), 'replay_service').stdout, 't');
    assert.equal(sql("SELECT count(*) FROM replay.used_nonces WHERE nonce=repeat('f',22);").stdout, '0');
    assert.equal(sql(consume('f'.repeat(22), "clock_timestamp()-interval '32 seconds'"), 'replay_service').stdout, 'f');
    assert.equal(sql(consume('e'.repeat(22)), 'replay_service').stdout, 'f');
  });
  check('clock_rollback_and_missing_guard_fail_closed', () => {
    sql("UPDATE replay.clock_guard SET high_water=clock_timestamp()+interval '1 hour';");
    assert.notEqual(sql(consume('h'.repeat(22)), 'replay_service', true).code, 0);
    sql('DELETE FROM replay.clock_guard;');
    assert.notEqual(sql(consume('i'.repeat(22)), 'replay_service', true).code, 0);
    sql('INSERT INTO replay.clock_guard VALUES(true,clock_timestamp());');
    assert.equal(sql(consume('j'.repeat(22)), 'replay_service').stdout, 't');
  });
  assert.deepEqual(hashes(), report.source_files);
  report.checks.push({ id: 'owned_sources_unchanged', status: 'passed' }); report.status = 'passed';
} catch (error) { report.error = String(error.message); }
finally {
  state.phase = 'cleanup'; save();
  try {
    // Exact random label reconciles any partial create; validate each identity before removal.
    const ids = state.createAttempted
      ? docker(['ps', '-aq', '--filter', 'label=' + label], { cleanup: true }).stdout.split(/\s+/).filter(Boolean) : [];
    // A timed-out create may complete AFTER an empty listing. Never certify absence then.
    if (state.createOutcomeUnknown && ids.length === 0) throw new Error('Create outcome unknown; reconcile exact name/label before retry');
    for (const owned of ids) {
      const info = JSON.parse(docker(['inspect', owned], { cleanup: true }).stdout)[0];
      assert.equal(info.Config.Labels['amqic.database.owner'], token);
      if (!state.containers.some(c => c.id === info.Id)) {
        state.containers.push({ id: info.Id, pid: info.State.Pid, startedAt: info.State.StartedAt,
          ports: info.NetworkSettings.Ports, discoveredDuringCleanup: true }); save();
      }
      docker(['rm', '-f', info.Id], { cleanup: true, timeout: 60000 });
    }
    if (state.createAttempted) assert.equal(docker(['ps', '-aq', '--filter', 'label=' + label], { cleanup: true }).stdout, '');
    report.cleanup = { status: 'passed', containers_absent: true, no_persistent_volume_or_network_created: true,
      verification: state.createAttempted ? 'exact-label listing' : 'no container creation attempted' };
    state.phase = 'cleaned';
  } catch (error) { report.cleanup = { status: 'cleanup_pending', error: error.message }; state.phase = 'cleanup_pending'; report.status = 'failed'; }
  save(); report.complete = report.status === 'passed'; report.elapsed_ms = Date.now() - started;
  report.git_after = { head: git('rev-parse', 'HEAD'), status: git('status', '--short') };
  writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
process.exitCode = report.status === 'passed' ? 0 : 1;
if (process.connected) process.disconnect();
