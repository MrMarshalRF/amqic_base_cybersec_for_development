import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { isAbsolute, dirname, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { postgresAdmission, redisAdmission } from './admission.mjs';

const postgres = 'docker.io/library/postgres:17.12-bookworm@sha256:837bed18782820fe967067cb5328b02b0d9992c1be9a37ee0c9c492cfc03af3b';
const redis = 'redis@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf';
const root = realpathSync(fileURLToPath(new URL('../../', import.meta.url)));
const planning = process.argv[2] === '--plan';
const target = process.argv[planning ? 3 : 2];
if (process.argv.length !== 4 || !isAbsolute(target ?? '')) {
  throw Error('Use --plan <absolute new external output directory> or <directory> <expected ETag>.');
}
const output = resolve(realpathSync(dirname(target)), target.slice(dirname(target).length).replace(/^[\\/]+/, ''));
const offset = relative(root, output);
if (!(offset === '..' || offset.startsWith('..' + sep) || isAbsolute(offset))) throw Error('Output must be outside source.');
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}
const sha = value => createHash('sha256').update(value).digest('hex');
const etag = value => 'sha256:' + sha(canonical(value));
function captureInputs() {
  const names = ['admission.mjs', 'integration.mjs', 'postgres.sql', 'redis.lua'];
  return { schema: 'amqic.distributed-admission-plan/v1', output,
    fixture: 'concurrent-requests-and-isolated-restart/v1',
    images: { postgres, redis },
    files: names.map(path => ({ path, sha256: sha(readFileSync(new URL('./' + path, import.meta.url))) })) };
}
const input = captureInputs();
const inputEtag = etag(input);
if (planning) {
  console.log(JSON.stringify({ ...input, etag: inputEtag }));
  process.exit(0);
}
if (process.argv[3] !== inputEtag) throw Error('Expected input ETag mismatch.');
mkdirSync(output);

const owner = 'amqic-distributed-' + randomUUID();
const owned = [];
const volume = { name: owner + '-pg-data', status: 'not_requested' };
const report = { schema: 'amqic.distributed-admission/v1', inputEtag, status: 'failed', checks: {}, cleanup: false };
function saveResources() {
  writeFileSync(resolve(output, 'resources.json'), JSON.stringify({ owner, process: process.pid, born: report.startedAt, owned, volume }, null, 2));
}
report.startedAt = new Date().toISOString();
saveResources();

function docker(args, input) {
  return new Promise((yes, no) => {
    const kid = spawn('docker', args, { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
    let data = '';
    const timer = setTimeout(() => kid.kill(), 45_000);
    kid.stdout.setEncoding('utf8').on('data', chunk => {
      data += chunk;
      if (data.length > 1_048_576) kid.kill();
    });
    kid.stdin.on('error', () => {});
    kid.on('error', error => { clearTimeout(timer); no(error); });
    kid.on('close', code => { clearTimeout(timer); code === 0 ? yes(data.trim()) : no(Error('Docker check failed')); });
    kid.stdin.end(input);
  });
}
async function container(engine, image, flags, command) {
  await docker(['image', 'inspect', image]);
  const name = owner + '-' + engine;
  const record = { engine, name, status: 'create_intent' };
  owned.push(record);
  saveResources();
  assert.equal(etag(captureInputs()), inputEtag);
  const id = await docker(['create', '--pull', 'never', '--name', name, '--label', 'amqic.admission=' + owner,
    '--network', 'none', '--security-opt', 'no-new-privileges', ...flags, image, ...command]);
  assert.match(id, /^[0-9a-f]{64}$/);
  Object.assign(record, { id, status: 'created' });
  saveResources();
  await docker(['start', id]);
  const observed = JSON.parse(await docker(['inspect', id]))[0];
  assert.equal(observed.Id, id);
  assert.equal(observed.HostConfig.NetworkMode, 'none');
  assert.ok(!observed.HostConfig.PortBindings || Object.keys(observed.HostConfig.PortBindings).length === 0);
  Object.assign(record, { pid: observed.State.Pid, startedAt: observed.State.StartedAt, status: 'running' });
  saveResources();
  return id;
}

async function ready(command) {
  for (let i = 0; i < 30; i++) {
    try { return await command(); } catch { await delay(1000); }
  }
  throw Error('Synthetic store did not become ready.');
}
const tenant = 'synthetic_tenant';
const generation = 'synthetic_generation';
const digest = 'a'.repeat(64);
const binding = 'b'.repeat(64);
const ms = 3_600_000;
const sqlLiteral = value => typeof value === 'number' ? String(value) : "'" + value.replaceAll("'", "''") + "'";
const projected = result => result.status;

async function exercise(admit, window, setFutureClock, replayAfterRestart) {
  const base = { tenant, generation, policyDigest: digest, bindingDigest: binding, risk: 'normal', window };
  const input = operationId => ({ ...base, operationId });
  const result = await Promise.all(Array.from({ length: 12 }, (_, i) => admit(input('op_' + i))));
  assert.equal(result.filter(x => x.allowed).length, 4);
  assert.equal(result.filter(x => x.status === 'rate_limited').length, 8);
  const granted = input('op_' + result.findIndex(x => x.allowed));
  assert.equal(projected(await admit(granted)), 'duplicate');
  assert.equal(projected(await admit({ ...granted, bindingDigest: 'c'.repeat(64) })), 'conflict');
  assert.equal(projected(await admit({ ...input('other'), generation: 'other' })), 'policy_mismatch');
  assert.equal(projected(await admit({ ...input('other'), window: window - 1 })), 'window_changed');
  assert.equal(projected(await admit({ ...input('other'), tenant: 'missing' })), 'unprovisioned');
  if (replayAfterRestart) await replayAfterRestart(granted);
  await setFutureClock();
  assert.equal(projected(await admit(input('clock_guard'))), 'clock_rollback');
  return input('after_loss');
}
let failed = false;
let stage = 'postgres';
try {
  assert.equal(etag(captureInputs()), inputEtag);
  assert.equal(await docker(['volume', 'ls', '-q', '--filter', 'name=^' + volume.name + '$']), '');
  volume.status = 'create_intent';
  saveResources();
  assert.equal(await docker(['volume', 'create', '--label', 'amqic.admission=' + owner, volume.name]), volume.name);
  const observedVolume = JSON.parse(await docker(['volume', 'inspect', volume.name]))[0];
  assert.equal(observedVolume.Name, volume.name);
  assert.equal(observedVolume.Labels['amqic.admission'], owner);
  volume.status = 'created';
  saveResources();
  const pg = await container('pg', postgres, [
    '--mount', 'type=volume,source=' + volume.name + ',target=/var/lib/postgresql/data',
    '-e', 'POSTGRES_HOST_AUTH_METHOD=trust'
  ], ['postgres', '-c', 'listen_addresses=']);
  const psql = statement => docker(['exec', '-i', pg, 'psql', '-X', '-U', 'postgres', '-d', 'postgres', '-qAt', '-v', 'ON_ERROR_STOP=1'], statement + '\n');
  await ready(() => psql('SELECT 1;'));
  await delay(1500);
  await ready(() => psql('SELECT 1;'));
  report.postgres_version = await psql('SHOW server_version;');
  report.postgres_version_num = await psql('SHOW server_version_num;');
  assert.match(report.postgres_version_num, /^\d{6}$/);
  const version = Number(report.postgres_version_num);
  assert.ok(Number.isSafeInteger(version) && version >= 170012 && version < 180000,
    'Pinned PostgreSQL 17 family requires server_version_num >= 170012');
  report.checks.postgres_17_fixed_minimum = true;
  await psql(readFileSync(new URL('./postgres.sql', import.meta.url), 'utf8'));
  await psql(`INSERT INTO amqic_quota.tenant_state(tenant,generation,policy_digest,window_ms,normal_cap,elevated_cap)
    VALUES (${sqlLiteral(tenant)},${sqlLiteral(generation)},${sqlLiteral(digest)},${ms},4,2);`);
  const pgWindow = Number(await psql(`SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint / ${ms};`));
  const pgAdmit = postgresAdmission({ query: async (_sql, values) => ({
    rows: [{ status: await psql('SELECT amqic_quota.admit(' + values.map(sqlLiteral).join(',') + ');') }]
  }) });
  await exercise(pgAdmit, pgWindow, () => psql('UPDATE amqic_quota.tenant_state SET last_ms=4000000000000;'), async granted => {
    await docker(['restart', pg]);
    const observed = JSON.parse(await docker(['inspect', pg]))[0];
    const record = owned.find(item => item.id === pg);
    assert.notEqual(observed.State.StartedAt, record.startedAt);
    Object.assign(record, { pid: observed.State.Pid, startedAt: observed.State.StartedAt });
    saveResources();
    await ready(() => psql('SELECT 1;'));
    assert.equal(projected(await pgAdmit(granted)), 'duplicate');
    report.checks.postgres_restart = true;
  });
  report.checks.postgres = true;

  stage = 'redis';
  const rd = await container('redis', redis, ['--tmpfs', '/data:rw,nosuid,nodev,noexec,size=32m'], ['redis-server', '--save', '', '--appendonly', 'no']);
  const redisCli = (...args) => docker(['exec', rd, 'redis-cli', '--raw', ...args]);
  await ready(async () => assert.equal(await redisCli('PING'), 'PONG'));
  const state = { generation, policyDigest: digest, windowMs: ms, normal: 4, elevatedCap: 2,
    used: 0, lastMs: 0, window: 0, elevated: false, operations: {} };
  const key = 'amqic:quota:v1:' + tenant;
  const put = () => redisCli('SET', key, JSON.stringify(state));
  await put();
  const t = (await redisCli('TIME')).split(/\r?\n/).map(Number);
  const redisWindow = Math.floor((t[0] * 1000 + Math.floor(t[1] / 1000)) / ms);
  const redisAdmit = redisAdmission({ eval: (script, args) => redisCli('EVAL', script, '1', ...args.keys, ...args.arguments) });
  const afterLoss = await exercise(redisAdmit, redisWindow, async () => { state.lastMs = 4_000_000_000_000; await put(); });
  await docker(['restart', rd]);
  const observed = JSON.parse(await docker(['inspect', rd]))[0];
  const record = owned.find(item => item.id === rd);
  assert.notEqual(observed.State.StartedAt, record.startedAt);
  Object.assign(record, { pid: observed.State.Pid, startedAt: observed.State.StartedAt });
  saveResources();
  await ready(async () => assert.equal(await redisCli('PING'), 'PONG'));
  assert.equal(projected(await redisAdmit(afterLoss)), 'unprovisioned');
  report.checks.redis_state_loss = true;
  report.checks.redis = true;
} catch {
  report.failureStage = stage;
  failed = true;
} finally {
  try {
    for (const record of owned) {
      const ids = (await docker(['ps', '-aq', '--no-trunc', '--filter', 'label=amqic.admission=' + owner,
        '--filter', 'name=^/' + record.name + '$'])).split(/\s+/).filter(Boolean);
      assert.ok(ids.length <= 1);
      if (ids.length) {
        assert.match(ids[0], /^[0-9a-f]{64}$/);
        assert.ok(!record.id || ids[0] === record.id);
        await docker(['rm', '-fv', ids[0]]);
      }
      record.status = 'absent';
    }
    assert.equal(await docker(['ps', '-aq', '--filter', 'label=amqic.admission=' + owner]), '');
    if (volume.status !== 'not_requested') {
      const remaining = await docker(['volume', 'ls', '-q', '--filter', 'name=^' + volume.name + '$',
        '--filter', 'label=amqic.admission=' + owner]);
      if (remaining) {
        assert.equal(remaining, volume.name);
        await docker(['volume', 'rm', volume.name]);
      }
      assert.equal(await docker(['volume', 'ls', '-q', '--filter', 'name=^' + volume.name + '$']), '');
      volume.status = 'absent';
    }
    report.cleanup = true;
  } catch { report.cleanupError = true; failed = true; }
  saveResources();
  try {
    report.sourceUnchanged = etag(captureInputs()) === inputEtag;
  } catch { report.sourceUnchanged = false; }
  if (!report.sourceUnchanged) failed = true;
  report.status = failed ? 'failed' : 'passed';
  report.etag = etag(report);
  writeFileSync(resolve(output, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  process.exitCode = failed ? 1 : 0;
}
