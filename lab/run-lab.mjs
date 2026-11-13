import { spawnSync, spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm, access, realpath, chmod } from 'node:fs/promises';
import { join, resolve, dirname, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createClamdScanner } from '../reference/clamd-client.mjs';
import { createLabApp } from './web-app.mjs';
import { createRedisRateLimiter } from '../reference/admission.mjs';

export const CLAMAV_IMAGE = 'clamav/clamav@sha256:64ca916618842ba469ef38a501e6c2f42a68281c064c03749b0126c0fb085ce5';
export const REDIS_IMAGE = 'redis@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf';
const sourceRoot = await realpath(fileURLToPath(new URL('..', import.meta.url)));
const orchestrationPaths = ['lab/run-lab.mjs', 'lab/redis-live.mjs', 'reference/admission.mjs'];
const orchestrationHashes = () => Promise.all(orchestrationPaths.map(async path => ({
  path, sha256: createHash('sha256').update(await readFile(join(sourceRoot, path))).digest('hex'),
})));
const orchestrationBefore = await orchestrationHashes();
const args = process.argv.slice(2);
if (args.length !== 3 || !['--verify', '--serve'].includes(args[0]) || args[1] !== '--output' || !isAbsolute(args[2])) {
  throw new Error('Use --verify or --serve followed by --output ABSOLUTE_EXTERNAL_REPORT.json');
}
const output = resolve(args[2]);
const realParent = await realpath(dirname(output));
const rel = relative(sourceRoot, realParent);
if (!(rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel))) throw new Error('Reports must be outside the source tree');
for (const file of [output, output + '.resources.json', output + '.consumer.json']) {
  try { await access(file); throw new Error('Output already exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
const token = randomBytes(8).toString('hex');
const name = 'security-lab-' + token;
const root = await mkdtemp(join(tmpdir(), 'security-lab-' + token + '-'));
const scannerRoot = join(root, 'scanner');
if (root.includes(',')) throw new Error('Temporary directory cannot contain a comma');
const state = { task: 'synthetic-v1.2-lab', token, image: CLAMAV_IMAGE, tempRoot: root, scannerRoot, phase: 'intent', container: null, network: null };
let savePending = Promise.resolve();
const save = () => {
  const value = JSON.stringify(state, null, 2) + '\n';
  savePending = savePending.then(() => writeFile(output + '.resources.json', value, { mode: 0o600 }));
  return savePending;
};
await save();
function docker(arguments_, allowFailure = false) {
  const result = spawnSync('docker', arguments_, { encoding: 'utf8', timeout: 60000, windowsHide: true, maxBuffer: 1024 * 1024 });
  if (!allowFailure && (result.error || result.status !== 0)) throw new Error('Docker command failed; consult private resource record');
  return result;
}
let app;
let report = { schema_version: 1, status: 'failed', cleanup: {}, image: CLAMAV_IMAGE };
try {
  // Installation is separate; never silently select another image or pull a mutable tag.
  docker(['image', 'inspect', CLAMAV_IMAGE]);
  if (args[0] === '--verify') docker(['image', 'inspect', REDIS_IMAGE]);
  await mkdir(scannerRoot, { mode: 0o755 });
  await mkdir(join(scannerRoot, 'db'), { mode: 0o755 });
  await chmod(scannerRoot, 0o755); await chmod(join(scannerRoot, 'db'), 0o755);
  const marker = Buffer.from('AMQIC_LAB_SCAN_MARKER');
  await writeFile(join(scannerRoot, 'db', 'lab.ndb'), `AMQIC.Lab.Marker:0:*:${marker.toString('hex')}\n`, { mode: 0o644 });
  await writeFile(join(scannerRoot, 'clamd.conf'), [
    'Foreground yes', 'TCPSocket 3310', 'TCPAddr 0.0.0.0', 'DatabaseDirectory /lab/db',
    'PidFile /tmp/clamd.pid', 'MaxThreads 2', 'MaxConnectionQueueLength 16',
    'StreamMaxLength 2M', 'ReadTimeout 10', 'CommandReadTimeout 10', 'SendBufTimeout 500',
    'MaxScanSize 4M', 'MaxFileSize 2M', 'MaxRecursion 4', 'MaxFiles 100', 'AlertExceedsMax yes', '',
  ].join('\n'), { mode: 0o644 });
  state.network = docker(['network', 'create', '--label', 'security.lab=' + token, name]).stdout.trim();
  await save();
  state.container = docker(['create', '--name', name, '--label', 'security.lab=' + token,
    '--network', state.network, '--user', '1000:1000', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true', '--memory', '512m', '--cpus', '1', '--pids-limit', '64',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
    '--mount', 'type=bind,src=' + scannerRoot + ',dst=/lab,readonly', '-p', '127.0.0.1::3310',
    '--entrypoint', '/usr/sbin/clamd', CLAMAV_IMAGE, '--foreground', '--config-file=/lab/clamd.conf']).stdout.trim();
  await save();
  docker(['start', state.container]);
  const inspect = JSON.parse(docker(['inspect', state.container]).stdout)[0];
  state.startedAt = inspect.State.StartedAt;
  const mapping = inspect.NetworkSettings.Ports['3310/tcp']?.find(item => item.HostIp === '127.0.0.1');
  if (!mapping) throw new Error('Expected loopback-only scanner port');
  state.port = Number(mapping.HostPort); state.phase = 'running'; await save();
  const probe = join(root, 'probe'); await writeFile(probe, Buffer.alloc(0));
  const scanner = createClamdScanner({ host: '127.0.0.1', port: state.port, timeoutMs: 1000 });
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    const result = await scanner({ path: probe, size: 0, sha256: createHash('sha256').update('').digest('hex') });
    if (result.status === 'clean') { ready = true; break; }
    await delay(500);
  }
  if (!ready) throw new Error('Scanner did not become ready');
  if (args[0] === '--verify') {
    const redisRoot = join(root, 'redis'); await mkdir(redisRoot, { mode: 0o755 }); await chmod(redisRoot, 0o755);
    await writeFile(join(redisRoot, 'redis.conf'), 'bind 0.0.0.0\nprotected-mode yes\nport 6379\nsave ""\nappendonly no\nrequirepass synthetic-lab-only-password\n', { mode: 0o644 });
    state.redis = docker(['create', '--name', name + '-redis', '--label', 'security.lab=' + token,
      '--network', state.network, '--user', '1000:1000', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges:true', '--memory', '128m', '--cpus', '0.5', '--pids-limit', '32',
      '--tmpfs', '/data:rw,noexec,nosuid,nodev,size=8m,mode=1777',
      '--mount', 'type=bind,src=' + redisRoot + ',dst=/lab,readonly', '-p', '127.0.0.1::6379',
      '--entrypoint', 'redis-server', REDIS_IMAGE, '/lab/redis.conf']).stdout.trim();
    await save(); docker(['start', state.redis]);
    const redisInspect = JSON.parse(docker(['inspect', state.redis]).stdout)[0];
    const redisMapping = redisInspect.NetworkSettings.Ports['6379/tcp']?.find(item => item.HostIp === '127.0.0.1');
    if (!redisMapping) throw new Error('Expected loopback-only Redis port');
    state.redisPort = Number(redisMapping.HostPort); state.redisStartedAt = redisInspect.State.StartedAt; await save();
    const redisProbe = createRedisRateLimiter({ host: '127.0.0.1', port: state.redisPort,
      password: 'synthetic-lab-only-password', prefix: 'lab:ready:' + token + ':', limit: 1, windowMs: 1000 });
    let redisReady = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      if ((await redisProbe.check('readiness')).reason !== 'unavailable') { redisReady = true; break; }
      await delay(250);
    }
    if (!redisReady) throw new Error('Redis did not become ready');
    const redisTest = spawnSync(process.execPath, ['--experimental-sqlite', join(sourceRoot, 'lab/redis-live.mjs')], {
      env: { ...process.env, AMQIC_REDIS_LAB_PORT: String(state.redisPort) },
      windowsHide: true, encoding: 'utf8', timeout: 20000, maxBuffer: 65536,
    });
    if (redisTest.error || redisTest.status !== 0) throw new Error('Live Redis verification failed');
    const child = spawn(process.execPath, ['--experimental-sqlite', join(sourceRoot, 'lab/live-verify.mjs'), '--output', output + '.consumer.json'], {
      env: { ...process.env, LAB_CLAMD_HOST: '127.0.0.1', LAB_CLAMD_PORT: String(state.port) },
      windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    state.consumerPid = child.pid; await save();
    child.on('message', message => {
      if (message?.type === 'browser-started') { state.browserPid = message.pid; save().catch(() => {}); }
      if (message?.type === 'application-started') {
        state.application = { pid: message.pid, origin: message.origin, port: message.port }; save().catch(() => {});
      }
    });
    const exited = new Promise(resolveExit => {
      child.once('error', () => resolveExit(-1));
      child.once('exit', code => resolveExit(code ?? -1));
    });
    let timer;
    const timeout = new Promise(resolveTimeout => { timer = setTimeout(() => resolveTimeout('timeout'), 150000); });
    let code = await Promise.race([exited, timeout]); clearTimeout(timer);
    if (code === 'timeout') {
      if (child.connected) child.send({ type: 'cancel' });
      code = await Promise.race([exited, delay(30000).then(() => 'unknown')]);
    }
    state.consumerExited = code !== 'unknown'; await save();
    try { report = JSON.parse(await readFile(output + '.consumer.json', 'utf8')); } catch {}
    if (code !== 0 || report.status !== 'passed') throw new Error('Live verification failed; inspect retained consumer lifecycle');
    report.checks.push({ id: 'redis-authenticated-atomic-limits', status: 'passed', image: REDIS_IMAGE,
      concurrent_requests: 8, admitted: 2, expiry_reset: true, synthetic_credential: true });
  } else {
    app = await createLabApp({ dataRoot: join(root, 'application'), clamdHost: '127.0.0.1', clamdPort: state.port });
    const address = await app.start();
    console.log(JSON.stringify({ ...address, synthetic: true, note: 'Public test accounts only. Ctrl+C closes the lab and removes its temporary data.' }));
    await new Promise(stop => { process.once('SIGINT', stop); process.once('SIGTERM', stop); });
    report = { schema_version: 1, status: 'stopped', image: CLAMAV_IMAGE, cleanup: {} };
  }
} catch (error) {
  report.status = 'failed'; report.error = error.message; process.exitCode = 1;
} finally {
  if (app) { try { await app.close(); } catch { report.status = 'failed'; process.exitCode = 1; } }
  const selectContainers = () => docker(['ps', '-a', '--filter', 'label=security.lab=' + token, '--format', '{{.ID}}'], true);
  const selectNetworks = () => docker(['network', 'ls', '--filter', 'label=security.lab=' + token, '--format', '{{.ID}}'], true);
  const containers = selectContainers();
  if (containers.status === 0) {
    for (const id of containers.stdout.trim().split(/\s+/).filter(Boolean)) {
      docker(['stop', '--time', '5', id], true); docker(['rm', id], true);
    }
    const after = selectContainers();
    report.cleanup.scanner_removed = after.status === 0 && after.stdout.trim() === '';
  } else report.cleanup.scanner_removed = false;
  const networks = selectNetworks();
  if (networks.status === 0) {
    for (const id of networks.stdout.trim().split(/\s+/).filter(Boolean)) docker(['network', 'rm', id], true);
    const after = selectNetworks();
    report.cleanup.network_removed = after.status === 0 && after.stdout.trim() === '';
  } else report.cleanup.network_removed = false;
  if (report.cleanup.scanner_removed && report.cleanup.network_removed && state.consumerExited !== false) {
    await rm(root, { recursive: true, force: true }); report.cleanup.scanner_temp_removed = true;
  } else { report.status = 'failed'; process.exitCode = 1; }
  report.orchestrator_source_files = orchestrationBefore;
  if (JSON.stringify(orchestrationBefore) !== JSON.stringify(await orchestrationHashes())) {
    report.status = 'failed'; report.error = 'Orchestrator source changed during verification'; process.exitCode = 1;
  }
  if (state.redis) report.cleanup.redis_removed = report.cleanup.scanner_removed;
  state.phase = report.status; await save();
  // The wrapper appends verified scanner teardown to its exclusively owned report.
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ status: report.status, checks: report.checks?.length ?? 0, cleanup: report.cleanup }));
}
