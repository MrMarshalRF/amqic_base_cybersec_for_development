import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, realpath, access } from 'node:fs/promises';
import { dirname, resolve, relative, isAbsolute, sep, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

export const NGINX_IMAGE = 'nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10';
const root = await realpath(fileURLToPath(new URL('..', import.meta.url)));
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--output' || !isAbsolute(args[1])) throw new Error('Use --output ABSOLUTE_EXTERNAL_NEW.json');
const output = resolve(args[1]);
const parent = await realpath(dirname(output));
const rel = relative(root, parent);
if (!(rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel))) throw new Error('Report must be outside source tree');
for (const path of [output, output + '.resources.json']) {
  try { await access(path); throw new Error('Output exists'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
const paths = ['lab/cache-verify.mjs', 'lab/cache-fixtures/upstream.conf', 'lab/cache-fixtures/proxy.conf'];
const hashes = () => Promise.all(paths.map(async path => ({ path, sha256: createHash('sha256').update(await readFile(join(root, path))).digest('hex') })));
const sourceFiles = await hashes();
const token = randomBytes(10).toString('hex');
const label = 'amqic.cache.lab=' + token;
const state = { task: 'synthetic-cache-lab', owner: 'cache-verify.mjs', token, phase: 'intent', image: NGINX_IMAGE,
  baseline: 'No existing containers or networks are used or changed', disposable: 'Only this token-labeled network and two containers; tmpfs cache', network: null, containers: [] };
const save = () => writeFile(output + '.resources.json', JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
function docker(args, timeout = 30000) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('Docker operation failed: ' + args.slice(0, 2).join(' '));
  return result.stdout.trim();
}
const report = { schema_version: 1, status: 'failed', complete: false, scope: 'isolated synthetic Nginx HTTP cache reference',
  realCloudflare: 'vendor_not_tested', image: NGINX_IMAGE, node: process.version, source_files: sourceFiles, checks: [], cleanup: {} };
await save();
let cancelled = false;
process.on('message', message => { if (message?.type === 'cancel') cancelled = true; });
try {
  report.image_id = JSON.parse(docker(['image', 'inspect', NGINX_IMAGE]))[0].Id;
  state.network = docker(['network', 'create', '--internal', '--label', label, 'amqic-cache-' + token]); await save();
  for (const role of ['upstream', 'proxy']) {
    state.pendingRole = role; await save();
    const createArgs = ['create', '--name', 'amqic-cache-' + token + '-' + role, '--label', label, '--network', state.network,
      '--read-only', '--user', '101:101', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '64m', '--cpus', '0.5', '--pids-limit', '32',
      '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
      '--mount', 'type=bind,src=' + join(root, 'lab/cache-fixtures/' + role + '.conf') + ',dst=/etc/nginx/nginx.conf,readonly'];
    if (role === 'upstream') createArgs.push('--network-alias', 'synthetic-upstream');
    createArgs.push('--entrypoint', 'nginx', NGINX_IMAGE, '-g', 'daemon off;');
    const id = docker(createArgs); state.containers.push({ role, id }); delete state.pendingRole; await save();
    docker(['start', id]);
    const observed = JSON.parse(docker(['inspect', id]))[0];
    Object.assign(state.containers.at(-1), { startedAt: observed.State.StartedAt, pid: observed.State.Pid, ports: observed.NetworkSettings.Ports }); await save();
  }
  state.phase = 'running'; await save();
  const proxy = state.containers.find(c => c.role === 'proxy');
  assert.ok(Object.values(proxy.ports).every(bindings => bindings === null || bindings.length === 0));
  const origin = 'http://127.0.0.1:8080'; // Loopback inside the proxy container; no host port.
  const version = spawnSync('docker', ['exec', proxy.id, 'nginx', '-v'], { encoding: 'utf8', timeout: 10000, windowsHide: true });
  if (version.error || version.status !== 0) throw new Error('Cannot observe Nginx version');
  report.nginx_version = version.stderr.trim() || version.stdout.trim();
  async function request(path, headers = {}) {
    if (cancelled) throw new Error('Cancelled');
    const command = ['exec', proxy.id, 'wget', '-S', '-T', '3', '-O', '-'];
    for (const [key, value] of Object.entries(headers)) command.push('--header', key + ': ' + value);
    command.push(origin + path);
    const response = spawnSync('docker', command, { encoding: 'utf8', timeout: 7000, windowsHide: true, maxBuffer: 8192 });
    if (response.error || response.status !== 0) throw new Error('Synthetic HTTP probe failed');
    const body = response.stdout; assert.ok(body.length < 2048); assert.match(response.stderr, /HTTP\/1\.[01] 200/);
    const observedHeaders = new Map(response.stderr.split(/\r?\n/).map(line => {
      const found = line.trim().match(/^([^: ]+):\s*(.*)$/); return found ? [found[1].toLowerCase(), found[2]] : ['', ''];
    }));
    return { body: JSON.parse(body), status: observedHeaders.get('x-lab-cache-status'), id: observedHeaders.get('x-upstream-request'),
      cacheControl: observedHeaders.get('cache-control'), cookie: observedHeaders.get('set-cookie') ?? null, server: observedHeaders.get('server') };
  }
  let ready = false;
  for (let i = 0; i < 20; i++) { try { await request('/ready'); ready = true; break; } catch (error) { if (cancelled) throw error; await delay(200); } }
  assert.ok(ready, 'Proxy did not become ready');
  const publicPath = '/assets/public.0123456789abcdef.js';
  const first = await request(publicPath); const second = await request(publicPath);
  assert.equal(first.status, 'MISS'); assert.equal(second.status, 'HIT'); assert.equal(first.id, second.id);
  assert.equal(second.body.user, 'anonymous'); assert.equal(second.cookie, null);
  assert.match(second.cacheControl, /public.*immutable/); assert.equal(second.server, 'nginx');
  report.checks.push({ id: 'public_fingerprinted_asset_cache_hit', status: 'passed', first: first.status, second: second.status });
  for (const path of [publicPath, '/private', '/api/profile', '/account', '/assets/no-store.0123456789abcdef.js', '/assets/cookie.0123456789abcdef.js']) {
    for (const kind of ['authorization', 'cookie']) {
      const header = user => kind === 'authorization' ? { Authorization: 'Bearer synthetic-' + user } : { Cookie: 'lab_user=' + user };
      const responses = [];
      for (const user of ['A', 'B', 'A', 'B']) { const r = await request(path, { ...header(user), 'X-Lab-Cache-Status': 'HIT' });
        assert.equal(r.body.user, user); assert.equal(r.status, 'BYPASS'); responses.push(r); }
      assert.equal(new Set(responses.map(r => r.id)).size, 4);
      report.checks.push({ id: 'client_isolation', path, credential: kind, status: 'passed', cache: 'BYPASS' });
    }
  }
  for (const path of ['/private', '/api/profile', '/account', '/assets/no-store.0123456789abcdef.js', '/assets/cookie.0123456789abcdef.js']) {
    const a = await request(path); const b = await request(path);
    assert.notEqual(a.status, 'HIT'); assert.notEqual(b.status, 'HIT'); assert.notEqual(a.id, b.id);
    if (!path.includes('/assets/cookie.')) assert.match(b.cacheControl, /private, no-store/);
    if (path.includes('/assets/cookie.')) assert.ok(b.cookie);
    report.checks.push({ id: 'origin_private_or_set_cookie_not_stored', path, status: 'passed', observed: [a.status, b.status] });
  }
  const publicAgain = await request(publicPath); assert.equal(publicAgain.status, 'HIT'); assert.equal(publicAgain.body.user, 'anonymous');
  assert.deepEqual(await hashes(), sourceFiles);
  report.checks.push({ id: 'source_stable_and_anonymous_cache_unpoisoned', status: 'passed' });
  report.status = 'passed';
} catch (error) { report.error = String(error.message); }
finally {
  state.phase = 'cleanup'; await save();
  try {
    // Discover partial creates by the exact random ownership label before removing anything.
    const ids = docker(['ps', '-aq', '--filter', 'label=' + label]).split(/\s+/).filter(Boolean);
    for (const id of ids) { assert.match(id, /^[a-f0-9]{12,64}$/); docker(['rm', '-f', id]); }
    const networks = docker(['network', 'ls', '-q', '--filter', 'label=' + label]).split(/\s+/).filter(Boolean);
    for (const id of networks) { assert.match(id, /^[a-f0-9]{12,64}$/); docker(['network', 'rm', id]); }
    assert.equal(docker(['ps', '-aq', '--filter', 'label=' + label]), '');
    assert.equal(docker(['network', 'ls', '-q', '--filter', 'label=' + label]), '');
    report.cleanup = { containers_absent: true, network_absent: true, verified_by_successful_listing: true };
    state.phase = 'cleaned';
  } catch (error) { report.cleanup = { status: 'cleanup_pending', error: error.message }; report.status = 'failed'; state.phase = 'cleanup_pending'; }
  await save(); report.complete = report.status === 'passed';
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
process.exitCode = report.status === 'passed' ? 0 : 1;
if (process.connected) process.disconnect();
