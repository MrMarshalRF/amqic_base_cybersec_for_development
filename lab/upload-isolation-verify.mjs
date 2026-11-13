import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, realpath, access } from 'node:fs/promises';
import { dirname, resolve, relative, isAbsolute, sep, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';

export const PYTHON_IMAGE = 'python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704';
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
const paths = ['lab/upload-isolation-verify.mjs', 'infra/container/uploads.compose.yaml'];
const hashes = () => Promise.all(paths.map(async path => ({ path, sha256: createHash('sha256').update(await readFile(join(root, path))).digest('hex') })));
const sourceFiles = await hashes();
const roles = ['prepare', 'intake', 'scanner', 'promoter', 'media'];
const keys = ['quarantine', 'verdicts', 'clean'];
const token = randomBytes(12).toString('hex');
const label = 'amqic.upload.lab=' + token;
const prefix = 'amqic-upload-' + token;
const state = { owner: 'upload-isolation-verify.mjs', task: 'synthetic-upload-storage-roles', token,
  phase: 'intent', image: PYTHON_IMAGE, containers: [], volumes: [],
  baseline: 'No existing application, network, host mount or data is used',
  disposable: 'Exactly three fresh labeled volumes and five labeled containers', cleanupOwner: 'upload-isolation-verify.mjs' };
const save = () => writeFile(output + '.resources.json', JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
function docker(args, env) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 60000, windowsHide: true, maxBuffer: 2 * 1024 * 1024, env });
  if (result.error || result.status !== 0) throw new Error('Docker operation failed: ' + args.slice(0, 2).join(' '));
  return result.stdout.trim();
}
const report = { schema_version: 1, status: 'failed', ok: false, complete: false,
  scope: 'Synthetic Linux upload-volume DAC and read-only mount enforcement; all roles network none',
  application_pipeline: 'not_tested', ingress_networks: 'not_tested', image: PYTHON_IMAGE,
  source_files: sourceFiles, checks: [], cleanup: { ok: false } };
const checked = id => report.checks.push({ id, status: 'passed', ok: true });
let cancelled = false;
process.on('message', message => { if (message?.type === 'cancel') cancelled = true; });
const common = `import os,json,errno,stat
os.umask(0o027)
def denied(path):
    try:
        with open(path,'ab') as f: f.write(b'forbidden')
    except OSError as e:
        assert e.errno in (errno.EACCES,errno.EROFS,errno.EPERM)
        return
    raise AssertionError('write unexpectedly allowed')
def meta(path,uid,gid,mode):
    s=os.stat(path)
    assert (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(uid,gid,mode)
`;
const snippets = {
  intake: `assert not os.path.exists('/clean') and not os.path.exists('/verdicts')
meta('/quarantine',10001,20001,0o750)
with open('/quarantine/sample','wb') as f: f.write(b'synthetic sample')
meta('/quarantine/sample',10001,20001,0o640)
`,
  scanner: `assert not os.path.exists('/clean')
assert open('/quarantine/sample','rb').read()==b'synthetic sample'
denied('/quarantine/sample'); denied('/quarantine/new')
meta('/verdicts',10002,20002,0o750)
with open('/verdicts/verdict','wb') as f: f.write(b'synthetic accepted')
meta('/verdicts/verdict',10002,20002,0o640)
`,
  promoter: `assert open('/quarantine/sample','rb').read()==b'synthetic sample'
assert open('/verdicts/verdict','rb').read()==b'synthetic accepted'
for p in ['/quarantine/sample','/quarantine/new','/verdicts/verdict','/verdicts/new']: denied(p)
meta('/clean',10003,20003,0o750)
with open('/clean/sample','wb') as f: f.write(b'synthetic sample')
meta('/clean/sample',10003,20003,0o640)
`,
  media: `assert not os.path.exists('/quarantine') and not os.path.exists('/verdicts')
assert open('/clean/sample','rb').read()==b'synthetic sample'
denied('/clean/sample'); denied('/clean/new')
` };
await writeFile(output + '.resources.json', JSON.stringify(state, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
try {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(COMPOSE_|PYTHON_IMAGE_|UPLOAD_)/.test(key)));
  Object.assign(env, { COMPOSE_DISABLE_ENV_FILE: '1', COMPOSE_PROJECT_NAME: prefix, PYTHON_IMAGE_REPOSITORY: 'python', PYTHON_IMAGE_SHA256: PYTHON_IMAGE.split('sha256:')[1] });
  for (const role of roles.slice(1)) {
    env['UPLOAD_' + role.toUpperCase() + '_REPOSITORY'] = 'python';
    env['UPLOAD_' + role.toUpperCase() + '_SHA256'] = PYTHON_IMAGE.split('sha256:')[1];
  }
  const config = JSON.parse(docker(['compose', '-f', join(root, paths[1]), '--profile', 'prepare', 'config', '--format', 'json'], env));
  assert.deepEqual(Object.keys(config.services).sort(), [...roles].sort());
  assert.deepEqual(Object.keys(config.volumes).sort(), [...keys].sort());
  assert.equal(new Set(Object.values(config.volumes).map(v => v.name)).size, 3);
  const expected = { prepare: ['0:0', [], [['quarantine', false], ['verdicts', false], ['clean', false]]], intake: ['10001:20001', [], [['quarantine', false]]], scanner: ['10002:20002', ['20001'], [['quarantine', true], ['verdicts', false]]], promoter: ['10003:20003', ['20001', '20002'], [['quarantine', true], ['verdicts', true], ['clean', false]]], media: ['10004:10004', ['20003'], [['clean', true]]] };
  for (const role of roles) {
    const s = config.services[role]; const [user, groups, mounts] = expected[role];
    assert.equal(s.image, PYTHON_IMAGE); assert.equal(s.user, user);
    assert.deepEqual((s.group_add ?? []).map(String).sort(), [...groups].sort());
    assert.equal(s.read_only, true); assert.equal(s.privileged ?? false, false);
    assert.deepEqual(s.cap_drop, ['ALL']); assert.deepEqual(s.cap_add ?? [], role === 'prepare' ? ['CHOWN'] : []);
    assert.ok(s.security_opt.includes('no-new-privileges:true'));
    assert.deepEqual(s.volumes.map(m => [m.source, m.read_only === true]), mounts);
    for (const m of s.volumes) { assert.equal(m.type, 'volume'); assert.equal(m.target, '/' + m.source); assert.equal(m.volume.nocopy, true); }
  }
  assert.deepEqual(config.services.prepare.entrypoint, ['python3', '-c']);
  assert.equal(config.services.prepare.command.length, 1);
  const prepare = config.services.prepare.command[0];
  report.prepare_sha256 = createHash('sha256').update(prepare).digest('hex');
  checked('compose_contract');
  const image = JSON.parse(docker(['image', 'inspect', PYTHON_IMAGE]))[0];
  assert.equal(image.Os, 'linux');
  for (const key of keys) {
    if (cancelled) throw new Error('Cancelled');
    const name = prefix + '-' + key; state.intent = { action: 'create-volume', name }; await save();
    // Refuse name collisions; listing success is required before mutation.
    assert.equal(docker(['volume', 'ls', '-q', '--filter', 'name=^' + name + '$']), '');
    assert.equal(docker(['volume', 'create', '--label', label, name]), name);
    const observed = JSON.parse(docker(['volume', 'inspect', name]))[0];
    assert.equal(observed.Labels['amqic.upload.lab'], token);
    state.volumes.push({ key, name, createdAt: observed.CreatedAt }); delete state.intent; await save();
  }
  for (const role of roles) {
    if (cancelled) throw new Error('Cancelled');
    const s = config.services[role]; const name = prefix + '-' + role;
    const command = role === 'prepare' ? prepare : common + `assert os.getuid()==${s.user.split(':')[0]} and os.getgid()==${s.user.split(':')[1]}\nassert set(os.getgroups())==set(${JSON.stringify([s.user.split(':')[1], ...(s.group_add ?? []).map(String)].map(Number))})\n` + snippets[role];
    const create = ['create', '--name', name, '--label', label, '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '32', '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5', '--ulimit', 'core=0:0', '--ulimit', 'nofile=1024:1024', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777', '--user', s.user];
    for (const cap of s.cap_add ?? []) create.push('--cap-add', cap);
    for (const group of s.group_add ?? []) create.push('--group-add', String(group));
    for (const m of s.volumes) create.push('--mount', 'type=volume,source=' + state.volumes.find(v => v.key === m.source).name + ',target=' + m.target + ',volume-nocopy' + (m.read_only ? ',readonly' : ''));
    create.push('--entrypoint', 'python3', PYTHON_IMAGE, '-c', command);
    state.intent = { action: 'create-container', role, name }; await save();
    assert.equal(docker(['ps', '-aq', '--filter', 'name=^/' + name + '$']), '');
    const id = docker(create); assert.match(id, /^[a-f0-9]{64}$/);
    state.containers.push({ role, name, id }); delete state.intent; await save();
    const observed = JSON.parse(docker(['inspect', id]))[0];
    assert.equal(observed.Config.Labels['amqic.upload.lab'], token);
    assert.equal(observed.Config.User, s.user); assert.equal(observed.Image, image.Id);
    assert.equal(observed.HostConfig.NetworkMode, 'none'); assert.equal(observed.HostConfig.ReadonlyRootfs, true);
    assert.equal(observed.HostConfig.Privileged, false); assert.deepEqual(observed.HostConfig.CapDrop, ['ALL']);
    assert.deepEqual((observed.HostConfig.CapAdd ?? []).map(cap => cap.replace(/^CAP_/, '')), role === 'prepare' ? ['CHOWN'] : []);
    assert.deepEqual((observed.HostConfig.GroupAdd ?? []).sort(), (s.group_add ?? []).map(String).sort());
    assert.equal(observed.Mounts.length, s.volumes.length);
    for (const m of s.volumes) {
      const actual = observed.Mounts.find(v => v.Destination === m.target);
      assert.equal(actual.Type, 'volume'); assert.equal(actual.Name, state.volumes.find(v => v.key === m.source).name); assert.equal(actual.RW, !m.read_only);
      assert.equal(observed.HostConfig.Mounts.find(v => v.Target === m.target).VolumeOptions.NoCopy, true);
    }
    docker(['start', '-a', id]);
    const finished = JSON.parse(docker(['inspect', id]))[0].State;
    Object.assign(state.containers.at(-1), { startedAt: finished.StartedAt, finishedAt: finished.FinishedAt, exitCode: finished.ExitCode }); await save();
    assert.equal(finished.Status, 'exited'); assert.equal(finished.ExitCode, 0);
    checked('runtime_' + role);
  }
  assert.deepEqual(await hashes(), sourceFiles); checked('source_stable');
  report.status = 'passed';
} catch (error) {
  state.failure = String(error.message);
  report.error = 'Upload isolation validation failed; inspect the private resource ledger';
}
finally {
  state.phase = 'cleanup'; await save();
  try {
    const ids = docker(['ps', '-aq', '--filter', 'label=' + label]).split(/\s+/).filter(Boolean);
    for (const id of ids) { assert.match(id, /^[a-f0-9]{12,64}$/); docker(['rm', '-f', id]); }
    const volumes = docker(['volume', 'ls', '-q', '--filter', 'label=' + label]).split(/\s+/).filter(Boolean);
    for (const name of volumes) { assert.ok(keys.some(key => name === prefix + '-' + key)); docker(['volume', 'rm', name]); }
    assert.equal(docker(['ps', '-aq', '--filter', 'label=' + label]), '');
    assert.equal(docker(['volume', 'ls', '-q', '--filter', 'label=' + label]), '');
    report.cleanup = { ok: true, containers_absent: true, volumes_absent: true, verified_by_successful_listing: true };
    state.phase = 'cleaned';
  } catch (error) {
    state.cleanupFailure = String(error.message);
    report.cleanup = { ok: false, status: 'cleanup_pending', error: 'Inspect the private resource ledger' };
    report.status = 'failed'; state.phase = 'cleanup_pending';
  }
  await save(); report.ok = report.complete = report.status === 'passed' && report.cleanup.ok;
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
process.exitCode = report.ok ? 0 : 1;
if (process.connected) process.disconnect();
