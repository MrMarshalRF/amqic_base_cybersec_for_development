import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, realpathSync, existsSync } from 'node:fs';
import { dirname, resolve, relative, isAbsolute, sep, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash } from 'node:crypto';

export const INFRA_IMAGE = 'amqic-infra-lab:1.2';
export const INFRA_DOCKERFILE = fileURLToPath(new URL('./infra-fixtures/Dockerfile', import.meta.url));
export const INFRA_BUILD_CONTEXT = dirname(INFRA_DOCKERFILE);
export const INFRA_RECIPE_SHA256 = createHash('sha256').update(readFileSync(INFRA_DOCKERFILE)).digest('hex');
const source = realpathSync(fileURLToPath(new URL('..', import.meta.url)));

export function verifyInfrastructure(output) {
  if (!isAbsolute(output)) throw new Error('Output must be absolute');
  output = resolve(output);
  const rel = relative(source, realpathSync(dirname(output)));
  if (!(rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel))) throw new Error('Report must be outside source tree');
  const ledger = output + '.resources.json';
  if (existsSync(output) || existsSync(ledger)) throw new Error('Output must be new');
  const token = randomBytes(10).toString('hex');
  const label = 'amqic.infra.owner=' + token;
  const state = { schemaVersion: 1, task: 'synthetic-infrastructure-lab', token, cleanupOwner: 'infra-verify', phase: 'intent', network: null, containers: [], intents: [], primaryEnvironment: 'none; isolated synthetic resources only' };
  const result = { schemaVersion: 1, ok: false, checks: {}, resources: state, cleanup: { ok: false }, image: null };
  const sourceFiles = ['lab/infra-verify.mjs', 'lab/infra-fixtures/probes.py', 'lab/infra-fixtures/runtime-probe.c', 'lab/infra-fixtures/Dockerfile', 'infra/container/Dockerfile', 'infra/ssh/00-security.conf.template', ...['render.py', 'addresses.py', 'nftables.conf.template', '__init__.py'].map(x => 'infra/firewall/' + x), ...['archive_crypto.mjs', 'backup.py', 'test_operations.py', 'test_terminal_input.py'].map(x => 'scripts/' + x)];
  const hashes = () => sourceFiles.map(path => ({ path, sha256: createHash('sha256').update(readFileSync(join(source, path))).digest('hex') }));
  result.sourceBefore = hashes();
  const save = () => writeFileSync(ledger, JSON.stringify(state, null, 2) + '\n');
  writeFileSync(ledger, JSON.stringify(state, null, 2) + '\n', { flag: 'wx' });
  const cmd = (args, allow = false, timeout = 90000) => {
    const p = spawnSync('docker', args, { encoding: 'utf8', timeout, maxBuffer: 8 * 1024 * 1024 });
    if (p.error || (!allow && p.status !== 0)) throw new Error(`docker ${args[0]} failed: ${(p.error?.message || p.stderr || '').slice(-2000)}`);
    return { status: p.status, stdout: p.stdout || '', stderr: p.stderr || '' };
  };
  const inspect = (kind, id) => JSON.parse(cmd([kind, 'inspect', id]).stdout)[0];
  const probe = (id, ...args) => JSON.parse(cmd(['exec', id, '/usr/local/bin/python3', '/lab/probes.py', ...args], false, 180000).stdout);
  const exec = (id, ...args) => cmd(['exec', id, ...args]);
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  try {
    const image = inspect('image', INFRA_IMAGE);
    result.image = image.Id;
    result.recipeSha256 = INFRA_RECIPE_SHA256;
    assert(image.Config.Labels?.['org.amqic.infra.recipe-sha256'] === INFRA_RECIPE_SHA256, 'Image recipe label differs; run explicit preparation');
    state.intents.push({ type: 'network', name: 'amqic-infra-' + token, internal: true }); save();
    const networkId = cmd(['network', 'create', '--internal', '--label', label, 'amqic-infra-' + token]).stdout.trim();
    state.network = { id: networkId }; save();
    const net = inspect('network', networkId);
    assert(net.Internal && net.Labels['amqic.infra.owner'] === token, 'Network ownership/internal confinement failed');
    for (const role of ['server', 'client', 'outsider']) {
      const name = 'amqic-infra-' + role + '-' + token;
      state.intents.push({ type: 'container', name, role, image: result.image }); save();
      const id = cmd(['create', '--name', name, '--label', label, '--network', networkId, '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'SYS_CHROOT', '--security-opt', 'no-new-privileges:true', result.image, 'sleep', 'infinity']).stdout.trim();
      const entry = { id, role, name, phase: 'created' }; state.containers.push(entry); save();
      let info = inspect('container', id);
      assert(info.Config.Labels['amqic.infra.owner'] === token && !info.HostConfig.Privileged && info.HostConfig.NetworkMode === networkId && info.Mounts.length === 0 && Object.keys(info.HostConfig.PortBindings || {}).length === 0, 'Container isolation inspection failed');
      cmd(['start', id]); info = inspect('container', id);
      Object.assign(entry, { phase: 'running', pid: info.State.Pid, startedAt: info.State.StartedAt, ip: Object.values(info.NetworkSettings.Networks)[0].IPAddress }); save();
      exec(id, 'mkdir', '-p', '/lab/scripts', '/lab/infra/firewall', '/lab/infra/ssh');
      cmd(['cp', join(INFRA_BUILD_CONTEXT, 'probes.py'), id + ':/lab/probes.py']);
      for (const file of ['archive_crypto.mjs', 'backup.py', 'test_operations.py', 'test_terminal_input.py']) cmd(['cp', join(source, 'scripts', file), id + ':/lab/scripts/' + file]);
      for (const file of ['render.py', 'addresses.py', 'nftables.conf.template', '__init__.py']) cmd(['cp', join(source, 'infra/firewall', file), id + ':/lab/infra/firewall/' + file]);
      cmd(['cp', join(source, 'infra/ssh/00-security.conf.template'), id + ':/lab/infra/ssh/00-security.conf.template']);
    }
    const [server, client, outsider] = state.containers;
    result.packages = exec(server.id, 'dpkg-query', '-W', 'openssh-server', 'openssh-client', 'nftables', 'iproute2', 'wireguard-tools', 'iputils-ping', 'python3', 'gcc', 'binutils', 'keepassxc').stdout.trim().split('\n');
    result.checks.sshSetup = probe(server.id, 'ssh-setup');
    for (const key of ['good', 'wrong', 'host.pub']) {
      // Transfer synthetic keys container-to-container through pipe input, never host files/logs.
      const archive = spawnSync('docker', ['cp', server.id + ':/lab/' + key, '-'], { maxBuffer: 1024 * 1024 });
      assert(archive.status === 0, 'Synthetic key transfer read failed');
      const copy = spawnSync('docker', ['cp', '-', client.id + ':/lab/'], { input: archive.stdout, maxBuffer: 1024 * 1024 });
      assert(copy.status === 0, 'Synthetic key transfer write failed');
    }
    result.checks.ssh = probe(client.id, 'ssh-probe', server.ip); assert(result.checks.ssh.ok, 'SSH policy check failed');
    // Actual listeners on namespace-only addresses, with no published host ports.
    exec(server.id, 'sh', '-c', 'python3 -m http.server 443 >/dev/null 2>&1 & python3 -m http.server 8080 >/dev/null 2>&1 &');
    result.checks.tcpBaseline = { admin: probe(client.id, 'tcp', server.ip, '2222'), proxy: probe(client.id, 'tcp', server.ip, '443'), arbitrary: probe(client.id, 'tcp', server.ip, '8080'), outsider: probe(outsider.id, 'tcp', server.ip, '2222') };
    assert(Object.values(result.checks.tcpBaseline).every(x => x.connected), 'Baseline TCP reachability failed');
    result.checks.firewallLoad = probe(server.id, 'firewall', client.ip);
    const firewall = { adminAllowed: probe(client.id, 'tcp', server.ip, '2222').connected, proxyAllowed: probe(client.id, 'tcp', server.ip, '443').connected, arbitraryDenied: !probe(client.id, 'tcp', server.ip, '8080').connected, outsiderSshDenied: !probe(outsider.id, 'tcp', server.ip, '2222').connected, outsiderWebDenied: !probe(outsider.id, 'tcp', server.ip, '443').connected };
    result.checks.firewall = { ok: Object.values(firewall).every(Boolean), ...firewall }; assert(result.checks.firewall.ok, 'nftables policy traffic check failed');
    exec(server.id, 'nft', 'delete', 'table', 'inet', 'amqic_origin_guard');
    const left = probe(server.id, 'wg-setup', client.ip, '-', '1');
    const right = probe(client.id, 'wg-setup', server.ip, '-', '2');
    if (left.status === 'unsupported' || right.status === 'unsupported') {
      result.checks.wireguard = { status: 'unsupported', ok: false, reason: left.reason || right.reason };
    } else {
      probe(server.id, 'wg-setup', client.ip, right.publicKey, '1');
      probe(client.id, 'wg-setup', server.ip, left.publicKey, '2');
      const ping = cmd(['exec', client.id, 'ping', '-c', '2', '-W', '2', '10.77.0.1'], true);
      const handshake = exec(client.id, 'wg', 'show', 'wgtest', 'latest-handshakes').stdout.trim().split(/\s+/).at(-1);
      exec(server.id, 'wg', 'set', 'wgtest', 'peer', right.publicKey, 'remove');
      const revoked = cmd(['exec', client.id, 'ping', '-c', '1', '-W', '2', '10.77.0.1'], true);
      result.checks.wireguard = { status: 'tested', ok: ping.status === 0 && Number(handshake) > 0 && revoked.status !== 0, tunnelPing: ping.status === 0, handshakeObserved: Number(handshake) > 0, revokedPeerDenied: revoked.status !== 0 };
    }
    result.checks.linuxComplements = probe(server.id, 'complements');
    assert(result.checks.linuxComplements.ok, 'Linux PTY/backup complement failed');
    result.checks.artifacts = probe(server.id, 'artifacts');
    assert(result.checks.artifacts.ok, 'Symbol separation or synthetic vault failed');
    exec(server.id, 'mkdir', '-p', '/lab/runtime');
    cmd(['cp', join(INFRA_BUILD_CONTEXT, 'runtime-probe.c'), server.id + ':/lab/runtime-probe.c']);
    cmd(['cp', join(source, 'infra/container/Dockerfile'), server.id + ':/lab/runtime/Dockerfile']);
    exec(server.id, 'gcc', '-static', '-O2', '/lab/runtime-probe.c', '-o', '/lab/runtime/app');
    const context = spawnSync('docker', ['cp', server.id + ':/lab/runtime/.', '-'], { maxBuffer: 16 * 1024 * 1024 });
    assert(context.status === 0, 'Runtime build context failed');
    const runtimeTag = 'amqic-synthetic-runtime:' + token;
    state.runtimeImage = { tag: runtimeTag, phase: 'intent' }; save();
    const built = spawnSync('docker', ['build', '--network=none', '--label', label, '-t', runtimeTag, '-'], { input: context.stdout, encoding: 'utf8', timeout: 120000, maxBuffer: 2 * 1024 * 1024 });
    assert(built.status === 0, 'Synthetic runtime build failed: ' + built.stderr?.slice(-1000));
    state.runtimeImage.id = inspect('image', runtimeTag).Id; save();
    const runtimeId = cmd(['create', '--label', label, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5', '--ulimit', 'core=0:0', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777', state.runtimeImage.id]).stdout.trim();
    state.containers.push({ id: runtimeId, role: 'runtime', phase: 'created' }); save();
    const runtimeBefore = inspect('container', runtimeId);
    assert(runtimeBefore.HostConfig.ReadonlyRootfs && !runtimeBefore.HostConfig.Privileged && runtimeBefore.HostConfig.NetworkMode === 'none' && runtimeBefore.Config.User === '65532:65532' && runtimeBefore.HostConfig.CapDrop.includes('ALL') && runtimeBefore.HostConfig.PidsLimit === 64 && runtimeBefore.Mounts.every(m => m.Type === 'tmpfs'), 'Runtime policy inspection failed');
    const runtimeOutput = cmd(['start', '-a', runtimeId]);
    result.checks.containerRuntime = JSON.parse(runtimeOutput.stdout);
    const runtimeInfo = inspect('container', runtimeId);
    Object.assign(state.containers.at(-1), { startedAt: runtimeInfo.State.StartedAt, finishedAt: runtimeInfo.State.FinishedAt, phase: 'exited' }); save();
    assert(result.checks.containerRuntime.ok && runtimeInfo.State.ExitCode === 0, 'Container confinement check failed');
    result.ok = result.checks.wireguard.ok;
  } catch (error) { result.error = error.message; }
  finally {
    state.phase = 'cleanup'; save();
    const failures = [];
    // Reconcile partial/unknown creates by the unique owner label, never retry creation.
    try {
      for (const id of cmd(['ps', '-aq', '--no-trunc', '--filter', 'label=' + label]).stdout.trim().split(/\s+/).filter(Boolean)) {
        if (!state.containers.some(item => item.id === id)) state.containers.push({ id, role: 'reconciled-partial-create' });
      }
      const networks = cmd(['network', 'ls', '-q', '--no-trunc', '--filter', 'label=' + label]).stdout.trim().split(/\s+/).filter(Boolean);
      if (!state.network && networks.length === 1) state.network = { id: networks[0] };
      assert(networks.length <= 1, 'Unexpected additional owned networks');
    } catch (error) { failures.push({ phase: 'reconcile', error: error.message }); }
    for (const container of state.containers.slice().reverse()) {
      try {
        const info = inspect('container', container.id);
        assert(info.Config.Labels['amqic.infra.owner'] === token, 'Cleanup owner mismatch');
        cmd(['rm', '-f', container.id]);
        assert(!cmd(['ps', '-aq', '--no-trunc', '--filter', 'id=' + container.id]).stdout.trim(), 'Container still present');
        container.phase = 'removed';
      } catch (error) { failures.push({ id: container.id, error: error.message }); }
      save();
    }
    if (state.network) {
      try {
        const info = inspect('network', state.network.id);
        assert(info.Labels['amqic.infra.owner'] === token && Object.keys(info.Containers || {}).length === 0, 'Network cleanup scope mismatch');
        cmd(['network', 'rm', state.network.id]);
        assert(!cmd(['network', 'ls', '-q', '--no-trunc', '--filter', 'id=' + state.network.id]).stdout.trim(), 'Network still present');
        state.network.phase = 'removed';
      } catch (error) { failures.push({ id: state.network.id, error: error.message }); }
    }
    if (state.runtimeImage) {
      try {
        const candidates = cmd(['image', 'ls', '-q', '--no-trunc', '--filter', 'label=' + label]).stdout.trim().split(/\s+/).filter(Boolean);
        for (const id of new Set(candidates)) { cmd(['image', 'rm', id]); }
        assert(!cmd(['image', 'ls', '-q', '--filter', 'label=' + label]).stdout.trim(), 'Runtime image still present');
        state.runtimeImage.phase = 'removed';
      } catch (error) { failures.push({ phase: 'runtime-image', error: error.message }); }
    }
    state.phase = failures.length ? 'cleanup_pending' : 'removed'; save();
    result.cleanup = { ok: failures.length === 0, failures }; result.ok &&= result.cleanup.ok;
    result.sourceAfter = hashes();
    result.sourceUnchanged = JSON.stringify(result.sourceBefore) === JSON.stringify(result.sourceAfter);
    result.ok &&= result.sourceUnchanged;
    result.status = result.ok ? 'passed' : 'failed'; result.complete = result.ok;
    writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
  }
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== '--output') throw new Error('Use --output ABSOLUTE_NEW_EXTERNAL.json');
  const result = verifyInfrastructure(process.argv[3]);
  console.log(JSON.stringify({ ok: result.ok, output: process.argv[3], cleanup: result.cleanup.ok }));
  process.exitCode = result.ok ? 0 : 1;
}
