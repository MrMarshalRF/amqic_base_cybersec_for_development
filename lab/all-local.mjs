// Fixed local scenario dispatcher. Arguments are metadata, never executable commands.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, realpathSync, existsSync, statSync, readdirSync, mkdtempSync, unlinkSync, rmdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname, relative, isAbsolute, sep, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const root = realpathSync(fileURLToPath(new URL('..', import.meta.url)));
const catalog = JSON.parse(readFileSync(resolve(root, 'lab/scenarios.json'), 'utf8'));
export function acceptStage(id, child) {
  const cleanup = child?.cleanup;
  const has = ids => Array.isArray(child?.checks) && ids.every(id => child.checks.some(check => check.id === id && check.status === 'passed'));
  if (id === 'baseline') return child?.schema_version === 1 && ['passed', 'incomplete'].includes(child.status) && has(['coverage-membership', 'sha256-registry', 'source-stability', 'node-runtime', 'python-runtime', 'node-syntax', 'node-tests', 'core-demo', 'operations', 'production', 'versions', 'quarantine', 'nginx-harness', 'firewall-render', 'compose-runtime', 'compose']) && child.checks.every(check => check.status === 'passed' || (check.status === 'not_run' && ['terminal', 'live-consumers', 'nginx-runtime'].includes(check.id)));
  if (id === 'live-consumers') return child?.schema_version === 1 && child.status === 'passed' && has(['clamav-clean', 'clamav-marker', 'browser-fixture-loaded', 'browser-full-login-stages', 'browser-stored-text-not-html', 'browser-upload-clean', 'browser-upload-rejected', 'redis-authenticated-atomic-limits']) && child.checks.every(check => check.status === 'passed') && ['scanner_removed', 'network_removed', 'scanner_temp_removed', 'redis_removed', 'browser_stopped', 'application_stopped', 'private_temp_removed'].every(key => cleanup?.[key] === true);
  if (id === 'infra-runtime') return child?.schemaVersion === 1 && child.ok === true && cleanup?.ok === true && cleanup.failures?.length === 0 && ['ssh', 'firewall', 'wireguard', 'linuxComplements', 'artifacts', 'containerRuntime'].every(key => child.checks?.[key]?.ok === true);
  if (id === 'cache-runtime') return child?.schema_version === 1 && child.status === 'passed' && child.complete === true && has(['public_fingerprinted_asset_cache_hit', 'client_isolation', 'origin_private_or_set_cookie_not_stored', 'source_stable_and_anonymous_cache_unpoisoned']) && child.checks.every(check => check.status === 'passed') && cleanup?.containers_absent === true && cleanup?.network_absent === true && cleanup?.verified_by_successful_listing === true;
  if (id === 'upload-isolation-runtime') return child?.schema_version === 1 && child.status === 'passed' && child.ok === true && child.complete === true && has(['compose_contract', 'runtime_prepare', 'runtime_intake', 'runtime_scanner', 'runtime_promoter', 'runtime_media', 'source_stable']) && child.checks.every(check => check.status === 'passed' && check.ok === true) && cleanup?.ok === true && cleanup?.containers_absent === true && cleanup?.volumes_absent === true && cleanup?.verified_by_successful_listing === true;
  if (id === 'nginx-runtime') return child?.result === 'passed' && child?.cleanup_pending === false && child?.container_absent === true && child?.network_absent === true && child?.source_unchanged === true;
  return false;
}
if (process.argv[1] && ['scripts/verify.mjs', 'lab/all-local.mjs'].some(path => resolve(process.argv[1]) === resolve(root, path))) {
const argv = process.argv.slice(2);
const options = {};
let invalid = null;
for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (options[arg] !== undefined) { invalid = 'duplicate_option'; break; }
  if (['--all', '--prepare', '--plan'].includes(arg)) options[arg] = true;
  else if (arg === '--output' && argv[i + 1] && !argv[i + 1].startsWith('--')) options[arg] = argv[++i];
  else { invalid = 'unknown_or_incomplete_option'; break; }
}
const fixedImages = [
  { id: 'clamav', reference: 'clamav/clamav@sha256:64ca916618842ba469ef38a501e6c2f42a68281c064c03749b0126c0fb085ce5' },
  { id: 'redis', reference: 'redis@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf' },
  { id: 'nginx', reference: 'nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10' },
  { id: 'node-tool-base', reference: 'node@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c' },
  { id: 'python-tool-base', reference: 'python@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7' },
  { id: 'upload-python', reference: 'python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704' },
];
const stageIds = ['baseline', 'live-consumers', 'nginx-runtime', 'infra-runtime', 'cache-runtime', 'upload-isolation-runtime'];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function sourceSnapshot(directory = root, prefix = '') {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (['.git', 'node_modules', '__pycache__', '.venv', '.agent-private', '.internal'].includes(entry.name)) return [];
    const name = prefix + entry.name;
    if (entry.isDirectory()) return sourceSnapshot(resolve(directory, entry.name), name + '/');
    if (!entry.isFile()) throw new Error('Nonregular public entry');
    return [{ path: name, sha256: digest(readFileSync(resolve(root, name))) }];
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
const invoke = (executable, args, timeout = 120000, env = process.env) => {
  const result = spawnSync(executable, args, { cwd: root, shell: false, windowsHide: true, timeout, env, maxBuffer: 8 * 1024 * 1024 });
  const bytes = Buffer.concat([result.stdout ?? Buffer.alloc(0), result.stderr ?? Buffer.alloc(0)]);
  return { result, evidence: { exit_code: result.status, signal: result.signal, error_code: result.error?.code ?? null, output_sha256: digest(bytes), output_bytes: bytes.length } };
};
const outside = path => { const rel = relative(root, realpathSync(dirname(path))); return rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel); };
const emit = (report, code, output) => {
  const json = JSON.stringify(report, null, 2) + '\n';
  if (output) writeFileSync(output, json, { flag: 'wx', mode: 0o600 });
  process.stdout.write(json); process.exitCode = code;
};
const base = { schema_version: 1, mode: 'all-local', scope: 'purpose-built synthetic local lab only', started_at: new Date().toISOString(), checks: [], prerequisites: [], scenarios: [] };
let output;
let initialSnapshot;
const suffixes = ['', '.baseline.json', '.baseline.json.node-tests.log', '.integration.json', '.integration.json.resources.json', '.integration.json.consumer.json', '.nginx', '.infra.json', '.infra.json.resources.json', '.cache.json', '.cache.json.resources.json', '.upload.json', '.upload.json.resources.json'];
for (const id of ['python-runtime', 'node-syntax', 'core-demo', 'operations', 'production',
  'versions', 'quarantine', 'nginx-harness', 'firewall-render', 'terminal', 'compose-runtime', 'compose']) {
  suffixes.push(`.baseline.json.${id}.log`);
}
try {
  if (invalid || (!options['--all'] && !options['--plan']) || (options['--all'] && options['--plan']) || (options['--plan'] && options['--output']) || (options['--prepare'] && (!options['--all'] || options['--plan']))) throw new Error(invalid ?? 'invalid_option_combination');
  if (catalog.schema_version !== 1 || JSON.stringify(catalog.images) !== JSON.stringify(fixedImages) || JSON.stringify(catalog.stages?.map(stage => stage.id)) !== JSON.stringify(stageIds) || catalog.stages.some(stage => !Number.isInteger(stage.timeout_ms) || stage.timeout_ms < 1000 || stage.timeout_ms > 1200000) || !Array.isArray(catalog.scenarios) || catalog.scenarios.some(scenario => !['local', 'source-reviewed', 'external'].includes(scenario.category) || !Array.isArray(scenario.stages) || scenario.stages.some(id => !stageIds.includes(id)) || (scenario.category !== 'external' && scenario.stages.length === 0))) throw new Error('invalid_fixed_catalog');
  const scenarioIds = new Set(catalog.scenarios.map(scenario => scenario.id));
  const claims = JSON.parse(readFileSync(resolve(root, 'verification/claims.json'), 'utf8'));
  if (scenarioIds.size !== catalog.scenarios.length || !Array.isArray(claims.claims) || claims.claims.some(claim => (claim.lab_scenarios ?? [claim.id]).some(id => !scenarioIds.has(id)))) throw new Error('incomplete_claim_catalog');
  if (options['--output']) {
    if (!isAbsolute(options['--output'])) throw new Error('absolute_external_output_required');
    output = resolve(options['--output']);
    if (!outside(output) || suffixes.some(suffix => existsSync(output + suffix))) throw new Error('new_external_output_and_sidecars_required');
  } else if (!options['--plan']) throw new Error('output_required');
  if (options['--all']) {
    initialSnapshot = sourceSnapshot();
    const payload = initialSnapshot.filter(entry => !['SHA256SUMS', 'SHA256SUMS.sig'].includes(entry.path));
    const registry = readFileSync(resolve(root, 'SHA256SUMS'), 'utf8').trim().split(/\r?\n/).map(line => /^([a-f0-9]{64})  (.+)$/.exec(line));
    const byPath = new Map(registry.filter(Boolean).map(match => [match[2], match[1]]));
    const coverage = JSON.parse(readFileSync(resolve(root, 'verification/coverage.json'), 'utf8'));
    if (registry.some(line => !line) || byPath.size !== registry.length || byPath.size !== payload.length || payload.some(entry => byPath.get(entry.path) !== entry.sha256) || !Array.isArray(coverage.files) || JSON.stringify(coverage.files.map(entry => entry.path).sort()) !== JSON.stringify(payload.map(entry => entry.path).sort())) throw new Error('stale_or_invalid_source_registry');
  }
} catch (error) { emit({ ...base, status: 'invalid_request', reason: error.message, exit_code: 1 }, 1); }

if (process.exitCode === undefined && options['--plan']) {
  emit({ ...base, status: 'plan', effect_free: true, images: fixedImages, prerequisites: catalog.prerequisites,
    tool_build: catalog.tool_build, stages: catalog.stages, scenarios: catalog.scenarios, status_categories: ['passed', 'failed', 'prerequisite_missing', 'source_reviewed', 'external_not_run'], exit_codes: { '0': 'all local checks accepted; external deployment unverified', '1': 'invalid request or failed check', '2': 'missing local prerequisite' } }, 0, output);
} else if (process.exitCode === undefined) {
  const report = base;
  const before = initialSnapshot;
  report.identity_excluded_files = ['verification/v1.2.0-report.json', 'SHA256SUMS', 'SHA256SUMS.sig'];
  report.source_files = before.filter(entry => !report.identity_excluded_files.includes(entry.path));
  report.source_digest = digest(JSON.stringify(report.source_files));
  const payloadDigest = digest(JSON.stringify(before));
  const progress = (event, id, status) => process.stderr.write(JSON.stringify({ event, id, ...(status ? { status } : {}), at: new Date().toISOString() }) + '\n');
  const record = (id, status, extra = {}) => { report.checks.push({ id, status, ...extra }); progress('stage-finish', id, status); };
  const childReports = {};
  const python = process.platform === 'win32' ? 'python' : 'python3';
  const remedies = { node22: 'Install Node.js 22 or later.', python312: 'Install Python 3.12 or later on PATH.', docker: 'Start a Docker engine using Linux containers.', compose: 'Install the Docker Compose v2 plugin.' };
  const preflight = (id, exe, args) => { const call = invoke(exe, args, 30000); report.prerequisites.push({ id, status: call.result.status === 0 && !call.result.error ? 'ready' : 'missing', remedy: remedies[id], ...call.evidence }); return call; };
  preflight('node22', process.execPath, ['-e', 'process.exit(Number(process.versions.node.split(".")[0])>=22?0:1)']);
  preflight('python312', python, ['-B', '-c', 'import sys;sys.exit(0 if sys.version_info >= (3,12) else 1)']);
  const dockerInfo = preflight('docker', 'docker', ['info', '--format', '{{.OSType}}']);
  if (dockerInfo.result.stdout?.toString('utf8').trim() !== 'linux') report.prerequisites.find(item => item.id === 'docker').status = 'missing';
  preflight('compose', 'docker', ['compose', 'version', '--short']);
  const opensslCandidates = process.platform === 'win32' ? ['C:/Program Files/Git/usr/bin/openssl.exe', 'C:/Program Files/Git/mingw64/bin/openssl.exe', 'openssl'] : ['openssl'];
  let openssl;
  for (const executable of opensslCandidates) {
    const call = invoke(executable, ['version'], 30000);
    if (call.result.status === 0 && /^OpenSSL 3\./.test(call.result.stdout?.toString('utf8') ?? '')) {
      const fixture = mkdtempSync(resolve(tmpdir(), 'amqic-openssl-probe-'));
      try {
        const probe = invoke(executable, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', resolve(fixture, 'key.pem'), '-out', resolve(fixture, 'cert.pem')], 30000);
        if (probe.result.status === 0 && !probe.result.error) openssl = { executable, ...call, probe: probe.evidence };
      } finally {
        for (const name of ['key.pem', 'cert.pem']) if (existsSync(resolve(fixture, name))) unlinkSync(resolve(fixture, name));
        rmdirSync(fixture);
      }
      if (openssl) break;
    }
  }
  report.prerequisites.push({ id: 'openssl3', status: openssl ? 'ready' : 'missing', remedy: 'Install OpenSSL 3 with a usable certificate configuration; on Windows an existing Git for Windows installation is detected automatically.', ...(openssl ? { executable: openssl.executable, certificate_probe: openssl.probe, ...(isAbsolute(openssl.executable) ? { executable_sha256: digest(readFileSync(openssl.executable)) } : {}), ...openssl.evidence } : {}) });
  const browsers = process.env.LAB_BROWSER_PATH ? [process.env.LAB_BROWSER_PATH] : ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  report.prerequisites.push({ id: 'chromium', status: browsers.some(path => { try { return isAbsolute(path) && statSync(path).isFile(); } catch { return false; } }) ? 'ready' : 'missing', remedy: 'Install a local Chromium browser or set LAB_BROWSER_PATH to its existing absolute executable.' });
  for (const image of fixedImages) {
    let call = invoke('docker', ['image', 'inspect', image.reference], 30000);
    if (call.result.status !== 0 && options['--prepare'] && report.prerequisites.find(item => item.id === 'docker')?.status === 'ready') {
      progress('stage-start', 'prepare-' + image.id);
      const pull = invoke('docker', ['pull', image.reference], 600000);
      record('prepare-' + image.id, pull.result.status === 0 && !pull.result.error ? 'passed' : 'failed', pull.evidence);
      call = invoke('docker', ['image', 'inspect', image.reference], 30000);
    }
    report.prerequisites.push({ id: image.id, reference: image.reference, status: call.result.status === 0 && !call.result.error ? 'ready' : 'missing', remedy: 'Use --all --prepare to pull the fixed digest.', ...call.evidence });
  }
  const recipe = resolve(root, 'lab/infra-fixtures/Dockerfile');
  const recipeHash = digest(readFileSync(recipe));
  let tool = invoke('docker', ['image', 'inspect', 'amqic-infra-lab:1.2', '--format', '{{index .Config.Labels "org.amqic.infra.recipe-sha256"}}'], 30000);
  if ((tool.result.status !== 0 || tool.result.stdout?.toString('utf8').trim() !== recipeHash) && options['--prepare'] && report.prerequisites.every(item => item.status === 'ready')) {
    progress('stage-start', 'prepare-infra-tools');
    const build = invoke('docker', ['build', '--pull=false', '--build-arg', 'LAB_RECIPE_SHA256=' + recipeHash, '--tag', 'amqic-infra-lab:1.2', '--file', recipe, resolve(root, 'lab/infra-fixtures')], 1200000);
    record('prepare-infra-tools', build.result.status === 0 && !build.result.error ? 'passed' : 'failed', build.evidence);
    tool = invoke('docker', ['image', 'inspect', 'amqic-infra-lab:1.2', '--format', '{{index .Config.Labels "org.amqic.infra.recipe-sha256"}}'], 30000);
  }
  report.prerequisites.push({ id: 'infra-tools', status: tool.result.status === 0 && tool.result.stdout?.toString('utf8').trim() === recipeHash ? 'ready' : 'missing', recipe_sha256: recipeHash,
    remedy: 'Use --all --prepare to build the fixed pinned-base, dated signed Debian snapshot recipe.', ...tool.evidence });
  const missing = report.prerequisites.some(item => item.status === 'missing');
  if (!missing) {
    for (const stage of catalog.stages) {
      progress('stage-start', stage.id);
      const args = stage.id === 'baseline' ? ['scripts/verify.mjs', '--compose', '--output', output + '.baseline.json']
        : stage.id === 'live-consumers' ? ['--experimental-sqlite', 'lab/run-lab.mjs', '--verify', '--output', output + '.integration.json']
        : stage.id === 'infra-runtime' ? ['lab/infra-verify.mjs', '--output', output + '.infra.json']
        : stage.id === 'cache-runtime' ? ['lab/cache-verify.mjs', '--output', output + '.cache.json']
        : stage.id === 'upload-isolation-runtime' ? ['lab/upload-isolation-verify.mjs', '--output', output + '.upload.json'] : null;
      if (stage.id === 'nginx-runtime') {
        const inspected = invoke('docker', ['image', 'inspect', fixedImages.find(image => image.id === 'nginx').reference, '--format', '{{.Id}}']);
        const id = inspected.result.stdout?.toString('utf8').trim();
        if (!/^sha256:[a-f0-9]{64}$/.test(id ?? '')) { record(stage.id, 'failed', { reason: 'invalid_local_image_identity' }); continue; }
        const nginxEnv = { ...process.env };
        if (isAbsolute(openssl.executable)) {
          for (const key of Object.keys(nginxEnv)) if (key.toLowerCase() === 'path') delete nginxEnv[key];
          nginxEnv.PATH = dirname(openssl.executable) + delimiter + (process.env.PATH ?? '');
        }
        const call = invoke(python, ['-B', 'infra/nginx/test_nginx.py', '--image', id, '--output', output + '.nginx'], 300000, nginxEnv);
        let child;
        try { child = JSON.parse(readFileSync(resolve(output + '.nginx', 'report.json'), 'utf8')); } catch {}
        childReports[stage.id] = child;
        record(stage.id, call.result.status === 0 && !call.result.error && acceptStage(stage.id, child) ? 'passed' : 'failed', call.evidence);
        if (call.result.error?.code === 'ETIMEDOUT' || child?.cleanup_pending !== false) { report.cleanup_pending = true; report.reconciliation_required = output + '.nginx'; break; }
      } else {
        const call = invoke(process.execPath, args, stage.timeout_ms);
        let child;
        const file = output + ({ baseline: '.baseline.json', 'live-consumers': '.integration.json', 'infra-runtime': '.infra.json', 'cache-runtime': '.cache.json', 'upload-isolation-runtime': '.upload.json' }[stage.id]);
        try { child = JSON.parse(readFileSync(file, 'utf8')); } catch {}
        childReports[stage.id] = child;
        const accepted = call.result.status === 0 && !call.result.error && acceptStage(stage.id, child);
        record(stage.id, accepted ? 'passed' : call.result.status === 2 ? 'prerequisite_missing' : 'failed', { ...call.evidence, report_file: file, report_sha256: child ? digest(readFileSync(file)) : null });
        const cleanupVerified = stage.id === 'baseline' || (stage.id === 'infra-runtime' ? child?.cleanup?.ok === true : stage.id === 'upload-isolation-runtime' ? child?.cleanup?.ok === true && child?.cleanup?.containers_absent === true && child?.cleanup?.volumes_absent === true : stage.id === 'cache-runtime' ? child?.cleanup?.containers_absent === true && child?.cleanup?.network_absent === true : child?.cleanup?.scanner_removed === true && child?.cleanup?.network_removed === true && child?.cleanup?.browser_stopped === true && child?.cleanup?.application_stopped === true);
        if (call.result.error?.code === 'ETIMEDOUT' || !cleanupVerified) { report.cleanup_pending = stage.id !== 'baseline'; report.reconciliation_required = stage.id === 'baseline' ? file : file + '.resources.json'; break; }
      }
    }
  }
  if (!missing) {
    const terminal = childReports.baseline?.checks.find(check => check.id === 'terminal');
    const complement = childReports['infra-runtime']?.checks?.linuxComplements;
    record('terminal-coverage', terminal?.status === 'passed' || (terminal?.status === 'not_run' && complement?.ok === true && complement.tests?.some(test => test.test?.includes('test_terminal_input') && test.ok === true)) ? 'passed' : 'failed');
  }
  const after = sourceSnapshot();
  const afterDigest = digest(JSON.stringify(after.filter(entry => !report.identity_excluded_files.includes(entry.path))));
  const fullPayloadUnchanged = digest(JSON.stringify(after)) === payloadDigest;
  record('source-stability', afterDigest === report.source_digest && fullPayloadUnchanged ? 'passed' : 'failed', { final_source_digest: afterDigest, full_payload_unchanged: fullPayloadUnchanged });
  for (const scenario of catalog.scenarios) {
    const states = scenario.stages.map(id => report.checks.find(check => check.id === id)?.status);
    const stable = report.checks.find(check => check.id === 'source-stability')?.status === 'passed';
    const status = scenario.category === 'external' ? 'external_not_run' : missing ? 'prerequisite_missing' : stable && states.every(status => status === 'passed') ? scenario.category === 'source-reviewed' ? 'source_reviewed' : 'passed' : 'failed';
    report.scenarios.push({ id: scenario.id, category: scenario.category, status, stages: scenario.stages, operational_scope: scenario.operational_scope });
  }
  const failed = report.checks.some(check => check.status === 'failed');
  const incomplete = missing || report.checks.some(check => check.status === 'prerequisite_missing');
  report.status = failed ? 'failed' : incomplete ? 'prerequisite_missing' : 'local_accepted';
  report.local_accepted = report.status === 'local_accepted'; report.production_verified = false;
  report.exit_code = failed ? 1 : incomplete ? 2 : 0; report.finished_at = new Date().toISOString();
  emit(report, report.exit_code, output);
}
}
