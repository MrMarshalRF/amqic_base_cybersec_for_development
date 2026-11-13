#!/usr/bin/env node
// Fixed local test dispatcher: no user-supplied command, shell or environment broker.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, lstatSync, writeFileSync, realpathSync, existsSync } from 'node:fs';
import { dirname, resolve, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const args = process.argv.slice(2);
if (args.includes('--all') || args.includes('--plan')) {
  await import('../lab/all-local.mjs');
} else {
const options = {};
for (let i = 0; i < args.length; i++) {
  const key = args[i];
  if (['--full', '--compose'].includes(key)) options[key] = true;
  else if (['--output', '--nginx-image', '--nginx-output'].includes(key) && args[i + 1] && !args[i + 1].startsWith('--')) options[key] = args[++i];
  else throw new Error(`Unknown or incomplete option: ${key}`);
}
if (options['--full'] && !options['--output']) throw new Error('--full requires --output for external integration evidence');
if (options['--output']) {
  const destination = resolve(options['--output']);
  const within = relative(root, realpathSync(dirname(destination)));
  if (!isAbsolute(options['--output']) || (!within.startsWith(`..${sep}`) && within !== '..' && !isAbsolute(within))) throw new Error('--output must be an absolute path outside the public kit');
  if ([destination, destination + '.node-tests.log', ...(options['--full'] ? [destination + '.integration.json'] : [])].some(existsSync)) throw new Error('Choose a new output filename and sidecars');
}
const report = { schema_version: 1, started_at: new Date().toISOString(), node: process.version, platform: process.platform, source_digest: null, checks: [] };
const identityExcluded = new Set(['verification/v1.2.0-report.json']);
report.identity_excluded_files = [...identityExcluded];
let initialPayloadDigest = null;
const checkIds = new Set(['coverage-membership', 'sha256-registry', 'source-stability', 'node-runtime', 'python-runtime', 'node-syntax', 'node-tests', 'core-demo', 'operations', 'production', 'versions', 'quarantine', 'nginx-harness', 'firewall-render', 'terminal', 'compose-runtime', 'compose', 'live-consumers', 'nginx-runtime', 'infra-runtime', 'cache-runtime', 'upload-isolation-runtime']);
function record(id, status, details = {}) { report.checks.push({ id, status, ...details }); }
function command(id, executable, commandArgs, timeout = 120000) {
  const start = Date.now();
  const result = spawnSync(executable, commandArgs, { cwd: root, shell: false, timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
  const output = Buffer.concat([result.stdout ?? Buffer.alloc(0), result.stderr ?? Buffer.alloc(0)]);
  const text = output.toString('utf8');
  const skipped = Number(text.match(/skipped=(\d+)/)?.[1] ?? text.match(/# skipped (\d+)/)?.[1] ?? 0);
  const failed = result.status !== 0 || !!result.error;
  if (failed && id === 'node-tests' && options['--output']) writeFileSync(options['--output'] + '.node-tests.log', output, { flag: 'wx', mode: 0o600 });
  record(id, result.status === 0 && !result.error ? 'passed' : 'failed', {
    exit_code: result.status, signal: result.signal, error_code: result.error?.code ?? null,
    elapsed_ms: Date.now() - start, output_sha256: sha(output), output_bytes: output.length,
    skipped_subtests: skipped,
  });
  return result;
}
const excluded = new Set(['SHA256SUMS', 'SHA256SUMS.sig']);
const ignoredDirs = new Set(['.git', '__pycache__', 'node_modules', '.venv', '.agent-private', '.internal']);
function inventory(directory = root, prefix = '') {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const name = prefix + entry.name;
    if (name === '.git') return [];
    if (entry.isDirectory()) return ignoredDirs.has(entry.name) ? [] : inventory(resolve(directory, entry.name), name + '/');
    if (excluded.has(name)) return [];
    if (!entry.isFile() || lstatSync(resolve(root, name)).isSymbolicLink()) throw new Error('Nonregular public entry');
    return [name];
  }).sort();
}
try {
  const files = inventory();
  const hashes = files.map(path => ({ path, sha256: sha(readFileSync(resolve(root, path))) }));
  initialPayloadDigest = sha(JSON.stringify(hashes));
  report.source_files = hashes.filter(entry => !identityExcluded.has(entry.path));
  report.source_digest = sha(JSON.stringify(report.source_files));
  report.integrity_registry_sha256 = sha(readFileSync(resolve(root, 'SHA256SUMS')));
  const coverage = JSON.parse(readFileSync(resolve(root, 'verification/coverage.json'), 'utf8'));
  const categories = new Set(['executable', 'configuration', 'source-reviewed-documentation', 'static-asset']);
  const entries = coverage.files;
  if (coverage.schema_version !== 1 || !Array.isArray(entries) || entries.some(e => !categories.has(e.category) || !e.scope || !Array.isArray(e.checks) || !e.checks.length || e.checks.some(id => !checkIds.has(id)))) throw new Error('Invalid coverage registry');
  const names = entries.map(e => e.path).sort();
  if (new Set(names).size !== names.length || JSON.stringify(names) !== JSON.stringify(files)) throw new Error('Coverage membership mismatch');
  record('coverage-membership', 'passed', { files: files.length, meaning: 'Every public payload file is classified; classification is not proof of implemented security.' });
  const lines = readFileSync(resolve(root, 'SHA256SUMS'), 'utf8').trim().split(/\r?\n/);
  const sums = new Map();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    if (!match || sums.has(match[2]) || !files.includes(match[2])) throw new Error('Invalid integrity registry membership');
    sums.set(match[2], match[1]);
  }
  if (sums.size !== files.length || hashes.some(e => sums.get(e.path) !== e.sha256)) throw new Error('Integrity registry mismatch');
  record('sha256-registry', 'passed', { files: files.length, signature_verified: false });
} catch { record('registry', 'failed', { reason: 'Missing, malformed, stale or incomplete coverage/SHA256SUMS registry' }); }

if (Number(process.versions.node.split('.')[0]) < 22) record('node-runtime', 'failed', { reason: 'Node.js 22 or later required' });
else record('node-runtime', 'passed');
const python = process.platform === 'win32' ? 'python' : 'python3';
const py = command('python-runtime', python, ['-B', '-c', 'import sys; print(sys.version.split()[0]); sys.exit(0 if sys.version_info >= (3,12) else 1)']);
report.python = py.status === 0 ? py.stdout.toString('utf8').trim() : null;
command('node-syntax', process.execPath, ['--check', 'scripts/verify.mjs']);
command('node-tests', process.execPath, ['--experimental-sqlite', '--test', '--test-concurrency=1',
  'reference/core.test.mjs', 'reference/login-client.test.mjs', 'reference/pii-input.test.mjs', 'reference/session-authorization.test.mjs',
  'reference/admission.test.mjs',
  'reference/upload-pipeline.test.mjs', 'reference/clamd-client.test.mjs', 'lab/web-app.test.mjs', 'lab/lifecycle.test.mjs', 'lab/all-local.test.mjs', 'lab/run-shell.test.mjs', 'scripts/test_crypto.mjs']);
command('core-demo', process.execPath, ['--experimental-sqlite', 'reference/demo.mjs']);
for (const [id, path] of [
  ['operations', 'scripts/test_operations.py'], ['production', 'scripts/test_prepare_production.py'],
  ['versions', 'scripts/test_check_versions.py'], ['quarantine', 'infra/container/test_quarantine.py'],
  ['nginx-harness', 'infra/nginx/test_harness.py'],
]) command(id, python, ['-B', path]);
command('firewall-render', python, ['-B', '-c', `import sys,json,tempfile,pathlib,unittest
sys.path.insert(0, 'infra')
from firewall.render import render
class RenderTests(unittest.TestCase):
 def policy(self):
  original=json.loads(pathlib.Path('infra/firewall/policy.example.json').read_text())
  return dict(original,ssh_port=2222,admin_cidrs=['192.0.2.10/32','2001:db8:1::/64'],proxy_cidrs=['198.51.100.0/24','2001:db8:2::/64'])
 def test_allowlist(self):
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'policy.json'
   path.write_text(json.dumps(self.policy()))
   rendered=render(path)
   self.assertIn('policy drop',rendered)
   self.assertNotIn('@@',rendered)
   self.assertIn('ct state established,related accept',rendered)
 def test_invalid(self):
  original=self.policy()
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'policy.json'
   for changes in [{'ssh_port':80},{'ssh_port':True},{'admin_cidrs':['0.0.0.0/0']},{'admin_cidrs':['127.0.0.1; accept']}]:
    path.write_text(json.dumps(dict(original,**changes)))
    with self.assertRaises(ValueError): render(path)
unittest.main()
`]);
if (process.platform === 'linux') command('terminal', python, ['-B', 'scripts/test_terminal_input.py']);
else record('terminal', 'not_run', { reason: 'Linux PTY required; run Linux CI for this check' });
if (options['--compose'] || options['--full']) {
  const prerequisite = command('compose-runtime', 'docker', ['compose', 'version', '--short'], 30000);
  if (prerequisite.status === 0) {
    const version = prerequisite.stdout.toString('utf8').trim();
    report.compose_version = /^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version) ? version : 'unrecognized';
    command('compose', python, ['-B', 'infra/container/test_compose.py']);
  }
  else record('compose', 'not_run', { reason: 'Requested Docker Compose prerequisite failed' });
} else record('compose', 'not_run', { reason: 'Use --compose; validates configuration only, creates no services' });
if (options['--full']) command('live-consumers', process.execPath, ['--experimental-sqlite', 'lab/run-lab.mjs', '--verify', '--output', options['--output'] + '.integration.json'], 300000);
else record('live-consumers', 'not_run', { reason: 'Use --full with the documented isolated integration prerequisites' });
if (options['--nginx-image'] && options['--nginx-output']) {
  if (!/^sha256:[a-f0-9]{64}$/.test(options['--nginx-image']) || !isAbsolute(options['--nginx-output'])) throw new Error('Nginx requires a reviewed local sha256 image and absolute new output directory');
  const within = relative(root, realpathSync(dirname(resolve(options['--nginx-output']))));
  if (!within.startsWith(`..${sep}`) && within !== '..' && !isAbsolute(within)) throw new Error('Nginx output directory must be outside the public kit');
  report.nginx_image = options['--nginx-image'];
  command('nginx-runtime', python, ['-B', 'infra/nginx/test_nginx.py', '--image', options['--nginx-image'], '--output', options['--nginx-output']], 300000);
} else {
  if (options['--nginx-image'] || options['--nginx-output']) throw new Error('Both nginx options are required');
  record('nginx-runtime', 'not_run', { reason: 'Requires explicit reviewed local image and new external output directory' });
}
try {
  const finalHashes = inventory().map(path => ({ path, sha256: sha(readFileSync(resolve(root, path))) }));
  const after = sha(JSON.stringify(finalHashes.filter(entry => !identityExcluded.has(entry.path))));
  const payloadUnchanged = initialPayloadDigest === sha(JSON.stringify(finalHashes));
  const sumsUnchanged = report.integrity_registry_sha256 === sha(readFileSync(resolve(root, 'SHA256SUMS')));
  record('source-stability', report.source_digest !== null && after === report.source_digest && sumsUnchanged && payloadUnchanged ? 'passed' : 'failed', { final_source_digest: after, integrity_registry_unchanged: sumsUnchanged, full_payload_unchanged: payloadUnchanged });
} catch { record('source-stability', 'failed', { reason: 'Public source inventory changed or became unreadable' }); }
report.finished_at = new Date().toISOString();
report.status = report.checks.some(check => check.status === 'failed') ? 'failed' : report.checks.some(check => check.status === 'not_run') ? 'incomplete' : 'passed';
report.complete = report.status === 'passed';
const json = JSON.stringify(report, null, 2) + '\n';
if (options['--output']) writeFileSync(options['--output'], json, { flag: 'wx', mode: 0o600 });
process.stdout.write(json);
process.exitCode = report.status === 'failed' ? 1 : 0;
}
