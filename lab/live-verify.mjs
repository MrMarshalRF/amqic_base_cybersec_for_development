import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, access, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createLabApp } from './web-app.mjs';
import { createClamdScanner } from '../reference/clamd-client.mjs';

const marker = 'AMQIC_LAB_SCAN_MARKER';
let cancelled = false;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
async function waitFor(check, timeout = 15000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    if (cancelled) throw new Error('Verification cancelled');
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  throw new Error('Integration observation timed out');
}

async function browserPath() {
  if (process.env.LAB_BROWSER_PATH) {
    await access(process.env.LAB_BROWSER_PATH);
    return process.env.LAB_BROWSER_PATH;
  }
  const candidates = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'].filter(Boolean);
  for (const path of candidates) { try { await access(path); return path; } catch {} }
  throw new Error('A locally installed Chromium browser is required');
}

async function connectCdp(url) {
  const socket = new WebSocket(url);
  await new Promise((ok, no) => {
    const timer = setTimeout(() => { socket.close(); no(new Error('Browser connection timed out')); }, 15000);
    socket.addEventListener('open', () => { clearTimeout(timer); ok(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); no(new Error('Browser connection failed')); }, { once: true });
  });
  let sequence = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(String(event.data));
    const item = pending.get(message.id);
    if (!item) return;
    pending.delete(message.id); clearTimeout(item.timer);
    if (message.error) item.reject(new Error('Browser protocol error'));
    else item.resolve(message.result);
  });
  socket.addEventListener('close', () => {
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('Browser closed')); }
    pending.clear();
  });
  return {
    call(method, params = {}) {
      return new Promise((resolveCall, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error('Browser command timed out')); }, 15000);
        pending.set(id, { resolve: resolveCall, reject, timer });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    close() { socket.close(); },
  };
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--output') throw new Error('Use --output with an external report path');
const output = resolve(args[1]);
const sourceRoot = await realpath(fileURLToPath(new URL('..', import.meta.url)));
if (!isAbsolute(args[1])) throw new Error('Report path must be absolute');
const reportParent = await realpath(dirname(output));
const withinSource = relative(sourceRoot, reportParent);
if (!(withinSource === '..' || withinSource.startsWith('..' + sep) || isAbsolute(withinSource))) throw new Error('Report must stay outside the source tree');
try { await access(output); throw new Error('Report already exists'); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const sourcePaths = ['lab/live-verify.mjs', 'lab/web-app.mjs', 'lab/public/index.html', 'lab/public/app.js',
  'reference/core.mjs', 'reference/crypto.mjs', 'reference/pii-input.mjs', 'reference/upload-pipeline.mjs', 'reference/clamd-client.mjs'];
const sourceHashes = async () => Promise.all(sourcePaths.map(async path => ({ path, sha256: digest(await readFile(join(sourceRoot, path))) })));
const beforeHashes = await sourceHashes();
const host = process.env.LAB_CLAMD_HOST;
const port = Number(process.env.LAB_CLAMD_PORT);
if (host !== '127.0.0.1' || !Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('Explicit LAB_CLAMD_HOST=127.0.0.1 and LAB_CLAMD_PORT are required');
}
const root = await mkdtemp(join(tmpdir(), 'amqic-live-verification-'));
const report = { schema_version: 1, node: process.version, source_files: beforeHashes, checks: [], cleanup: {}, status: 'failed' };
let app, child, childExited, cdp;
process.on('message', message => {
  if (message?.type !== 'cancel') return;
  cancelled = true;
  cdp?.close();
  if (child && child.exitCode === null && child.signalCode === null) child.kill();
});
const check = (id, details = {}) => report.checks.push({ id, status: 'passed', ...details });
try {
  const scanner = createClamdScanner({ host, port });
  const clean = Buffer.from('Synthetic clean upload, not personal data.');
  const infected = Buffer.from(marker);
  for (const [name, bytes, expected] of [['clean', clean, 'clean'], ['marker', infected, 'infected']]) {
    const path = join(root, name); await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    const result = await scanner({ path, size: bytes.length, sha256: digest(bytes) });
    assert.equal(result.status, expected, 'The configured daemon must detect the documented custom lab signature');
    check('clamav-' + name, { engine: result.engine, version: result.version, synthetic_database: true });
  }
  app = await createLabApp({ dataRoot: join(root, 'app'), clamdHost: host, clamdPort: port });
  const { origin, port: applicationPort } = await app.start();
  process.send?.({ type: 'application-started', pid: process.pid, origin, port: applicationPort });
  const profile = join(root, 'browser');
  child = spawn(await browserPath(), ['--headless=new', '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + profile,
    '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--window-size=1200,900', 'about:blank'], { stdio: 'ignore', windowsHide: true });
  childExited = new Promise(resolveExit => child.once('exit', resolveExit));
  process.send?.({ type: 'browser-started', pid: child.pid });
  let spawnError;
  child.once('error', error => { spawnError = error; });
  const debugPort = await waitFor(async () => {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) throw new Error('Browser exited before readiness');
    try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); } catch { return null; }
  });
  const version = await (await fetch(`http://127.0.0.1:${debugPort}/json/version`, { signal: AbortSignal.timeout(15000) })).json();
  report.browser = version.Browser;
  const pages = await (await fetch(`http://127.0.0.1:${debugPort}/json/list`, { signal: AbortSignal.timeout(15000) })).json();
  const page = pages.find(item => item.type === 'page'); assert.ok(page);
  cdp = await connectCdp(page.webSocketDebuggerUrl);
  await cdp.call('Page.enable');
  await cdp.call('Runtime.enable');
  const evaluate = async expression => {
    const result = await cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error('Browser test expression failed');
    return result.result.value;
  };
  await cdp.call('Page.navigate', { url: origin });
  await waitFor(() => evaluate("Boolean(document.getElementById('hints')?.textContent.includes('alice@example.test'))"));
  check('browser-fixture-loaded');
  const account = await evaluate("JSON.parse(document.getElementById('hints').textContent).users[0]");
  for (const [value, next] of [[account.identity, 'password'], [account.password, 'captcha'], ['synthetic-human', 'totp']]) {
    await evaluate(`document.getElementById('value').value=${JSON.stringify(value)};document.getElementById('login').requestSubmit();true`);
    await waitFor(() => evaluate(`document.getElementById('stage').textContent===${JSON.stringify(next)}`));
  }
  // Refresh the public synthetic factor at the moment it is submitted.
  const currentCode = await evaluate("(async()=> (await (await fetch('/api/bootstrap')).json()).users[0].code)()");
  await evaluate(`document.getElementById('value').value=${JSON.stringify(currentCode)};document.getElementById('login').requestSubmit();true`);
  await waitFor(() => evaluate("document.getElementById('stage').textContent==='authenticated'"));
  check('browser-full-login-stages');
  const payload = "'); DROP TABLE contacts;-- <img src=x onerror=\"window.__unexpectedExecution=true\"> $(not-a-command)";
  await evaluate(`window.__unexpectedExecution=false;document.querySelector('[name=fullName]').value='Example Person';document.querySelector('[name=email]').value='example@example.test';document.querySelector('[name=message]').value=${JSON.stringify(payload)};document.getElementById('contact').requestSubmit();true`);
  await waitFor(() => evaluate("(() => {try{return Number.isInteger(JSON.parse(document.getElementById('result').textContent).id)}catch{return false}})()"));
  await evaluate("document.getElementById('list').click();true");
  await waitFor(() => evaluate(`document.getElementById('result').textContent.includes('DROP TABLE')`));
  const rendering = await evaluate("({text:document.getElementById('result').textContent, images:document.getElementById('result').querySelectorAll('img,script').length, executed:window.__unexpectedExecution})");
  assert.equal(rendering.images, 0); assert.equal(rendering.executed, false);
  assert.ok(rendering.text.includes('DROP TABLE')); assert.ok(rendering.text.includes('<img'));
  check('browser-stored-text-not-html', { literal_output: true, injected_dom_nodes: 0, script_executed: false });
  // Exercise the actual HTTP admission and antivirus path with this authenticated browser.
  for (const [bytes, expected] of [[clean.toString(), 'clean'], [marker, 'rejected']]) {
    const result = await evaluate(`(async()=>{const b=await(await fetch('/api/bootstrap')).json();const h={'X-CSRF-Token':b.csrf,'Content-Type':'application/octet-stream'};const staged=await fetch('/api/uploads',{method:'POST',headers:h,body:${JSON.stringify(bytes)}});const file=await staged.json();const pending=await fetch('/api/uploads/'+file.id);const processed=await fetch('/api/uploads/'+file.id+'/process',{method:'POST',headers:{'X-CSRF-Token':b.csrf,'Content-Type':'application/json'},body:'{}'});const verdict=await processed.json();const download=await fetch('/api/uploads/'+file.id);return {stage:staged.status,pending:pending.status,process:processed.status,verdict:verdict.status,download:download.status,body:download.ok?await download.text():null};})()`);
    assert.equal(result.stage, 201); assert.equal(result.pending, 404);
    assert.equal(result.process, 200); assert.equal(result.verdict, expected);
    assert.equal(result.download, expected === 'clean' ? 200 : 404);
    if (expected === 'clean') assert.equal(result.body, bytes);
    check('browser-upload-' + expected, { pending_denied: true, verdict: result.verdict, download_status: result.download });
  }
  report.status = 'passed';
} catch (error) {
  report.error = error instanceof assert.AssertionError ? 'Integration assertion failed: ' + error.message : String(error.message);
  process.exitCode = 1;
} finally {
  if (cdp) { try { await cdp.call('Browser.close'); } catch {} cdp.close(); }
  if (child && child.exitCode === null && child.signalCode === null) {
    await Promise.race([childExited, delay(5000)]);
    if (child.exitCode === null && child.signalCode === null) { child.kill(); await Promise.race([childExited, delay(5000)]); }
  }
  report.cleanup.browser_stopped = !child || child.exitCode !== null || child.signalCode !== null;
  try { if (app) await app.close(); report.cleanup.application_stopped = true; }
  catch { report.cleanup.application_stopped = false; }
  if (report.cleanup.browser_stopped && report.cleanup.application_stopped) {
    await rm(root, { recursive: true, force: true }); report.cleanup.private_temp_removed = true;
  } else { report.cleanup.private_temp_removed = false; report.status = 'failed'; process.exitCode = 1; }
  if (JSON.stringify(beforeHashes) !== JSON.stringify(await sourceHashes())) {
    report.status = 'failed'; report.error = 'Source changed during verification'; process.exitCode = 1;
  }
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ status: report.status, checks: report.checks.length, cleanup: report.cleanup }));
  if (process.connected) process.disconnect();
}
