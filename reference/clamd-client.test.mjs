import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createClamdScanner } from './clamd-client.mjs';

async function fakeServer(t, response, options = {}) {
  const sockets = new Set(); const captured = [];
  const server = createServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    let data = Buffer.alloc(0);
    socket.on('data', chunk => {
      data = Buffer.concat([data, chunk]);
      if (data.equals(Buffer.from('zVERSION\0'))) { if (!options.silent) socket.end(options.version ?? 'ClamAV 1.4.3/123/Thu Jan 1 00:00:00 2026\0'); return; }
      if (data.length < 10 || data.subarray(0, 10).toString() !== 'zINSTREAM\0') return;
      let at = 10; const chunks = [];
      while (at + 4 <= data.length) {
        const size = data.readUInt32BE(at); at += 4;
        if (size === 0) { assert.equal(at, data.length); captured.push(Buffer.concat(chunks)); socket.end(response); return; }
        if (at + size > data.length) return;
        assert.ok(size <= 65536); chunks.push(data.subarray(at, at + size)); at += size;
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { port: server.address().port, captured };
}
async function request(t, bytes = Buffer.alloc(150000, 42)) {
  const root = await mkdtemp(join(tmpdir(), 'amqic-clamd-unit-')); t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'input'); await writeFile(path, bytes);
  return { path, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}

test('INSTREAM frames are length-prefixed big-endian and zero-terminated', async t => {
  const { port, captured } = await fakeServer(t, 'stream: OK\0'); const input = await request(t);
  const scan = createClamdScanner({ host: '127.0.0.1', port });
  const verdict = await scan(input); assert.equal(verdict.status, 'clean'); assert.match(verdict.version, /^ClamAV 1\.4\.3/);
  assert.deepEqual(captured, [Buffer.alloc(150000, 42)]);
});
test('malware response maps to infected; errors and malformed responses fail closed', async t => {
  for (const [response, status] of [['stream: Unit-Test-Signature FOUND\0', 'infected'], ['stream: size limit exceeded ERROR\0', 'error'], ['stream: OK\0garbage', 'error'], ['stream: OK\n', 'error'], ['something OK\0', 'error']]) {
    const { port } = await fakeServer(t, response); const input = await request(t, Buffer.from('synthetic'));
    assert.equal((await createClamdScanner({ host: '127.0.0.1', port })(input)).status, status);
  }
});
test('timeout, abort, bad version, oversize and identity mismatch fail closed', async t => {
  const input = await request(t, Buffer.from('synthetic'));
  const silent = await fakeServer(t, '', { silent: true });
  assert.equal((await createClamdScanner({ host: '127.0.0.1', port: silent.port, timeoutMs: 20 })(input)).status, 'error');
  assert.equal((await createClamdScanner({ host: '127.0.0.1', port: silent.port })({ ...input, signal: AbortSignal.abort() })).status, 'error');
  const bad = await fakeServer(t, 'stream: OK\0', { version: 'nonsense\0' });
  const scan = createClamdScanner({ host: '127.0.0.1', port: bad.port, maxBytes: 5 });
  assert.equal((await scan(input)).status, 'error');
  assert.equal((await createClamdScanner({ host: '127.0.0.1', port: bad.port })(input)).status, 'error');
  assert.equal((await scan({ ...input, size: 1, sha256: 'bad' })).status, 'error');
});
test('endpoint must be explicit and configuration bounded', () => {
  assert.throws(() => createClamdScanner());
  assert.throws(() => createClamdScanner({ host: 'localhost', port: 0 }));
});
