import { createConnection } from 'node:net';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const result = (status, version = 'unknown') => ({ status, engine: 'ClamAV', version });
function exchange({ host, port, timeoutMs, maxResponseBytes, signal }, frames) {
  return new Promise((resolve, reject) => {
    let response = Buffer.alloc(0);
    const socket = createConnection({ host, port });
    const timer = setTimeout(() => finish(new Error('clamd_timeout')), timeoutMs);
    function abort() { finish(new Error('clamd_aborted')); }
    function finish(error, value) {
      clearTimeout(timer); signal?.removeEventListener('abort', abort); socket.destroy();
      if (error) reject(error); else resolve(value);
    }
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    socket.on('error', error => finish(error));
    socket.on('end', () => finish(new Error('clamd_truncated')));
    socket.on('data', data => {
      response = Buffer.concat([response, data]);
      if (response.length > maxResponseBytes) return finish(new Error('clamd_response_limit'));
      const end = response.indexOf(0);
      if (end >= 0) {
        if (end !== response.length - 1 || response.subarray(0, end).some(byte => byte < 32 || byte > 126)) return finish(new Error('clamd_malformed'));
        finish(null, response.subarray(0, end).toString('ascii'));
      }
    });
    socket.once('connect', async () => {
      try {
        for (const frame of frames) {
          if (socket.destroyed) return;
          if (!socket.write(frame)) await new Promise((resolve, reject) => {
            const drained = () => { socket.removeListener('close', closed); resolve(); };
            const closed = () => { socket.removeListener('drain', drained); reject(new Error('clamd_closed')); };
            socket.once('drain', drained); socket.once('close', closed);
          });
        }
      } catch (error) { finish(error); }
    });
  });
}

/** Use only an explicitly trusted clamd endpoint; this protocol has no TLS or authentication. */
export function createClamdScanner({ host, port, timeoutMs = 10000, maxBytes = 1048576, maxResponseBytes = 4096 } = {}) {
  if (typeof host !== 'string' || !host || !Number.isInteger(port) || port < 1 || port > 65535 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 64 || maxResponseBytes > 65536) throw new Error('invalid_clamd_configuration');
  const options = { host, port, timeoutMs, maxResponseBytes };
  return async ({ path, sha256, size, signal }) => {
    try {
      if (!Number.isSafeInteger(size) || size < 0 || size > maxBytes) return result('error');
      const bytes = await readFile(path);
      if (bytes.length !== size || bytes.length > maxBytes || createHash('sha256').update(bytes).digest('hex') !== sha256) return result('error');
      const version = await exchange({ ...options, signal }, [Buffer.from('zVERSION\0')]);
      if (!/^ClamAV [0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[ /][ -~]*)?$/.test(version)) return result('error');
      const frames = [Buffer.from('zINSTREAM\0')];
      for (let start = 0; start < bytes.length; start += 65536) {
        const chunk = bytes.subarray(start, start + 65536);
        const header = Buffer.alloc(4); header.writeUInt32BE(chunk.length);
        frames.push(header, chunk);
      }
      frames.push(Buffer.alloc(4));
      const response = await exchange({ ...options, signal }, frames);
      if (response === 'stream: OK') return result('clean', version);
      if (/^stream: [A-Za-z0-9][A-Za-z0-9_.:() /-]{0,240} FOUND$/.test(response)) return result('infected', version);
      return result('error', version);
    } catch { return result('error'); }
  };
}
