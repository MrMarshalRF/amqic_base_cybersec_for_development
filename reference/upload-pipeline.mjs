import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, rename, link, unlink, lstat, rmdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OWNER = /^[A-Za-z0-9_-]{1,128}$/;
function fail(code) { const error = new Error(code); error.code = code; return error; }
function identity(id, ownerId) {
  if (typeof id !== 'string' || typeof ownerId !== 'string' || !ID.test(id) || !OWNER.test(ownerId)) throw fail('invalid_identity');
}
const publicMetadata = ({ id, status, size, sha256, mediaType }) => ({ id, status, size, sha256, mediaType, filename: `${id}.bin` });

/** The store root and scanner are trusted. Directories are not an OS sandbox.
 * One filesystem with atomic mkdir/link/rename and exclusive service ownership is required.
 * A crashed lock is intentionally not reclaimed automatically: reconcile it offline.
 */
export async function createUploadStore({ root, scanner, maxBytes = 1048576, scanTimeoutMs = 15000 } = {}) {
  if (typeof root !== 'string' || !root || typeof scanner !== 'function' || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Number.isSafeInteger(scanTimeoutMs) || scanTimeoutMs < 1) throw fail('invalid_configuration');
  root = resolve(root);
  const paths = Object.fromEntries(['pending', 'approved', 'metadata', 'scanning', 'locks'].map(name => [name, join(root, name)]));
  await mkdir(root, { recursive: true, mode: 0o700 });
  for (const path of [root, ...Object.values(paths)]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw fail('unsafe_store');
  }
  const blob = (area, id) => join(paths[area], `${id}.bin`);
  const metaPath = id => join(paths.metadata, `${id}.json`);
  async function metadata(id, ownerId) {
    identity(id, ownerId);
    let item;
    try { item = JSON.parse(await readFile(metaPath(id), 'utf8')); } catch { throw fail('not_found'); }
    if (item.id !== id || item.ownerId !== ownerId) throw fail('not_found');
    if (!['pending', 'clean', 'rejected'].includes(item.status) || !Number.isSafeInteger(item.size) || item.size < 0 || item.size > maxBytes || !/^[a-f0-9]{64}$/.test(item.sha256)) throw fail('invalid_metadata');
    return item;
  }
  async function save(item) {
    const temporary = join(paths.metadata, `${item.id}.${randomUUID()}.tmp`);
    try { await writeFile(temporary, JSON.stringify(item), { flag: 'wx', mode: 0o600 }); await rename(temporary, metaPath(item.id)); }
    finally { await unlink(temporary).catch(() => {}); }
  }
  async function locked(id, fn) {
    const path = join(paths.locks, id);
    try { await mkdir(path, { mode: 0o700 }); } catch (error) { if (error.code === 'EEXIST') throw fail('upload_busy'); throw error; }
    try { return await fn(); } finally { await rmdir(path); }
  }
  return {
    async stage({ ownerId, bytes, mediaType = 'application/octet-stream' } = {}) {
      if (typeof ownerId !== 'string' || !OWNER.test(ownerId)) throw fail('invalid_identity');
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > maxBytes) throw fail('invalid_size');
      if (typeof mediaType !== 'string' || mediaType.length > 127 || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mediaType)) throw fail('invalid_media_type');
      const copy = Buffer.from(bytes); // caller mutation cannot change staged content
      const id = randomUUID();
      const item = { id, ownerId, status: 'pending', size: copy.length, sha256: digest(copy), mediaType };
      await writeFile(blob('pending', id), copy, { flag: 'wx', mode: 0o600 });
      await writeFile(metaPath(id), JSON.stringify(item), { flag: 'wx', mode: 0o600 });
      return publicMetadata(item);
    },
    async scanAndPromote({ id, ownerId } = {}) {
      identity(id, ownerId);
      return locked(id, async () => {
        const item = await metadata(id, ownerId);
        if (item.status !== 'pending') return publicMetadata(item);
        const snapshot = join(paths.scanning, `${id}.${randomUUID()}.bin`);
        let timer;
        const controller = new AbortController();
        try {
          const original = await readFile(blob('pending', id));
          if (original.length !== item.size || digest(original) !== item.sha256) throw fail('content_changed');
          await writeFile(snapshot, original, { flag: 'wx', mode: 0o400 });
          const timeout = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(fail('scanner_timeout')); }, scanTimeoutMs); });
          const verdict = await Promise.race([Promise.resolve().then(() => scanner({ path: snapshot, sha256: item.sha256, size: item.size, signal: controller.signal })), timeout]);
          if (!verdict || verdict.status !== 'clean' || typeof verdict.engine !== 'string' || !verdict.engine || typeof verdict.version !== 'string' || !verdict.version) throw fail('scanner_rejected');
          // Capture only bytes matching the scan identity. Never publish the scanner's mutable pathname.
          const scanned = await readFile(snapshot);
          if (scanned.length !== item.size || digest(scanned) !== item.sha256) throw fail('content_changed');
          const candidate = join(paths.scanning, `${id}.${randomUUID()}.approved`);
          try {
            await writeFile(candidate, scanned, { flag: 'wx', mode: 0o400 });
            try { await link(candidate, blob('approved', id)); }
            catch (error) {
              if (error.code !== 'EEXIST') throw error;
              const existing = await readFile(blob('approved', id));
              if (existing.length !== item.size || digest(existing) !== item.sha256) throw fail('promotion_conflict');
            }
          } finally { await unlink(candidate).catch(() => {}); }
          item.status = 'clean';
          item.scanner = { engine: verdict.engine, version: verdict.version };
        } catch {
          item.status = 'rejected';
        } finally { clearTimeout(timer); controller.abort(); await unlink(snapshot).catch(() => {}); }
        await save(item); // readers see approved bytes only after the clean metadata commit
        await unlink(blob('pending', id)).catch(() => {});
        return publicMetadata(item);
      });
    },
    async get({ id, ownerId } = {}) {
      const item = await metadata(id, ownerId);
      if (item.status !== 'clean') throw fail('not_available');
      const bytes = await readFile(blob('approved', id));
      if (bytes.length !== item.size || digest(bytes) !== item.sha256) throw fail('content_changed');
      return { bytes, mediaType: item.mediaType, filename: `${id}.bin` };
    },
    async close() {},
  };
}
