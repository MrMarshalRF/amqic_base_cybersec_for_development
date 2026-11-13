import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createUploadStore } from './upload-pipeline.mjs';

// Synthetic scanner fixtures, never wired to a web application.
const cleanFixture = async () => ({ status: 'clean', engine: 'unit-fixture', version: '1' });
async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'amqic-upload-unit-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, store: await createUploadStore({ root, scanner: cleanFixture, ...options }) };
}
const input = () => ({ ownerId: 'alice', bytes: Buffer.from('ordinary upload'), mediaType: 'text/plain' });

test('pending is inaccessible; clean result is durable and owner-bound', async t => {
  const { root, store } = await fixture(t);
  const request = input(); const original = Buffer.from(request.bytes);
  const item = await store.stage(request); request.bytes.fill(0);
  assert.equal(item.status, 'pending'); assert.equal(item.size, original.length);
  await assert.rejects(store.get({ id: item.id, ownerId: 'alice' }), { code: 'not_available' });
  await assert.rejects(store.get({ id: item.id, ownerId: 'bob' }), { code: 'not_found' });
  assert.equal((await store.scanAndPromote({ id: item.id, ownerId: 'alice' })).status, 'clean');
  const restarted = await createUploadStore({ root, scanner: cleanFixture });
  assert.deepEqual((await restarted.get({ id: item.id, ownerId: 'alice' })).bytes, original);
  assert.equal((await restarted.scanAndPromote({ id: item.id, ownerId: 'alice' })).status, 'clean');
});

test('malformed IDs, owner traversal, media type and oversized data fail', async t => {
  const { store } = await fixture(t, { maxBytes: 16 });
  for (const id of ['../x', '../../approved/a', '', 'not-a-uuid']) await assert.rejects(store.get({ id, ownerId: 'alice' }), { code: 'invalid_identity' });
  await assert.rejects(store.stage({ ...input(), ownerId: '../alice' }), { code: 'invalid_identity' });
  await assert.rejects(store.stage({ ...input(), bytes: Buffer.alloc(17) }), { code: 'invalid_size' });
  await assert.rejects(store.stage({ ...input(), mediaType: 'text/plain\r\nX: injected' }), { code: 'invalid_media_type' });
});

test('failure, malformed verdict, malware and timeout reject permanently', async t => {
  for (const scanner of [async () => { throw Error('unavailable'); }, async () => ({ status: 'clean' }), async () => ({ status: 'infected', engine: 'fixture', version: '1' }), async () => new Promise(() => {})]) {
    const { store } = await fixture(t, { scanner, scanTimeoutMs: 25 });
    const item = await store.stage(input());
    assert.equal((await store.scanAndPromote({ id: item.id, ownerId: 'alice' })).status, 'rejected');
    await assert.rejects(store.get({ id: item.id, ownerId: 'alice' }), { code: 'not_available' });
  }
});

test('scanner replacing its input cannot approve substituted bytes', async t => {
  const { store } = await fixture(t, { scanner: async ({ path }) => { await chmod(path, 0o600); await writeFile(path, 'substituted'); return cleanFixture(); } });
  const item = await store.stage(input());
  assert.equal((await store.scanAndPromote({ id: item.id, ownerId: 'alice' })).status, 'rejected');
});

test('pending replacement after snapshot does not alter promoted exact bytes', async t => {
  let root; let item;
  const setup = await fixture(t, { scanner: async ({ path }) => {
    assert.deepEqual(await readFile(path), input().bytes);
    await writeFile(join(root, 'pending', `${item.id}.bin`), 'substituted pending');
    return cleanFixture();
  } });
  root = setup.root; item = await setup.store.stage(input());
  assert.equal((await setup.store.scanAndPromote({ id: item.id, ownerId: 'alice' })).status, 'clean');
  assert.deepEqual((await setup.store.get({ id: item.id, ownerId: 'alice' })).bytes, input().bytes);
});

test('cross-instance concurrent promotion is exclusive and readers remain gated', async t => {
  let release; let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const { root, store } = await fixture(t, { scanner: async () => { entered(); await gate; return cleanFixture(); } });
  const second = await createUploadStore({ root, scanner: cleanFixture });
  const item = await store.stage(input()); const request = { id: item.id, ownerId: 'alice' };
  const running = store.scanAndPromote(request); await started;
  await assert.rejects(second.scanAndPromote(request), { code: 'upload_busy' });
  await assert.rejects(second.get(request), { code: 'not_available' });
  release(); assert.equal((await running).status, 'clean');
  assert.deepEqual((await second.get(request)).bytes, input().bytes);
});

test('existing conflicting approved destination is never overwritten', async t => {
  const { root, store } = await fixture(t); const item = await store.stage(input());
  const path = join(root, 'approved', `${item.id}.bin`); await writeFile(path, 'existing');
  assert.equal((await store.scanAndPromote({ id: item.id, ownerId: 'alice' })).status, 'rejected');
  assert.equal(await readFile(path, 'utf8'), 'existing');
});

test('wrong-owner scan and approved-file tampering remain inaccessible', async t => {
  const { root, store } = await fixture(t); const item = await store.stage(input());
  await assert.rejects(store.scanAndPromote({ id: item.id, ownerId: 'bob' }), { code: 'not_found' });
  await store.scanAndPromote({ id: item.id, ownerId: 'alice' });
  const path = join(root, 'approved', `${item.id}.bin`); await chmod(path, 0o600); await writeFile(path, 'tampered');
  await assert.rejects(store.get({ id: item.id, ownerId: 'alice' }), { code: 'content_changed' });
});
