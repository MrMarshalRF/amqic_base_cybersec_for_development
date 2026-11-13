import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './fixtures.mjs';
import { AccessDenied } from './core.mjs';

test('session authorization exposes only current identity for an explicitly allowed scope', t => {
  const f = fixture(); f.provision(); t.after(() => f.core.close());
  const session = f.login();
  assert.deepEqual(f.core.authorizeSession(session, 'records.remove'), { userId: 'user-1' });
  for (const scope of [undefined, '', '*', 'contacts.read']) {
    assert.throws(() => f.core.authorizeSession(session, scope), AccessDenied);
  }
  assert.throws(() => f.core.authorizeSession('not-a-session', 'records.remove'), AccessDenied);
  f.core.logout(session);
  assert.throws(() => f.core.authorizeSession(session, 'records.remove'), AccessDenied);
});

test('session authorization checks expiry and user revocation on subsequent requests', t => {
  const f = fixture(); f.provision(); t.after(() => f.core.close());
  const session = f.login();
  f.core.revokeUser('user-1');
  assert.throws(() => f.core.authorizeSession(session, 'records.remove'), AccessDenied);
  const g = fixture(); g.provision(); t.after(() => g.core.close());
  const expiring = g.login(); g.advance(901);
  assert.throws(() => g.core.authorizeSession(expiring, 'records.remove'), AccessDenied);
});
