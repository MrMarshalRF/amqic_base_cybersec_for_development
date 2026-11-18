import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { createFederation, sqliteChallenges } from './federation.mjs';
import { oidcAdapter, samlAdapter } from './adapters.mjs';

const time = 1_700_000_000_000;
const issuer = 'https://idp.example';
const redirectUri = 'https://app.example/oidc';
const audience = 'workbench';
const browserBinding = 'B'.repeat(43);
const request = { tenant: 'one', providerId: 'corporate', browserBinding };
const config = { serverMetadata: () => ({
  issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/keys',
}), clientMetadata: () => ({ client_id: audience }) };

function oidcFixture(patch = x => x) {
  const captures = { grant: 0, sign: 0 };
  const lib = {
    enableNonRepudiationChecks(c) { assert.equal(c, config); captures.sign++; },
    calculatePKCECodeChallenge: async verifier => {
      assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
      captures.verifier = verifier;
      return 'fixture-pkce';
    },
    buildAuthorizationUrl(c, params) {
      assert.equal(c, config);
      captures.authorize = params;
      return new URL(issuer + '/authorize?' + new URLSearchParams(params));
    },
    async authorizationCodeGrant(c, u, checks) {
      assert.equal(c, config);
      assert.equal(u.searchParams.get('code'), 'synthetic-code');
      assert.deepEqual(checks, {
        expectedNonce: captures.authorize.nonce,
        expectedState: captures.authorize.state,
        pkceCodeVerifier: captures.verifier,
        idTokenExpected: true,
      });
      captures.grant++;
      return { claims: () => patch({
        iss: issuer, aud: audience, sub: 'immutable-user', nonce: checks.expectedNonce,
        iat: time / 1000, exp: time / 1000 + 600, groups: ['staff', 'unmapped'],
      }) };
    },
  };
  return { adapter: oidcAdapter({ library: lib, configuration: config, issuer, audience, redirectUri, clock: () => time }), captures };
}

function setup(t, adapter, overrides = {}) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const seen = [];
  const service = createFederation({
    providers: [{ tenant: 'one', id: 'corporate', revision: 'a'.repeat(64), adapter,
      groupRoles: [['staff', 'reader']] }],
    challenges: sqliteChallenges(db),
    clock: () => time,
    resolveIdentity: async binding => {
      seen.push(binding);
      return { id: 'local-user', tenant: binding.tenant, enabled: true };
    },
    ...overrides,
  });
  return { service, seen };
}

async function oidcCallback(service) {
  const { redirect } = await service.start(request);
  const params = new URL(redirect).searchParams;
  assert.equal(params.get('code_challenge_method'), 'S256');
  assert.equal(params.get('scope'), 'openid');
  const state = params.get('state');
  return { ...request, redirectUri, state, response: redirectUri + '?state=' + state + '&code=synthetic-code' };
}

test('OIDC uses signed, PKCE-bound code flow; only one concurrent callback resolves identity', async t => {
  const { adapter, captures } = oidcFixture();
  const { service, seen } = setup(t, adapter);
  const callback = await oidcCallback(service);
  assert.equal(captures.sign, 1);
  await assert.rejects(service.complete({ ...callback, browserBinding: 'C'.repeat(43) }), { code: 'rejected' });
  await assert.rejects(service.complete({ ...callback, tenant: 'other' }), { code: 'invalid_request' });
  assert.equal(captures.grant, 0);
  const parallel = await Promise.allSettled([service.complete(callback), service.complete(callback)]);
  assert.equal(parallel.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(captures.grant, 1);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].allowProvisioning, false);
  assert.match(seen[0].key, /^[a-f0-9]{64}$/);
  assert.deepEqual(parallel.find(x => x.status === 'fulfilled').value, {
    tenant: 'one', userId: 'local-user', roles: ['reader'], expiresAt: time + 600_000,
  });
});

test('wrong issuer, missing nonce, wrong multi-audience presenter, and expired tokens cannot provision', async t => {
  for (const change of [
    { iss: 'https://other.example' }, { nonce: undefined }, { aud: [audience, 'other-client'], azp: 'other-client' },
    { aud: [audience, 'other-client'] }, { exp: time / 1000 }, { iat: time / 1000 - 120 }, { iat: time / 1000 + 10 },
  ]) {
    const { adapter } = oidcFixture(claims => ({ ...claims, ...change }));
    const { service, seen } = setup(t, adapter);
    const callback = await oidcCallback(service);
    await assert.rejects(service.complete(callback), { code: 'rejected' });
    assert.equal(seen.length, 0);
  }
});

test('wrong callback route, duplicate parameters and stale challenges prevent token exchange', async t => {
  for (const change of [
    callback => ({ ...callback, response: callback.response.replace('/oidc?', '/other?') }),
    callback => ({ ...callback, response: callback.response + '&code=another-code' }),
    callback => ({ ...callback, response: callback.response + '&iss=https://other.example' }),
  ]) {
    const { adapter, captures } = oidcFixture();
    const { service } = setup(t, adapter);
    await assert.rejects(service.complete(change(await oidcCallback(service))), { code: 'rejected' });
    assert.equal(captures.grant, 0);
  }
  const { adapter, captures } = oidcFixture();
  let now = time;
  const { service } = setup(t, adapter, { clock: () => now });
  const callback = await oidcCallback(service);
  now += 300_000;
  await assert.rejects(service.complete(callback), { code: 'rejected' });
  assert.equal(captures.grant, 0);
});

test('unmapped roles deny, resolver may reject admission and disabled users remain disabled', async t => {
  let { adapter } = oidcFixture(claims => ({ ...claims, groups: ['admin'] }));
  const a = setup(t, adapter);
  await assert.rejects(a.service.complete(await oidcCallback(a.service)), { code: 'identity_denied' });
  assert.equal(a.seen.length, 0);
  ({ adapter } = oidcFixture());
  const b = setup(t, adapter, { resolveIdentity: async () => ({ id: 'local-user', enabled: false, tenant: 'one' }) });
  await assert.rejects(b.service.complete(await oidcCallback(b.service)), { code: 'identity_denied' });
});

const samlCallbackUri = 'https://app.example/saml';
function samlFixture(patch = () => {}) {
  let requestId;
  const calls = { validate: 0, options: [] };
  class SyntheticSAML {
    constructor(options) { this.options = options; calls.options.push(options); }
    async getAuthorizeUrlAsync(state) {
      requestId = this.options.generateUniqueId();
      return issuer + '/sso?RelayState=' + state;
    }
    async validatePostResponseAsync({ SAMLResponse }) {
      assert.equal(SAMLResponse, 'Zml4dHVyZQ==');
      calls.validate++;
      const bound = { Recipient: samlCallbackUri, InResponseTo: requestId, NotOnOrAfter: new Date(time + 60_000).toISOString() };
      const assertion = {
        $: { IssueInstant: new Date(time).toISOString() },
        Subject: [{ SubjectConfirmation: [{ $: { Method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer' },
          SubjectConfirmationData: [{ $: bound }] }] }],
        Conditions: [{ $: { NotOnOrAfter: new Date(time + 60_000).toISOString() } }],
        AuthnStatement: [{ $: { AuthnInstant: new Date(time).toISOString() } }],
        AttributeStatement: [{ Attribute: [{ $: { Name: 'groups' }, AttributeValue: ['staff'] }] }],
      };
      patch(bound, assertion);
      return { loggedOut: false, profile: {
        issuer, nameID: 'persistent-id', nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        groups: ['ignored-flattened-attribute'], getAssertion: () => assertion,
      } };
    }
  }
  const cacheProvider = { saveAsync() {}, getAsync() {}, removeAsync() {} };
  return { adapter: samlAdapter({ SAML: SyntheticSAML, cacheProvider, issuer, audience, entryPoint: issuer + '/sso',
    redirectUri: samlCallbackUri, idpCert: 'fixture-idp',
    requestSigningKey: 'fixture-key', requestSigningCert: 'fixture-sp-cert', clock: () => time }), calls };
}

async function samlCallback(service) {
  const { redirect } = await service.start(request);
  return { ...request, redirectUri: samlCallbackUri, state: new URL(redirect).searchParams.get('RelayState'), response: 'Zml4dHVyZQ==' };
}

test('SAML adapter enforces strict SDK options, signed confirmation binding and one-time RelayState', async t => {
  const { adapter, calls } = samlFixture();
  const { service } = setup(t, adapter);
  const callback = await samlCallback(service);
  assert.equal(calls.options.every(o => o.audience === audience &&
    o.validateInResponseTo === 'always' && o.wantAssertionsSigned && o.wantAuthnResponseSigned), true);
  assert.deepEqual(await service.complete(callback), {
    tenant: 'one', userId: 'local-user', roles: ['reader'], expiresAt: time + 60_000,
  });
  await assert.rejects(service.complete(callback), { code: 'rejected' });
  assert.equal(calls.validate, 1);
});

test('SAML rejects a signed assertion with a mismatched bearer recipient, request ID or time window', async t => {
  for (const patch of [
    bound => { bound.InResponseTo = '_not-original'; },
    bound => { bound.Recipient = 'https://other.example/acs'; },
    bound => { bound.NotOnOrAfter = new Date(time).toISOString(); },
    bound => { bound.NotBefore = new Date(time + 1000).toISOString(); },
    (_bound, assertion) => { assertion.AttributeStatement.push(assertion.AttributeStatement[0]); },
  ]) {
    const { adapter } = samlFixture(patch);
    const { service, seen } = setup(t, adapter);
    await assert.rejects(service.complete(await samlCallback(service)), { code: 'rejected' });
    assert.equal(seen.length, 0);
  }
});

test('multi-IdP entries isolate callbacks and use explicit JIT policy', async t => {
  const oidc = oidcFixture();
  const saml = samlFixture();
  const { service, seen } = setup(t, oidc.adapter, { providers: [
    { ...request, id: 'corporate', revision: 'a'.repeat(64), adapter: oidc.adapter, groupRoles: [['staff', 'reader']] },
    { tenant: 'two', id: 'partner', revision: 'b'.repeat(64), adapter: saml.adapter,
      groupRoles: [['staff', 'limited']], allowProvisioning: true },
  ] });
  const oidcReturn = await oidcCallback(service);
  await assert.rejects(service.complete({ ...oidcReturn, tenant: 'two', providerId: 'partner', redirectUri: samlCallbackUri }), { code: 'rejected' });
  assert.equal(saml.calls.validate, 0);
  const partner = { ...request, tenant: 'two', providerId: 'partner' };
  const { redirect } = await service.start(partner);
  const result = await service.complete({ ...partner, state: new URL(redirect).searchParams.get('RelayState'),
    redirectUri: samlCallbackUri, response: 'Zml4dHVyZQ==' });
  assert.deepEqual(result.roles, ['limited']);
  assert.equal(result.tenant, 'two');
  assert.equal(seen[0].allowProvisioning, true);
});
