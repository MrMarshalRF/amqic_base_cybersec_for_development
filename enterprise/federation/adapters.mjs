import { callbackUrl, FederationError } from './federation.mjs';

function ensure(condition) {
  if (!condition) throw new FederationError('rejected');
}

const handle = v => typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v);
const fieldName = v => typeof v === 'string' && /^[A-Za-z0-9_.:/-]{1,128}$/.test(v);
const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

function httpsEndpoint(value) {
  ensure(typeof value === 'string' && value.startsWith('https://'));
  const url = new URL(value);
  ensure(!url.username && !url.password && !url.hash);
  return url;
}

function exactAudience(claims, expected) {
  const values = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  return values.length > 0 && values.length <= 16 && values.every(x => typeof x === 'string') &&
    new Set(values).size === values.length && values.includes(expected) &&
    (values.length === 1 ? claims.azp === undefined || claims.azp === expected : claims.azp === expected);
}

/** openid-client v6, supplied by the adopter from its reviewed, pinned dependencies. */
export function oidcAdapter({ library, configuration, issuer, audience, redirectUri, groupsClaim = 'groups', clock = Date.now }) {
  const callback = callbackUrl(redirectUri);
  const metadata = configuration.serverMetadata();
  ensure(metadata.issuer === issuer && configuration.clientMetadata().client_id === audience && fieldName(groupsClaim) && typeof clock === 'function');
  for (const value of [issuer, metadata.authorization_endpoint, metadata.token_endpoint, metadata.jwks_uri]) httpsEndpoint(value);
  library.enableNonRepudiationChecks(configuration);
  return Object.freeze({
    protocol: 'oidc', issuer, audience, redirectUri,
    async start(txn) {
      ensure(handle(txn.state) && handle(txn.verifier) && handle(txn.nonce));
      const challenge = await library.calculatePKCECodeChallenge(txn.verifier);
      return library.buildAuthorizationUrl(configuration, {
        redirect_uri: redirectUri, response_type: 'code', scope: 'openid',
        state: txn.state, nonce: txn.nonce, code_challenge: challenge, code_challenge_method: 'S256',
      }).href;
    },
    async verify(response, txn) {
      ensure(typeof response === 'string' && response.length <= 8192);
      ensure(handle(txn.state) && handle(txn.verifier) && handle(txn.nonce));
      const url = httpsEndpoint(response);
      ensure(url.origin === callback.origin && url.pathname === callback.pathname);
      for (const parameter of ['state', 'code', 'iss']) ensure(url.searchParams.getAll(parameter).length <= 1);
      ensure(url.searchParams.get('state') === txn.state && url.searchParams.get('code') && !url.searchParams.has('error'));
      const returnedIssuer = url.searchParams.get('iss');
      ensure(returnedIssuer === null || returnedIssuer === issuer);
      const tokens = await library.authorizationCodeGrant(configuration, url, {
        expectedState: txn.state, expectedNonce: txn.nonce, pkceCodeVerifier: txn.verifier, idTokenExpected: true,
      });
      const claims = tokens.claims();
      const checkedAt = clock();
      ensure(claims?.iss === issuer && exactAudience(claims, audience) && claims.nonce === txn.nonce &&
        Number.isSafeInteger(claims.exp) && claims.exp > 0 && Number.isSafeInteger(claims.exp * 1000) &&
        Number.isSafeInteger(claims.iat) && claims.iat >= 0 && claims.iat < claims.exp &&
        Number.isSafeInteger(checkedAt) && checkedAt >= txn.issuedAt &&
        claims.iat * 1000 >= txn.issuedAt - 1000 && claims.iat * 1000 <= checkedAt &&
        claims.exp * 1000 > checkedAt);
      const groups = Object.hasOwn(claims, groupsClaim) ? claims[groupsClaim] : [];
      ensure(Array.isArray(groups));
      return Object.freeze({ protocol: 'oidc', issuer, audience, subject: claims.sub, expiresAt: claims.exp * 1000, groups });
    },
  });
}

const only = list => Array.isArray(list) && list.length === 1 ? list[0] : undefined;
const samlId = v => typeof v === 'string' && /^_[A-Za-z0-9_-]{43}$/.test(v);
function instant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value)) return NaN;
  return Date.parse(value);
}

function signedAttributes(assertion, wantedName) {
  const matches = (assertion.AttributeStatement ?? []).flatMap(s => s.Attribute ?? []).filter(a => a.$?.Name === wantedName);
  ensure(matches.length <= 1);
  if (matches.length === 0) return [];
  const values = matches[0].AttributeValue;
  ensure(Array.isArray(values) && values.length <= 128);
  return values.map(value => {
    if (typeof value === 'string') return value;
    ensure(value && Object.keys(value).every(k => k === '_' || k === '$') && typeof value._ === 'string');
    return value._;
  });
}

/** @node-saml/node-saml with a dedicated shared request cache per tenant and IdP. */
export function samlAdapter({ SAML, cacheProvider, issuer, audience, entryPoint, redirectUri, idpCert,
  requestSigningKey, requestSigningCert, groupsAttribute = 'groups', clock = Date.now }) {
  callbackUrl(redirectUri);
  httpsEndpoint(entryPoint);
  ensure(typeof SAML === 'function' && typeof cacheProvider?.saveAsync === 'function' &&
    typeof cacheProvider?.getAsync === 'function' && typeof cacheProvider?.removeAsync === 'function' &&
    typeof idpCert === 'string' && idpCert.length > 0 &&
    typeof requestSigningKey === 'string' && requestSigningKey.length > 0 &&
    typeof requestSigningCert === 'string' && requestSigningCert.length > 0 && fieldName(groupsAttribute) &&
    typeof clock === 'function');
  const options = {
    issuer: audience, audience, idpCert, entryPoint, callbackUrl: redirectUri, cacheProvider,
    wantAuthnResponseSigned: true, wantAssertionsSigned: true, validateInResponseTo: 'always',
    acceptedClockSkewMs: 0, maxAssertionAgeMs: 300_000, requestIdExpirationPeriodMs: 300_000,
    identifierFormat: PERSISTENT, disableRequestedAuthnContext: true,
    privateKey: requestSigningKey, publicCert: requestSigningCert, signatureAlgorithm: 'sha256', digestAlgorithm: 'sha256',
  };
  const verifier = new SAML(options);
  return Object.freeze({
    protocol: 'saml', issuer, audience, redirectUri,
    async start(txn) {
      ensure(samlId(txn.requestId) && handle(txn.state));
      const generator = new SAML({ ...options, generateUniqueId: () => txn.requestId });
      return generator.getAuthorizeUrlAsync(txn.state, {});
    },
    async verify(response, txn) {
      ensure(typeof response === 'string' && response.length <= 1024 * 1024 &&
        /^[A-Za-z0-9+/]+={0,2}$/.test(response) && samlId(txn.requestId));
      const { profile, loggedOut } = await verifier.validatePostResponseAsync({ SAMLResponse: response });
      ensure(loggedOut === false && profile?.issuer === issuer && profile.nameIDFormat === PERSISTENT &&
        (profile.nameQualifier === undefined || profile.nameQualifier === issuer) &&
        (profile.spNameQualifier === undefined || profile.spNameQualifier === audience) &&
        typeof profile.getAssertion === 'function');
      // Use only the maintained library's parsed, verified assertion.
      const assertion = profile.getAssertion();
      const conditions = only(assertion.Conditions);
      const subject = only(assertion.Subject);
      const confirmation = only(subject?.SubjectConfirmation);
      const bound = only(confirmation?.SubjectConfirmationData)?.$;
      const authn = only(assertion.AuthnStatement)?.$;
      ensure(authn && conditions?.$ && confirmation?.$?.Method === BEARER &&
        bound?.Recipient === redirectUri && bound?.InResponseTo === txn.requestId &&
        bound?.NotBefore === undefined);
      const now = clock();
      const issuedAt = instant(assertion.$?.IssueInstant);
      const lower = conditions.$.NotBefore === undefined ? issuedAt : instant(conditions.$.NotBefore);
      const sessionExpiry = authn.SessionNotOnOrAfter === undefined ? Infinity : instant(authn.SessionNotOnOrAfter);
      const expiresAt = Math.min(instant(conditions.$.NotOnOrAfter), instant(bound.NotOnOrAfter),
        issuedAt + 300_000, sessionExpiry);
      ensure(Number.isSafeInteger(now) && Number.isSafeInteger(expiresAt) &&
        issuedAt >= txn.issuedAt - 1000 && issuedAt <= now && lower <= now && expiresAt > now);
      const groups = signedAttributes(assertion, groupsAttribute);
      return Object.freeze({ protocol: 'saml', issuer, audience, subject: profile.nameID, expiresAt, groups });
    },
  });
}
