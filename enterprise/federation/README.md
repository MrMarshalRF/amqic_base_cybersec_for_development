# Tenant-scoped OIDC and SAML federation

Use the federation gate at a server-owned login callback. Each tenant and provider has a fixed configuration, a distinct HTTPS callback URL and an explicit map from external groups to local roles. Use the IdP's stable subject identifier as the identity. The resolver grants just-in-time provisioning only where the provider policy explicitly enables it.

## Wire the SDKs

Install reviewed, pinned releases of `openid-client` v6 and `@node-saml/node-saml` in the adopting application. Keep their dependencies in that application's lockfile and review advisories before use. The reference accepts the SDKs from the application. This repository can run the synthetic tests with Node.js alone.

```js
import * as oidc from 'openid-client';
import { SAML } from '@node-saml/node-saml';
import { createFederation } from './enterprise/federation/federation.mjs';
import { oidcAdapter, samlAdapter } from './enterprise/federation/adapters.mjs';

// These inputs come from reviewed server configuration, workload identity
// and secret storage. Callers never control issuer metadata or SDK options.
const oidcConfiguration = new oidc.Configuration(
  trustedOidcMetadata, clientId, { id_token_signed_response_alg: 'RS256' }, oidc.ClientSecretBasic(clientSecret),
);
const corporate = oidcAdapter({
  library: oidc, configuration: oidcConfiguration,
  issuer: trustedOidcMetadata.issuer, audience: clientId,
  redirectUri: 'https://service.example/auth/corporate/callback',
  groupsClaim: 'groups',
});
const partner = samlAdapter({
  SAML, cacheProvider: sharedPartnerRequestCache,
  issuer: trustedPartnerEntityId, audience: partnerServiceProviderId,
  entryPoint: trustedPartnerEntryPoint,
  redirectUri: 'https://service.example/auth/partner/acs',
  idpCert: trustedPartnerCertificate,
  requestSigningKey: serviceProviderPrivateKey, requestSigningCert: serviceProviderPublicCertificate,
  groupsAttribute: 'groups',
});
const federation = createFederation({
  providers: [
    { tenant: 'acme', id: 'corporate', revision: corporatePolicyDigest,
      adapter: corporate, groupRoles: [['staff', 'reader']] },
    { tenant: 'acme', id: 'partner', revision: partnerPolicyDigest,
      adapter: partner, groupRoles: [['approved-partner', 'partner-reader']], allowProvisioning: true },
  ],
  challenges: sharedChallengeStore,
  resolveIdentity: resolveTenantIdentity,
});
```

Use SHA-256 of a canonical public configuration revision for each `revision`, with tenant, provider, endpoints, audience, verification profile, public trust roots and role policy covered. On a policy or trust change, stale flows fail closed. Secret values stay in the application's secret provider. For credential rotations which require invalidating active flows, advance the public configuration revision as well.

The OIDC adapter uses authorization code flow, S256 PKCE, state, nonce and JWS signature verification. Review fixed issuer metadata and pin allowed egress for authorization, token and JWKS endpoints. Use a bounded SDK network timeout. Verify that configuration changes and signing-key rollover keep the intended issuer and algorithm. Register every exact redirect URI with its provider. [openid-client grant checks](https://github.com/panva/openid-client/blob/main/docs/interfaces/AuthorizationCodeGrantChecks.md) · [Signature validation](https://github.com/panva/openid-client/blob/main/docs/functions/enableNonRepudiationChecks.md)

The SAML adapter uses an SP-initiated HTTP-Redirect request and a signed HTTP-POST response. Configure the IdP to sign both response and assertion and send persistent NameIDs, one bearer confirmation with the ACS recipient, the request ID and a validity window. Configure a dedicated request cache per tenant and IdP using the SDK's documented cache interface. Prefer its atomic consumption primitive where supported. The application separately consumes RelayState atomically and binds the signed bearer confirmation to that exact request ID. Use a maintained release whose `getAssertion()` exposes parsed and verified assertion data. Plan certificate rollover as a reviewed provider configuration update. [Node-SAML options and profile API](https://github.com/node-saml/node-saml)

## Run the callback

1. Establish a high-entropy browser session binding before login. Use a cryptographically random 32-byte base64url handle, stored or referenced by a protected cookie. Select the tenant from the application's trusted routing or bootstrap session. Resolve the provider identifier through that tenant's configuration. Rate limit new challenge creation.
2. Call `federation.start({ tenant, providerId, browserBinding })` and redirect to the returned URL. The challenge holds the PKCE verifier and nonce or SAML request ID on the server.
3. Reconstruct and validate the actual callback route through trusted server and proxy configuration. Supply the exact configured `redirectUri`, the OIDC `state` or SAML `RelayState`, and the protocol response to `federation.complete({ tenant, providerId, browserBinding, redirectUri, state, response })`. Give the OIDC adapter the original callback URL including the query. Give the SAML adapter the single base64 `SAMLResponse` field from a bounded, form-encoded POST. Reject duplicate form fields. Verify the browser binding on the matching callback. For a cross-site SAML POST, configure a dedicated short-lived `SameSite=None; Secure; HttpOnly` correlation cookie if the browser and deployment require it.
4. After success, rotate the session identifier and issue the bounded local session. Apply authorization and the kit's existing step-up gate at use time. Federation does not establish MFA equivalence to the local step-up policy. Deprovisioning, session revocation, account linking and role updates outside new logins need separate application controls.

The `challenges` port uses `put(digest, challenge)` for atomic create-if-absent and `take(digest, nowMs)` for atomic delete-and-return of an unexpired challenge. A rejected or ambiguous consume never starts a new external exchange. The built-in SQLite store is suitable for same-host workers sharing one durable file. Multi-host deployments need a shared transactional store with durable consume behavior under failover. Treat losing the store or seeing an unknown write result as a failed login. Purge expired records with `purgeExpired(nowMs)` for SQLite or equivalent store retention. Keep challenge values private and restrict access to the store. Key the separate SAML library cache by tenant and IdP, and verify expiry and correlation across workers.

Implement `resolveTenantIdentity` as an atomic canonical binding lookup and optional create. Its input contains the key derived from tenant, provider, issuer and immutable subject, mapped roles, provisioning permission and `validUntil`. Validate the deadline and tenant again in the transaction, use a unique constraint on the federation key, honor disabled users and reject creation when provisioning is off. Return `{ id, tenant, enabled }` only for the resolved local subject. Never link accounts by email, even when the IdP claims it is verified. Keep role policy exact and reviewed. The gate ignores unrecognized groups and denies admission when no mapped role remains. Keep cookies, tokens, SAML XML and raw identity attributes out of logs. Only the adopter's approved local roles should authorize resources.

## Verification

```sh
node --experimental-sqlite --test enterprise/federation/federation.test.mjs
```

The local tests verify request options, tenant and protocol binding, replay rejection, claim validation, role mapping and one-time SQLite consumption using synthetic SDKs. Production review must exercise the pinned SDKs, representative signed provider artifacts, browser cookie policy, IdP and key rollover, distributed store failover, deprovisioning and the final authorization effect. Monitor issuer and callback mismatches, state failures, provider connection errors and provisioning denials with redacted event codes. Treat federation as an identity boundary described by NIST SP 800-63C-4 and SP 800-53 AC-2 and AC-3. [NIST SP 800-63C-4](https://pages.nist.gov/800-63-4/sp800-63c.html) · [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
