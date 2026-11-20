# Outbound requests, return destinations and account recovery

These references add specific server-side boundaries. None infers authorization from model output, a query parameter, an email address or a researcher label. Use each module's executable example and tests before adapting it.

## Outbound HTTPS requests

Prefer server-selected endpoint IDs to arbitrary caller-supplied URLs. [The outbound reference](../enterprise/outbound/README.md) supplies a real bounded HTTPS GET path for a deliberately narrow profile. Trusted startup configuration selects the exact host, path, response type, byte limit and deadline. It resolves the destination, refuses the entire answer set if any address is unsupported or prohibited, and pins the checked IPv4 address while retaining the original TLS hostname and verification. Redirects and ambient caller credentials are not permitted.

The supported profile excludes arbitrary URLs, IPv6, private endpoints, caller headers/bodies, proxy routing and credential injection. Extend it through a separate reviewed profile with its own tests, not by disabling address checks or falling back to an unrestricted HTTP client. A deadline must include DNS and response consumption; a slow resolver must not schedule a request after the caller has already timed out. Bound the actual streamed bytes, not only Content-Length.

The [agent egress planner](../enterprise/agent-runtime/README.md) remains an offline plan. It is not a substitute for this request transport, a firewall or a broker. Returned content remains untrusted data even when TLS and destination checks pass. Parse only expected formats, apply application authorization and never execute fetched content or follow instructions from it. Redact upstream error details in public responses.

Example: a caller selects `public-report`, and the server's fixed catalog maps that ID to one approved HTTPS resource. A body field containing a metadata URL cannot choose the destination. The tests exercise DNS answer changes, prohibited address mixtures, redirects, late activity and size/deadline failures with synthetic transport adapters; they do not send probes to real services.

## In-application return paths

Use the local return-route resolver in the same module to map a small server-authored ID to a canonical local path. Reject unknown IDs and unsafe configured destinations. Absolute external URLs, protocol-relative paths, backslashes, encoded separators, dot segments and control characters are not this profile's return values. Do not echo a client-provided `next`, `returnTo` or redirect URL directly into Location.

For example, `after-login` may map to `/account`; it cannot select a different host. OIDC/SAML callback and issuer/audience validation still follow the [federation contract](../enterprise/federation/README.md). A safe local return path does not authenticate an identity or prevent every OAuth flow defect.

## Recovery and security-context changes

[The recovery reference](../enterprise/recovery/README.md) demonstrates random one-use tokens, hash-only storage, purpose/account/tenant/security-epoch binding, short expiration and atomic consumption. Email-change intent uses a trusted pending-change reference, not an arbitrary address supplied during redemption. Consuming a valid token advances the reference's account epoch and invalidates outstanding contexts. Actual password, email or factor changes and revocation of application sessions remain integration work.

Issue recovery material only after the application's authorized workflow and delivery controls select the account, purpose and intended change. Use protected delivery and generic public responses to reduce account enumeration. Apply independent source/account admission to issuance and verification, limit attempts, and do not let a client choose trusted clocks or current epochs. Do not automatically link accounts by matching email addresses.

A consume result is a claim, not evidence that an external password mutation completed. Apply business state and recovery state in one trusted transaction where possible. Across services use durable idempotent fulfillment/outbox and reconcile unknown outcomes. A crash after token consumption can burn a token before fulfillment; do not replay a possibly completed external operation. Provide a separate trusted reissue/recovery path.

Test recovery after password changes, email changes and factor enrollment/removal; include concurrent redemptions, old tokens and sessions, delayed callbacks, issuer failures and restore behavior. Local SQLite state cannot by itself invalidate an IdP token, a browser session in another store or a token accepted by another independent instance. Multiple workers must share authoritative account/security state and its rollback policy.

## Standards and verification scope

Relevant primary references include [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [unvalidated redirect prevention](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) and [forgot-password guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html). CWE-918, CWE-601 and CWE-640 describe related weakness classes. Selected [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) relationships are SC-7, AC-3, AC-6, IA-5, SI-10 and AU-3. These are implementation/testing leads, not a claim of complete coverage or certification.

Read the precise module contracts for supported syntax and executable tests. Live DNS/TLS deployments, approved endpoint ownership, mail/SMS delivery, identity proof, session revocation, shared-state recovery and operational effectiveness require target-specific validation.

## Host-level monitoring boundary

The application outbound catalog does not mediate connections initiated independently by another process. Apply [host/container egress policy](HOST-EGRESS-MONITORING.md) at the enforcement point, and combine approved [SSH integrity](SSH-KEY-INTEGRITY.md), [runtime](../enterprise/runtime/README.md#runtime-signals) and [identity](IDENTITY-MONITORING.md) review procedures. The [SIEM helper](../enterprise/operations/README.md) exports operator-authored metadata; it does not deploy or collect these sensors.
