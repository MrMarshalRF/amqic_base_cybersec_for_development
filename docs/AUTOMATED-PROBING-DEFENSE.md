# Defending applications against automated probing

This guide addresses unauthorized enumeration, account abuse and high-rate API exploration, including traffic orchestrated by LLM agents. The same application defects can be found by a human, a script or an agent. Reduce exposure, enforce authorization and observe behavior regardless of the client's name. An authorized tester's identity and scope come from an agreed engagement, not a User-Agent or an assertion in a request.

The [companion runtime guide](AI-AGENT-RUNTIME.md) protects agents you operate. This guide protects services they may contact. Neither guide promises to prevent all vulnerability discovery or replace fixing vulnerabilities.

## Start with the exposed estate

Inventory every hostname, address, port, application and owner, including mobile backends, partner portals, publishing endpoints, legacy systems and staging. Compare intended exposure with DNS, certificate inventories, cloud load balancers and firewall rules. Historical DNS and sibling services can reveal an origin even after proxying is enabled. Inventory is an ongoing reconciliation, not a guarantee that an IP was never visible.

Publish only reviewed routes and methods. Retire old endpoints with real 404/410 behavior instead of returning the application shell with 200. Remove secrets, private backend names and unused privileged features from public bundles. Source maps, source-control metadata, debug/actuator endpoints and API descriptions should be exposed only when intentionally required and protected for that purpose. Public API documentation and discovery endpoints can be valid product features; hiding them never replaces authorization on the underlying operations.

Keep management access behind a VPN/private administrative path and the host firewall. Nginx restricts HTTP traffic; it does not secure SSH, a database port, a publishing service or a hypervisor. Retain [origin/firewall controls](INFRASTRUCTURE.md), authenticated proxy-to-origin connections, [database RLS/column restrictions](DATABASE-SECURITY.md) and application checks on every object operation.

This GitHub repository intentionally publishes documentation and source. Do not deploy its root as a website document root. A public `AGENTS.md` here is useful project documentation; a deployment's private agent configuration, credentials and working files belong outside the served tree.

## Layer admission across trusted identities

The [probe-defense reference](../enterprise/probe-defense/README.md) supplies a working SQLite example of atomic admission across configured dimensions. The fixed local laboratory runs its tests:

```sh
node --experimental-sqlite --test enterprise/probe-defense/probe-defense.test.mjs
node scripts/verify.mjs --all --output /absolute/external/all-local.json
```

Select a canonical route class on the server. Derive source identity from the socket or an explicitly verified proxy chain, and derive tenant, account and session from authoritative authentication. Authenticated routes require identity. Set the explicit per-route `allowAnonymous` flag only for a reviewed public route; otherwise null authentication denies admission. Never convert failed authentication into anonymous admission. A forged forwarded header, self-selected session ID, User-Agent, client-declared ASN or researcher label must not create a fresh trusted allowance.

Use source, account, session, tenant and overall route limits together. Rotating source addresses should not reset an authenticated account's budget; rotating accounts should not reset the source/global budget. Set tighter limits for login, OTP, reset, search, record lookup, exports and recipient/transaction operations. Keep separate cost/concurrency limits for expensive work. Do not let a client declare its own operation cost. Authentication, CAPTCHA, step-up and object authorization remain independent controls after admission.

Tune limits against legitimate traffic, NAT/shared networks, mobile clients and API integrations. ASN and fingerprint aggregation can assist correlation but should not be primary identity or an automatic permanent ban. Authorized testers follow separately approved scope and rate limits; a claimed testing header must not skip authentication, throttling or data isolation.

The reference's same-host transactions check the configured budgets together. Subject buckets are tenant-scoped, and session buckets include tenant and subject so local IDs from different tenants do not share a quota. Its HMAC bucket identifiers reduce raw identity storage, but the database and key still need access protection and retention. It uses fixed windows with a known boundary-burst tradeoff. Multiple processes must share the protected database and policy/key configuration. Across hosts, use a datastore-side atomic operation and the [distributed admission guidance](../enterprise/distributed/README.md). Sequentially asking independent limiters and calling that an atomic combined decision is insufficient. Document time, failover, persistence and restore behavior; do not erase live security state to recover capacity.

## Keep denial responses small and useful

Return generic bodies without raw input, SQL errors, stack traces, internal paths or private rule names. The reference provides a fixed response body with explicit 403, 404 or 429 semantics. A concealed forbidden resource may use 404 by design, but keep rate-limit responses meaningful and use Retry-After when the server can calculate it. Do not turn every failure into 200 or promise identical timing across different code paths.

Keep security headers on errors and prevent sensitive denial responses from being cached. Record detailed reasons only in the protected service record. Avoid intentionally holding large numbers of connections or spending expensive work to waste a visitor's budget: bound the defender's own resources and reject excess work promptly. Existing Nginx controls still apply independently of this application reference.

## Harmless canary signals

Use an inert route with no legitimate application purpose and a server-selected opaque identifier. It returns the same generic denial and records a minimal event. The reference demonstrates this boundary with synthetic IDs. Its private operator result can report whether the alert sink accepted the event; expose only the generic response to the client. A sink failure must also reach monitoring, because a silent tripwire is ineffective.

Keep actual route/identifier mappings outside public source, public bundles, robots.txt and the protected-path list. The public deny list is not a secret and cannot serve as a hidden canary registry. Never include a usable cloud key, password, customer data, privileged account, executable payload or instruction telling a visiting agent to act on its own machine. This example does not call a visitor, follow a callback URL or trigger any external credential service.

A canary hit is an investigation lead. Authorized testers, monitoring mistakes and misconfigured clients can trigger it. Correlate with other events and have a human decide consequential containment. No single hit, 404, User-Agent or browser-fingerprint mismatch establishes malicious intent or authorizes action against a visitor's system.

## Correlate behavior with minimal data

Useful signals include repeated protected-path attempts, route breadth, sequential record access, records returned per authenticated session, denial bursts, unusual identity changes, unexpected publishing activity, drop-counter changes and server egress to destinations the application does not need. A server's request to an interaction-capture or LLM API endpoint warrants investigation in context; it is not proof of exploitation or attribution by itself.

At trusted ingestion, derive route classes, counts and opaque source/session references. Avoid raw query strings, request bodies, cookies, authorization headers and customer identifiers. Keep timestamps, asset reference, request reference, authenticated principal reference where necessary, route class, outcome, count/window and policy revision. Pseudonymous identifiers are not anonymous data; protect access, retention and key custody.

Map events deliberately into the [SIEM exporter](../enterprise/operations/README.md). The reference's event object is not automatically an OCSF event or a valid audit-chain entry. Authenticate collectors, synchronize time and test alerts, delivery failure, deduplication and retention. Correlation rules need deployment baselines; this kit does not ship an automatically blocking AI-client classifier.

## Disclosure and security.txt

Follow the [repository disclosure policy](DISCLOSURE-POLICY.md) and [SECURITY.md](../SECURITY.md). Source review and isolated tests are welcome. This repository does not grant permission to scan amqic.ai, a maintainer's systems, third-party services or applications that adopt the kit.

The reference's security.txt generator creates a conservative [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html) profile with a contact URI, future expiry, canonical HTTPS location and policy link. It generates content only; it does not publish it or grant testing permission. Generate fresh deployment content with the actual contact/policy and review the result before serving it as UTF-8 text/plain at `/.well-known/security.txt` over HTTPS. Monitor expiry and arrange renewal before it expires. Authenticate the file and site through the chosen delivery/signing channel; a checksum alone does not establish the publisher.

**The current Nginx template denies dot paths, including `/.well-known/security.txt`.** To publish the generated file on a selected deployment, add a narrow reviewed exception to the protected-URI guard and an exact GET/HEAD route for this one file. A location block alone does not override the earlier guard. Keep all other hidden paths denied. Test exact content, HTTPS/Host/SNI, allowed methods, content type, expiry and continued rejection of sibling, encoded and traversal paths. This deployment exception is not installed by this update; the default origin remains deny-by-default.

## Response playbook

1. Confirm the affected asset and whether a testing engagement exists. Preserve minimal request/identity references and the current policy revision.
2. Check authorization, route exposure, limits and canary/identity/egress correlations. Separate a failed probe from evidence of access or a completed business effect.
3. Apply approved scoped containment at the edge/application/identity layer. Protect legitimate service access, keep recovery access available and preserve evidence without delaying urgent containment.
4. For suspected credential compromise, revoke at the issuer, rotate affected material and inspect app credentials, grants, owners and publishing access. A local block does not revoke an upstream token.
5. Reproduce defects only in an isolated authorized environment. Fix the root cause; a WAF rule may provide temporary mitigation but is not proof of closure.
6. Verify the fix with a regression test, restore service under reviewed limits and record the completion evidence. Reconcile unknown effects before retries.

For incoming reports, assess evidence and impact rather than prose style or suspected AI authorship. Ask for the affected commit/asset, prerequisites and a minimal safe reproduction. Do not auto-run reporter attachments. Accept a credible partial report for assessment when demonstrating full impact would require unauthorized access or disclosure. Use the existing response targets and coordinate sensitive disclosure privately.

## Primary guidance and standards

The [FBI FLASH-20261113-001](https://www.ic3.gov/CSA/2026/261113.pdf), dated 13 November 2026, describes abuse of an agentic penetration-testing framework and recommends inventory, management-plane restrictions, identity monitoring, limits on high-impact APIs, error hygiene and evidence preservation. It does not establish that all agent frameworks or security researchers are malicious. This guide uses the defensive recommendations; no offensive framework was installed or executed to validate them.

Use [indicator handling](INDICATOR-HANDLING.md) for dated provenance, a private operator store and mandatory expiry or withdrawal. Do not commit FLASH/feed values or infer attribution from a match. For a federated or cloud IdP, follow [identity monitoring](IDENTITY-MONITORING.md); a local block cannot revoke a token at its issuer.

| Area | Official reference | Evidence boundary |
| --- | --- | --- |
| Business limits and automation | [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) 2.1.3, 2.3.2, 2.4.1; [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | Synthetic multi-dimension admission tests; target load, fairness, distributed failover and business authorization remain separate |
| Exposure and errors | ASVS 5.0.0 13.4.1, 13.4.2, 13.4.5, 16.5.1 | Reviewed deployment inventory and generic-response tests; actual exposed routes and deployed responses require target checks |
| Monitoring and containment | [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) AC-7, SC-5, SI-4, AU-3, AU-9, IR-4 | Inert canary metadata tests and operating procedure; collector delivery, alert effectiveness and response drills require deployment evidence |
| Disclosure contact | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html); [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585.html) section 4 | Conservative generated-content tests and meaningful 429 responses; no public security.txt route or testing authorization is created |

Mappings identify selected relationships, not certification or complete coverage. Tool fingerprints, current campaign indicators and product defaults change; use verified current context when investigating an incident.

## Multi-source and delayed campaigns

A campaign can map several assets quietly, then return later from different sources. Correlate approved asset/route classes, time windows, opaque source/session/principal references and confirmed outcomes across days. Preserve timestamps and policy revisions; an individual source limit or short alert window alone will miss cross-source sequences. Compare mapping breadth with subsequent focused requests, authenticated record access and unusual account changes.

Tag an authorized engagement only through an operator-owned registry with scope, expiry and contact. A client-provided testing header is enrichment until verified, and never bypasses authentication, quotas or data isolation. Distinguish authorized testing, monitoring mistakes and unauthorized activity; do not infer malice from cadence, a framework name or a single canary.

Protect pseudonymous linkage keys and retention, deduplicate alerts and have a human review the evidence before consequential blocks. Record what reached origin and what was denied or actually completed. The [behavior starting specification and offline evaluator](AGENTIC-ATTACK-DETECTION.md) now provide bounded synthetic callback, rotating-source and protected-path examples. This playbook still does not install a multi-day collector or establish measured detection effectiveness; the existing `campaign-note` action records a review.

## Bounded correlation starting rules

For a callback review, compare an inbound source reference with an outbound destination reference on the same asset and within an operator-approved window. Both collectors must use the same protected pseudonymization key and epoch; incompatible keys, missing clocks or unrelated assets cannot establish a match. Exclude registered two-way integrations. An outbound attempt after an inbound probe is a lead, not proof that code executed.

For rotating sources, baseline distinct-source count and route-class breadth per asset, role and hour of week. Public crawler fleets, CDN health checks and a fleet touching one approved health route are near matches. Header/TLS/timing classes may enrich private review; they do not identify a person or malicious actor. The [offline examples](../enterprise/detection/README.md) consume operator-classified synthetic records and do not fingerprint visitors or query an edge provider.

Protected-path monitoring distinguishes the background denial floor from an unusual clustered burst. Any protected-path request that was not denied requires high-priority configuration review; link subsequent authenticated activity through trusted opaque references. Preserve the aggregate [THREAT-DATA](../THREAT-DATA.md) without adding raw sources. Correlations use `campaign` / `campaign-note`; configuration-integrity reviews use `runtime` / `config-integrity`, matching the existing exporter. Do not add raw routes, addresses, prompts or undeclared fields to SIEM.

## Short-window multi-stage review

Use the [multi-stage procedure](AGENTIC-ATTACK-DETECTION.md#multi-stage-bursts-and-persistence-follow-on)
alongside delayed/multi-source review. Preserve signal diversity, observed
outcomes, trusted temporal order and private asset/identity linkage. A shared
network address or denied request pair cannot prove that access occurred. Missing
sources or incomparable key epochs leave correlation incomplete.

Engagement registration requires a separate owner/reviewer, exact action,
asset/account/target scope, approval time and expiry. The monitored tool cannot
register or extend its own exception. An approved exercise is a documented
near match only for its actual scope and time; exceptions never disable tenant
isolation, independent grants or investigation of an unexpected integrity
change. Store the rationale privately and preserve coarse review records.

Correlate new service/task/identity creation only with independently supported
preceding signals. Confirm authorized maintenance and actual effects before
containment. These additions supply a playbook; they add no new executable
campaign detector or telemetry collector.

## Operation-level budgets and selective responses

Follow the [countermeasure guide](AGENTIC-OFFENSE-DEGRADATION.md) for the twelve
limiter boundaries and manual match/near-match cases. Bind budgets to trusted
tenant/account and canonical operation IDs, not raw URI spelling, client-minted
cookies, changing browser strings or arbitrary request fields. Supported method,
representation and version aliases share the appropriate operation budget;
unsupported variants remain rejected and never gain authorization by sharing a key.

Use the observed socket peer as provenance. Only reviewed immediate proxies may
supply a verified chain; walk from the trusted application side to the first
non-trusted boundary. That address need not identify the initiating user. Keep
edge/global peer capacity distinct from authenticated per-client budgets so a
shared proxy or carrier does not become one victim-wide lockout.

Reject invalid/ambiguous request encodings under one reviewed parser contract;
do not strip controls, repeatedly decode, lowercase every path or silently merge
different handlers. Resolve account IDs using issuer-defined identity rules.
Provider-specific mailbox delivery equivalence may support a separate abuse
budget only when verified; it never merges account ownership or authorization.

Require shared atomic reservation/update/expiry/reset and reviewed failover
continuity for global limits. A single local counter per replica cannot enforce
the global cap. Keep aggregate abuse windows and request-pressure budgets
separate from an account's narrowly scoped full-authentication success reset.
Duplicate transport requests can still count against pressure limits even when
idempotency forbids repeating their business effect. Lost effect replies need
reconciliation of the original operation, not fresh identity/window resets.

If required protection is unavailable, hold that sensitive/costly operation or
use an explicitly reviewed bounded fallback; do not multiply a global allowance
through uncoordinated per-instance fallback. Preserve truthful quota and outage
responses. No new distributed limiter, normalizer or challenge provider is
implemented by this documentation increment.

Selective delay needs global connection/queue/time/memory limits and cheap
load shedding before the application is saturated. Fast refusal is the safe
starting point. Keep real authorization, meaningful statuses, cache validators,
CSP, cookie/token rules and idempotency stable. Any response variation belongs
only on isolated inert decoys after review; no prompt-based retaliation or
off-estate action is supplied.

## External reconnaissance and fleet context

Use [external reconnaissance guidance](EXTERNAL-RECON-DEGRADATION.md) to connect low-rate distributed breadth with an authorized-scanner inventory, actual edge/origin dispositions and coverage gaps. IP, ASN, client fingerprints and canary contact are leads; approved crawlers and shared networks need near-match handling. This procedure does not add an identity resolver, new detector family or automatic shared-network ban.
