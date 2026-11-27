# Complete toolkit capability catalog

## TL;DR

AMQIC Base Cybersecurity for Development is a reusable security toolkit: executable reference components, infrastructure candidates, verification tools, operating guidance and task-specific AI skills. Select the components that fit your application and integrate their trusted adapters. It is not a preconfigured production service, a universal attack blocker or a certification.

This catalog covers the whole kit, including the unreleased v1.9.3 documentation additions. The traceability appendix includes every entry in [the claim registry](verification/claims.json), with its declared kind, source, check and adoption limit. A listed check identifies how to obtain evidence; it is not a claim that a new run passed or that a control is active on your infrastructure.

## Where it helps

Use the kit to establish explicit authorization, data, network, resource and release boundaries in a web application, API, MCP integration or containerized service. Developers can learn from the synthetic examples; integrators can adapt the components; operators can follow the deployment and response procedures. Start with [Security basics](docs/SECURITY-BASICS.md) when a mechanism is unfamiliar, then read its implementation contract.

Navigate by the boundary you need:

- [Identity, sessions and operations](#identity-sessions-and-sensitive-operations)
- [Application input, data and outbound access](#application-input-data-and-outbound-access)
- [Admission, uploads and resource abuse](#admission-uploads-and-resource-abuse)
- [Origin, network and container protection](#origin-network-and-container-protection)
- [Secrets, backups and recovery](#secrets-backups-and-recovery)
- [Enterprise integration and evidence](#enterprise-integration-and-evidence)
- [Agents, monitoring and defensive operations](#agents-monitoring-and-defensive-operations)
- [Development, packaging and release](#development-packaging-and-release)
- [Verification and AI skills](#verification-and-ai-skills)
- [Claim-by-claim traceability](#claim-by-claim-traceability)

## Read capability status correctly

| Registry kind | What the kit supplies | What adoption still requires |
| --- | --- | --- |
| `executable` | Code with a defined interface and the associated local/synthetic checks or laboratory consumer. | Correct application wiring, trusted inputs, real provider configuration and target verification. A local reference may deliberately support only one store, protocol or topology. |
| `configuration` | A template, generator, rollout profile or static configuration contract. Some have isolated runtime tests; others have static checks only. | Review the generated candidate, verify actual platform behavior, obtain target authority, apply it and confirm effective state. Generation is not activation. |
| `guidance` | Source-reviewed procedures, design constraints, checklists and manual review examples. | An operator, collectors and enforcement integrations where needed; the guide alone implements no runtime control. |

Consult [validation](docs/VALIDATION.md), [the validation matrix](docs/VALIDATION-MATRIX.md) and the scenario's actual result for finer scope. The label `executable` does not turn a synthetic adapter into a real IdP or KMS. `source_reviewed`, `not_run`, `external_not_run`, unavailable prerequisites and failed checks are distinct from a successful executed assertion.

Optional third-party resources are organized in [Recommendations](RECOMMENDATIONS.md). They are not toolkit implementations, bundled dependencies or laboratory passes. The catalog below describes kit-owned components and documented integration boundaries.

## Identity, sessions and sensitive operations

The [authorization core](reference/README.md) enforces a server-side login sequence: identity, password, CAPTCHA, TOTP and session. It uses scrypt password hashing and random ticket/session material stored as verifiers. Each stage has single-use tickets, expiration and attempt controls. A client cannot skip a stage by changing its UI. The bundled enrollment, CAPTCHA and factor fixtures are synthetic; production enrollment, protected factor storage, recovery and transport belong to the adopting application.

The [headless login controller](reference/login-client.mjs) lets a frontend drive that sequence without a framework dependency. It handles duplicate submissions, cancellation, stale responses and transport failures. It does not make the browser an authorization authority or supply a finished login page.

Machine requests use an Ed25519-signed envelope bound to the audience, method/path, timestamp, nonce and exact serialized body. Keys have scoped registration/revocation, and authorization checks current user/key state. The custom machine API is separate from SSH keys, TLS identity and human factors. It is not a complete HTTP OAuth or MCP authorization server.

For sensitive actions, fresh TOTP confirmation creates a short-lived single-use grant bound to the session, exact action, argument digest and logical operation. The SQLite reference consumes that grant, performs its local data change and records the result in one transaction. A retry with a new request nonce and the same authorized operation returns the stored result. Changed arguments cannot reuse the operation identity.

Replay protection and idempotency serve different purposes. Replay admission rejects reused signed-request nonces; idempotency prevents a permitted business retry from creating a second effect. The reference's synchronous handlers may modify only its own SQLite database. Network calls, other databases and external business effects require a separately designed durable outbox/job and unknown-outcome reconciliation.

The fixed tool catalog exposes only trusted, predefined operations with argument validation, scopes and per-object authorization. It contains no arbitrary shell or SQL executor. HTTP middleware, MCP protocol negotiation, transport authentication and production tool adapters remain integration work.

The [recovery-token reference](enterprise/recovery/README.md) adds purpose/account/tenant/epoch binding, random one-use tokens, expiry, attempt controls and atomic consumption. Local token state is implemented; protected delivery, identity proof, password/factor mutation and revocation at an external issuer are separate responsibilities.

The [billing eligibility reference](reference/README.md#subscription-offer-eligibility) verifies server-supplied purchase/account bindings, allowed products/offers, active non-test state, expiry and campaign eligibility. A shared SQLite ledger limits initial grants and makes retries retain the original result. Provider API verification, refunds, renewals, revocations and external entitlement fulfillment require the application's billing integration.

## Application input, data and outbound access

[Web input protection](docs/WEB-INPUT-PROTECTION.md) supplies one bounded contact-form schema, Unicode/input checks and fixed parameterized SQLite insertion. Its browser consumer renders submitted text as text. The profile does not validate every human name or sanitize arbitrary HTML; use a schema suited to the actual form and preserve explicit unsupported-input behavior.

HTTP adapters must separately limit request/decompression bytes, parsing depth/time and concurrency, reject ambiguous input, enforce authentication/authorization and protect cookie-authenticated state changes. SQL parameters keep accepted values separate from statement structure. Neither field validation nor a container repairs a dynamically constructed query or shell command.

[Database security](docs/DATABASE-SECURITY.md) and the [PostgreSQL example](infra/database/README.md) demonstrate tenant-bound database principals, row-level `USING`/`WITH CHECK` policies, column grants and restricted object creation. Authorization must hold under the actual service role and pool configuration. A tenant value in a request or a client-modifiable database setting cannot become trusted tenant identity.

Shared replay state includes atomic nonce admission and consistent expiry/clock handling. SQLite tests cover separate connections sharing a local file; PostgreSQL tests cover an isolated shared primary. A working primary fixture does not establish replication/failover safety, restore behavior or exactly-once external effects.

[Field-envelope encryption](reference/field-encryption.README.md) implements AES-256-GCM with authenticated tenant, record, field and version binding. Row/field authorization precedes KMS unwrap. Ciphertext metadata and tenant key selection are checked; plaintext and data-encryption keys must remain inside protected consumers.

[Cloud KMS adapters](enterprise/cloud-kms/README.md) provide explicit AWS, Google Cloud and Azure SDK ports for the envelope contract. The application supplies reviewed SDK clients and workload identity, with resource-scoped permissions and key policy. Synthetic SDK tests establish adapter behavior; they do not prove a live cloud account's IAM grants, key availability, rotation or old-envelope recovery.

[Outbound and return boundaries](docs/APPLICATION-BOUNDARIES.md) provide a deliberately narrow real HTTPS GET transport selected by server-owned endpoint IDs. It checks the complete DNS answer set, pins the accepted address, retains TLS hostname verification and bounds time/response bytes. Its profile excludes arbitrary caller URLs, redirects, ambient credentials, proxies and unsupported address families.

The same area supplies fixed local return-route IDs instead of caller-selected redirect destinations. Returned HTTPS content remains untrusted data. Synthetic transport tests do not establish live remote TLS behavior or OS-level egress enforcement.

[Database-engine patching](docs/DATABASE-ENGINE-PATCHING.md) separates application query safety, database privileges and native engine vulnerabilities. The laboratory checks the actual isolated PostgreSQL version and effective privilege restrictions. Vendor-specific branches, native extension rebuild provenance and deployment-specific settings retain their stated verification gaps.

## Admission, uploads and resource abuse

[Request admission](lab/admission.README.md) includes optional bound proof-of-work, a persistent replay store and a fixed Redis atomic counter. These are API components, not automatically installed HTTP middleware or a standardized proof protocol. Redis ACL/TLS, durability, memory bounds and production failure policy need explicit configuration.

[Service protection](docs/SERVICE-PROTECTION.md) connects byte/time limits, expensive-operation concurrency, rate budgets, challenge policy and upstream protection. Admission limits resource use; it does not authenticate an actor, authorize an object or make challenge input trustworthy.

The [probe-defense reference](enterprise/probe-defense/README.md) atomically admits requests across configured same-host source/account/session/tenant/route dimensions. Trusted server code selects route and identity; each request has a fixed unit cost. It supplies generic meaningful denials, an inert canary event and conservative security.txt content generation. It neither opens a disclosure route nor installs a distributed gate or visitor classifier. More general operation-cost budgets are design guidance outside this reference's contract.

[Distributed admission](enterprise/distributed/README.md) adds Redis/PostgreSQL adapters and contracts for tenant quotas, concurrency, replay and authoritative time/state. Isolated integration checks exercise the documented local topology. Primary fencing, failover, state-loss handling and recovery must be verified against the actual service topology.

The [upload pipeline](docs/UPLOAD-ISOLATION.md) separates intake, quarantine, scanning, verdict and promotion. The executable reference speaks the real ClamAV protocol and uses bounded content handling with explicit rejected/error states. The laboratory uses harmless synthetic content/signatures. A clean malware verdict is neither authorization nor proof that content is safe for every downstream parser.

The upload Compose candidate separates role-specific mounts and identities for intake/scanner/promoter/media. Its role contract and isolated fixtures are distinct from a complete production split-service implementation. Configure private scanner access, update policy, file limits, failure handling and non-executable approved storage for the actual deployment.

## Origin, network and container protection

[Initial deployment](docs/INITIAL-DEPLOYMENT.md) and [infrastructure](docs/INFRASTRUCTURE.md) connect restricted origin exposure, HTTPS, explicit routes/methods, closed management ports and a recovery path. Firewall renderers produce candidates; SSH key authentication remains sshd's responsibility. Neither renderer mutates a real host automatically.

The Nginx candidate includes TLS and Host/SNI checks, protected-path/source-map denial before static dispatch, distinct website/API rate policy, meaningful 429 responses and CSP on normal/error paths. Preserve stricter upstream browser policy. Use [edge response guidance](docs/NGINX-EDGE-SECURITY.md) for patched protocol defaults and exact binary/master/worker replacement evidence.

Source allowlisting distinguishes the actual socket peer from an end-client address restored through explicitly trusted proxies. Validate the configured chain and stop at its first untrusted boundary; arbitrary client assertions cannot grant access. A correct generated policy is not proof of live CDN, physical IPv6 or ingress behavior.

[VPN guidance](docs/VPN-TUNNELS.md) covers private administrative access, source-address verification and coordinated tunnel/host-firewall policy. The infrastructure laboratory exercises its own isolated tunnel endpoints and namespaces. It does not configure a personal VPN, alter a live routing table or prove a provider account's access policy.

[Cloud edge guidance](docs/CLOUDFLARE-EDGE.md) explains CDN/proxy exposure, restricted origins, WAF/rate limits, safe caching and DDoS responsibility. Cache public static content deliberately; preserve authenticated/sensitive response boundaries. These are source-reviewed deployment recipes, not an activated Cloudflare integration or an assurance against every denial-of-service event.

Container candidates use a minimal runtime, non-root identity, read-only code filesystem, dropped capabilities, no-new-privileges, controlled temporary writes, network restrictions and resource limits. A container still executes its application and can access its own memory. The [security model](docs/SECURITY-MODEL.md) describes when a separately verified sandbox/VM and secret isolation are needed.

[Dependency quarantine](docs/OPERATIONS.md) separates acquisition from bounded offline archive inspection. Inventory checks reject unsupported/unsafe members without executing package code or installation hooks. Content review, origin authentication and approval of exact bytes remain separate steps; package text cannot authorize itself.

## Secrets, backups and recovery

[Operations](docs/OPERATIONS.md) and [protected input](skills/protected-terminal-input/SKILL.md) keep new secret entry in the human's own hidden-input terminal and connect only a pre-reviewed fixed consumer. Agents work with metadata; values must not enter chat, arguments, environment, reports or source. Same-user hidden input alone does not isolate secrets from a fully privileged process.

[Encrypted backups](skills/verified-backup/SKILL.md) select explicit files, build a manifest, verify hashes, encrypt with AES-256-GCM and verify restoration. Preserve source originals and independent recovery-key custody. A running database needs its native consistent dump/snapshot first; copying active database files is not a backup consistency mechanism.

[KeePassXC guidance](docs/KEEPASSXC.md) covers KDBX storage, separate factors and recovery. The infrastructure fixture creates its own synthetic vault and checks correct/incorrect password behavior. It reads no real user vault and supplies no password-recovery service.

[Enterprise rotation](enterprise/rotation/README.md) stages a candidate credential binding, probes it through a protected adapter and conditionally promotes the correct revision. It covers short-lived leases and KMS writer rotation, retaining scope, expiry, reconciliation and old-key-read requirements. Actual provider effects and secrets remain with the workload identity/consumer; synthetic stores do not establish real revocation or availability.

## Enterprise integration and evidence

[Policy and tenant quotas](enterprise/policy/README.md) compile an exact allow policy for service routes, methods, resource kinds, classifications and roles. Missing rules deny. Trusted adapters authenticate membership, load authoritative ownership and assess risk. The gate checks tenant scope and configured quotas; it cannot trust tenant/role fields supplied by a caller or enforce storage outside its integration boundary.

[Federation](enterprise/federation/README.md) supplies tenant/provider-scoped OIDC and SAML adapter contracts, one-use login state, fixed callbacks, explicit external-group role maps and optional policy-controlled just-in-time provisioning. Use stable issuer/subject identities and separate provider registration. Reviewed protocol SDKs and actual IdP keys/assertions/configuration belong to the adopting application; matching email addresses must not merge accounts.

[Audit and evidence](enterprise/evidence/README.md) bind verification reports to source hashes and generate compact JSON/Markdown projections. Audit records use canonical bytes, sequence/hash continuity and independently held checkpoints. Signature verification authenticates exact reviewed bytes under a trusted key; it does not prove an omitted test ran or authenticate a key distributed only with the bundle.

[Supply-chain tools](enterprise/supply/README.md) check a release's checksum registry, build deterministic staged-payload inventories, verify detached inventory signatures and generate a CycloneDX inventory from declared components/lockfile data. Exact paths, sizes, source commit assertions and policy digests are bound. This does not independently attest an isolated builder, complete dependency coverage or an assurance level.

[SIEM export](enterprise/operations/README.md) validates bounded contiguous audit segments against protected stream/checkpoint bindings and expected input tags, then emits privacy-conscious NDJSON plus a receipt. Stable event identity supports deduplication and reconciliation. Actual authenticated delivery, durable acknowledgement, retention, alerting and response drills remain operational integrations.

[Runtime controls](enterprise/runtime/README.md) compare rollout records with actual JVM/proxy instance inventories, artifact digests and replacement evidence. Templates and starting profiles cover deployment/runtime configuration. Real Helm/OpenTofu rendering, platform syntax, running process identity and kernel/sensor behavior need target checks.

[Policy property tests](enterprise/policy/policy-properties.test.mjs) exercise normalized policy permutations, generated invalid input and bounded concurrency/invariants. Other suites test replay, expiration, error and privacy boundaries. These are local correctness checks, not production throughput, latency or resistance to all attacks.

## Agents, monitoring and defensive operations

[Agent runtime protection](docs/AI-AGENT-RUNTIME.md) and the [reference guard](enterprise/agent-runtime/README.md) constrain fixed tools/arguments, exact approval scope, policy narrowing, local call/lifetime budgets and generation revocation. Egress planning is conservative and offline. Independent OS containment, real network enforcement, secret brokers, external stop and distributed replay require actual deployment controls.

[Runtime integrity](docs/AGENT-RUNTIME-INTEGRITY.md) covers installed-file baselines, plugin/skill/MCP admission and effective permissions held outside an agent's control. Production preparation and protected-path rules exclude private agent state. A package hash alone does not prove installed bytes or enforce permissions; documented review ownership does not activate a hosting-provider rule.

[Static configuration review](docs/AGENT-CONFIG-REVIEW.md) implements ten bounded risk classes: disabled approval, unrestricted shell pre-approval, remote acquisition/execution, instruction-authority manipulation, instruction Unicode anomalies, credential access, unpinned MCP launchers, plaintext MCP secrets, unencrypted remote MCP and agent state in artifacts. It consumes known normalized profiles with separately trusted scoped expiring exceptions. Unsupported or incomplete collection is not a clean result; heuristics do not prove semantic prompt safety or activate admission.

[Client secret review](docs/CLIENT-SECRET-EXPOSURE.md) checks explicit source/build snapshots for risky public variables, environment examples and known credential patterns, with redacted findings and production-staging integration. It does not test credential validity, scan the whole Git history, trace every data flow or certify a bundle free of secrets.

[Behavior detection](docs/AGENTIC-ATTACK-DETECTION.md) supplies an offline evaluator for eight families:

1. An agent ancestor starts a classified security utility.
2. An unentitled server calls a model API.
3. A server uses a privately classified interaction-capture destination.
4. A credential has unusual cloud action/service velocity and breadth.
5. A host/service starts a classified child process or has the separate file companion.
6. A probe precedes a matching outbound callback in the reviewed scope/window.
7. Rotating low-volume sources sweep route classes under a trusted cluster binding.
8. Protected-path denials rise above baseline, or a protected request is unexpectedly not denied.

These families use trusted private classifications, bounded windows, expiry, opaque references and exact synthetic match/near-match expectations. They do not install collectors, fingerprint every visitor, attribute an actor, prove an intrusion or automatically ban a source. Linux/Falco and Windows starting profiles are static templates/specifications; indirect ancestry, dropped events, actual platform support and deployed catch rates remain target work.

[SSH key integrity](docs/SSH-KEY-INTEGRITY.md) supplies inventory/watch procedures and a static audit template. [Host egress](docs/HOST-EGRESS-MONITORING.md) describes workload-specific destinations, DNS/connection evidence and network enforcement ownership. [Indicator handling](docs/INDICATOR-HANDLING.md) supplies provenance, confidence, private custody, expiry and withdrawal procedures. These do not ship a live feed, audit daemon, packet collector or automatic block list.

[Identity monitoring](docs/IDENTITY-MONITORING.md) covers issuer-side credentials, consent/grants and privilege changes. [Directory monitoring](docs/DIRECTORY-IDENTITY-MONITORING.md) covers directory/Kerberos/certificate evidence and audit prerequisites. [C2 monitoring](docs/COMMAND-AND-CONTROL-MONITORING.md) covers workload-aware callback/channel review. They supply manual operational guidance, not provider connectors, domain hardening or additional executable detector families.

The [multi-stage procedure](docs/AGENTIC-ATTACK-DETECTION.md#multi-stage-bursts-and-persistence-follow-on) joins independent signal classes only with trusted scope, comparable clocks and protected linkage. Manual high-risk capability admission and untrusted tool-output composition requirements keep policy/approval separate from external text. These additions do not extend the evaluator's eight families or configuration review's ten rules.

[Agentic probing countermeasures](docs/AGENTIC-OFFENSE-DEGRADATION.md) describe twelve limiter boundaries, stable legitimate semantics, shared atomic budgets, bounded optional delay/load shedding, monitored inert decoys and root remediation. Managed-workstation correlation needs independent local evidence. Deception/callback denial does not prove a vulnerability closed; the guide adds no limiter, tarpit, deception service or measured effectiveness.

[Disclosure handling](docs/DISCLOSURE-POLICY.md) connects incoming reports, independently scoped engagements and meaningful evidence. [Aggregate threat data](THREAT-DATA.md) records its stated aggregate observations without publishing private source identities. No guide grants permission to probe public systems, run offensive frameworks, hack back or act against a suspected operator.

## Development, packaging and release

[Version checking](docs/VERSIONS.md) inventories supported Node/Python/npm/PyPI inputs and compares official metadata or verified dated snapshots without automatic upgrades. Preserve observed versus declared versions and unsupported formats. A current version does not establish vulnerability clearance, and an application dependency listing does not identify the runtime actually serving traffic.

The repository includes pinned workflow references and dependency-update configuration. CI can validate policy, run laboratory checks, export control evidence and retain isolated distributed-admission results. A configured workflow or an update proposal is not evidence of a completed hosted run; review its actual run and exact artifacts.

[Analyst tooling guidance](docs/ANALYST-TOOLING-SECURITY.md) covers version/runtime inventory, isolated APK/XAPK/JAR review, plugin integrity and untrusted exported build projects. It is source-reviewed operating guidance for an existing analysis workflow; it installs or executes no external analysis tool. Runtime patching and dependency admission remain separate checks.

[Production preparation](docs/PRODUCTION.md) stages a new explicit allowlisted UTF-8 source payload and a separate manifest. It rejects unsafe paths/links, private operational state and detected credential literals while preserving the source tree. Git ignore state cannot override protected exclusions; tracked private files remain excluded. This is bounded staging, not arbitrary binary analysis or proof that no secret exists.

[Binary guidance](docs/BINARY-OBFUSCATION.md) covers symbol separation, runtime-contract checks, private diagnostics and application-specific obfuscation/shrinking choices. The isolated ELF fixture has its own evidence scope. Do not treat symbols removed, strings changed or one local fixture as confidentiality for embedded credentials or coverage of every language/runtime.

[Deployment](docs/DEPLOYMENT.md) and [initial rollout](docs/INITIAL-DEPLOYMENT.md) require exact reviewed candidates, backups/recovery, target authority and effective-state confirmation. Local generation/build/staging are separate from deployment. Release instructions do not silently activate firewalls, cloud settings, new access or destructive actions.

[Release verification](docs/RELEASE-VERIFICATION.md) binds exact files to SHA-256 registry entries and a separately authenticated maintainer signature. [GitHub release guidance](docs/GITHUB-RELEASES.md) separates source state, artifact inventory, final-byte verification and publication. Hashes identify bytes; the trusted signing channel identifies the publisher. Evidence-signature examples and the maintainer's public release-signing process have separate contracts.

Per-file VirusTotal observations retain the exact scanned digest, date and available result/coverage. Generated metadata, absent results and incomplete observations remain explicit. Such a result is neither a signature nor a guarantee against malware, vulnerabilities or malicious future behavior. Never upload private inputs merely because a release procedure mentions scanning.

## Verification and AI skills

The fixed verifier supports a baseline, the interactive HTTP/browser consumer, selected full checks and the all-local controller. Start with its side-effect-free plan:

```sh
node scripts/verify.mjs --plan
```

The [all-local guide](docs/ALL-LAB.md) defines seven stages: baseline, live consumers, Nginx runtime, infrastructure runtime, cache runtime, upload-role isolation and database runtime. The [scenario catalog](lab/scenarios.json) connects each mechanism to required assertions, prerequisites, scope and external/manual work. The fixed controller chooses known commands; the catalog is not an arbitrary command-execution input.

The laboratory can use real local HTTP/browser, ClamAV, Redis, PostgreSQL, Nginx and isolated infrastructure consumers with synthetic data. It also exercises a synthetic password-manager database, local tunnel/namespace contracts and binary symbol separation. It does not access personal vaults, production credentials or real cloud/VPN accounts.

Reports bind actual source hashes, versions, assertions, failures and resource cleanup to the recorded run. The [protocol schema](lab/protocol.schema.json), [verification guide](docs/VERIFICATION.md), [coverage inventory](verification/coverage.json) and claim registry make evidence discoverable. Preserve child-report bindings and exact source stability; an old report does not cover newly edited bytes.

Before running, review [host requirements](lab/host-requirements.md). Use a new external report path and independently authorize prerequisite preparation when needed. Missing kernel features or unsupported hosts leave the affected scenario incomplete; they do not justify weakening the host to manufacture a pass.

### Small adoption examples

From the kit root, this [core demo](reference/README.md#local-execution) uses only temporary in-memory state, a synthetic identity/key and a synthetic record; it starts no network server:

```sh
node --experimental-sqlite reference/demo.mjs
```

Validate the shipped example policy without applying it to a service:

```sh
node enterprise/policy/policy-cli.mjs --check enterprise/policy/example-policy.json
```

After plan/prerequisite review, the [all-local workflow](docs/ALL-LAB.md) runs its fixed local laboratory with a new external output path. Do not substitute a real public target or production database. To adopt one component, follow its guide, replace only its trusted synthetic adapters and add checks for your application's permitted and forbidden operations.

### Eight task-specific AI skills

These are bounded instructions for an assistant operating under actual user/host authority. They do not install an agent, grant access, replace review or authorize a secret/external effect.

| Skill | Supported workflow | Boundary |
| --- | --- | --- |
| [Check versions](skills/check-versions/SKILL.md) | Inventory and compare supported versions before release. | No automatic package installation/update; observed/declared inputs remain distinct. |
| [Obfuscate binaries](skills/obfuscate-binaries/SKILL.md) | Plan symbol separation/obfuscation and verify final artifacts and runtime contracts. | Exact authorized application/runtime only; signing and deployment retain their own authority. |
| [Prepare production](skills/prepare-production/SKILL.md) | Stage a clean explicit payload and verify exclusions/content. | Preserve source originals; a scanner is not proof of no secrets. |
| [Protected terminal input](skills/protected-terminal-input/SKILL.md) | Prepare metadata and a fixed consumer for human-only secret entry. | The assistant never supplies or reads secret payloads. |
| [Review dependencies](skills/review-dependencies/SKILL.md) | Review quarantined dependency/agent-extension inventory and exact bytes. | Untrusted package text is data; review is not execution permission. |
| [Case-guided review](skills/review-with-sandhive/SKILL.md) | Use optional external investigation cases as context for a scoped review. | No bundled corpus, launcher or automatic fetch/execution; it is not implemented detection coverage. |
| [Run security lab](skills/run-security-lab/SKILL.md) | Inspect the fixed plan, run authorized local checks and interpret typed outcomes. | No substitution of a live target or inference that external/manual items passed. |
| [Verified backup](skills/verified-backup/SKILL.md) | Select, encrypt, verify and restore explicit file snapshots. | Native database consistency and separately authorized destructive actions remain outside ordinary file backup. |

## Claim-by-claim traceability

The rows below reproduce the registry's declared kind, check identifiers and limitations for this candidate. The linked source is an entry point, not a claim that every file in its module ran. Follow [claims.json](verification/claims.json) for all associated files and [lab/scenarios.json](lab/scenarios.json) for scenario bindings. Empty fixed-runner check lists are shown explicitly with the relevant scenario instead of inventing a test.

This appendix is a traceability inventory, not a numeric security score. Several claims contribute to one feature and one feature may span several claims. Check IDs name verification routes; only a current trusted report establishes their observed outcome.

| Claim ID | Kind | Source entry | Check / scenario | Adoption and evidence limit |
| --- | --- | --- | --- | --- |
| `staged-authentication` | `executable` | [reference/core.mjs](reference/core.mjs) | node-tests | Synthetic enrollment and CAPTCHA only; production identity/factor storage is external. |
| `web-input-and-sql` | `executable` | [reference/pii-input.mjs](reference/pii-input.mjs) | node-tests, live-consumers | One contact-form profile; actual browser verifies plain-text rendering, not arbitrary downstream code. |
| `machine-signatures` | `executable` | [reference/crypto.mjs](reference/crypto.mjs) | node-tests, core-demo | Custom request envelope, not a complete HTTP/MCP OAuth implementation. |
| `sensitive-operations` | `executable` | [reference/core.mjs](reference/core.mjs) | node-tests, core-demo | Synthetic records; external effects require their own durable transaction/result handling. |
| `upload-and-clamd` | `executable` | [reference/upload-pipeline.mjs](reference/upload-pipeline.mjs) | node-tests, live-consumers | Real ClamAV with harmless custom signature; same-process storage API is not an OS sandbox or a durability guarantee. |
| `upload-role-isolation` | `configuration` | [infra/container/uploads.compose.yaml](infra/container/uploads.compose.yaml) | compose | Template role mount contract; actual prior synthetic role tests are documented separately, full production split services not supplied. |
| `pow-replay` | `executable` | [reference/admission.mjs](reference/admission.mjs) | node-tests | Optional API component, not automatically wired into HTTP; not a standardized HTTP proof protocol. |
| `redis-limiter` | `executable` | [reference/admission.mjs](reference/admission.mjs) | node-tests, live-consumers | Fixed atomic counter; live fixture uses public synthetic password, no production TLS/failover claim. |
| `encrypted-backups` | `executable` | [scripts/archive_crypto.mjs](scripts/archive_crypto.mjs) | node-tests, operations, terminal | Database consistency requires database-native snapshot/dump; terminal consumer requires Linux. |
| `source-preparation` | `executable` | [scripts/prepare_production.py](scripts/prepare_production.py) | production | Bounded UTF-8 file staging with independent private-artifact path exclusions even for tracked files; not arbitrary binary analysis or proof of no credentials. |
| `version-checking` | `executable` | [scripts/check_versions.py](scripts/check_versions.py) | versions | Version currency is not proof of vulnerability clearance. |
| `dependency-quarantine` | `executable` | [infra/container/quarantine.py](infra/container/quarantine.py) | quarantine, compose | Archive inspection without executing dependencies; AI/manual content review is separate. |
| `origin-configuration` | `configuration` | [infra/nginx/render.py](infra/nginx/render.py) | nginx-runtime, nginx-harness, firewall-render | Pre-location protected-path/source-map denial is tested with a permissive synthetic static owner; actual Nginx needs an explicit pinned image. No live Cloudflare/firewall/IPv6 routing configuration. |
| `container-configuration` | `configuration` | [infra/container/compose.yaml](infra/container/compose.yaml) | compose | Config normalization is not a complete escape-resistance assessment. |
| `vpn-and-cloudflare` | `guidance` | [docs/VPN-TUNNELS.md](docs/VPN-TUNNELS.md) | coverage-membership, sha256-registry | Source-reviewed recipes; no user VPN or Cloudflare account mutation or current-live protection claim. |
| `binary-obfuscation` | `guidance` | [docs/BINARY-OBFUSCATION.md](docs/BINARY-OBFUSCATION.md) | coverage-membership, sha256-registry | The local ELF/symbol-reduction fixture is tested in the infrastructure lab; application-specific Garble/R8/.NET transformations require separate integration. |
| `release-provenance` | `executable` | [scripts/verify.mjs](scripts/verify.mjs) | coverage-membership, sha256-registry, source-stability | Hashes and source stability only; maintainer signature is verified separately. |
| `password-manager-lab` | `executable` | [lab/infra-verify.mjs](lab/infra-verify.mjs) | No fixed-runner check ID; scenario: keepassxc | Synthetic KeePassXC CLI database only; no real user vault is read or changed. |
| `all-local-control` | `executable` | [lab/all-local.mjs](lab/all-local.mjs) | No fixed-runner check ID; all-local scenario bindings in catalog | Only required local scenarios can be accepted; external/provider/manual steps are listed separately and never inferred from local tests. |
| `database-row-and-column-isolation` | `executable` | [infra/database/schema.sql](infra/database/schema.sql) | database-runtime | Dedicated tenant DB principals with RLS and column grants in an isolated PostgreSQL primary. Application identity, pool configuration, TLS and production roles require separate integration. |
| `distributed-database-replay` | `executable` | [infra/database/schema.sql](infra/database/schema.sql) | database-runtime, node-tests | Atomic shared-primary nonce state and expiry/clock policy; SQLite fixtures cover shared same-host file. No production failover or exactly-once external-effect claim. |
| `field-envelope-encryption` | `executable` | [reference/field-encryption.mjs](reference/field-encryption.mjs) | node-tests | AES-256-GCM authenticated envelope with tenant/record/field/version binding and trusted KMS/authorization ports. Synthetic providers do not establish live KMS/IAM policy. |
| `billing-offer-eligibility` | `executable` | [reference/billing-offer.mjs](reference/billing-offer.mjs) | node-tests | Synthetic verified purchase adapter and shared SQLite claim ledger. Provider API, lifecycle, and live billing deployment require separate integration. |
| `enterprise-policy` | `executable` | [enterprise/policy/policy.test.mjs](enterprise/policy/policy.test.mjs) | node-tests | Same-host SQLite and synthetic trusted context. Service principal wiring, storage enforcement and distributed quotas require target checks. |
| `enterprise-evidence` | `executable` | [enterprise/evidence/evidence.test.mjs](enterprise/evidence/evidence.test.mjs) | node-tests | Synthetic audit and signing fixtures. Verify signer trust, collection periods and delivery against deployment records. |
| `enterprise-supply` | `executable` | [enterprise/supply/supply.test.mjs](enterprise/supply/supply.test.mjs) | node-tests | Synthetic artifacts and declared components. Assess package coverage, authenticated build provenance and trust anchors in the real pipeline. |
| `enterprise-secrets` | `executable` | [enterprise/rotation/rotation.test.mjs](enterprise/rotation/rotation.test.mjs) | node-tests | Synthetic provider stores. Exercise real workload identity, atomic promotion, lease revocation and retained key recovery before deployment. |
| `enterprise-runtime` | `executable` | [enterprise/runtime/runtime.test.mjs](enterprise/runtime/runtime.test.mjs) | node-tests | Static reference profiles and synthetic inventory records. Validate actual Helm/OpenTofu rendering, kernel behavior, Falco support and running JVM inventory for the target. |
| `distributed-admission` | `executable` | [enterprise/distributed/admission.test.mjs](enterprise/distributed/admission.test.mjs) | node-tests | Local fixtures and documented adapter guarantees. Verify actual primary fencing, recovery and durability in the deployment. |
| `cloud-kms-adapters` | `executable` | [enterprise/cloud-kms/cloud-kms.test.mjs](enterprise/cloud-kms/cloud-kms.test.mjs) | node-tests | Synthetic SDK clients. Live cloud access, IAM and key availability are deployment checks. |
| `identity-federation` | `executable` | [enterprise/federation/federation.test.mjs](enterprise/federation/federation.test.mjs) | node-tests | Synthetic responses and trusted verifier adapters. Verify actual IdP protocol and library configuration before deployment. |
| `siem-export` | `executable` | [enterprise/operations/siem.test.mjs](enterprise/operations/siem.test.mjs) | node-tests | Offline event checks and export. Validate delivery, retention, incident response and loss detection in the target environment. |
| `policy-properties` | `executable` | [enterprise/policy/policy-properties.test.mjs](enterprise/policy/policy-properties.test.mjs) | node-tests | Synthetic same-host fixture. Throughput, distributed quotas and service latency require separate performance evaluation. |
| `nginx-parser-response` | `executable` | [enterprise/runtime/nginx-rollout.mjs](enterprise/runtime/nginx-rollout.mjs) | node-tests, nginx-harness, nginx-runtime | Synthetic rollout snapshots and benign ALPN with pinned patched Nginx. Real vendor inventory, CDN protocols and old-worker drain require target verification. |
| `agent-runtime-boundary` | `executable` | [enterprise/agent-runtime/agent-runtime.mjs](enterprise/agent-runtime/agent-runtime.mjs) | node-tests | Synthetic trusted-adapter tests and offline IPv4-only egress planning. Kernel containment, real DNS/socket pinning, secret brokers, external stop and distributed replay require target verification. |
| `automated-probing-defense` | `executable` | [enterprise/probe-defense/probe-defense.mjs](enterprise/probe-defense/probe-defense.mjs) | node-tests | Synthetic same-host atomic budgets, generic denials, inert canary events and generated contact content. Multi-host state, real disclosure HTTP serving, SIEM delivery and deployment effectiveness require target checks. |
| `agent-config-exclusions` | `executable` | [scripts/prepare_production.py](scripts/prepare_production.py) | production, nginx-harness, nginx-runtime | Kit-owned exclusions and current path registry are executable checks. Optional third-party material, installed runtime FIM, effective host permissions and GitHub ruleset activation remain external/source-reviewed. |
| `database-engine-patching` | `executable` | [lab/database-verify.mjs](lab/database-verify.mjs) | database-runtime | Real isolated PostgreSQL 17 fixed-minimum and effective-privilege assertions; CVE-2026-6460 C-extension rebuild provenance and effective composite_type_mismatch=error are not verified by these fixtures. Other vendor products, branches and production patching require target verification. |
| `outbound-and-return-boundaries` | `executable` | [enterprise/outbound/outbound.mjs](enterprise/outbound/outbound.mjs) | node-tests | Synthetic trusted-resolver/transport tests of real HTTPS implementation plus local route-ID mapping. No real remote service probes, OS egress firewall or arbitrary URL fetch supported. |
| `recovery-token-lifecycle` | `executable` | [enterprise/recovery/recovery.mjs](enterprise/recovery/recovery.mjs) | node-tests | Real local SQLite one-use/epoch/concurrent-worker tests. Actual identity proof, protected delivery, business mutation, session revocation and multi-host continuity require application integration. |
| `ssh-key-integrity` | `configuration` | [docs/SSH-KEY-INTEGRITY.md](docs/SSH-KEY-INTEGRITY.md) | node-tests | Source-reviewed SSH inventory/watch procedure and static template checks only; no auditd/FIM execution, login trial, deployed detection or automatic lockout. Native records require protected storage and an explicit sanitized projection. |
| `service-child-shell-starting-rules` | `configuration` | [enterprise/runtime/profiles/node-shell.falco.yaml](enterprise/runtime/profiles/node-shell.falco.yaml) | node-tests | Source-reviewed direct-child container Falco starting rules with static field checks; no Falco or kernel execution claimed. Host daemons, indirect children, dropped events, legitimate maintenance and alert effectiveness require target verification. |
| `host-egress-monitoring` | `guidance` | [docs/HOST-EGRESS-MONITORING.md](docs/HOST-EGRESS-MONITORING.md) | coverage-membership, sha256-registry | Source-reviewed host/container policy and telemetry guidance only; no live egress enforcement, packet capture, deployed NSM or catch-rate claim. Application catalog checks are separate; IPv6, proxies and tunnels require target policy. |
| `indicator-handling` | `guidance` | [docs/INDICATOR-HANDLING.md](docs/INDICATOR-HANDLING.md) | coverage-membership, sha256-registry | Source-reviewed private-store provenance, expiry and withdrawal procedure only; no indicator feed, scraper, shipped values, automatic blocking or attribution. |
| `identity-plane-monitoring` | `guidance` | [docs/IDENTITY-MONITORING.md](docs/IDENTITY-MONITORING.md) | coverage-membership, sha256-registry | Source-reviewed procedure conditional on a federated/cloud IdP; no provider connector, live consent-catalog test, production monitoring or AD/Windows hardening. Revocation and rotation occur at the issuer. |
| `host-telemetry-siem-schema` | `executable` | [enterprise/operations/siem.schema.json](enterprise/operations/siem.schema.json) | node-tests | Offline synthetic export/schema and canonical v1 compatibility tests only. Operator-authored records are not event collection, campaign/process detection, provider connectors, alert delivery or deployed effectiveness. |
| `agentic-behavior-review` | `executable` | [enterprise/detection/detection.mjs](enterprise/detection/detection.mjs) | node-tests | Offline synthetic review of eight behavior families with private trusted classifications, explicit baselines, expiry and bounded opaque events. Match/near-match fixtures are not real-intrusion validation, attribution, automated blocking or deployed sensor coverage. |
| `behavior-starting-profiles` | `configuration` | [enterprise/runtime/profiles/agent-tool-spawn.falco.yaml.template](enterprise/runtime/profiles/agent-tool-spawn.falco.yaml.template) | node-tests | Source-reviewed agent/host templates and Windows starting specification, statically tested only. No Falco/kernel/Windows collector execution, verified deployment syntax, process-identity attestation or effectiveness claim. |
| `agent-config-static-review` | `executable` | [enterprise/config-review/config-review.mjs](enterprise/config-review/config-review.mjs) | node-tests | Known normalized-profile configuration and narrow instruction-text heuristics with separately trusted scoped exceptions, exact expected findings and incomplete states. No raw vendor configuration parser, semantic prompt-injection proof, effective-permission collector or admission activation. |
| `client-secret-exposure-review` | `executable` | [scripts/client_secret_review.py](scripts/client_secret_review.py) | production | Pattern-based explicit snapshot review and production-staging integration with redacted findings and synthetic public-variable/environment fixtures. No secret validity test, whole-Git-history scan, data-flow analysis or clean-bundle certification. Environment examples preserve LF/CRLF/CR line boundaries and subsequent public-secret detection; general JavaScript/JSON assignment review retains multiline support. |
| `directory-identity-review` | `guidance` | [docs/DIRECTORY-IDENTITY-MONITORING.md](docs/DIRECTORY-IDENTITY-MONITORING.md) | coverage-membership, sha256-registry | Source-reviewed directory/Kerberos/certificate audit prerequisites and manual review examples. No collector, domain hardening, live logs or detection-effectiveness test. |
| `c2-behavior-review` | `guidance` | [docs/COMMAND-AND-CONTROL-MONITORING.md](docs/COMMAND-AND-CONTROL-MONITORING.md) | coverage-membership, sha256-registry | Source-reviewed workload-aware callback/channel procedure and manual near matches. No packet parser, deployed sensor, new evaluator family or real-traffic detection test. |
| `multistage-agent-boundaries` | `guidance` | [docs/AGENTIC-ATTACK-DETECTION.md](docs/AGENTIC-ATTACK-DETECTION.md) | coverage-membership, sha256-registry | Source-reviewed correlation, scoped high-risk admission and model-input composition requirements. Existing eight-family/ten-rule/schema contracts unchanged; no new detector, serializer, sanitizer or enforcing gate is implemented. |
| `agentic-probing-countermeasures` | `guidance` | [docs/AGENTIC-OFFENSE-DEGRADATION.md](docs/AGENTIC-OFFENSE-DEGRADATION.md) | coverage-membership, sha256-registry | Source-reviewed operation-level limiter boundaries, bounded selective responses, monitored inert decoys and manual triage examples. No new limiter, normalizer, tarpit, deception service, detector or demonstrated effectiveness; existing executable contracts unchanged. |
