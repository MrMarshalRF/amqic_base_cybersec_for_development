# Changelog

This file records user-visible additions, changes and validation notes by version. See [GitHub Releases](https://github.com/MrMarshalRF/amqic_base_cybersec_for_development/releases) for release assets and [VALIDATION.md](docs/VALIDATION.md) for the tested scope.

## v1.8.1

- Add SSH trust-file integrity guidance and a source-reviewed watch template; key-only login remains a separate preventive control.
- Add source-reviewed Falco starting rules for container Node and PostgreSQL child shells alongside the Java and Nginx profiles.
- Add host/container egress guidance, separate from the application outbound catalog, and a private indicator provenance/expiry procedure without shipped indicator values.
- Add federated identity-plane review guidance and additive SIEM runtime, egress, campaign and identity records with v1 compatibility tests.
- Keep synthetic HTTP fixtures on Fetch-compatible loopback ports with bounded listener reallocation and concurrent start/close cleanup tests.
- Correct glued words in validation/claim limits and extra blank lines in the v1.8.0 changelog section. Host sensor deployment and detection effectiveness remain target verification.

## v1.8.0

- Refresh the consolidated threat-data register to 617 distinct public paths/aliases, preserving historical and supplemental counts separately.

- Refresh the reviewed PostgreSQL 17.12 lab image and require observed fixed-branch server versions; test effective TEMP/schema creation restrictions with permitted operations.
- Add fixed outbound HTTPS GET transport with connect-time address pinning, conservative destination/response bounds and local return-route resolution.
- Add a one-use recovery-token lifecycle reference with purpose/tenant/account/security-epoch binding, bounded storage and concurrency checks.
- Add database-engine advisory and optional Oracle patch guidance, multi-source campaign correlation and safe findings-ledger handling; update security mappings and laboratory coverage.

- Update README with press coverage, the linked technical paper and its repository-specific Section 15.

## v1.7.0

- Add optional external agent-integrity reference guidance, extension-review criteria and code-owner mapping; exclude `.dsh` and standing override files from production staging and origin exposure.

- Add automated-probing defense guidance, atomic multi-dimension admission, inert canary signals, generic denials and a tested security.txt content generator.
- Add disclosure scope and evidence requirements, with updated standards mappings and laboratory coverage.

- Add the AI agent runtime threat model, containment and credential-broker guidance, fixed tool-guard references and regression tests.

- Pin the Nginx lab to the patched 1.30.7 Alpine image and preserve the reviewed Node 22 Bookworm baseline.
- Make HTTP/2-off explicit, suppress upstream Alt-Svc and test benign ALPN negotiation.
- Confirm opaque Python/OpenSSL TLS errors through independent ALPN alert evidence while keeping unrelated failures closed.
- Add a per-replica rollout gate for exact vendor/CVE findings, artifacts, master/worker replacement, fresh protocol observations and ETags.
- Add the edge parser response guide and update infrastructure, version inventory and security mappings.

## v1.6.0

- Add PostgreSQL and Redis admission references with concurrent accounting, datastore time, replay handling and explicit failover requirements.
- Add AWS KMS, Google Cloud KMS and Azure Key Vault adapters with workload identity guidance.
- Add multi-provider OIDC and SAML federation, tenant-bound JIT provisioning and explicit role mapping.
- Add monitoring, retention, incident response and cloud key rotation playbooks with a versioned SIEM export.
- Expand policy property and bounded burst tests, component threat models, weekly Dependabot updates and CI dependency review.

## v1.5.0

- Add Rust tool, migration and endpoint-protection references to README.
- Document the enterprise controls, verification scope and deployment checks in SECURITY.md.
- Add an enterprise profile with executable policy, tenant-scoped admission and abuse controls.
- Add security audit and evidence tooling with JSON and human-readable output, digest verification and an offline signature workflow.
- Add source inventory verification, SBOM and release provenance workflows.
- Add short-lived credential and tenant-key rotation references with synthetic provider tests.
- Document defensive Java runtime triage, hardened workload examples and deployment verification boundaries.

## v1.4.0

- Update README.
- Expand the November threat report and map the subscription offer controls in SECURITY.md.
- Add a provider-neutral billing offer guard with backend purchase verification, an explicit offer allowlist, and a single atomic trial claim per account and campaign.

## v1.3.2

### Attribution

- Acknowledge OpenAI Codex assistance with implementation, testing, and review in README.
- Record the co-author trailer for future Codex-assisted commits while preserving human authorship and published history.
- Group SandHive and Stonecell.AI security recommendations separately from Oarwise computer vision and Codex desktop-automation tooling.
- Refresh hash-bound verification metadata for changed documentation; unscanned new bytes remain explicitly pending.

## v1.3.1

### Edge, origin and repository boundaries

- Extend reviewed technical-path protections and explicitly deny administrative source maps before Nginx location selection, including a synthetic static-prefix bypass regression.
- Explain terminating edge blocks, plan-dependent matching, origin rule persistence, safe rollout checks and the distinction between public compiled assets and private deployment artifacts.
- Extend private agent-work, evidence, delegated-operation and encrypted-secret exclusions; check production payload policy separately from Git ignore decisions.
- Keep private incident provenance outside the public kit. These portable changes do not configure any Cloudflare zone or production origin.

## v1.3.0

### Database security

- Add a PostgreSQL row-level-security example with tenant-bound principals, column privileges and explicit bound-value selection, plus an isolated database laboratory.
- Add authenticated field-envelope encryption and a provider-neutral KMS contract, with authorization before decrypt, strict key selection and tenant/record/field binding.
- Explain consistent nonce uniqueness, expiration and shared replay enforcement across instances; add a stale-instance/expired-nonce regression for the existing SQLite core.
- Document key rotation, query limits, connection identity, failover/recovery risks and standards references. Local provider fixtures do not establish live cloud KMS or production deployment readiness.

### Origin and verification

- Extend the protected-path registry from 56 to 146 reviewed entries for private configuration, credentials, source and deployment artifacts; retain literal boundaries and deny-by-default routing.
- Extend the example Git ignore policy for private secret manifests and runtime state while keeping ordinary source/deployment configuration and public examples versionable. Add isolated Git and registry matching regressions plus all-registry HTTP denial checks.
- Expand the security policy with explicit VirusTotal report semantics, exact-hash and generated-metadata boundaries, and version-qualified OWASP/NIST references for database and field security.
- Bound retries when removing owned SQLite test fixtures on Windows, where transient directory-removal errors can otherwise fail a completed test.

## v1.2.2 — 2026-11-14

### Added

- Recommend SandHive's security-investigation corpus for optional case-guided review, with an external GitHub link, applicability examples and a reading-only AI skill.

### Removed

- Remove the active SandHive adapter, its tests, automatic download/execution command and associated laboratory check/scenario.

## v1.2.1 — 2026-11-13

### Fixed

- Apply the SQLite busy timeout before WAL initialization so concurrent replay-store constructors wait for the database lock.
- Resolve the project directory before excluding project-local executables from runtime discovery, including Windows short-path aliases.
- Wait for both synthetic HTTP listeners to become ready before infrastructure reachability checks.
- Preserve diagnostics for every failed verification command and reserve their output paths before laboratory preparation.

- Update the pinned GitHub actions to Node 24-based releases to remove the Node 20 runtime deprecation warning.

### Validation

- All five jobs passed in the hosted CI candidate, covering Node 22/24 on Ubuntu/Windows and the complete local infrastructure/service lab. The recorded run identifies its tested commit in [VALIDATION.md](docs/VALIDATION.md).

## v1.2.0 — 2026-11-13

### Added

- Runnable loopback HTTP/browser lab with full synthetic login stages, server-side contact handling and owner-scoped upload/download.
- Real ClamAV INSTREAM client, persistent quarantine/promotion reference and content-identity/concurrency tests.
- Bounded request proof-of-work API with SQLite replay storage, fixed Redis rate limiter and real Redis consumer test.
- One-command disposable service/browser verification, fixed whole-kit runner, per-file coverage, standards-linked claims and a final completion protocol.
- All-local scenario catalogue, machine-readable plan/result schema, infrastructure and cache/privacy labs, and an AI laboratory skill.
- POSIX one-command wrapper and inspectable host/Linux configuration parameters.
- Read-only CI workflow definitions with pinned actions and service images. Hosted results remain separate from local verification.

### Changed

- Added current-session scope verification for real HTTP adapters, with expiry/logout/revocation tests.
- Separated implemented references, configuration templates and guidance in the verification record.
- Expanded reproduction instructions and preserved explicit synthetic-data, production-integration and environment limitations.

## v1.1.0 — 2026-11-13

### Added

- [Production binary protection](docs/BINARY-OBFUSCATION.md): symbol/debug separation, version-specific obfuscation examples, diagnostic recovery, signing order and NIST SSDF / OWASP resilience references.
- [Binary protection AI skill](skills/obfuscate-binaries/SKILL.md), with bounded scope and explicit validation requirements.
- [Private administration guide](docs/VPN-TUNNELS.md) for WireGuard/WireSock, Tailscale, subnet routes and firewall/Nginx integration.
- [Secure deployment runbook](docs/DEPLOYMENT.md) covering verified artifacts, secrets, recovery, migrations, rollout checks and rollback.
- [GitHub release guide](docs/GITHUB-RELEASES.md) covering public documentation/licensing, deterministic SHA-256 registries, signing, tags, draft assets and readback verification.
- [ClamAV, Redis and request proof-of-work guidance](docs/SERVICE-PROTECTION.md), with explicit failure, isolation and authorization boundaries.
- [Website form-input module](reference/pii-input.mjs) and [guide](docs/WEB-INPUT-PROTECTION.md): constrained contact-field validation, fixed parameterized SQLite storage, safe output and the relationship to container restrictions.
- [Beginner guide](docs/SECURITY-BASICS.md) explaining 27 mechanisms using simple examples and limits, linked from contributor instructions.
- [Cloudflare edge guide](docs/CLOUDFLARE-EDGE.md) explaining DDoS, safe public caching, sensitive-response bypasses, WAF/rate limits and restricted origin access.
- [Upload-isolation topology and guide](docs/UPLOAD-ISOLATION.md), separating quarantine, verdicts and approved content with distinct service identities and a trusted promotion boundary.
- Explicit [standards mapping for the new mechanisms](SECURITY.md#standards-mapping-for-the-v11-additions), including version-qualified ASVS requirements, NIST controls/SSDF and HTTP caching semantics.
- This changelog and contributor requirements to keep it current.

### Changed

- Expanded README navigation, SECURITY references, production-preparation guidance and the file-validation matrix for the new material.
- Removed the three AMQIC-specific patterns from the demonstration `.gitignore`; generic secret, backup, editor and dependency exclusions remain.
- Updated the production-preparation skill to link to binary, deployment and release procedures without changing the UTF-8-only staging-tool contract.

### Validation and limits

- Executed synthetic Go metadata-reduction and Linux ELF debug-separation examples; inspected output parity, symbols, debug links and hashes.
- Exercised the documented registry generator against private fixtures, including a corrected reserved-name case collision and failure cases that preserve the previous registry.
- Passed eight new web-input tests and 36 existing core/client tests. The SQL-injection regression uses a real in-memory SQLite database and retains hostile-looking text as data.
- Checked skill structure, documentation links, generic Git ignore behavior and VPN-template syntax; completed independent source/contract review.
- Passed four Compose checks and Linux preparation/role-permission tests for isolated upload storage; verified cleanup of the five test containers and three dedicated volumes. Scanner, promotion-race and real HTTP integration remain untested application contracts.
- No live VPN, Cloudflare, ClamAV, Redis, proof-of-work gateway or production rollout is deployed by this update. Garble/R8/.NET and browser/HTTP integration still need target-specific validation. The final registry requires maintainer signing before publication.

## v1.0.0 — 2026-11-13

Initial published release of the baseline cybersecurity starter kit.

- Transport-neutral authorization examples: staged login, CAPTCHA/TOTP, Ed25519 machine requests, replay controls and sensitive-operation grants.
- Embeddable login controller and synthetic regression tests.
- Nginx, SSH, firewall and container templates with documented integration boundaries.
- Protected credential input, encrypted backup/restore, dependency quarantine, version checks and source release preparation.
- Five AI skills, KeePassXC guidance, MIT licensing, security policy and documented validation scope.
- SHA-256 file registry with the maintainer's external signature-verification process, plus public operational threat data and repository-activity links.

[Published v1.0.0](https://github.com/MrMarshalRF/amqic_base_cybersec_for_development/releases/tag/v1.0.0)
