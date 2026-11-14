# Changelog

This file records user-visible additions, changes and validation notes by version. See [GitHub Releases](https://github.com/MrMarshalRF/amqic_base_cybersec_for_development/releases) for release assets and [VALIDATION.md](docs/VALIDATION.md) for the tested scope.

## Unreleased

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
