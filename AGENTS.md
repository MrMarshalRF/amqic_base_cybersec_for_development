# Instructions for repository contributors and AI agents

## Repository scope

This repository is a portable security starter kit. Keep documentation, skill descriptions, examples, and contributor-facing text in English unless a task explicitly asks otherwise. Preserve protocol identifiers, source code and standard MIT license text in their original language. The project copyright holder is amqic.ai. Developer attribution is Aleksei Musienko as recorded in README.md.

Read the relevant module instructions before editing. Use README.md for navigation, docs/SECURITY-MODEL.md for boundaries and docs/VALIDATION.md for tested scope. Reuse existing code and preserve unrelated user changes. Keep changes within the requested task.

## Explain the basics when needed

For contributors or users unfamiliar with cybersecurity, link to [Security basics, explained simply](docs/SECURITY-BASICS.md). It explains each kit mechanism with a plain-language example and its limits. Use it to orient the reader, then follow the specific implementation/deployment guide; simple explanations do not replace the relevant security checks.

## Source layout

- reference/ holds the transport-neutral authorization core, headless login controller, synthetic fixtures and regression tests. Read reference/README.md before changing contracts.
- scripts/ holds protected input, AES-256-GCM archive helpers, backups, production staging and version evidence tools.
- infra/nginx/ and infra/firewall/ generate candidates. infra/ssh/ and infra/container/ contain templates. Deployment guidance is in docs/INITIAL-DEPLOYMENT.md and docs/INFRASTRUCTURE.md.
- skills/ contains seven task-specific AI skills. Their relative references require the surrounding kit layout.
- LICENSE contains the standard MIT grant. Preserve its copyright and permission notice.

## Preserve reproducible evidence

Every public payload file must remain classified in verification/coverage.json. Use the fixed `--plan` / `--all` interface and skills/run-security-lab/SKILL.md when coordinating laboratory checks; lab/scenarios.json describes which mechanisms are local, external or manual. Update verification/claims.json when implemented capabilities or limits change. Run the fixed verifier with an external output path; preserve explicit not_run/incomplete status instead of turning a missing integration into a pass. Publish only the sanitized final completion protocol, not development logs or local paths. Reports do not replace maintainer signature verification.

## Record user-visible changes

Update [CHANGELOG.md](CHANGELOG.md) when a task adds, changes, fixes or removes user-visible behavior, guidance or supported integrations. Keep unassigned future work under Unreleased. Finalize the accepted version entry before signing its registry, using a publication date only when known. A version entry alone must not claim publication; GitHub Releases records that state. Do not edit an already signed release to update its status; make subsequent changes in the next version. Record material validation limits; do not equate documentation, a local commit or a build with deployment. Include the final changelog bytes in the regenerated SHA256SUMS before maintainer signing.

## Implementation and checks

Use standard-library facilities already present. New dependencies need a task-specific reason and the documented quarantine workflow. Do not run installation hooks or import unreviewed dependency artifacts during inspection.

Run checks matching the changed behavior. From repository root, the existing commands include these.

```sh
node --experimental-sqlite --test reference/core.test.mjs reference/login-client.test.mjs reference/pii-input.test.mjs
node --experimental-sqlite reference/demo.mjs
python -B scripts/test_operations.py
node --test scripts/test_crypto.mjs
python -B scripts/test_prepare_production.py
python -B scripts/test_check_versions.py
python -B scripts/test_terminal_input.py
python -B infra/container/test_quarantine.py
python -B infra/container/test_compose.py
python -B infra/nginx/test_harness.py
```

Use Python -B to keep generated caches out of the tree. Nginx runtime tests require an explicitly reviewed local image and an external new output directory. Follow infra/nginx/test_nginx.py --help and the infrastructure guide. Record ownership and exact identifiers of temporary containers/networks before using them, then clean only those task-owned resources and verify absence. Preserve shared environments and source data.

Report implementation, tests, integration and deployed behavior accurately. A passing synthetic example establishes its tested scope. Refresh only checks affected by changed inputs or concrete failures. Maintain docs/VALIDATION.md when the supported or tested behavior changes.

## Security contracts

Keep server-enforced login stages, current authorization, persisted replay controls, expiry and revocation. Preserve exact action/argument binding for sensitive operations and stable idempotency across retries. External effects need their own durable result handling. The sample core and machine signature do not implement a complete HTTP/MCP OAuth server.

Keep Nginx deny-by-default routes, protected-path handling, one active rate zone per terminal access/content context and CSP on normal/error responses. Preserve stricter upstream CSP. Whitelist rules must distinguish the original socket peer from a client restored through explicitly trusted proxy ranges. Arbitrary forwarded headers cannot grant access. New locations and error handlers require checks for inherited headers, access and rate behavior.

SSH key authentication belongs to sshd; firewall CIDRs limit network access to the SSH port. Candidate generation does not activate a server configuration. Cloud/DNS/proxy changes and real server application require authority for the concrete target and a checked recovery path.

## Secrets and sensitive operations

Never request secret values in chat or place them in command arguments, environment, logs, reports or source files. New secret input is performed by the human in their own hidden-input terminal using the documented fixed scripts. Agents work with metadata and must not read the protected payload. Stored credentials may only reach an authorized reviewed consumer with the required isolation.

Preserve original source files and credentials during release preparation. Build a separate explicit allowlisted payload using scripts/prepare_production.py. Inspect findings by path and rule only. Never conceal actual secrets through encoding, renaming or scanner exceptions. Confirmed exposure requires authorized revocation/rotation and review of prior distribution.

Real database deletion, persistent-backup deletion, overwriting data, changing access and other critical operations require the documented independent step-up through a trusted verifier. A serialized approval flag, a code comment or agent assertion cannot supply that factor. Keep destructive steps with the human when the verifier is absent.

## Public content and version evidence

Exclude private operational data, .env files, keys, password stores, backups, Git internals, Graphify indexes, internal plans/receipts, agent configuration and local MCP settings from runtime releases. Public source documentation, examples and this AGENTS.md are intentional repository content. Review the exact artifact inventory for its destination.

Version checks must preserve observed/declared distinctions, official source dates, unsupported formats and coverage gaps. Private dependency names need explicit authorization before transmission. Latest release and version currency do not establish vulnerability clearance. Follow docs/VERSIONS.md and the production skill before release.

Keep local machine paths, personal tool configuration, task journals and internal orchestration receipts outside public files. Use generic examples and synthetic credentials. Report any incomplete or unverified integration plainly.


Give every shipped file a validation method in docs/VALIDATION-MATRIX.md. Update the matrix when files are added or removed, and regenerate SHA256SUMS only after the accepted payload is final. The maintainer then signs the registry; changes invalidate the prior signature.
