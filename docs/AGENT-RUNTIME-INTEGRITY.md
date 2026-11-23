# Agent runtime integrity and extension review

Agents that read untrusted repositories need controls outside their own writable instruction/configuration files. Treat model refusals as model behavior, not server-side authorization or proof of containment. Use the [runtime guide](AI-AGENT-RUNTIME.md) for separate identities, credentials, egress, exact approvals and an external stop path. The [automated-probing guide](AUTOMATED-PROBING-DEFENSE.md) addresses requests from agents outside your control.

## Inventory the installed and effective state separately

Record the exact agent/runtime version, platform, installation identity and artifact digest; package and launcher locations; approved plugins/skills/MCP servers; global instruction/override files; effective permission semantics; and the authority that controls them. Keep real paths, credential exposure and host inventory private. A version label alone cannot establish that installed files still match that version.

Monitor package files, launchers, configuration and instruction/override files for unexplained changes. Include missing and extra files, file types/links and relevant ownership/permissions. Separate authorized upgrades and documented generated files from unexpected drift. A file changing during collection needs a consistent snapshot or a clearly incomplete result. Do not automatically replace the trusted baseline with whatever is currently installed.

Keep the baseline, verifier and security-event custody outside the agent's write authority. Same-user hashes and prompts cannot prevent an unrestricted same-user process from changing files or falsifying its report. Use a separate administrative identity, immutable image or appropriate OS/VM boundary for enforcement. This guide does not install a launch gate or inspect the current workstation.

## Artifact integrity is not installed-tree integrity

An npm lockfile's `integrity` value binds fetched artifact bytes, usually the tarball. It is not a directory digest. Registry signatures, cache verification, code review and installed-state comparison answer different questions. Do not compare a tarball SHA-512 directly to a directory SHA-256, or treat a cache check as installed-file verification. [npm lockfile documentation](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/) · [Registry signatures](https://docs.npmjs.com/about-registry-signatures/)

The kit already has a [bounded inventory/verifier](../enterprise/supply/README.md). It can demonstrate exact file membership and byte comparison on a sealed, reviewed staging tree. For example, following that guide's trusted inputs:

```sh
node enterprise/supply/supply.mjs inventory "$PAYLOAD_DIR" "$BINARY_POLICY" "$SOURCE_COMMIT" > "$INVENTORY"
node enterprise/supply/supply.mjs check "$PAYLOAD_DIR" "$BINARY_POLICY" "$INVENTORY" "$SOURCE_COMMIT"
```

Create the baseline from an independently trusted clean artifact, protect it outside the checked tree and authenticate it through the chosen signing channel. Generating a baseline from a possibly modified tree and immediately checking it proves only self-consistency. The existing detached-signature format is described in the supply guide; it is separate from the maintainer's release-registry signing service.

This verifier accepts bounded regular-file payloads and rejects links/hardlinks and unsupported paths. Real package installations may contain shims, symlinks, generated files or artifacts outside its limits. Do not point it blindly at a global package directory, dereference links automatically or flatten an installation and claim equivalent security. Use a version/platform-aware installed-state monitor. The existing byte inventory does not check OS ownership, ACLs, executable modes, process memory or the effective sandbox; collect those separately.

## Permission policy belongs to the operator

Define allowed capabilities for each host/task, including documented exceptions. Determine semantics from the exact product/version and configuration precedence. An approval label such as `never` can mean different things in different products; it is not evidence of permission to execute, denial or compromise by itself. Inspect actual granted capabilities through a trusted collector rather than trusting an agent's own assertion.

| Environment | Review focus |
| --- | --- |
| Account with production access or sensitive credentials | Separate the agent identity, minimize reachable credentials and require externally enforced policy for privileged actions |
| Isolated disposable development VM | The owner may authorize broad guest access while maintaining the host/credential/egress boundary and bounded resources |
| CI/release worker | Use the exact reviewed workload, minimal permissions, protected policy and signing separation; untrusted jobs cannot alter trusted checks |

A full-access mode may be an explicit authorized choice. Record who approved its scope and how containment is actually maintained; do not classify that choice as an incident automatically. A configuration file owned by the same unrestricted session user is not an external enforcement boundary.

## Review extensions before admission

Use [review-dependencies](../skills/review-dependencies/SKILL.md) for plugins, skills and MCP servers as well as libraries. Pin the exact artifact and verify publisher/repository/registry identity. Review initialization hooks, writes outside the extension, modification of vendor files or launchers, persistent override loading, self-permission-changing tools and local web control endpoints. Model-facing instructions do not grant these capabilities.

For a normal low-privilege extension, hold or reject unexplained vendor patching, permission expansion or unauthenticated state changes. A legitimate administrative updater may need different capabilities, but it requires a separate explicit operator-reviewed scope and deployment process; a routine extension approval does not authorize it. An exact hash identifies reviewed bytes, not benign behavior or publisher authenticity by itself.

## Protect the kit's instruction supply chain

[CODEOWNERS](../.github/CODEOWNERS) identifies the repository owner for instruction files, skills, workflows, integrity metadata and security-sensitive source. Configure GitHub branch/ruleset review requirements separately, including required code-owner review and appropriate bypass restrictions. The file alone does not activate branch protection or prevent a push. No remote repository setting is changed by this update. [GitHub CODEOWNERS documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)

Review instruction-file changes like executable supply-chain inputs. Preserve their data/authority boundaries and do not add instructions that fetch/run third-party code, disclose private files or silently change credentials. A public kit's AGENTS.md is intended documentation; an application's private agent home, launcher state or standing override is not a web asset.

The production staging helper, demonstration Git ignore and protected-path registry now include `.dsh` and `prompt-inject.md`. The origin guard and production filters keep their separate roles: ignoring a local file does not prevent HTTP access to a deployed copy. Tests exercise staging/ignore behavior and generated origin rules; target deployment validation remains necessary.

## Detect and recover from unexplained drift

Collect protected events for runtime/launcher changes, permission or approval-policy changes, extension admission/removal, override changes and attempts to change one's own execution authority. Record actor, time, policy revision, artifact identity and the approved change reference without credentials, prompt contents or sensitive paths. The [existing SIEM schema](../enterprise/operations/README.md) has a general administration category; richer agent-event types require an explicit schema/adapter change. Do not append arbitrary fields and assume the exporter accepts them. Keep detailed incident context in a protected case record linked by an opaque correlation ID.

When an unexplained change is confirmed, use the authorized incident process: preserve relevant files/metadata and external evidence, stop the affected run through the operator-controlled path, evaluate exposure, and reinstall from an authenticated clean source if required. Avoid invoking an untrusted extension's own repair/revert logic as evidence of recovery. Scope credential revocation/rotation to observed or plausible exposure. Re-verify the installed state and actual permission behavior before resuming. This documentation does not stop agents, delete files, change permissions or rotate credentials on this machine.

## Standards and evidence scope

| Area | Primary reference | Scope |
| --- | --- | --- |
| Authorized configuration and integrity | [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) CM-3, CM-5, CM-6, SI-7 | Change control, protected configuration and detection of unauthorized drift; no installed-host FIM deployment claimed |
| Least privilege and isolation | NIST SP 800-53 AC-6, SC-39 | Operator-defined task/host capabilities and verified external boundaries; no universal prohibition inferred from a mode label |
| Component provenance and source protection | [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) PS.1.1, PS.2.1, PW.4.4; [OWASP LLM03](https://genai.owasp.org/llmrisk/llm032025-supply-chain/) | Reviewed extension bytes, trusted artifact inputs and code-owner mapping; branch/ruleset enforcement remains a separate setting |
| Agent configuration and authority | [MITRE ATLAS](https://atlas.mitre.org/) AML.T0081, AML.T0051.001, AML.M0037; [OWASP LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | Threat/control relationships, not attribution or proof of compromised local configuration |
| Protected event custody | NIST SP 800-53 AU-2, AU-9, AU-12 | Deployment event collection/retention requirements; no new SIEM event schema or collector activated |

Local validation covers the kit-owned exclusions, existing supply tests, source review and current artifact registry. No third-party guardrail-removal code, real installed agent, FIM product or host posture was tested or changed.

## Findings ledgers and browser folder access

Review locally hosted findings desks and their agent skills like other untrusted extensions. Offline-first wording does not prove absence of external fonts, optional hosted models or later requests. Treat imported finding Markdown/HTML as data; render safely, isolate it from credentials and do not grant writable folder access merely to view a report. Keep sensitive ledgers private and minimize customer data.

A Git authentication error does not authorize asking for a token in chat. Use the protected human terminal workflow and a fixed reviewed consumer. Review exact artifact/publisher identity and permission requests before enabling browser File System Access or agent write access. No third-party ledger is integrated by this guidance.

## Static pre-admission checks

Use the [agent configuration checklist](AGENT-CONFIG-REVIEW.md) and [offline review reference](../enterprise/config-review/README.md) before admitting a configuration, skill, hook or MCP definition and when its snapshot changes. Review approval/shell scope, remote execution, instruction integrity, credential access, MCP pins/transport and artifact exclusions. Pass an explicit normalized snapshot from a trusted collector; these checks neither discover every product's effective configuration nor execute hooks.

Keep exceptions in an independently reviewed policy with owner, exact scope, source-file binding and finite expiry. Documentation describing a risky setting is not the setting itself. Known-pattern findings and clean results require human interpretation; neither establishes installed-tree integrity, a sandbox or absence of prompt injection.
