# One entry point for the security laboratory

The laboratory is a test consumer of the reusable kit, not an application deployment. Its purpose is to make each mechanism's evidence discoverable and repeatable. Local checks use synthetic data and task-owned resources. External account controls remain explicitly separate.

Linux/macOS users can start with `sh lab/run.sh`. The wrapper selects a new external report directory and runs the fixed all-local plan with explicit lab preparation. See [host requirements and configuration parameters](../lab/host-requirements.md); use `--no-prepare` when only cached images are permitted.

## For a person or an AI agent

Inspect the plan without starting services:

```sh
node scripts/verify.mjs --plan
```

Run all available local scenarios with one command, choosing a new absolute report path outside this repository:

```sh
node scripts/verify.mjs --all --output /private/reports/all-local.json
```

On the first run, when you authorize the fixed prerequisites shown in the plan, allow preparation in the same command:

```sh
node scripts/verify.mjs --all --prepare --output /private/reports/all-local.json
```

Windows uses an absolute Windows output path, for example `C:/lab-reports/all-local.json`. The parent directory must already exist. Keep old reports; do not overwrite evidence from a different source revision. Node, Python and Docker host requirements are reported in the plan. The runner selects no arbitrary commands from the catalogue or a remote response.

`--prepare` may download the explicitly pinned service/base images and build the fixed laboratory tool image. It does not configure a production host, install a VPN into the user's operating system, modify real firewall rules or access real password stores. Check pinned sources and image/build metadata before use. A reproducible test procedure is not a promise that an upstream package repository remains unchanged; the final protocol must identify the exact tool image and versions actually used.

## What “all” means

The [scenario catalogue](../lab/scenarios.json) maps the kit's mechanisms to a check, an expected result and a scope. Executable components run their tests. Infrastructure runs in disposable local namespaces/containers when the required host capabilities exist. External services and manual operations are listed with the information needed to validate them; they are not silently marked successful.

In particular:

- Form, authentication, machine-signature, step-up, replay, backup, archive, version and release-preparation checks exercise the supplied code.
- HTTP/browser, ClamAV and Redis scenarios use actual local consumers with clearly labelled synthetic identities and data.
- Nginx/cache and infrastructure scenarios exercise the named local service or namespace, not a user's public origin.
- A local cache/route/VPN contract test does not establish the configuration of Cloudflare, WireSock, Tailscale or another real provider account.
- Real signing keys, production backups, actual password-manager contents and destructive operations need their own protected process and authorization. The laboratory never needs those secrets.

The infrastructure fixture also exercises a separate synthetic KeePassXC database, native debug-symbol separation and a minimal runtime image. A correct test password succeeds and an incorrect one fails; no personal vault is accessed. The container probe checks its actual UID, capabilities, no-new-privileges, writable temporary area and absence of a shell or Docker socket. Local WireGuard endpoints test a handshake and peer removal inside their own network namespaces.

Unsupported kernel capabilities or unavailable prerequisites produce an explicit non-success state for the affected scenario. Review that state and the recorded scope; do not disable host protections, switch to host networking or grant a container broad privileges merely to suppress a skipped check.

## AI-native contract

The command exposes a machine-readable plan and JSON results. It requires no AI-provider API key or paid model call; an AI agent can consume the same plan and protocol as a human. Integrators should use scenario/check IDs and status fields rather than scrape prose. The [AI skill](../skills/run-security-lab/SKILL.md) describes the bounded workflow. Preparation, execution, successful assertions, omitted work and cleanup are different states.

The output binds the tested files to their hashes and records actual tool versions, result status and cleanup. No secrets or private development logs belong in a public protocol. Publish only a reviewed final projection; keep the complete raw diagnostics privately when investigating a failed check.

An agent may summarize a scenario as passed only when that scenario's required assertions ran successfully on the stated inputs. It must keep external/manual items and untested production behavior visible. Standards links explain the test objective; they do not confer certification.

## Review and reuse

Start with [REPRODUCIBLE-LAB.md](REPRODUCIBLE-LAB.md) for the interactive form/upload flow and [VERIFICATION.md](VERIFICATION.md) for the fixed verifier. The final accepted results are in [the completion protocol](../verification/v1.2.0-report.json). The report is tied to its recorded source revision; edits require new verification and a refreshed signed registry before release.

When adapting this laboratory to another application, replace the synthetic adapters through explicit reviewed integration points. Keep the same observable negative cases and add domain-specific authorization/data tests. Do not infer that passing this kit's own fixture proves that the adapted application is protected.
