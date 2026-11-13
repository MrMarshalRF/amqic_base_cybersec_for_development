# Reproduce the working security examples

This lab is an executable consumer of the toolkit. It is deliberately restricted to loopback and synthetic accounts, not a production application or a replacement for real enrollment, CAPTCHA and identity management. Use no real personal data or credentials. The public fixture passwords, OTP seeds and Redis password are test data.

For the complete local scenario catalogue and one AI-native entry point, start with [ALL-LAB.md](ALL-LAB.md). The commands below remain useful when you want only the focused web/upload example.

## Prerequisites and pinned services

Install supported Node.js 22 or later, Python 3.12 or later, Docker Engine with Compose, and a local Chromium browser. Record the versions you actually use. These examples use Node standard-library APIs without an npm install. The SQLite API is experimental in the tested Node 22 runtime.

The lab requires these exact service images already present locally:

```sh
docker pull clamav/clamav@sha256:64ca916618842ba469ef38a501e6c2f42a68281c064c03749b0126c0fb085ce5
docker pull redis@sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf
```

These are deliberate downloads of pinned upstream images. Inspect/review the source and platform compatibility through your normal dependency process before executing them. The launcher refuses a missing image instead of silently selecting another version. Pinning identifies bytes; it does not prove that an image has no defects.

Before running repository scripts obtained from someone else, authenticate the release and its file registry using [RELEASE-VERIFICATION.md](RELEASE-VERIFICATION.md).

## One-command interactive lab

From the kit root, replace the output path with a new absolute path **outside this repository** whose parent directory already exists:

```sh
node --experimental-sqlite lab/run-lab.mjs --serve --output /private/lab-session.json
```

Windows example:

```powershell
node --experimental-sqlite lab/run-lab.mjs --serve --output C:/lab-reports/session.json
```

The launcher creates an isolated temporary area, a dedicated Docker network, and a non-root ClamAV container with a read-only root and a loopback-only randomly assigned port. It supplies a small custom database that detects only the harmless `AMQIC_LAB_SCAN_MARKER` string. It disables the normal updater startup by selecting the daemon directly. **This is a real ClamAV engine with synthetic detection data, not a malware-detection benchmark.** Production detection databases and updates require their separate workflow.

Open the printed `http://127.0.0.1:<port>` URL. It displays two public synthetic accounts and current test OTP codes. Complete login, password, simulated CAPTCHA and TOTP in order. No step is disabled. Submit a contact message and list it. Upload a harmless text file, observe that it is initially unavailable, request scanning, then download the approved bytes.

For the negative antivirus case, create a text file containing the literal string `AMQIC_LAB_SCAN_MARKER`. After scanning, this fixture must be rejected and remain unavailable. Do not use real malware or upload personal files. Finish with Ctrl+C; the lab stops its owned services and removes its temporary application data. The completion/resource records are outside the public source tree. Preserve them if cleanup reports uncertainty; do not delete unrelated Docker resources.

The interactive mode uses one trusted application process coordinating separate storage areas and a separate scanner process. The [production upload topology](UPLOAD-ISOLATION.md) additionally separates service identities and volume permissions. A working single-process lab is not proof that those production roles have been deployed.

## One-command browser and real-service verification

```sh
node --experimental-sqlite lab/run-lab.mjs --verify --output /private/live-result.json
```

The parent directory must exist and the report must not exist. Optionally set `LAB_BROWSER_PATH` to an explicitly reviewed local Chromium executable; an invalid explicit path is an error, not permission to select a different binary. The default discovery checks known Chrome/Chromium/Edge locations. Browser sandboxing is not disabled.

This command automatically starts the pinned ClamAV and Redis services, runs a headless real browser against the loopback application, then verifies cleanup. Redis uses an explicit **public synthetic password**, disposable memory-only data and a loopback-only port; it must not be connected to a production Redis or configured with real credentials.

The resulting JSON contains named assertions and the exact hashes of the consumer source files. It checks:

| Scenario | Observable acceptance condition |
| --- | --- |
| ClamAV protocol | The real daemon reports its version, accepts a harmless file and detects the custom marker. |
| Browser login | The actual page advances through all four server-enforced stages. |
| Stored text / XSS | SQL/HTML-looking text is stored and displayed literally; no injected DOM nodes or probe script execution appear. |
| Upload admission | Pending content returns denial; clean content becomes downloadable with identical bytes. |
| Antivirus rejection | The marked object remains unavailable after processing. |
| Redis concurrency | Eight simultaneous attempts produce exactly two allowed responses under a two-request limit; the counter resets after its TTL. |
| Resource cleanup | Browser/application exit, both service containers and the dedicated network are removed, and temporary areas are removed only after known cleanup. |

The Redis limiter is exercised separately, not silently installed as the web application's global limiter. The PoW implementation is also a separate consumer with its own tests. A solved proof never bypasses the application's authentication stages. See [admission.README.md](../lab/admission.README.md).

## Full fixed test suite and evidence

```sh
node scripts/verify.mjs --full --output /private/whole-kit-result.json
```

The fixed runner executes the core, HTTP, upload, scanner-protocol, PoW/Redis protocol, crypto and Python tests, checks every payload file against its coverage entry and SHA-256, and invokes the real-service/browser lifecycle. It accepts no arbitrary shell commands. It records explicit `not_run` results for environment-specific checks rather than counting them as passes.

On Windows, the Linux PTY check is not run. Actual Nginx integration additionally requires a correctly configured OpenSSL executable in PATH, a reviewed local image and a new external directory. Check `openssl version` and use a supported toolchain; do not accidentally select an unrelated legacy web-server installation on Windows:

```sh
node scripts/verify.mjs --full --output /private/whole-kit-result.json \
  --nginx-image sha256:YOUR_REVIEWED_LOCAL_IMAGE_ID \
  --nginx-output /private/new-nginx-lab
```

Do not pass a tag or guessed digest. Use the image you inspected and tested. Read the JSON `status`, individual checks and `complete` field; exit code zero for a supported baseline does not imply every optional integration ran. An incomplete report must remain labelled incomplete.

## Protocols and negative cases

The [web lab contract](../lab/web.README.md) documents methods, routes, cookie/CSRF handling, limits and errors. [Upload/clamd contracts](../lab/upload-pipeline.README.md) document persistent states, framing, deadlines and content identity. These are inspectable application contracts, not newly claimed industry standards.

Unit and integration cases exercise wrong owners, absent/revoked sessions, malformed/oversized requests, streaming-time revocation, invalid CSRF/Origin/Host, scanner timeouts/errors, tampered bytes, concurrent promotion, invalid PoW binding/MAC/expiry, and concurrent durable replay checks. The scanner parser uses length-prefixed big-endian INSTREAM frames and bounded replies; no permissive scanner fallback is used.

`verification/claims.json` connects the claims to standards and named checks. `verification/coverage.json` classifies every file as code, configuration, static data or source-reviewed documentation. A documentation entry does not establish an executable control or complete standards conformance.

## Evidence and remaining boundaries

The public [completion protocol](../verification/v1.2.0-report.json) contains final results, versions, tested source hashes and scope. It excludes private development logs and its own bytes from the source identity to avoid a circular hash. The release SHA-256 registry covers the report file itself.

Hosted [CI](../.github/workflows/verify.yml) is configured separately. A checked-in workflow is not evidence that its hosted matrix has run. Real production identity providers, protected keys, real CAPTCHA, Cloudflare account rules, VPN routes, production malware databases, durable multi-region operations and a deployed operating system require their own target-specific evidence. Preserve those distinctions when describing the kit.
