# Kit validation

Verified on 12 November 2026 using the current source and synthetic data. Every public file has a validation method recorded in [VALIDATION-MATRIX.md](VALIDATION-MATRIX.md). These results establish the tested behavior and environment; they do not prove the absence of every possible defect.

## Test environments

- Windows: Python 3.13.5 and Node.js 22.14.0.
- Isolated Linux containers: Python 3.12, Alpine Python 3.14.10, and Node.js 22.23.2, with pinned base-image identities retained in the private test evidence.
- Configuration laboratories: Docker Engine 29.4.0, Nginx 1.27.5, nftables 1.1.1, and OpenSSH 9.9p2. A static Go 1.25.0 program was used solely as the synthetic application fixture for the shipped scratch image.

These are observed test versions. Select currently supported patched runtimes and repeat relevant checks for an actual deployment; see [VERSIONS.md](VERSIONS.md).

## Executed code checks

| Area | Result | Covered behavior |
| --- | --- | --- |
| Authorization core and login client | 36/36 tests passed on Windows and Linux | Ordered login stages, TOTP vectors and replay controls, current scopes, request signatures, expiry, revocation, exact UTF-8 body bytes, rollback, persistence, concurrent SQLite connections, idempotency, and client callback/cancellation behavior. |
| Backup files | 14 tests per platform; 11 passed and three platform/privilege-specific skips on each | Binary roundtrip, unchanged existing targets, corruption, path traversal, links/junctions, Windows aliases, and valid platform-specific Unicode/filenames. Linux executed actual symlink cases; Windows executed NTFS junction and ordinal-name cases. |
| Production preparation | Windows 14/14; Linux 13 passed with one Windows-only junction test skipped | Exact file/directory inventory, source preservation, no overwrite, private-file exclusions, malformed manifest refusal, and safe generated output. |
| Version checker | 14/14 on Windows and Linux | Source identity, timestamps, coverage gaps, private metadata protection, unsupported input, endpoint restrictions, and stable-version comparisons. |
| Crypto primitives and CLI refusal | 16 assertions passed on Windows and Linux | AES-256-GCM roundtrip, randomization, altered headers/data/tags, truncation, wrong passphrase, overwrite refusal, and rejection of noninteractive input. |
| Public terminal regression | One Linux test passed, containing five immediate encrypt/decrypt roundtrips; skipped on Windows | Input is sent immediately after each prompt; the public synthetic passphrase is absent from the transcript and restored bytes match. |
| Combined backup and secret-entry terminal workflow | 15 Linux assertions passed | Encrypted backup creation/restore, wrong passphrase, tamper, existing-target protection, encrypted credential entry, directory/file permissions, duplicate refusal, and immediate-input behavior. |
| Archive inspection | 56/56 checks passed on Windows and Linux | ZIP/TAR/gzip-TAR membership, unsafe names, links, duplicate/case collisions, limits, exact hash, full gzip CRC/trailer validation, and trailing expansion. |
| Compose normalization | 3/3 tests passed through the actual Compose CLI | Complete tmpfs entries, application restrictions, and refusal of missing required parameters. |
| Nginx test-harness failure handling | 12/12 daemon-free tests passed | Bounded commands, independent cleanup attempts, unknown outcomes, delayed listener readiness, and validated loopback port bindings. |

The end-to-end `reference/demo.mjs` also completed on Windows and Linux with `sameResult=true`. The animated README demonstration contains actual captured stdout; its playback pacing is illustrative.

## Real configuration consumers

### Nginx

The full current laboratory completed after the startup/readiness corrections. It exercised syntax validation, allowed and denied routes, separate website/API rate buckets, 403/429 behavior, refill, fixed HTTPS redirects, Host/SNI rejection, CSP and other response headers, preservation of stricter upstream CSP, peer whitelists, and trusted-client address handling. It also checked missing, malformed, duplicate, unselected, and spoofed proxy headers.

Each rate-limited final handler uses one selected bucket. Listener readiness probes send no HTTP request and therefore do not consume a bucket. The harness records actual container identities, starts, port mappings, and cleanup results. Physical IPv6 TCP ingress remains a target-environment check; IPv6 address/header cases were exercised.

### Firewall and SSH

Generated nftables rules passed actual kernel syntax checking and application inside an isolated network namespace. A second application was refused without altering the ruleset. Unrelated sentinel rules remained present, and an invalid multi-command transaction left no partial table. Separate client containers exercised allowed and denied traffic on TCP 80 and a synthetic configured administrative port of 8080.

The actual OpenSSH daemon consumed the shipped template with a synthetic account and a laboratory port of 2222. Syntax and effective settings passed. A correct Ed25519 key logged in as the synthetic user; a different key, a root login with the installed key, and password-only authentication were refused. These tests validate the directives and configured-port mechanism; real provider rules, addressing, and administrative recovery still need target checks.

### Scratch image and application Compose

The shipped Dockerfile built a synthetic static application. Image-layer and ELF inspection found the application alone, with the configured non-root identity and no interpreter or shell files. A separate constrained runtime used a new internal network and a new client, with no published host ports or connection to pre-existing test clients.

Actual HTTP results and container configuration confirmed UID/GID 65532, denied root-filesystem writes, writable tmpfs, zero effective capabilities, `NoNewPrivs`, zero core-dump limits, no Docker socket, and the requested memory/CPU/PID settings. Resource exhaustion and hypervisor escape resistance were not tested. An earlier broader test command was rejected before execution; the reduced test used explicit isolated ownership and omitted shell execution and cross-network attachment.

### Dependency quarantine

The actual shipped prepare, fetch, and offline-inspect profiles passed using a fixed public `packaging` 25.0 source archive. The retrieved object had the expected 165727-byte length and SHA-256; inspection reported 79 members and `executed=false`, `installed=false`, `extracted=false`. A fresh volume with an intentionally wrong hash refused the download as trusted input and retained only the partial artifact. Volume owner/group and mode matched the intended 65532/0700 policy.

This test exercised fixed-source download and offline inspection. It did not establish publisher trust beyond the recorded official metadata/HTTPS source, execute package code, or configure a production egress gateway.

## Corrections verified during this audit

Regression checks cover Windows backup junction traversal and filename aliasing, incomplete gzip validation, malformed UTF-8 acceptance, asynchronous callback rejection handling, client notification recovery, deeply nested manifest input, the hidden-input prompt/echo race, incorrectly split YAML tmpfs mounts, and Docker listener/cleanup timing in the test harness. Valid behavior was retained and independently reviewed alongside each correction.

An initial Docker Engine outage and several laboratory-harness failures were preserved in the private evidence. The final consumer checks above completed after the relevant corrections. Task-owned containers, networks, volumes, and generated images are removed after verification; shared services and base images are preserved.

## Operational telemetry export

The supplied Vallatum-collected public-site export was checked for internal arithmetic and publication scope. Its 22 daily rows sum to 17,872 Block decisions and 787 Managed Challenges. The maintenance subtotal is 8,106; the remaining Block decisions total 9,766. The 514 distinct probe paths sum to 1,537 Block and 143 Managed Challenge sample records, or 1,680 records. The reported interval durations match the stated observation period. The supplied chart was visually compared with the table.

The report and chart were copied without changing their bytes. Review covered the supplied public export, its redaction and stated limits. Raw provider events, the collector, and the site's operational investigation were not independently re-audited as part of this publication. See [THREAT-DATA.md](../THREAT-DATA.md) for the source definitions and distinctions between decisions, requests, samples, and attacks.

## Adoption boundaries

The HTTP/MCP transport, real CAPTCHA provider, production factor store, enrollment/recovery, audit delivery, and operational database handlers require application integration according to [reference/README.md](../reference/README.md). The examples changed only synthetic records and files.

Production rollout additionally requires the actual certificates, domain, proxy ranges, host routes, DHCP/IPv6 behavior, SSH recovery access, egress policy, application compatibility, and operational rollback plan. The examples and laboratory results do not activate those systems.

The maintainer signs the final SHA256SUMS registry separately. A matching hash list without its authenticated signature does not establish release provenance; follow [RELEASE-VERIFICATION.md](RELEASE-VERIFICATION.md).
