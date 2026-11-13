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

## Binary and delivery documentation update — 13 November 2026

The synthetic Go metadata-reduction example ran with Go 1.24.2 on Windows/amd64. Both binaries exited successfully with identical output. The baseline was 2,296,832 bytes and the candidate 1,530,368 bytes; `go tool nm` listed the baseline symbols and reported no symbols for the candidate. Build information remained readable. These observations demonstrate the documented metadata reduction, not secret protection or actual Garble transformation.

The exact ELF example ran with GCC 12.2.0 and GNU binutils 2.40 in an existing local Linux/amd64 tool image, with networking disabled and no host mounts. Baseline/candidate output matched. The candidate removed the baseline debug sections and static symbol table, retained `.dynsym` and `.gnu_debuglink`, and had a debuglink CRC matching the separate debug file. Independent inspection found unchanged dynamic-symbol bytes and build-ID notes in this fixture. Sizes were 17,216 bytes baseline, 14,576 bytes candidate and 5,824 bytes separate debug data. Both task-owned containers were removed and their absence verified.

No debugger was available: actual crash symbolication, production ABI/plugin behavior, platform signatures, Garble, Android R8 and .NET transformations remain untested integration steps. The first container used a non-executable tmpfs and refused execution; a corrected isolated mount exercised the example successfully. A subsequent wrapper newline error was separately reconciled by successful final parity/hash checks. No application defect or production guarantee is inferred from these laboratory outcomes.

The added VPN, deployment and GitHub-release guidance was reviewed against official references and existing kit contracts. VPN profiles contain invalid placeholder keys intentionally. No VPN software/configuration was activated, no live network policy or database changed, and no new GitHub release or signing operation was performed for this documentation update. The new skill passed structural validation and independent scenario review. The exact Python registry-generator example was exercised on Python 3.13.5 and Git 2.49.0.windows.1 using private fixtures. Exact ordering/hashes and self/signature exclusion passed; unstaged changes, unsupported index modes, unresolved merges, empty payloads, case collisions and alternate-case reserved names were rejected. The latter exposed a case-alias overwrite defect during review, which was fixed before these checks passed. Real symlink creation was denied by Windows and unusual index names were rejected by Windows Git before reaching the generator; those cases remain untested end-to-end. Four VPN INI/JSON fragments parsed using standard-library parsers, which does not validate keys, vendor schemas, policy or connectivity.

Eight Git ignore checks confirmed removal of the three AMQIC-specific patterns while preserving representative generic secret, credential-store and dependency exclusions. ClamAV/Redis/PoW documentation was reviewed as design guidance only; no scanner, datastore or admission gateway was run or installed. No malicious specimen is distributed.

## Website personal-data input update — 13 November 2026

Eight new Node tests passed for `pii-input.mjs`, and all 36 existing core/login tests remained passing. New cases cover the supported Unicode/IDNA profiles, valid email punctuation, schema/type/mass-assignment rejection, getter non-execution, length/control limits and errors without echoed values. An actual in-memory SQLite test inserts SQL, shell and HTML-looking message text through fixed bound parameters, reads the same text back, and confirms the table remains present with the expected rows. Invalid input causes no insert.

Independent adversarial checks confirmed IDNA expansion length enforcement, apostrophe-containing address storage, SQL-looking message retention and zero insertion on rejected fields. The test source uses synthetic values only and invokes no shell. The guide's safe DOM snippet and HTTP/body/CSRF/container integration requirements were source-reviewed, not exercised as a running website. This result does not establish that a consuming application's SQL, templates, exports or container configuration are safe.

The beginner walkthrough and Cloudflare edge guide received source/consistency and link review. They add no running protection by themselves. No Cloudflare zone, WAF/cache rule, DNS record or origin certificate was changed, and no live DDoS/traffic experiment was performed. The documented cache and reachability acceptance checks remain target-deployment requirements.

## Upload storage-isolation update — 13 November 2026

Four Compose configuration tests pass, including required-image refusal, distinct project-scoped volumes, no-copy mounts, role-specific read/write access, separate ingress networks and offline scanner/promoter settings. A Linux/amd64 laboratory used an existing Python 3.12.15 image by its immutable digest to run the exact Compose-expanded preparation code and four synthetic role programs. Directory ownership/mode 0750 and file mode 0640 matched the documented UID/GID plan. Intake could write quarantine without a clean/verdict mount; scanner could read quarantine but could not append; promoter could read inputs/verdicts and write clean content without modifying its read-only inputs; media could read clean content but could not append and had no quarantine/verdict mount.

All five laboratory containers and all three exclusively owned volumes were removed, followed by exact absence checks. No host paths or production data were mounted. All laboratory roles used network none, including the two roles that have separate internal networks in the template; actual ingress networking was not exercised. The result establishes these synthetic filesystem/mount boundaries, not antivirus detection, verdict trust, race-safe promotion, HTTP access control or the behavior of a supplied production image. Those application contracts remain explicit integration requirements in [UPLOAD-ISOLATION.md](UPLOAD-ISOLATION.md).

## Adoption boundaries

The HTTP/MCP transport, real CAPTCHA provider, production factor store, enrollment/recovery, audit delivery, and operational database handlers require application integration according to [reference/README.md](../reference/README.md). The examples changed only synthetic records and files.

Production rollout additionally requires the actual certificates, domain, proxy ranges, host routes, DHCP/IPv6 behavior, SSH recovery access, egress policy, application compatibility, and operational rollback plan. The examples and laboratory results do not activate those systems.

The maintainer signs the final SHA256SUMS registry separately. A matching hash list without its authenticated signature does not establish release provenance; follow [RELEASE-VERIFICATION.md](RELEASE-VERIFICATION.md).
