# Verification results and scope

## v1.8 database and application references

The fixed runner includes synthetic outbound transport/return-route and real local SQLite recovery tests. The PostgreSQL fixture records actual server_version and server_version_num, requires the reviewed17branch fixed minimum, and tests effective TEMP/public-schema denial under runtime roles while retaining allowed CRUD/replay. Distributed admission separately records its actual version and fixed-minimum result. No CVE triggers or external offensive tooling are executed.

The outbound suite validates checked-address lookup/TLS options and bounded event/cleanup behavior using synthetic trusted transports; live external TLS endpoints are not probed. Recovery tests do not mutate real credentials, prove delivery or revoke an external session. Oracle, campaign correlation, monitoring and cluster/provider integrations retain their documented operational scope. Current completion evidence must be generated against the final source snapshot; an earlier release's report is not reused as a new run.


## Nginx protocol-parser security profile

The baseline includes synthetic per-replica rollout tests. The pinned Nginx integration exercises protocol defaults and benign ALPN alongside existing TLS, Host/SNI, CSP, route, limiter and whitelist checks. Real provider settings, worker drain and ingress behavior require target observations. [Edge response guide](NGINX-EDGE-SECURITY.md)

## Distributed enterprise references

The baseline includes deterministic policy permutations, generated invalid inputs and a 256-request synthetic burst on the same-host policy fixture. The checks exercise canonical identity, denial and quota conservation. The runtime adapter suites use synthetic provider inputs and exercise the documented fail-closed boundary.

The separate distributed admission command exercises concurrent calls against pinned Redis and PostgreSQL containers, PostgreSQL restart with persisted state, and Redis state loss. The CI workflow saves its report alongside control evidence. Replication, promotion and split-brain recovery must be exercised on the target topology.

GitHub Actions includes PR dependency review with a pinned action. Dependabot proposes weekly GitHub Actions and Dockerfile updates. These checks cover their supported dependency graph and update inputs. Validate provider SDKs, workload identities, datastore failover and the IdP environment before deployment.

## Enterprise references

The fixed baseline runs the policy, evidence, supply-chain, rotation and runtime suites. The corresponding scenarios appear in the laboratory report, where their scope is limited to the named local tests. Hosted CI exports evidence after a successful full laboratory run. Test output records actual outcomes for each source revision.

Provider authorization, infrastructure rollout, signer identity, compliance assessment and production audit retention require verification in the intended environment. See the [enterprise adoption guide](../enterprise/README.md).

## Subscription offer eligibility

The synthetic billing tests exercise verified account binding, active purchase state, exact offer selection, expiry and campaign eligibility. Two SQLite connections check single issuance, idempotent retry, cross-account replay rejection and the one-claim-per-campaign rule. The baseline runner includes these tests. Provider integration and refund, renewal and revocation handling must be verified separately.

## Edge/origin boundary candidate — v1.3.1

The registry preserves the prior 146 entries and adds 12 canonical technical paths, for 158 total. A successful isolated Nginx run checked all 158 for exact `403`, with separate canonical/encoded/traversal controls. A deliberately permissive synthetic `^~ /assets/admin/` owner returned `200` for ordinary JavaScript/CSS, benign filename near-matches and a query-only source-map mention, while nested/case/slash/encoding map variants returned `403` before static dispatch. The permissive owner is a test fixture, not a new public route in the portable template.

All 33 runtime regression categories completed, including existing HTTP/TLS, hostname/SNI, CSP/error headers, website/API rate separation, upstream-policy preservation and trusted-peer/header checks. Six runtime-bound source hashes stayed unchanged; the exact test process, container and network were verified absent, and shared Docker container/network/volume membership was unchanged. The successful run used an explicit synthetic TLS fixture. Physical IPv6 transport and live Cloudflare parser/rule/configuration behavior were not tested.

Seventeen daemon-free harness/Git tests and eighteen production-preparation tests passed. The latter include a force-tracked ignored private file and a forged payload manifest: Git ignore decisions do not override package exclusions. Current tracked membership and the supplied private incident markers were reviewed separately; no private case identifiers or machine paths were copied into these changes. This bounded review is not an exhaustive proof of no secrets.

The Cloudflare expression is source-reviewed, plan-dependent guidance. It is not a deployed rule or a complete registry export. New or modified file bytes need matching VirusTotal observations and a newly authenticated final release registry; cached results from another hash do not cover this candidate.

## Origin-path and security-policy candidate — v1.3.0

The v1.3.0 registry had 146 canonical entries. The isolated Nginx run checked every entry for exact `403`, three encoded source-path default-deny cases, and fresh permitted root/API `200` controls, alongside the existing HTTP/TLS, Host/SNI, headers, CSP, rate and whitelist checks. The runtime-bound sources stayed unchanged and the owned Nginx container and network were verified absent. These are synthetic local results, not activation of a public origin or proof that a requested sensitive file existed.

Fifteen daemon-free tests passed, including per-literal rendered rule boundaries and actual Git ignore decisions for private files versus versionable source/public examples. Git fixtures isolate inherited Git variables, system/global/default excludes and templates; no user Git settings or source repository are modified. The security policy now documents VirusTotal category/hash boundaries and selected database/crypto/replay standards. Changes after any scan or signature need new evidence and a newly authenticated registry.

## Database-security candidate

The field-encryption module passed 23 tests on Node.js 22.14.0 using real AES-GCM and synthetic KMS adapters. The targeted combined suite passed 67 tests on both native Windows Node.js 22.14.0 and 24.22.3, covering field envelopes, core/PoW replay and laboratory dispatch. New replay regressions cover stale instance clocks after another connection advances time and prunes expired nonces. These results do not establish a live KMS policy or a production database deployment.

The PostgreSQL stage passed all eleven checks against PostgreSQL 17.12 (Debian 17.12-1.pgdg12+1) in the fixed digest-pinned image. It exercised real tenant/column/role restrictions, bound-value query fixtures, two independent connection claims with exactly one winner, a real server restart, expiration/pruning and clock-guard failure. Its exact owned container was removed and absence verified. This is a synthetic isolated primary, not a production tenant/KMS/failover assessment. The previous completion protocol below predates these additions.

The final [v1.2 completion protocol](../verification/v1.2.0-report.json) records the actual commands, observed versions, source identities, results and remaining checks. [VERIFICATION.md](VERIFICATION.md) explains report semantics; [REPRODUCIBLE-LAB.md](REPRODUCIBLE-LAB.md) provides the working examples. A passing report establishes the exercised assertions, not that all defects or deployment risks are absent.

## Hosted CI corrections — v1.2.1

The first published v1.2.0 workflow exposed a concurrent SQLite initialization failure, incorrect project-path comparison with Windows short aliases, and a race between starting synthetic HTTP servers and probing their ports. The corrected code applies the busy timeout before WAL setup, resolves both sides of the executable-path comparison, and waits for the actual listener sockets before continuing. Security assertions and supported Node/OS matrix entries remain enabled.

All five jobs passed on the corrected candidate commit `06209c0a88c562b6d970e62a891cc076a3fa6a85`, including Node 22 and 24 on Ubuntu 24.04 and Windows Server 2022, plus the complete `all-local` job. The workflow retains bounded JSON/log diagnostic artifacts for seven days, so individual failed commands and infrastructure checks can be inspected. This hosted result complements the historical local v1.2.0 protocol. [Verified GitHub Actions run](https://github.com/MrMarshalRF/amqic_base_cybersec_for_development/actions/runs/43474444198)

## Optional SandHive reference

The [SandHive recommendation](SANDHIVE.md) and its reading skill are source-reviewed documentation. There is no adapter, automatic download, external command execution or laboratory scenario for SandHive in this payload. Recommendation-only guidance is checked through skill validation, source/link review and exact coverage/registry membership. Reading a case is not a completed target security assessment.

## Reproduce the checks

```sh
node scripts/verify.mjs --output /absolute/external/baseline.json
node scripts/verify.mjs --full --output /absolute/external/full.json
```

Use a new report filename outside the source tree. The full profile requires the pinned local service images and Chromium browser described in the lab guide. Actual Nginx checks additionally require the explicit reviewed image and output arguments documented in VERIFICATION.md. The registry must match the final source before verification; the runner does not silently rewrite it.

## What each test establishes

| Area | Executed consumer or assertion | Boundary |
| --- | --- | --- |
| Authorization | Real core/login tests, current-session scope checks, expiry/revocation, replay and SQLite concurrency | Synthetic factor/CAPTCHA adapters; production identity lifecycle remains external. |
| Personal-data input | Typed schema/Unicode/size checks and real parameterized SQLite writes | One contact profile; not a universal identity parser or encrypted PII store. |
| HTTP application | Actual loopback requests for full login, CSRF, Host/Origin, owner checks, streaming-body limits and revocation | Local educational fixture, not public TLS or production scaling. |
| Browser output | Real Chromium form submission and readback; hostile-looking text remains literal and creates no executable DOM nodes | The supplied fixture only; other templates/exports need their own tests. |
| Upload pipeline | Persistent states, owner denial, exact content hashes, rejection, concurrent processing and changed-byte cases | Trusted service filesystem; no power-loss/fsync durability or hostile same-user sandbox claim. |
| ClamAV | Real VERSION/INSTREAM protocol, clean and custom-marker verdicts, rejection before download | Custom harmless signature database; not a malware-detection benchmark. |
| PoW | Bound challenge, MAC, proof, expiry, clock and replay tests including separate SQLite workers | Standalone API; no claim that every HTTP request is PoW-gated or that DoS is solved. |
| Redis | Fixed authenticated protocol, atomic concurrent limits and TTL reset against a real isolated service | Public synthetic lab password; production TLS, ACL policies, eviction and failover need deployment validation. |
| Backups/crypto | Archive/encryption/restore and tamper tests through existing public helpers | Running databases still need native consistent dumps/snapshots. |
| Release preparation | Existing include/exclusion, path and content checks | Bounded UTF-8 source, not arbitrary binary safety analysis. |
| Dependency/version handling | Offline quarantine/parser tests and version-report fixtures | Does not certify publisher trust, absence of vulnerabilities or future upstream versions. |
| Infrastructure | Compose normalization and existing Nginx/firewall generator tests; explicit actual-Nginx invocation when selected | Config checks alone do not prove provider/host enforcement or VPN reachability. |
| Evidence lifecycle | Missing/stale inventory refusal, source stability, outside-tree reports, browser/app/container/network cleanup | Hosted CI and production deployment are distinct observations. |

The machine-readable [claims](../verification/claims.json) connect these scopes to standards; [coverage](../verification/coverage.json) classifies every payload file. Documentation is marked as source-reviewed guidance rather than executable functionality. Each actual report preserves platform-specific skipped tests and omitted integrations.

## All-local mechanism laboratory

The [one-command entry](ALL-LAB.md) adds actual cache/privacy, SSH, nftables, WireGuard, password-manager, native-symbol and container-role checks to the fixed code/service suite. The public completion protocol records the final combined run; individual fixtures remain source-bound and can be rerun separately.

The infrastructure fixture exercises correct/wrong SSH keys, denied root/password login, allowed and denied TCP traffic under the shipped firewall renderer, and a real WireGuard handshake plus peer revocation inside disposable namespaces. It also checks a synthetic KeePassXC database, ELF debug-symbol separation and the shipped scratch-image restrictions. None of these operations changes a host VPN, firewall, account or personal vault.

The cache fixture uses two real Nginx instances with no public host ports. It verifies public MISS/HIT behavior, distinct upstream request identity, authorization/cookie bypass and private-response separation. It does not inspect Cloudflare account settings. The upload-role fixture consumes the real Compose mount/user configuration and checks read/write boundaries across dedicated volumes. These local consumer results are separate from production deployment assurance.

## Completion protocol interpretation

`passed` means the named check completed successfully; `failed` means it did not; `not_run` means that evidence is missing. The runner's aggregate `incomplete` status remains explicit even if a supported baseline exits zero. Read `status`, `complete` and every check rather than treating an exit code alone as full coverage.

The final public protocol contains the successful assertions and honest omissions. Private development logs are not release artifacts. Source identities exclude the final protocol itself to avoid self-reference; SHA256SUMS still covers that protocol. Hash matching is separate from verifying the maintainer signature.

## Environment and deployment limits

The recorded environment is the environment actually tested. A Windows host can exercise Node/Python, browser and Linux service containers, but cannot establish the Linux PTY result by a Windows skip. Node 24 and hosted Ubuntu/Windows matrix jobs are not considered run merely because a workflow lists them. Inspect a completed hosted run before citing its result.

No production Cloudflare zone, VPN, real-secret consumer, running application database, public origin, account or firewall is configured by these tests. Compiler/obfuscator guidance and provider-specific deployment steps retain their stated platform limits. Earlier release tests of unchanged infrastructure remain historical evidence, not a claim that this release activated those systems.

To deploy, follow [DEPLOYMENT.md](DEPLOYMENT.md) with target authorization, backups, restore proof, actual TLS/network policy, real enrollment/recovery and rollback. To authenticate the final package, follow [RELEASE-VERIFICATION.md](RELEASE-VERIFICATION.md).

## Agent runtime reference checks

The fixed baseline includes `enterprise/agent-runtime/agent-runtime.test.mjs`. The local scenario records the supported tool/argument, approval, generation, admission and offline egress checks. These tests use synthetic trusted adapters. They do not exercise OpenShell, kernel confinement, real secret injection, connect-time DNS/socket pinning, external token revocation or a SIEM collector. Keep these target checks distinct from the local completion result.

## Automated-probing reference checks

The fixed baseline runs `enterprise/probe-defense/probe-defense.test.mjs` with synthetic identities, temporary local SQLite databases and bounded concurrent workers. It checks combined limits, state continuity, ordinary denial semantics, inert canary delivery metadata and a conservative security.txt content profile. It does not run third-party scanners, identify an AI visitor, publish a contact endpoint, install a multi-host limiter or establish production detection effectiveness. The current Nginx path guard is preserved.

## Agent homes and standing overrides

The current protected-path registry contains 160 canonical entries. Production tests reject `.dsh` directories and `prompt-inject.md` override files before source reads, including nested/case variants and forged staging manifests. The offline harness checks the generated literal boundaries and actual Git ignore behavior; isolated Nginx validates every current registry entry. Runtime-integrity and third-party-reference guidance is source-reviewed only. No external plugin, installed-agent state or host FIM is executed or inferred as verified.
