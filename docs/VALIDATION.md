# Verification results and scope

The final [v1.2 completion protocol](../verification/v1.2.0-report.json) records the actual commands, observed versions, source identities, results and remaining checks. [VERIFICATION.md](VERIFICATION.md) explains report semantics; [REPRODUCIBLE-LAB.md](REPRODUCIBLE-LAB.md) provides the working examples. A passing report establishes the exercised assertions, not that all defects or deployment risks are absent.

## Hosted CI corrections — v1.2.1

The first published v1.2.0 workflow exposed a concurrent SQLite initialization failure, incorrect project-path comparison with Windows short aliases, and a race between starting synthetic HTTP servers and probing their ports. The corrected code applies the busy timeout before WAL setup, resolves both sides of the executable-path comparison, and waits for the actual listener sockets before continuing. Security assertions and supported Node/OS matrix entries remain enabled.

All five jobs passed on the corrected candidate commit `06209c0a88c562b6d970e62a891cc076a3fa6a85`, including Node 22 and 24 on Ubuntu 24.04 and Windows Server 2022, plus the complete `all-local` job. The workflow retains bounded JSON/log diagnostic artifacts for seven days, so individual failed commands and infrastructure checks can be inspected. This hosted result complements the historical local v1.2.0 protocol. [Verified GitHub Actions run](https://github.com/MrMarshalRF/amqic_base_cybersec_for_development/actions/runs/43474444198)

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
