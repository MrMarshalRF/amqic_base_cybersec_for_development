# File validation matrix

Every public file in this candidate has a validation method recorded below. The matrix links to the files themselves; execution results and environments are summarized in [VALIDATION.md](VALIDATION.md). This is evidence for the tested scope, not a proof that every possible defect is absent.

Platform-specific skips are retained in the test reports. A file can be checked through a test suite or configuration consumer without being an executable entry point itself. The signed-registry step remains with the maintainer.

| File | Validation method | Scope boundary |
| --- | --- | --- |
| [.gitattributes](../.gitattributes) | Git attribute evaluation and raw Git/archive byte comparison | Preserves file bytes across checkout. |
| [.gitignore](../.gitignore) | Git check-ignore with current payload and private/public fixture paths | Commit filtering; not an HTTP access control. |
| [AGENTS.md](../AGENTS.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [LICENSE](../LICENSE) | Standard MIT text, holder, and year comparison | No separate ownership or third-party licensing audit. |
| [MANIFESTO.md](../MANIFESTO.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [README.md](../README.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [SECURITY.md](../SECURITY.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [SHA256SUMS](../SHA256SUMS) | Final digest and exact-membership check; raw Git/archive byte comparison | Registry authenticity requires the maintainer signature. |
| [THREAT-DATA.md](../THREAT-DATA.md) | Export arithmetic, path/sample totals, period duration, privacy and interpretation review | Underlying raw telemetry remains outside the public repository. |
| [assets/demo.gif](../assets/demo.gif) | All frames decoded; actual captured demo output compared; preview approved | Playback pacing is illustrative. |
| [assets/threat-data-daily.png](../assets/threat-data-daily.png) | Visual comparison with the supplied daily table and exact-byte source copy | Chart describes observed policy decisions, with maintenance denials separated. |
| [docs/INFRASTRUCTURE.md](../docs/INFRASTRUCTURE.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/INITIAL-DEPLOYMENT.md](../docs/INITIAL-DEPLOYMENT.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/KEEPASSXC.md](../docs/KEEPASSXC.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/OPERATIONS.md](../docs/OPERATIONS.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/OWASP-MAPPING.md](../docs/OWASP-MAPPING.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/PRODUCTION.md](../docs/PRODUCTION.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/RELEASE-VERIFICATION.md](../docs/RELEASE-VERIFICATION.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/SECURITY-MODEL.md](../docs/SECURITY-MODEL.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/VALIDATION-MATRIX.md](../docs/VALIDATION-MATRIX.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/VALIDATION.md](../docs/VALIDATION.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [docs/VERSIONS.md](../docs/VERSIONS.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [infra/container/Dockerfile](../infra/container/Dockerfile) | Actual static image build/layer inspection and isolated non-root app runtime | Runtime flags and observed behavior; no exhaustive escape or resource-exhaustion test. |
| [infra/container/compose.yaml](../infra/container/compose.yaml) | Actual static image build/layer inspection and isolated non-root app runtime | Runtime flags and observed behavior; no exhaustive escape or resource-exhaustion test. |
| [infra/container/quarantine.compose.yaml](../infra/container/quarantine.compose.yaml) | Actual prepare/fetch/offline-inspect profiles and wrong-hash refusal | External egress gateway policy remains deployment-specific. |
| [infra/container/quarantine.py](../infra/container/quarantine.py) | 56 archive checks plus actual pinned fetch/inspect workflow | No archive payload execution or installation. |
| [infra/container/test_compose.py](../infra/container/test_compose.py) | Three actual Compose normalization/refusal tests without starting services | Catches malformed mount lists and missing required inputs. |
| [infra/container/test_quarantine.py](../infra/container/test_quarantine.py) | 56 archive checks plus actual pinned fetch/inspect workflow | No archive payload execution or installation. |
| [infra/firewall/__init__.py](../infra/firewall/__init__.py) | 82 parser/policy checks; actual nft syntax, transaction, and packet tests | Synthetic configured addresses/ports; provider routing and DHCP remain target-specific. |
| [infra/firewall/addresses.py](../infra/firewall/addresses.py) | 82 parser/policy checks; actual nft syntax, transaction, and packet tests | Synthetic configured addresses/ports; provider routing and DHCP remain target-specific. |
| [infra/firewall/nftables.conf.template](../infra/firewall/nftables.conf.template) | 82 parser/policy checks; actual nft syntax, transaction, and packet tests | Synthetic configured addresses/ports; provider routing and DHCP remain target-specific. |
| [infra/firewall/policy.example.json](../infra/firewall/policy.example.json) | JSON placeholder/schema review; unconfigured input rejected; substituted policy tested in the lab | Operator must supply real trusted CIDRs before use. |
| [infra/firewall/render.py](../infra/firewall/render.py) | 82 parser/policy checks; actual nft syntax, transaction, and packet tests | Synthetic configured addresses/ports; provider routing and DHCP remain target-specific. |
| [infra/nginx/allowlist.client.example.json](../infra/nginx/allowlist.client.example.json) | JSON placeholder/schema review; unconfigured input rejected; substituted policy tested in the lab | Operator must supply real trusted CIDRs before use. |
| [infra/nginx/allowlist.peer.example.json](../infra/nginx/allowlist.peer.example.json) | JSON placeholder/schema review; unconfigured input rejected; substituted policy tested in the lab | Operator must supply real trusted CIDRs before use. |
| [infra/nginx/nginx.conf.template](../infra/nginx/nginx.conf.template) | Full isolated Nginx HTTP/TLS, rate, CSP, whitelist, and spoofed-header tests | IPv6 header data checked; physical IPv6 ingress remains target-specific. |
| [infra/nginx/render.py](../infra/nginx/render.py) | Full isolated Nginx HTTP/TLS, rate, CSP, whitelist, and spoofed-header tests | IPv6 header data checked; physical IPv6 ingress remains target-specific. |
| [infra/nginx/test_harness.py](../infra/nginx/test_harness.py) | 12 daemon-free timeout, cleanup, readiness, and port-metadata tests | Mocks cover failure paths; actual Nginx run covers the consumer. |
| [infra/nginx/test_nginx.py](../infra/nginx/test_nginx.py) | Full isolated Nginx HTTP/TLS, rate, CSP, whitelist, and spoofed-header tests | IPv6 header data checked; physical IPv6 ingress remains target-specific. |
| [infra/protected-paths.json](../infra/protected-paths.json) | Full isolated Nginx HTTP/TLS, rate, CSP, whitelist, and spoofed-header tests | IPv6 header data checked; physical IPv6 ingress remains target-specific. |
| [infra/ssh/00-security.conf.template](../infra/ssh/00-security.conf.template) | Actual sshd syntax/effective settings; good/wrong/root/password-only authentication | Ephemeral lab account and Ed25519 keys; no production access. |
| [reference/README.md](../reference/README.md) | English content/relative-link review and implementation/source consistency | External services, mailbox delivery, and future maintainer signing are separate. |
| [reference/core.mjs](../reference/core.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/core.test.mjs](../reference/core.test.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/crypto.mjs](../reference/crypto.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/demo.mjs](../reference/demo.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/fixtures.mjs](../reference/fixtures.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/login-client.mjs](../reference/login-client.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/login-client.test.mjs](../reference/login-client.test.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [reference/race-worker.mjs](../reference/race-worker.mjs) | 36 Node core/client tests plus actual end-to-end demo on Windows and Linux | Synthetic adapters; actual application integration remains separate. |
| [scripts/archive_crypto.mjs](../scripts/archive_crypto.mjs) | 16 crypto assertions, actual Linux PTY workflows, and immediate-input regression | Synthetic values only; protected production consumer not configured. |
| [scripts/backup.py](../scripts/backup.py) | 14 backup tests on Windows and Linux, with platform-specific cases | Static-file snapshots, links/names/roundtrip/corruption checked. |
| [scripts/check_versions.py](../scripts/check_versions.py) | 14 offline tests; live official runtime and public npm/PyPI metadata | Version currency and source coverage; no automatic updates. |
| [scripts/prepare_production.py](../scripts/prepare_production.py) | 14 production-preparation tests and real core-file staging/validation | Explicit text-file inventory; binary releases use a separate review. |
| [scripts/protected_input.mjs](../scripts/protected_input.mjs) | 16 crypto assertions, actual Linux PTY workflows, and immediate-input regression | Synthetic values only; protected production consumer not configured. |
| [scripts/secure_backup.mjs](../scripts/secure_backup.mjs) | 16 crypto assertions, actual Linux PTY workflows, and immediate-input regression | Synthetic values only; protected production consumer not configured. |
| [scripts/test_check_versions.py](../scripts/test_check_versions.py) | 14 offline tests; live official runtime and public npm/PyPI metadata | Version currency and source coverage; no automatic updates. |
| [scripts/test_crypto.mjs](../scripts/test_crypto.mjs) | 16 crypto assertions, actual Linux PTY workflows, and immediate-input regression | Synthetic values only; protected production consumer not configured. |
| [scripts/test_operations.py](../scripts/test_operations.py) | 14 backup tests on Windows and Linux, with platform-specific cases | Static-file snapshots, links/names/roundtrip/corruption checked. |
| [scripts/test_prepare_production.py](../scripts/test_prepare_production.py) | 14 production-preparation tests and real core-file staging/validation | Explicit text-file inventory; binary releases use a separate review. |
| [scripts/test_terminal_input.py](../scripts/test_terminal_input.py) | 16 crypto assertions, actual Linux PTY workflows, and immediate-input regression | Synthetic values only; protected production consumer not configured. |
| [skills/check-versions/SKILL.md](../skills/check-versions/SKILL.md) | Skill structure validation and consistency review against referenced helpers | Language instructions; no claim of enforced agent isolation. |
| [skills/prepare-production/SKILL.md](../skills/prepare-production/SKILL.md) | Skill structure validation and consistency review against referenced helpers | Language instructions; no claim of enforced agent isolation. |
| [skills/protected-terminal-input/SKILL.md](../skills/protected-terminal-input/SKILL.md) | Skill structure validation and consistency review against referenced helpers | Language instructions; no claim of enforced agent isolation. |
| [skills/review-dependencies/SKILL.md](../skills/review-dependencies/SKILL.md) | Skill structure validation and consistency review against referenced helpers | Language instructions; no claim of enforced agent isolation. |
| [skills/verified-backup/SKILL.md](../skills/verified-backup/SKILL.md) | Skill structure validation and consistency review against referenced helpers | Language instructions; no claim of enforced agent isolation. |
| [wallets.txt](../wallets.txt) | Exact user-provided addresses; Base58Check/network prefix or hex-format checks | Ownership/authenticity comes from the signed registry. |
