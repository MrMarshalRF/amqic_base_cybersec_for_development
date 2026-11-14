# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to [cyber@amqic.ai](mailto:cyber@amqic.ai). Use a subject such as `Security report: amqic_base_cybersec_for_development`.

Include the affected file and commit or release, the expected and observed behavior, prerequisites, impact, and a minimal reproduction using synthetic data. Explain whether the issue affects an example, a generator, an integration contract, or a deployed configuration. Remove passwords, tokens, private keys, personal data, and production records before sending.

Keep exploit details out of public issues while the report is being assessed. A public issue can point to this policy without including sensitive details. Reports should stay within authorized, non-disruptive source review and isolated testing.

## Response targets

We aim to acknowledge reports within **three business days** and provide an initial assessment within **seven business days**. For an accepted report, we aim to send a progress update at least every **14 calendar days** while work continues. These are best-effort targets rather than a guaranteed service level. If an acknowledgement has not arrived, please follow up on the same email thread.

Severity, reproducibility, affected integrations, and the availability of a compatible fix determine the remediation schedule. We will coordinate disclosure with the reporter after a fix or mitigation is available, or agree on another date if resolution requires more time.

## Supported source

Security fixes are developed against the current `main` branch and the latest maintained release once releases are published. Please include the exact commit or signed release files used in a report. Older snapshots should be checked against the current source before relying on a fix. This project provides baseline examples and templates; applications that integrate them remain responsible for their own configuration and deployment validation.

## Release and wallet verification

Official release signing is performed by the maintainer before publication. Verify the signed [SHA256SUMS registry](SHA256SUMS) at [AMQIC request verification](https://amqic.ai/pages/request-verification), then compare the exact release files with its entries. The maintainer's verification service and trusted signing identity are the authority for that check.

The public support addresses are also listed in [wallets.txt](wallets.txt). Verify the registry signature and the wallets.txt hash before relying on its addresses. A matching address copied from two files in the same repository does not independently establish authenticity. Changed files require an updated registry and a new registry signature.

## Scope and attribution

Security reports may cover authorization, cryptography usage, file handling, metadata parsing, generated infrastructure rules, tests, and misleading security claims in the documentation. Please distinguish a demonstrated defect from a deployment prerequisite or an unsupported use case.

We appreciate coordinated reports and can credit reporters with their consent. This policy does not establish a paid bug bounty or authorize testing of third-party systems.

## Binary transformation and VPN boundaries

The [binary guide](docs/BINARY-OBFUSCATION.md) distinguishes metadata reduction from obfuscation and maps the release process to NIST SSDF 1.1 PO.3, PO.4, PW.6, PW.8, PS.2 and PS.3. [OWASP MASVS-RESILIENCE](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE/) and [MASTG](https://mas.owasp.org/MASTG/) supply mobile resilience goals and testing references, not a general certification for this kit. The added references were checked on 13 November 2026. Compilers, GNU binutils, Go, version-specific Garble and Android R8 sources are linked next to the respective recipes.

Obfuscation is not a boundary for passwords, private keys, access control or release authenticity. Preserve privately recoverable diagnostics and required runtime contracts, verify the transformed artifact, and sign/hash the final bytes. A downloaded binary with matching hashes can still contain defects or malicious behavior; authenticate the registry and review the source and build process.

The [VPN guide](docs/VPN-TUNNELS.md) references official WireGuard, WireSock and Tailscale documentation. Tunnels protect transport and restrict network reachability when configured correctly; they do not replace host firewall policy, application authentication, administrative authorization, or safe recovery. Verify the actual source address seen by Nginx after proxies, relays and subnet routing. No VPN client, server or live access policy is installed by this repository update. The [deployment runbook](docs/DEPLOYMENT.md) describes authorization, backup/restore, target checks and rollback; the [GitHub release guide](docs/GITHUB-RELEASES.md) separates source inventories, final artifact hashes, registry signatures and publication. Neither checklist establishes that an untested deployment is secure.

## Website personal-data input

The [web input module and guide](docs/WEB-INPUT-PROTECTION.md) separate strict contact-field validation from injection prevention: database statements are fixed and values bound; output uses text-safe contexts and the handler does not invoke a shell. Container privilege, runtime/tool, filesystem and network restrictions add containment without making submitted bytes trusted. The module is not an HTTP server, universal identity validator or encrypted PII store. Applications must implement body limits, CSRF where applicable, authorization, safe views/exports, privacy controls and target-container checks. OWASP input-validation, SQL/OS-command injection and XSS guidance is linked with scope in the guide.

## External web edge and caching

The [Cloudflare guide](docs/CLOUDFLARE-EDGE.md) cites official proxy, TLS, origin authentication, DDoS, WAF and caching documentation. Its acceptance conditions include restricted origin ingress and explicit bypasses for authenticated/personal responses, with independent-user tests. Product availability and effective rule ordering must be checked on the target zone. No Cloudflare account, cache, DNS, firewall or WAF setting was changed or live-tested for this documentation.

## Additional service-protection guidance

The [service-protection guide](docs/SERVICE-PROTECTION.md) references the official ClamAV manual, Redis security/ACL/TLS and persistence documentation, and OWASP denial-of-service and API resource-consumption guidance. ClamAV is an additional content check, not a proof of safety. Redis must stay private and its eviction/restart/failover behavior must match the security state it stores. A request proof-of-work gate cannot replace authentication, CAPTCHA, step-up, container isolation or durable idempotency. The standalone [admission implementation](reference/admission.mjs) now supplies a tested challenge and Redis limiter; it is not automatically attached to the existing core or a production API. These additions are source-reviewed guidance, not an attestation of a production deployment.

## Optional SandHive review boundary

[SandHive](docs/SANDHIVE.md) is an optional external reference for case-guided review, consistent with NIST SSDF PW.7 and PW.8. This kit does not download, install or execute its toolkit and does not include it in the laboratory. External cases are untrusted evidence: assess their assumptions and collect current-target evidence before reporting a vulnerability. Reading recommendations grant no installation or execution authority.

## AI-driven local verification

[The all-local laboratory](docs/ALL-LAB.md) provides a fixed scenario runner and typed plan/results for agents. Preparation is explicit; commands are not accepted from HTTP input or generated test reports. The catalogue distinguishes local mechanisms from real provider/account/manual validation, and resource cleanup is part of acceptance. Source integrity and a successful local plan do not authorize a production or external-account change.

## Reproducible v1.2 evidence

The [working lab](docs/REPRODUCIBLE-LAB.md), [machine-readable claims](verification/claims.json), [per-file coverage](verification/coverage.json) and [completion protocol](verification/v1.2.0-report.json) distinguish executable references, configuration and guidance. HTTP/SQL/browser and ClamAV/Redis consumers use synthetic data and loopback services. The standard mappings below identify objectives, not certification. Follow the named commands and inspect actual results; neither a workflow file nor a source comment proves a test passed.

## Standards mapping for the v1.1 additions

These are **selected reference mappings, not certification or evidence of complete conformance**. A standard/control explains an objective; a vendor manual explains a particular product. Neither proves that a template has been deployed or that an application satisfies the complete requirement. New mappings were checked on **13 November 2026**; [VALIDATION.md](docs/VALIDATION.md) records the actual tested scope.

Version-qualified ASVS IDs below refer to the [official ASVS 5.0.0 release data](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv). NIST control IDs refer to [SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final). SSDF practices refer specifically to [SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final). Select the full applicable requirements and assessment criteria for the target system; a subset of IDs does not establish an ASVS level or NIST assessment.

| New mechanism | Explicit standard / practice references | Relationship and evidence boundary |
| --- | --- | --- |
| [Website PII fields and injection prevention](docs/WEB-INPUT-PROTECTION.md) | ASVS `v5.0.0-1.2.1`, `v5.0.0-1.2.4`, `v5.0.0-1.2.5`, `v5.0.0-2.1.1`, `v5.0.0-2.2.2`; NIST `SI-10`, `AC-3` | Output handling, query/command boundaries, input rules and server enforcement. The reference validates one contact profile and binds SQL values; HTTP, rendering and application authorization need integration tests. |
| [Upload isolation and controlled promotion](docs/UPLOAD-ISOLATION.md) | ASVS `v5.0.0-5.1.1`, `v5.0.0-5.2.1`–`v5.0.0-5.2.6`, `v5.0.0-5.3.1`–`v5.0.0-5.3.3`; NIST `AC-3`, `AC-6`, `SC-7`, `SI-10` | Document upload policy, bound content, avoid uploaded-code execution and attacker-selected paths. The Compose topology separates mounts and identities; trusted split-role production intake/scan/promotion/download implementations remain required. |
| [ClamAV and quarantine](docs/SERVICE-PROTECTION.md) | ASVS `v5.0.0-5.4.3`; NIST `SI-3` | Scan untrusted content before serving it, maintain detection data and define failure/response handling. A clean scan does not prove harmlessness; the real scanner is exercised only in the synthetic lab; production detection data/service is not supplied or certified. |
| [Redis security state](docs/SERVICE-PROTECTION.md) | NIST `AC-3`, `AC-6`, `SC-7`, `SC-28`; ASVS `v5.0.0-2.2.2` where untrusted structured data is consumed | Restrict identities, commands, namespaces and network access; protect sensitive stored state. Redis is an implementation option, not a standard or an automatic durable authorization authority. |
| [Request proof of work and resource limits](docs/SERVICE-PROTECTION.md) | NIST `SC-5`; [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | Optional bounded request admission relates to availability/resource protection. The standalone reference has binding/replay tests; no standard HTTP/MCP puzzle protocol, DoS-resistance proof or production activation is claimed. |
| [VPN, private access and constrained containers](docs/VPN-TUNNELS.md) | NIST `AC-3`, `AC-6`, `SC-7`; [SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) for human authentication lifecycle | Keep network boundaries and authentication separate. WireSock/Tailscale and Docker manuals govern implementation details; a tunnel or container does not establish an authentication assurance level. |
| [Cloudflare edge and sensitive caching](docs/CLOUDFLARE-EDGE.md) | NIST `SC-5`, `SC-7`, `AC-3`; ASVS `v5.0.0-14.2.2`, `v5.0.0-14.2.5`, `v5.0.0-14.3.2`; [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) §§3.5, 5.2, 7.3 | Availability, origin boundaries and sensitive-cache separation. RFC cache semantics and effective vendor overrides must both be checked; no live Cloudflare settings or cache-isolation tests are asserted. |
| [Binary transformations](docs/BINARY-OBFUSCATION.md) | [OWASP MASVS-RESILIENCE](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE/), [MASTG](https://mas.owasp.org/MASTG/); SSDF `PW.6`, `PW.8` | Mobile resilience references inform appropriate threat-specific choices; SSDF covers build configuration and tests. Stripping/obfuscation does not substitute for access control, encryption or complete mobile-standard conformance. |
| [Secure deployment and recovery](docs/DEPLOYMENT.md) | NIST `AC-6`, `CP-9`, `CP-10`; SSDF `PO.3`, `PO.4`, `PW.8` | Least privilege, backups/recovery, toolchains and acceptance evidence. The runbook needs actual target-specific authorization, restore, migration and rollout tests. |
| [GitHub releases and SHA-256 registries](docs/GITHUB-RELEASES.md) | SSDF `PS.2`, `PS.3`; [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | Release integrity, archival and the hash primitive. A registry needs authenticated provenance; SHA-256 does not by itself authenticate a maintainer or establish safety. |

For upload handling, also use the [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) as implementation guidance. In particular, perform the ASVS pre-extraction size/count checks **before** uncompressing, then enforce actual expansion/time limits while processing untrusted archives. Runtime-only limits do not demonstrate satisfaction of the preflight requirement. Vendor documentation and cheat sheets are distinguished from formal specifications/control catalogs.

## Technical source register

The register below identifies algorithm specifications, verification references, and official component guidance relevant to the kit. Links and publication versions were checked on **12 November 2026**. A reference documents the basis for a design choice or a review target; it does not establish complete conformance, certification, or a validated cryptographic module. Executed evidence is recorded separately in [VALIDATION.md](docs/VALIDATION.md).

### NIST publications

| Reference | Relationship to this repository | Scope of the reference |
| --- | --- | --- |
| [FIPS 197, AES, updated 2023](https://csrc.nist.gov/pubs/fips/197/final) | AES-256 used through Node's crypto library in `scripts/archive_crypto.mjs`. | Block-cipher specification; platform/module validation remains separate. |
| [SP 800-38D, GCM, 2007](https://csrc.nist.gov/pubs/sp/800/38/d/final) | Authenticated archive encryption, AAD-bound headers, nonces, and tag verification. | GCM reference. NIST has announced revision work; review current updates before deployment. |
| [FIPS 180-4, SHA-2, 2015](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | SHA-256 file registries, body digests, and verifier records for random tokens. | Hash algorithm reference. Hashes require an authenticated origin to establish provenance. |
| [FIPS 186-5, Digital Signature Standard, 2023](https://csrc.nist.gov/pubs/fips/186-5/final) | Background for classical digital signatures; the internal machine-request example uses Ed25519. | Distinct from the maintainer's post-quantum release-registry signing system. Review published errata. |
| [SP 800-63B-4, authentication, 2025](https://pages.nist.gov/800-63-4/sp800-63b.html) | Review reference for authenticator lifecycle, OTP replay control, rate limiting, sessions, and recovery. | The sample does not assert an Authentication Assurance Level. Enrollment, recovery, browser transport, and phishing-resistant options need application verification. |
| [SP 800-57 Part 1 Rev. 5, key management, 2020](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Review reference for key ownership, protection, registration, rotation, revocation, and recovery. | The kit supplies examples and operator guidance, with protected production key stores integrated separately. |
| [SP 800-218, SSDF v1.1, 2022](https://csrc.nist.gov/pubs/sp/800/218/final) | Review reference for dependency handling, code review, release integrity, and vulnerability response. | This project records selected practices and tests; it does not assert a complete SSDF assessment. |

### Algorithm and protocol specifications

| Source | Repository relationship |
| --- | --- |
| [RFC 8032, EdDSA](https://www.rfc-editor.org/rfc/rfc8032.html) | Ed25519 machine-request signing through Node crypto. The custom request envelope also needs its own transport and authorization checks. |
| [RFC 6238, TOTP](https://www.rfc-editor.org/rfc/rfc6238.html) | TOTP generation, published test vectors, and persisted consumption of accepted counters. |
| [RFC 7914, scrypt](https://www.rfc-editor.org/rfc/rfc7914.html) | Password and archive-passphrase key derivation through the runtime library. Select resource parameters for the target environment; listing NIST references above does not classify scrypt as a FIPS-validated implementation. |
| [W3C CSP Level 3](https://www.w3.org/TR/CSP3/) | Origin response policy and preservation of jointly enforced application policies. The referenced CSP3 document is a working draft; browser behavior and application compatibility require testing. |
| [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Transport-integration requirements for an application exposing the fixed tool catalog over HTTP MCP. The kit supplies an internal authorization core, with the full protocol adapter integrated separately. |

### Verification and component guidance

| Source | Repository relationship |
| --- | --- |
| [OWASP ASVS 5.0.0](https://asvs.owasp.org/) and [Top 10:2025](https://top10.owasp.org/2025/) | Selected requirements and risk categories are mapped, with evidence and integration gaps, in [OWASP-MAPPING.md](docs/OWASP-MAPPING.md). |
| [Node.js crypto](https://nodejs.org/docs/latest-v22.x/api/crypto.html) and [SQLite API](https://nodejs.org/docs/latest-v22.x/api/sqlite.html) | Runtime cryptographic primitives and local transaction behavior used by the reference implementation. |
| [Nginx request limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html), [real IP](https://nginx.org/en/docs/http/ngx_http_realip_module.html), and [headers](https://nginx.org/en/docs/http/ngx_http_headers_module.html) | Per-location rate handling, trusted-proxy address restoration, and header inheritance. |
| [OpenSSH server configuration](https://man.openbsd.org/sshd_config) and [nftables manual](https://netfilter.org/projects/nftables/manpage.html) | Key-only administrative access and typed ingress-firewall candidates. |
| [Docker security](https://docs.docker.com/engine/security/) and [seccomp](https://docs.docker.com/engine/security/seccomp/) | Reduced container privileges, namespaces, syscall restrictions, and their limits. |
| [KeePassXC user guide](https://keepassxc.org/docs/KeePassXC_UserGuide) | Password database, backup, key-file, and recovery guidance. |

The original source code and documentation are licensed under [MIT](LICENSE). External standards and documentation retain their own licenses. Their inclusion here does not imply endorsement by NIST, OWASP, component maintainers, or a certification authority.
