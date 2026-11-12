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
