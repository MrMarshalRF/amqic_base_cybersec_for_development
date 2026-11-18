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

## VirusTotal file verification

The [current file register](VIRUSTOTAL.md) links each available observation to its exact SHA-256. The [JSON report](VIRUSTOTAL.json) retains individual engine results, analysis/retrieval times and category totals. Compare the local file hash before relying on a report. A result for an older revision does not cover a changed file, even when its name is identical. Pending rows have no current scan result and are not a passed check.

The [official VirusTotal result definitions](https://docs.virustotal.com/reference/analyses-object) distinguish completed analyses from individual engine outcomes. `undetected` means the engine reported no detection; it does not prove that source code or its deployment is safe. `type-unsupported` means that an engine could not analyze the file type. `timeout`, `confirmed-timeout` and `failure` remain visible operational limitations; they are never converted into successful checks. Local tests and source review provide different evidence and do not erase a scanner observation.

This repository's register contains only current file paths. Generated `VIRUSTOTAL.json`, `VIRUSTOTAL.md` and `SHA256SUMS` are identified as metadata rather than claiming recursive antivirus self-verification. The reports are covered by the authenticated release registry; the registry excludes itself and needs the maintainer's signature. Report updates or any source edit require new hashes and a newly authenticated registry before publication.

Submitting a file to the public service can disclose it to VirusTotal and its partners; see [VirusTotal's upload documentation](https://docs.virustotal.com/reference/files-scan). Upload only explicitly authorized public payloads. Do not submit credentials, private source, customer records, database exports or sensitive diagnostics. A VirusTotal API key is entered through the operator's protected terminal process and is not included in source, reports or release assets.

These observations relate to the malware-protection objective in [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) `SI-3`. Broader vulnerability review/monitoring (`RA-5`) and [SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) `PW.7`/`PW.8` still require appropriate source analysis and executable tests. Antivirus observations alone do not establish CVE coverage, application authorization correctness, certification or complete satisfaction of those controls.

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

## Database security and field-encryption references

The [database guide](docs/DATABASE-SECURITY.md) distinguishes row authorization, column selection, authenticated field encryption and distributed replay state. The PostgreSQL example enforces tenant isolation through restricted database principals and RLS; the field module enforces a trusted authorization/KMS contract. Real application identity, production KMS/IAM, replication/failover, TLS and key recovery require deployment-specific verification.

The database mapping below was checked against the linked primary sources on **15 November 2026**. ASVS identifiers refer to the [official 5.0.0 English requirement data](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv); chapter references identify review areas, not an achieved verification level. NIST references are selected Rev. 5 control relationships, not a full assessment or a claim that every supplemental update is implemented.

| Mechanism | Primary sources and applicable control areas | Boundary |
| --- | --- | --- |
| Row and column authorization | ASVS `v5.0.0-8.2.2` (data-item authorization), `v5.0.0-8.2.3` (field authorization); [PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html), [privileges](https://www.postgresql.org/docs/current/ddl-priv.html), [OWASP Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html); NIST `AC-3`/`AC-6` | Tenant identity comes from restricted DB principals. Superuser/BYPASSRLS, migration roles, pooled identity and security-definer interfaces remain privileged boundaries. |
| Safe selection and output | ASVS `v5.0.0-1.2.4` (parameterized data selection); [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html); NIST `SI-10` | Bind values, allowlist identifiers and select explicit fields. Bound SQL does not authorize rows, HTML output or operating-system commands. |
| Field encryption and KMS | ASVS 5.0.0 chapters `V11` (Cryptography) and `V14` (Data Protection); [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), [SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final), [OWASP Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html); NIST `SC-12`/`SC-13`/`SC-28` | Authorize before KMS unwrap; authenticate tenant/record/field/version identity and key metadata. Wrapped DEKs complement access control. Test providers are not live KMS/HSM or certification. |
| Shared replay enforcement | [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) `AC-3`/`SC-23` and [PostgreSQL unique constraints](https://www.postgresql.org/docs/current/ddl-constraints.html) | Nonce uniqueness, expiry and replay-state enforcement must remain consistent across instances. Atomic primary writes, time sampled after serialization, persistence and fail-closed storage behavior are distinct from production failover verification. |

## Origin path registry and repository hygiene

The [protected-path registry](infra/protected-paths.json) supplies literal path boundaries for the [Nginx renderer](infra/nginx/render.py), complementing deny-by-default routes. The example [.gitignore](.gitignore) controls future Git tracking; it does not restrict HTTP access or remove credentials already committed. Probe logs identify requested paths, not proof that a file exists, that a secret was disclosed or that an attacker succeeded. Public resources and legitimate versioned configuration must be reviewed separately from private runtime credentials.

These boundaries relate to [OWASP Secrets Management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), NIST `AC-3`/`AC-6`/`SC-7`, and SSDF `PS.1` (protect code from unauthorized access and tampering). A generated rule, ignore pattern or successful local test does not establish the configuration of a live origin.


### Technical paths, static-location precedence and release hygiene

The portable origin model evaluates protected-path predicates at server rewrite level before location dispatch. Administrative source maps need this boundary even when a later `^~` static-assets location owns their directory: a location-only regex may be skipped. Keep the canonical literal registry distinct from executable class predicates; a descriptive `*.map` label is not automatically an enforced wildcard rule. See the [Cloudflare/Origin procedure](docs/CLOUDFLARE-EDGE.md#closed-technical-paths-and-administrative-source-maps) and the [Nginx rewrite processing order](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html).

These measures support the existing NIST SP 800-53 `AC-3`/`SC-7` boundary goals and SSDF `PS.2`/`PS.3` release-integrity practices; they are implementation examples, not certification or complete traversal/exposure prevention. Git ignore rules, tracked-file review, deployment-artifact inspection and HTTP denial serve separate purposes. A user-agent name, isolated 4xx response or sampled edge event is not evidence of a compromise. Public incident summaries must exclude raw per-source operational evidence and private infrastructure identifiers.

## v1.6.0 distributed and operational controls

| Area | Control objectives and reference | Deployment check |
| --- | --- | --- |
| Distributed admission | AC-3, SC-5 and SC-23. [PostgreSQL and Redis reference](enterprise/distributed/README.md). | Test primary fencing, durability, clock discontinuity and replay retention before reopening traffic after failover. |
| Cloud key custody | AC-6 and SC-12. [Cloud KMS adapters](enterprise/cloud-kms/README.md). | Pin provider resources and enforce workload IAM. Verify unwrap of existing records across rollout and key rotation. |
| Federation | IA-2 and AC-3. [Federation reference](enterprise/federation/README.md). | Review each tenant/issuer binding, key rollover, replay state, role mapping and deprovisioning. |
| Operational records | AU-6, AU-9, AU-11, AU-12 and IR-4. [Operational playbooks and SIEM export](enterprise/operations/README.md). | Establish checkpoint custody, transport authentication, retention ownership, alerts and incident exercises. |

See the [component threat models](enterprise/THREAT-MODELS.md) and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for the applicable control objectives.

## v1.5.0 enterprise security controls

The [enterprise profile](enterprise/README.md) maps the new references to local tests and deployment checks. See the [scenario catalogue](lab/scenarios.json), [claims](verification/claims.json) and [validation guide](docs/VALIDATION.md) for the executable scope. The references below are control objectives from [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) and [SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

| Area | Controls and local verification | Deployment verification |
| --- | --- | --- |
| Policy enforcement, tenant isolation and abuse controls | [Policy reference](enterprise/policy/README.md). AC-3 and SC-5. CI validates the example policy. Local tests exercise tenant and resource binding, denial, and per-tenant risk-based quotas using a shared SQLite file. | Verify trusted identity and authorization at the storage or side-effect boundary. Apply and test PostgreSQL RLS with actual service roles, tenant key separation and shared quota enforcement for distributed workers. |
| Audit trail and evidence | [Evidence and audit tools](enterprise/evidence/README.md). AU-9 and AU-12. Tests exercise event integrity, checkpoint binding and detached Ed25519 verification. The workflow exports JSON and Markdown and retains check outcomes and digests. | Verify the trusted checkpoint and verifier key, access to raw diagnostics, evidence retention, and delivery to the production collector. The assessor determines how the evidence applies to the operating period and control scope. |
| Supply chain | [Supply-chain tools](enterprise/supply/README.md). SSDF PS.2 and PS.3. Local checks cover hashes, npm archive integrity, binary allowances and signed payload bindings. CI exports a CycloneDX inventory of declared lab images. | Generate the SBOM from the actual build inputs and outputs, verify the signer and builder, and assess build provenance. The signed inventory and example workflows do not assign a SLSA level. |
| Credential lifecycle and KMS rotation | [Rotation reference](enterprise/rotation/README.md). IA-5 and SC-12. Synthetic tests cover scope, expiry, activation, ambiguous outcomes and retention of old key versions. | Verify real Vault or cloud KMS permissions, workload identity, atomic provider reservations, lease revocation, old-key recovery and emergency rollback. |
| Workload hardening and Java response | [Runtime guide](enterprise/runtime/README.md). CM-6 and SI-2. Offline checks bind vendor findings to inventory and confirm a recorded rollout against the expected build, artifact and replacement process. The shipped Helm, OpenTofu and Falco examples are source reviewed. | Validate actual rendering, network and admission enforcement, the active workload profiles and runtime signals. Follow the vendor advisory for CVE-2026-114938, update each affected JVM and verify the running version after restart. |

The current report keeps local passes, source review, skipped checks and external work visible as separate outcomes. Audit mappings are preparation for an assessment. Production assurance requires evidence from the deployed system.

### Endpoint protection recommendation

The [README recommendation](README.md#kaspersky-endpoint-protection) treats endpoint protection as a deployment choice. Confirm supported updates, vendor trust, procurement restrictions and telemetry handling before installation. Endpoint scan observations, release integrity and the enterprise control tests each retain their own evidence.

## Subscription offers and entitlement grants

The [billing offer reference](reference/README.md#subscription-offer-eligibility) applies eligibility checks before recording a promotional entitlement. The backend matches the authenticated account and a provider-verified purchase against an explicit campaign policy. Client catalog entries, UI visibility and offer identifiers are untrusted inputs.

| Measure | Reference | Coverage |
| --- | --- | --- |
| Enforce eligibility on the backend. Bind the verified purchase to the authenticated account and match the product, base plan and offer against server policy. | [CWE-602](https://cwe.mitre.org/data/definitions/602.html), [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) AC-3 and SI-10 | The guard rejects mismatches, ineligible accounts, inactive or expired purchases, and test purchases. The application supplies the trusted account, policy and provider verification adapters. |
| Bound the trial at first issuance and enforce a single claim across workers. | [CWE-837](https://cwe.mitre.org/data/definitions/837.html), [OWASP API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | The shared SQLite ledger enforces uniqueness by purchase token digest and account/campaign. A retry preserves the original expiry cap. Local tests exercise two connections to the same database. |
| Configure eligibility at the billing provider and verify purchase state before granting or continuing access. | [Google Play billing abuse guidance](https://developer.android.com/google/play/billing/security), [SubscriptionPurchaseV2](https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptionsv2) | Deployment responsibility. Verify the application and line item through the authenticated provider API. Reconcile purchase acknowledgement, renewals, linked tokens, refunds, voided purchases and revocation. Use idempotent fulfillment for access granted by a separate service. |
| Limit campaign provisioning and monitor repeated denials or unusual issuance. | [OWASP API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/), [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) SI-4, AU-6 and AU-12 | Deployment responsibility. Set quotas and alert thresholds for the campaign. Use minimal redacted audit data and keep raw purchase tokens and payment credentials out of logs. |

The [billing tests](reference/billing-offer.test.mjs) use synthetic provider responses. Live provider and entitlement lifecycle behavior requires target-specific verification.
