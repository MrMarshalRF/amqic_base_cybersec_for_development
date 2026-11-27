# AI agent runtime: containment and controlled actions

This guide applies to coding agents, tool-using assistants, local MCP processes and autonomous workers that read untrusted material. Repository files, issues, web pages, tool descriptions, tool responses and messages from other agents are data, not authorization. A model may misunderstand that boundary. Enforce permissions in trusted services and the operating environment.

## Threat model and trust boundaries

Protect source, customer data, credentials, release integrity, privileged APIs, compute budgets and the ability to stop a run. Relevant entry points include retrieved content, poisoned tool descriptions, dependency installation, persistent memory and compromised operators. Distinguish the model, execution environment, egress mediator, control plane and human approval channel. Compromise of the trusted mediator or host is outside the reference guard's boundary.

| Risk | Primary control | Verify before deployment |
| --- | --- | --- |
| Prompt injection and misleading tool output | Separate unprivileged reading from privileged effects; fixed server-side tool authorization | Untrusted content cannot grant a tool or approve its arguments |
| Tool abuse and confused deputy | Exact catalog, argument schema, authenticated tenant and generation | Unknown tools, extra fields and a different generation are rejected |
| Credential disclosure | Separate secret broker, short-lived scoped identity, authenticated egress | Secrets absent from agent home, environment, mounts, logs and responses |
| SSRF and exfiltration | Exact destinations, connect-time address checks, outer egress fence | Metadata, loopback, link-local and undeclared destinations unreachable |
| Host access or persistence | Separate OS identity, non-root sandbox, immutable system paths | No Docker socket, SSH agent socket, host home or control-plane credentials |
| Supply-chain compromise | Reviewed pinned skills, MCP servers, images and dependencies | Description/version changes require review; no automatic install hooks |
| Permission drift | Reviewed boundary and explicit approval for widening | Unsupported policy dimensions fail closed |
| Cross-tenant access | Server-derived tenant, subject, resource ownership and per-run identity | Tokens and approvals from another run cannot authorize this run |
| Loss of operator control | External stop, token revocation and egress removal | Stop works while the agent is unresponsive |
| Resource exhaustion | Admission, duration, concurrency and spend budgets | Parallel attempts cannot overrun the permitted allowance |

## Deploy two separate enforcement layers

Use a sandbox with its own identity. Mount only the required working data, make system paths read-only, remove capabilities, enable no-new-privileges and an appropriate seccomp policy, and disable core dumps. Apply resource limits. A container shares the host kernel; use an appropriately isolated VM or user-space kernel for high-value or mutually untrusted workloads. Validate platform-specific confinement rather than assuming every Linux feature is available.

Route permitted traffic through an independently administered mediator. Add an outer firewall, enforced Kubernetes NetworkPolicy or disconnected network so ignoring proxy settings cannot bypass it. A Kubernetes policy requires a CNI that actually enforces it. Keep the policy, approval service, token issuer and kill switch outside the agent's writable filesystem and execution identity. Running a JavaScript guard inside an unrestricted agent process cannot constrain that process.

For an offline worker, start with no network at all. For a networked worker, allow only named destinations and specific methods and paths required by the task. Bind access to the reviewed executable or MCP identity/version where the enforcement platform supports it. Broad executable globs, unrestricted interpreter access and shell access invalidate that restriction. A file hash identifies bytes; establish publisher authenticity separately.

## Tested reference guard

[enterprise/agent-runtime](../enterprise/agent-runtime/README.md) contains a standard-library JavaScript reference and its runnable tests. It demonstrates a fixed tool catalog, strict arguments, exact approval binding, per-generation revocation, bounded single-instance admission, conservative egress planning and supported-policy narrowing. The normal one-command laboratory runs these tests:

```sh
node --test enterprise/agent-runtime/agent-runtime.test.mjs
node scripts/verify.mjs --all --output /absolute/external/all-local.json
```

Read the module's complete API and example before integration. Register handlers in trusted application code; do not let the model register a handler, provide an approval callback or change the policy. In this reference, approval hashes endpoint IDs, not endpoint definitions, real credential scope, executable hashes or MCP versions. Keep the trusted endpoint-ID-to-host/path/method/credential-reference mapping and handler/version mapping immutable for a session. Changing any mapping, executable or MCP revision requires revoking old generations and creating a freshly reviewed session. The actual handler and transport must enforce those definitions; the guard does not verify them. The example uses synthetic approval, not a real human confirmation channel. Retain the existing [step-up and exact sensitive-action binding](../reference/README.md#confirming-sensitive-actions) for destructive operations. A policy check does not replace that independent factor.

The egress helper checks a supplied address snapshot and produces a plan. It does not open sockets or enforce a sandbox. Its supported profile is deliberately narrow: exact HTTPS targets and public IPv4 addresses. IPv6 and other unsupported shapes are rejected. The trusted transport must resolve at connection time, reject the whole result if any answer is disallowed, connect to the checked address without resolving again, preserve the original hostname for SNI and certificate validation, and disable redirects. Never substitute a user-provided IP list for a trusted resolver. Recheck every new connection and after policy changes. Do not pass a successful offline plan to an unrestricted HTTP client and call that SSRF prevention.

The local policy comparator checks only its declared schema. It is not an SMT solver, a proof of deployment isolation or a statement that an allowed action is useful or safe. Unknown, unsupported and malformed input must not auto-approve. The local admission/replay state is bounded and held in one process. Multiple instances need a shared atomic authority; see [distributed admission and replay](../enterprise/distributed/README.md). Restart and failover must not silently revive an old generation.

## Credentials belong in a separate broker

Prefer workload identity and short-lived tokens. Where possible, the agent holds an opaque credential reference while an external mediator adds a credential only for an approved tool identity, hostname, port, method and path. Never attach a real secret to a request before destination authorization. Do not expose credential retrieval as an agent tool. Do not mount a user certificate that also grants operator control of the sandbox.

Credential injection reduces direct secret access. It does not guarantee that an upstream service, debugging endpoint, error response or framework exception cannot reflect that credential back. Restrict allowed APIs, avoid credential-echoing endpoints, review response handling and apply appropriate redaction/DLP. An authorized write can still be harmful. Keep destructive actions behind independent confirmation and application authorization. Do not include request bodies, authorization headers, URLs with tokens or tool arguments in general audit output.

Uninspected TLS, raw TCP, SSH and other bypass paths require a separate reviewed design. Do not assume the mediator can inspect or inject credentials into them. Use audience-specific tokens; never forward an MCP client token to an upstream API. See the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) and [security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices).

## Policy changes and confirmations

1. Load an authenticated, reviewed boundary policy outside the sandbox. Protect its files and distribution identity; SHA-256 alone is not authentication.
2. Derive tenant, actor, run generation and tool identity from trusted authentication and deployment state. The model cannot choose its own roles.
3. Validate and snapshot the exact arguments before requesting confirmation. Bind approval to the policy digest, generation, actor, tool and argument digest. Display the actual consequential action in the human channel.
4. Reserve admission and replay state before awaiting a decision. Check expiry, revocation and binding again immediately before dispatch.
5. Permit only supported narrowing automatically. New destinations, credentials, filesystem writes, executables or weaker approvals require a reviewed change outside the agent session.
6. Recreate the sandbox when changing immutable filesystem/process restrictions. Do not work around an unavailable confinement feature by granting the agent more privilege.

Manual approval can become ineffective through fatigue. Bound proposal rates and show a concise exact diff. A model's assertion that an action was approved supplies no independent evidence. A callback that always returns approval is only a test fixture. A correlation ID is a join key, not proof of identity, authorization or delivery.

## MCP clients and extension supply chain

Allowlist server identity, transport, version and tool catalog. Review tool descriptions on first use and after a change. Treat tool results and streamed responses as untrusted even if the request passed a gateway check. Run local MCP servers under their own constrained identity and egress policy. Pin and quarantine skills, plugins and helper packages using the [dependency workflow](OPERATIONS.md#dependency-quarantine). Avoid piping an installer directly into a shell. Inspect the artifact and authenticate its provenance first.

## Operations and emergency stop

Inventory each run's owner, tenant, generation, agent/runtime versions, artifact digests, OS identity, mounts, executable/tool permissions, destinations, credential references, limits, approval mode, telemetry choice and expiry. Record which component actually enforces every restriction. Never put secret values in this inventory.

Collect policy decisions, denials, proposals, approvals, credential-use metadata, generation changes and operator mutations. Use authenticated actor identity and server time. Correlate decision and execution results with an opaque request ID. The local guard emits only reserved/dispatch metadata. Denial reasons, authenticated approvals, completion/unknown-effect records and collector delivery are separate host responsibilities. Feed a reviewed mapping into the [SIEM reference](../enterprise/operations/README.md); its custom schema is not automatically an OCSF event. If using OCSF, validate against the selected release and class, and test schema/selector changes before upgrading collectors. Alert on repeated denials, unexpected destinations, policy weakening, confinement degradation, worker child shells, lost telemetry and failure to stop.

For a suspected hijack:

1. Freeze or stop the exact run through the external control plane, and prevent new dispatches and egress. Preserve identifiers and safe audit evidence.
2. Revoke the generation and detach/revoke its tokens through the issuing authority. Confirm acknowledgement and expiry behavior across replicas.
3. Check whether pending or already-running effects completed. Do not blindly retry actions with unknown outcomes. Local revocation can block a pending call; it cannot undo a request already delivered or a handler already running.
4. Preserve required diagnostics privately. Remove secrets and customer content before sharing evidence.
5. Recreate from a reviewed image and narrower policy. Verify confinement, approved traffic, denials and stop behavior before resuming. Do not restore a vulnerable runtime or weakened policy as rollback.

Keep retention, incident ownership, recovery access and token rotation in the [operations playbooks](../enterprise/operations/README.md). Exercise an unresponsive-agent stop and issuer-side revocation in the actual environment; a unit test of a revoked boolean is not that exercise.

## Optional reference: OpenShell

[OpenShell](https://github.com/NVIDIA/OpenShell) is an optional reference architecture, not an installed dependency or a certification of this kit. Review its exact deployed release, [security guidance](https://docs.nvidia.com/openshell/v0.1.9/security/best-practices), [policy model](https://docs.nvidia.com/openshell/v0.1.9/how-it-works/policies/overview), [providers](https://docs.nvidia.com/openshell/v0.1.9/how-it-works/providers/overview) and [prover limitations](https://docs.nvidia.com/openshell/v0.1.9/how-it-works/policies/prover). The linked v0.1.9 documentation was reviewed on 19 November 2026. This repository has not installed or tested OpenShell. Read the release and upgrade notes for the version actually deployed.

Make explicit decisions about telemetry, L7 enforcement, proposal approval, credential exposure, filesystem-policy degradation and administrator roles. The reviewed version documents `OPENSHELL_TELEMETRY_ENABLED=false` as an opt-out for its telemetry; configured external models/tools have separate data paths. Audit mode may record a violation while forwarding the request. Additional filesystem policy can have weaker behavior than the mandatory baseline. A policy prover covers only its modeled dimensions; unsupported protocols cannot be treated as a successful boundary check. Reconfirm these details against the deployed version and do not assume that changing a config file activates a host restriction.

## Standards and verification scope

| Control area | Official reference | Local evidence and remaining deployment work |
| --- | --- | --- |
| Prompt injection and excessive agency | [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) LLM01 and LLM06; [OWASP Agentic Top 10 announcement](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) ASI01/02/03/04/05/09/10 | Negative tool/argument/approval tests; real separation of reader and actor remains deployment work |
| Access and least privilege | [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) AC-3, AC-6 | Fixed catalog and exact binding; authenticated adapters, tenant enforcement and OS boundary require target evidence |
| Network boundaries and monitoring | NIST SP 800-53 SC-7, SI-4 | Conservative address tests; actual socket pinning, firewall/CNI behavior and alerts require target checks |
| Audit and change control | NIST SP 800-53 AU-3, AU-9, CM-3, CM-6 | Sanitized decision metadata and policy narrowing tests; collector custody, delivery and retention require operations |
| Incident response and supply chain | NIST SP 800-53 IR-4, [SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) PW.7/PW.8 | Revocation regressions and pinned source inventory; emergency stop, dependency review and recovery drills remain distinct |
| Agent threat taxonomy | [MITRE ATLAS](https://atlas.mitre.org/) | AML.T0051 prompt injection; AML.M0028 tool access, AML.M0029 approval, AML.M0032 segmentation and AML.M0037 authority expansion. Investigation/control leads, not a claim that every technique is blocked |
| AI risk governance | [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) and [NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1) | Task-specific risk ownership and evaluation; neither a sandbox standard nor a certification |

These are selected control relationships. Local tests demonstrate only the implemented reference behavior. They do not establish complete standards coverage, prompt-injection immunity, absence of exfiltration or deployment assurance.

## Installed files and policy provenance

The [integrity companion](AGENT-RUNTIME-INTEGRITY.md) covers approved installed-file baselines, launcher/configuration changes and extension review, with an optional external reference and no third-party integration. Interpret effective permission semantics for the exact product/version; compare them with the owner's approved host/task policy. Keep the enforcing identity, baseline and audit custody outside the agent's write authority.

## Untrusted tool output and role boundaries

Treat browser, crawl, retrieval and tool responses as untrusted data, even when
the request was authorized or the transport was authenticated. Never concatenate
raw response bytes into a handcrafted trusted conversation transcript or promote
them into system/developer policy. Use the backend's structured message/tool-result
interface, bounded decoding and provider-aware escaping/validation of control
syntax where required by that backend. Preserve provenance outside the content's
write authority and retain original evidence only in protected custody.

Delimiters and labels help a reader distinguish evidence, but cannot guarantee
neutralization or prompt-injection immunity. Test the actual serializer,
tokenizer/model endpoint and consumer boundary. A hosted provider, self-hosted
endpoint, filter or summarizer is not an independent authorization authority. If
the composition boundary cannot be established, hold that content for controlled
review or a bounded data-only projection; do not silently grant it trusted roles.

For example, a crawl response proposing a broader tool or network permission
remains an observation for review. The unchanged outside policy must deny any
ungranted action. An ordinary response containing useful domain facts is a near
match and should still be usable as data; rejecting all tool content is not a
functional integration. Original bytes, escaped display and separately reviewed
policy must remain distinguishable.

Enforce tool/catalog, exact arguments, actor/tenant, generation, expiry and
revocation independently of model text. A model can still be influenced after
formatting controls; it must not gain wider filesystem/network/credential rights.
For [high-risk networked tools](AGENT-CONFIG-REVIEW.md#manual-admission-for-high-risk-capabilities),
require the separate scoped grant and private engagement record where relevant.
These requirements are adoption guidance. This patch installs no serializer,
prompt filter, model gateway or new runtime guard behavior.

### Related application-boundary advisory

An [application-layer advisory](https://github.com/BitterSecurity/Decepticon/security/advisories/GHSA-g5f9-3xfg-p9mf),
published on 24 June 2026, describes untrusted crawl output crossing model role
boundaries under susceptible backend/tokenizer handling, with execution inside
the application's sandbox. It is related work for the composition requirement,
not a tool recommendation or proof that this kit reproduced, prevents or is
affected by that issue. No advisory control strings, procedures or third-party
implementation are copied. Hosted and self-hosted endpoints each require their
actual boundary to be evaluated.

## Independent resilience acceptance

Use [LLM resilience](LLM-JAILBREAK-RESILIENCE.md) to review identity, delegated scope, exact dispatch and output boundaries with ordinary, disallowed and unknown offline cases. Prompt delimiters, a persona claim or a tool result do not supply approval; standing low-risk authority and high-impact step-up retain their independently verified scopes. Shared state across replicas, OS isolation and actual network/credential enforcement remain deployment responsibilities. The [external reconnaissance guide](EXTERNAL-RECON-DEGRADATION.md) covers custody of inventory and captured service data supplied to a model.
