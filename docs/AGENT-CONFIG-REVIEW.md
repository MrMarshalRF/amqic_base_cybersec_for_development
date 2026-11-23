# Static agent configuration review

Review effective agent configuration and the complete instruction/skill/hook/MCP inventory before admission and on every change. Use the [offline reference module](../enterprise/config-review/README.md) with [runtime integrity](AGENT-RUNTIME-INTEGRITY.md), [extension review](../skills/review-dependencies/SKILL.md) and [runtime containment](AI-AGENT-RUNTIME.md). This supplies a CI/admission API, not an activated machine scanner or gate.

## Checklist

| Rule ID | Class and priority | Scoped or documented alternative |
| --- | --- | --- |
| `approval-disabled` | High: global effective approval disabled | Scoped approval or externally reviewed disposable-environment exception |
| `shell-unrestricted` | High: unrestricted shell pre-approval | Exact tools and bounded arguments enforced independently |
| `remote-execution` | High: hooks/skills combine remote acquisition with execution, including offers | Separate acquisition, exact-byte review and authorized execution; download without execution is a near match |
| `instruction-authority` | High: active instructions seek policy override, action concealment or confirmation bypass | Descriptive documentation stays data; active instruction changes need review |
| `instruction-unicode` | Medium: invisible/control/bidirectional characters in active instructions | Review exact bytes/rendering and legitimate language needs |
| `credential-access` | High: active instructions seek credential stores, SSH material, cloud credential files or password stores | Fixed broker references outside agent control |
| `mcp-unpinned` | High: package/image MCP launcher lacks an exact supported pin | Exact version/digest plus publisher and installed-state review |
| `mcp-plaintext` | High: plaintext MCP token/key storage | Protected credential reference; never collect the token value |
| `mcp-http` | High: remote MCP uses unencrypted HTTP | Authenticated TLS plus independent identity/authorization |
| `artifact-agent-state` | High: agent homes, transcripts or worktrees enter public/deployable artifacts | Exclude that state from exact payload inventory |

These are risk classes, not vendor signatures or operative instruction examples. Text checks are narrow heuristics, not semantic analysis or data-flow tracing; path-only credential references and paraphrases may be missed. Documentation describing a risk is not enabled configuration. File kinds and effective settings must come from a protected version-aware collector; reviewed files cannot classify themselves or waive review.

## Review and exception process

1. Authenticate source and effective configuration precedence. Inventory all active files, installed extension identities, MCP definitions and public/deployable membership. Missing coverage or unsupported formats leave review incomplete. Keep real paths, credentials and personal configuration private.
2. Normalize supported semantics using the module's closed contract; preserve original bytes and normalization evidence privately. Invoke `reviewConfiguration` with separately protected policy, authoritative clock and expected strong input ETag captured for this snapshot. Verify the result tag. Hashes identify bytes; they do not authenticate provenance or enforce a boundary.
3. Investigate findings. Broad guest access may be an explicit owner choice for a disposable environment; it is not automatically compromise. Record rationale, containment, owner, scope, reviewer and mandatory expiry privately. Policy carries opaque IDs and `block`/`review` actions for every rule.
4. Approve exceptions outside untrusted files, bound to exact rule and SHA-256 of exact file content, owner, scope, review and expiry. Changed bytes require review again. Missing exceptions preserve findings; expired/invalid policy or exception input fails closed. Accepted exceptions remain visible, never silently clean.
5. Hold blocked, unresolved, incomplete or stale reviews. Final admission belongs to an independent authority. `no-findings` is known-profile coverage, not deployment authorization. Keep artifact admission, installed-state checks and effective permission enforcement separate.

## Reporting and SIEM compatibility

The reference returns only nonsecret logical path, rule ID, severity and coarse check state, aggregate status and strong input/result byte tags. Keep instructions, command lines, URLs, credentials, real inventory and exception rationale in protected case custody linked by opaque references. Even hashes may reveal guessable content.

A separately implemented blocked-admission exporter must use the existing SIEM v1 `runtime` category, `config-integrity` action and `deny` outcome, with the existing required fields and supported signal class. The exporter maps this action to runtime; administration would contradict its contract. Use the [operations schema](../enterprise/operations/README.md) without new enums or arbitrary scanner fields. No collector/export adapter or external technique-ID assertion is added here.

## Validation scope

Offline Node builtin tests cover all ten classes with exact expected finding lists, risk/near-match/description/exception pairs and failure/privacy cases. They do not execute extensions, probe live systems, scan real credentials or measure false-positive rates. Target collection, precedence, custody, consumer binding and enforcement remain operator integration. Findings are investigation leads, never attribution or automatic bans; all providers and countries receive identical treatment.
