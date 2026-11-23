# Offline agent configuration review

This standard-library module reviews an explicitly supplied normalized snapshot. It does not read files, walk agent homes, import extensions, run hooks, make network requests or change permissions. Start with the [checklist](../../docs/AGENT-CONFIG-REVIEW.md) and [runtime containment](../../docs/AI-AGENT-RUNTIME.md).

## API and adoption

Import `inputETag` and `reviewConfiguration` from `config-review.mjs` in a trusted CI/admission consumer:

```js
const expected = inputETag(snapshotJson, trustedPolicyJson, trustedNow);
const result = reviewConfiguration(snapshotJson, trustedPolicyJson, trustedNow, expected);
```

The caller supplies JSON strings, an authoritative nonnegative safe-integer clock in milliseconds, and the expected strong input ETag. Capture that tag with the reviewed snapshot; recomputing it from an untrusted replacement at admission defeats freshness checking. `inputETag` binds exact serialized snapshot/policy bytes, schema domain and clock. `resultETag` binds the exact JSON-serialized result body excluding `resultETag`. These byte identities are not signatures, secrecy or source authentication. Restrict custody: low-entropy content may be guessed from a hash.

A protected version-aware collector must determine effective configuration precedence, complete file inventory, each file's kind, hook/skill semantics, MCP launcher/transport/credential storage and deployable membership. This module does not collect or authenticate these observations. The reviewed agent cannot supply its own trusted policy, omit active files, relabel instructions as documentation or label plaintext tokens as references. Never pass actual token values: classify their storage before collection. Normalization is an external assertion, not vendor parsing or installed-state attestation.

The consumer must require matching input and result tags and inspect `status`. `blocked`, `review-required` and `incomplete` hold admission. `exceptions-present` remains visible for operator decision. `no-findings` means no known patterns in this supplied profile; it does not authorize deployment. No gate or workstation review is activated here. CI exercises synthetic tests; reviewing a target requires its actual trusted snapshot and consumer binding.

## Closed snapshot contract

Unknown/missing keys, duplicate decoded JSON keys (including escaped aliases) and unsupported values refuse at every serialized boundary. Snapshot has exactly `profile: "normalized-agent-config/1"` and `files`, a nonempty array of at most 100 descriptors with exactly:

- `path`: collector-assigned nonsecret logical path, 1–160 ASCII bytes; alphanumeric first, then letters/digits/underscore/slash/dot/hyphen; no empty, dot or dot-dot segments. Never private paths, URLs, credentials or arbitrary user text.
- `kind`: `configuration`, `instructions` or `documentation`, determined independently by the protected collector. Documentation is intentionally not scanned.
- `content`: at most 65,536 UTF-8 bytes of text. Configuration content must be JSON with the exact fields below.

| Field | Supported normalized values |
| --- | --- |
| `approvals` | `enabled`, `disabled`: global effective behavior |
| `shell` | `scoped`, `unrestricted`: effective pre-approval scope |
| `hooks` | Up to 100 `{source, execute}` records: source `local`/`remote`, execute boolean; includes skill offers combining remote acquisition/execution |
| `mcp` | Up to 100 `{launcher, pin, tokenStorage, transport}` records |
| `artifacts` | Up to 100 `{included, class}` records: included boolean; class `application`/`agent-home`/`transcript`/`worktree` |

MCP launcher is `package`, `image` or `fixed`. Pin is null or a string up to 128 UTF-8 bytes. Packages require an exact numeric three-component version with optional prerelease; ranges, tags and build metadata are deliberately unsupported as pins. Images require `sha256:` plus 64 lowercase hex characters. `fixed` denotes a separately reviewed immutable local executable whose identity must be checked externally. A pin alone does not establish publisher authenticity or installed-tree integrity. Token storage is `none`, `reference` or `plaintext`; transport is `stdio`, `https` or `http`.

Each top-level JSON string is at most 1 MiB; parsed snapshot/policy trees have maximum depth 12 and 20,000 values each. Configuration has the closed shape and bounded flat arrays above. YAML, TOML, vendor formats, archives and executable configuration are unsupported. A safe configuration example is `{"approvals":"enabled","shell":"scoped","hooks":[],"mcp":[],"artifacts":[]}`. Empty arrays assert that the collector found none, not that collection was skipped.

## Trusted policy and exceptions

Policy has exactly `owner`, `scope`, `review`, `validUntil`, `ruleActions`, `exceptions`. Owner/scope/review are opaque nonsecret IDs, 1–64 ASCII alphanumeric/underscore/hyphen characters starting alphanumeric. `validUntil` is an exclusive millisecond expiry after trusted now. `ruleActions` contains every exported `RULE_IDS` key exactly once, each `block` or `review`; there is no ignore action. All checks run regardless of disposition.

Exceptions has up to 100 records, each exactly `{ruleId, fileSha256, owner, scope, review, validUntil}`. Hash exact UTF-8 content bytes (64 lowercase SHA-256 hex); bind exact rule, matching owner/scope, an exception review reference and expiry no later than policy expiry. The externally authenticated owner must decide and protect the exception outside the reviewed files. Matching ID strings alone do not authenticate a human. Missing exceptions preserve findings; expired, malformed or mismatched exceptions make the whole review incomplete. Changed bytes lose the exception. Accepted exceptions remain findings with `accepted-exception` and status `exceptions-present`, never silently clean. Keep rationale and containment evidence in the protected case record.

## Results and limits

Findings contain only `file`, `ruleId`, `severity`, `checkState`, deduplicated by file/rule and sorted by logical path then exported rule order. Severity is high except medium for `instruction-unicode`; it is review priority, not incident confidence. No source text, credentials, commands, URLs or parser errors are returned. Status is `no-findings`, `exceptions-present`, `review-required`, `blocked` or `incomplete`. Aggregate check state is `complete-known-profile`, `stale-input` or `unsupported-input`; failure discards partial findings. Finding check state is `blocked`, `review-required` or `accepted-exception`.

Instruction heuristics recognize bounded same-line English phrases concerning authority override/concealment/confirmation, remote acquisition plus execution, credential-store access and a fixed invisible/control-character set. They do not understand semantics, decode obfuscation or trace data flow. Negated descriptions in active instructions can match; paraphrases, path-only credential references, other languages and encoding changes can be missed. Describe risks in externally classified documentation. A finding is a lead, not proof of compromise or an automatic ban. No provider or country ranking is performed.

```sh
node --test enterprise/config-review/config-review.test.mjs
```

Inert synthetic fixtures cover all ten classes with exact expected risk, scoped/pinned, description and expiring exception findings. Further tests cover privacy, malformed/unsupported profiles, bounds, stale tags, deterministic output and changed-byte exception rejection. Static fixture results do not establish installed-agent safety, sensor coverage or effectiveness against real intrusions.
