# Client-exposed secret review

Public build variables may be embedded in a browser bundle. Review `PUBLIC_`,
`VITE_`, `NEXT_PUBLIC_`, `NUXT_PUBLIC_` and `REACT_APP_` variables before release.
Prefixes describe exposure conventions, not a guarantee about every framework's
configuration. Public URLs and identifiers are often intentional. Some API keys
are designed to be public; the credential-name heuristic cannot decide that.
Keep privileged credentials on the server and authorize their use there.

## Offline snapshot review

`scripts/client_secret_review.py` uses only Python's standard library. Give it
one explicitly selected JSON snapshot. It never discovers repositories, follows
logical paths, reads environment variables or secret stores, executes source, or
contacts a network. Prepare sanitized text through an authorized process; do not
paste actual credentials into chat, command arguments, environment or reports.
Keep any sensitive review input in the operator-private workspace.

The exact schema is `{"format":1,"files":[{"path":"app/settings.js",
"text":"export const PUBLIC_BASE_URL = 'https://example.invalid';",
"committed":false}]}`. Each file has exactly these three fields. Paths are
relative ASCII logical labels, not filesystem destinations. `committed` is a
trusted caller observation, not a status inferred by the reviewer. Include the
root `.gitignore` explicitly to assess its environment-ignore hint. Omitted
files, Git history, other ignore sources and unsupplied build configuration
remain unreviewed.

```sh
python -B scripts/client_secret_review.py /operator-private/review-snapshot.json
python -B scripts/test_client_secret_review.py
python -B scripts/test_prepare_production.py
```

The CLI reads only that snapshot and refuses linked/reparse-point ancestors,
nonregular or hardlinked input, input over 4 MiB, duplicate JSON fields and
observed input changes. The snapshot permits 1–256 files, at most 256 KiB of
UTF-8 text per file and 2 MiB total. Use the pure `review(document,
expected_input_etag=None)` API for already supplied text. The result contains
strong `input_etag` and `result_etag` hashes over canonical JSON; supplying an
expected input tag refuses a different snapshot. These are content-binding
metadata, not authenticity or secrecy guarantees. Protect review metadata too.
The result tag covers the result without its own `result_etag` field.

## Checklist and findings

| Rule | Severity | Review action |
| --- | --- | --- |
| `client-public-secret-literal` | high | Inspect a public-prefixed assignment whose name suggests a credential and whose literal value is not a recognized placeholder. |
| `committed-environment-file` | high | Review caller-confirmed committed `.env` / `.env.*` files, even with harmless text. Examples are assessed separately. |
| `example-environment-nonplaceholder` | high | Replace credential-like example values with explicit placeholders; keep any real credential outside source. |
| `environment-ignore-review` | low | Review omission or ambiguous negation of environment ignore rules. |

Outputs contain logical path, rule and coarse severity only, plus status/tags.
They do not contain variable names, values, excerpts, line text or exception
details. Findings require review (CLI exit 1); `no-known-pattern` (exit 0) means
only that these patterns did not match. Invalid input returns a generic blocked
result (exit 2), including malformed arguments, without echoing their values.

Credential names include password, secret, token, API key, private key, access
key and auth key segments. The value heuristic requires at least eight
characters, excludes explicit placeholders such as `<required>`, `YOUR_...`,
`CHANGE_...`, `REDACTED` and environment references, and handles simple quoted
JavaScript/JSON or unquoted environment assignments. A server-only variable is
outside the public-prefix rule; it may still contain an unsafe credential and
needs the existing server credential review. Example review uses the same
name/value heuristic. Public URLs with URL names remain clean. Short secrets,
computed/concatenated/encoded values, runtime flow, aliases, arbitrary syntax,
framework transformations and credential validity are not covered. Comments
and inert strings may match: this is text review, not a language parser.

Ignore handling is deliberately conservative, not a complete Git parser:
only explicit `.env` plus `.env.*` (or both root-anchored equivalents), without
any negation, suppress the hint. Valid complex policies can still require
manual review. An ignore rule cannot remove an already committed file.

## Production staging and response

The real `scripts/prepare_production.py` content check invokes the same
public-prefix rule during preparation **and** manifest validation. Existing
credential, private-key, provider-token and bearer checks remain. Staging still
rejects every `.env*` path, including placeholder-only examples; a clean review
does not allow an environment file into a runtime payload. Source preservation,
explicit allowlists, source-change checks and destination non-overwrite remain
required. See [the production skill](../skills/prepare-production/SKILL.md).

There is no automatic exception, credential validation, revocation or rotation.
An owner may document a reviewed public-key use outside the payload, but this
does not bypass staging. For confirmed exposure, revoke/rotate at the issuer,
review past bundles and distribution, remove unsafe source, and repeat the
authorized release checks. Static synthetic fixtures establish pattern and
staging behavior only; detection effectiveness and actual deployment remain
target verification.
