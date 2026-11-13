# Reproducible whole-kit verification

## One-command local acceptance

```sh
node scripts/verify.mjs --plan
node scripts/verify.mjs --all --prepare --output /absolute/external/new-all-local.json
```

`--plan` reads the fixed [scenario catalog](../lab/scenarios.json) and prints JSON without spawning commands, downloading dependencies, writing files or starting services. `--all` performs prerequisite checks, the baseline and Compose checks, actual ClamAV/Redis/browser consumers, Nginx origin and cache assertions, isolated Linux infrastructure fixtures, and five upload roles exercising three volumes and forbidden writes. Infrastructure fixtures cover key-only SSH, nftables traffic, WireGuard, Linux terminal/backup tests, ELF debug-symbol separation and a synthetic KeePassXC vault. A missing or failed required local scenario cannot produce `local_accepted`.

Only explicit `--prepare` permits pulling the catalog's immutable image references and building the fixed infrastructure Dockerfile. Its bases use image digests; packages come from the dated signed Debian snapshots declared in that recipe. The local tool image must carry the current recipe hash; its actual image ID and package versions remain runtime evidence. Node, Python, OpenSSL 3, Docker/Compose and an existing Chromium browser are host prerequisites, never silently installed. Windows detects existing Git OpenSSL installations automatically and verifies synthetic certificate creation; only the Nginx child receives the selected executable's directory on PATH. An unavailable kernel capability remains a failed local fixture, not a deployment pass.

Reports and every reserved sidecar must be new paths outside the public kit. Arguments accept metadata only: there is no command, shell, image or configuration broker. `--all` rejects legacy mode flags rather than mixing contracts. It emits the schema in [protocol.schema.json](../lab/protocol.schema.json): exit **0** means every required local check was accepted, **1** means invalid input or a failed check, and **2** means a missing local prerequisite. `production_verified` always remains false. Read `scenarios` for the distinct `source_reviewed` and `external_not_run` entries: real provider accounts, identity services, VPN deployment and release signing need separate authorization and verification.

Acceptance requires exact child status, named assertions, teardown evidence and unchanged public source hashes. An outer subprocess timeout records `cleanup_pending` and the exact resource-ledger path, stops further stages, and fails the run. Reconcile those recorded resources before starting another attempt. Process exit alone is insufficient. A missing Windows PTY check is accepted only through the actual Linux complement fixture. Failed Node logs remain in the external baseline sidecar; public JSON contains hashes and bounded metadata, not those logs or credentials.

The original baseline, `--compose`, `--full` and explicit Nginx modes below remain available with their original compatibility contracts. Their exit conventions differ from `--all`.

From the kit root, use Node.js 22 or later and Python 3.12 or later:

```sh
node scripts/verify.mjs --output /absolute/external/new-report.json
node scripts/verify.mjs --compose --output /absolute/external/new-compose-report.json
```

On Windows use an absolute Windows path outside the kit for `--output`. The report is exclusively created; choose a new filename for each run. Without `--output`, JSON is printed to standard output. No dependencies are downloaded by the baseline runner. Each child uses a fixed argument list, no shell, bounded output and a timeout. The runner never accepts commands to execute.

The baseline executes the authorization, session revocation, login, PII, proof-of-work/admission, upload, ClamAV protocol, synthetic HTTP application and cryptography tests; a core demonstration; Python backup, staging, version evidence, quarantine and Nginx harness tests; and real firewall-renderer positive/negative fixtures. Linux also executes the synthetic PTY test. These are local synthetic tests, not probes of production systems. The Nginx harness unit tests use mocks; they do not prove that Nginx ran. `--compose` checks normalized configuration and does not create containers. Subtest skips remain counted in each result, including platform-specific filesystem cases.

`verification/coverage.json` classifies every public payload file and relates it to fixed check IDs. The inventory excludes only `SHA256SUMS`, its detached `SHA256SUMS.sig`, Git metadata and named local cache/private directories. Missing, duplicate, unknown or stale members fail the runner. `SHA256SUMS` must contain exactly the same payload membership and current file digests. The report binds the sorted path/digest list in `source_files` and `source_digest`. The final public evidence projection `verification/v1.2.0-report.json` is excluded from that source identity to avoid self-reference; it remains covered by the payload registry and full before/after stability check. Raw logs and environment values are not included in the JSON. A failing synthetic Node suite may create `<output>.node-tests.log` beside the external report for private diagnosis. Output digests and byte counts are evidence of the captured process output, not substitutes for test assertions. Signature verification remains the separate procedure in [RELEASE-VERIFICATION.md](RELEASE-VERIFICATION.md).

Categories deliberately distinguish executable fixtures, configuration, source-reviewed documentation and static assets. A documentation entry checks membership/integrity; it does not make the described security mechanism executable, prove its guidance complete, or certify a deployment. Configuration tests do not prove live firewall/SSH enforcement. Static asset hashes do not prove browser appearance. Review the scope on each entry and [VALIDATION.md](VALIDATION.md) before drawing conclusions.

Each check reports `passed`, `failed` or `not_run`. Requested missing runtimes, missing test files, subprocess timeouts, stale registries and failing assertions are failures. Optional integration work is `not_run`, never silently passed. Overall `failed` exits 1; overall `incomplete` exits 0 for a successful baseline with explicitly omitted integrations, with `complete: false`. `passed`/`complete: true` requires every listed check. Read the JSON status, not only the exit code.

## Actual service and browser integrations

```sh
node scripts/verify.mjs --full --output /absolute/external/new-full-report.json
```

`--full` also requires Docker Compose, the reviewed ClamAV/Redis images and a local Chromium browser. It invokes the fixed `lab/run-lab.mjs --verify` lifecycle and writes separate integration evidence at `<report>.integration.json`. The lab owns synthetic loopback scanner/Redis services and their cleanup; `lab/live-verify.mjs` and `lab/redis-live.mjs` exercise the actual service/browser paths. Follow [the lab guide](../lab/web.README.md) for image preparation. `LAB_BROWSER_PATH` can identify an existing Chromium installation; it is a local executable path, never a credential. A requested unavailable integration fails. Mock protocol tests remain separate from actual daemon/browser results. This local fixture is not an application for production.

Actual Nginx tests additionally need an already reviewed local image and a new external output directory:

```sh
node scripts/verify.mjs --nginx-image sha256:REPLACE_WITH_REVIEWED_64_HEX_DIGEST --nginx-output /absolute/external/new-nginx-run --output /absolute/external/new-report.json
```

The runner does not pull an Nginx image. `infra/nginx/test_nginx.py` owns its synthetic fixtures and exact resource cleanup. Preserve its report and reconcile any `cleanup_pending` state before retrying. Full baseline/integration success is evidence for the exercised local paths only; it does not activate a server, validate production credentials, sign a release or publish anything.

## CI

[The workflow](../.github/workflows/verify.yml) runs Node 22/24 on Ubuntu and Windows with Python 3.12. Its permissions are read-only; checkout does not persist credentials. It has no deployment/signing step, secret input or `pull_request_target` trigger. Action identities are pinned to upstream Git commits: [checkout v4](https://github.com/actions/checkout/commit/11d5960a326750d5838078e36cf38b85af677262), [setup-node v4](https://github.com/actions/setup-node/commit/49933ea5288caeca8642d1e84afbd3f7d6820020), [setup-python v5](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065). Recheck upstream source before updating pins. Local edits still need regenerated reviewed SHA256SUMS before this verification can pass.

A separate Linux job invokes actual browser/ClamAV/Redis consumers through the lab lifecycle using digest-pinned official images. The scanner database contains only the harmless `AMQIC_LAB_SCAN_MARKER` test signature. This establishes clean/infected protocol and application transitions for synthetic files; it does not measure malware-detection quality or claim current production signatures. Redis uses public synthetic credentials and no persistent data. The lab lifecycle removes its exact containers on exit. A workflow definition is not evidence that GitHub Actions has run; inspect the actual run result separately.

The optional actual Nginx harness also invokes `openssl` from PATH to generate short-lived synthetic certificates. Verify the selected OpenSSL executable and configuration before running it; those certificates are test fixtures, not production credentials.

For a failed fixed command, an invocation with `--output` preserves its bounded diagnostic output beside the report as `<output>.<check-id>.log`. Existing reports and logs are preserved by rejecting colliding output paths before execution. The hosted workflow uploads top-level JSON reports and diagnostic logs after each job, including failures, with seven-day retention. Certificate files and nested temporary working directories are excluded from that upload.
