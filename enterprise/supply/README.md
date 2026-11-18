# Release integrity and software inventory

Use Node.js 22 or later. These commands operate on files supplied locally and use no package installation or network requests. Run them with a reviewed copy of `supply.mjs` and a trusted Node runtime. Stage artifacts with exclusive producer access. Seal the staging directory before verification and use an immutable artifact or read-only snapshot for deployment. Path checks and open-file identity checks assume that other processes cannot mutate the directory during verification.

## Repository release checks

Use the repository's signed checksum registry and established signer trust path. Then check the registry against all regular files in the extracted release or the source checkout:

```sh
node enterprise/supply/supply.mjs check-sha256 .
```

The root checksum registry, its optional signature and root Git metadata have separate roles. All other files must match the registry by path and SHA-256. The tool rejects unsupported path syntax, case collisions, links, hardlinks, special files, and sizes outside its limits. Verify extracted archive membership and execution modes in the release pipeline. See [release verification](../../docs/RELEASE-VERIFICATION.md).

## Build a signed subject for a staged payload

Place only deployable files in the staging directory. Keep the binary policy, signed inventory and detached signature outside it. The policy lists approved paths and exact SHA-256 values. For a payload with no approved binaries, use:

```json
{"schemaVersion":1,"binaries":{}}
```

For a required binary, independently review its origin, select the exact bytes and add a path-to-digest entry. Every listed file must exist and match its digest. Files that fail strict UTF‑8 decoding or contain non-whitespace control characters require approval. UTF‑8 is a byte classification and can include scripts and other executable content. Review all text and enforce application-specific content and path restrictions in the staging pipeline.

```sh
node enterprise/supply/supply.mjs inventory "$PAYLOAD_DIR" "$BINARY_POLICY" "$SOURCE_COMMIT" > "$INVENTORY"
node enterprise/supply/supply.mjs check "$PAYLOAD_DIR" "$BINARY_POLICY" "$INVENTORY" "$SOURCE_COMMIT"
node enterprise/supply/supply.mjs verify "$PAYLOAD_DIR" "$BINARY_POLICY" "$INVENTORY" "$INVENTORY_SIGNATURE" "$TRUSTED_PUBLIC_KEY" "$SOURCE_COMMIT"
```

`inventory` emits a deterministic JSON subject with a full source commit, the canonical policy digest, and path, size, SHA-256 and classification for each file. `check` compares an inventory to the staging directory. Generate the raw detached Ed25519 signature over the exact inventory bytes using an approved external signer. `verify` requires a 64-byte signature and an SPKI PEM public key obtained independently of the bundle. The expected commit and binary policy also come from trusted release configuration. The signature authenticates the inventory under that key. The source commit is a signer assertion. This format borrows the artifact-subject concept from SLSA and carries no SLSA level, provenance predicate or isolated-builder guarantee. [SLSA v1.2](https://slsa.dev/spec/v1.2/)

## Generate an SBOM and verify a quarantined input

```sh
node enterprise/supply/supply.mjs sbom "$PAYLOAD_DIR/package-lock.json" > "$PAYLOAD_DIR/bom.cdx.json"
node enterprise/supply/supply.mjs check-dependency "$QUARANTINED_TARBALL" "$TRUSTED_LOCKFILE" "node_modules/example"
node enterprise/supply/supply.mjs sbom-components "$COMPONENTS_JSON" > "$DECLARED_SBOM"
```

The npm reader supports lockfile versions 2 and 3 and regular `node_modules` package entries with SHA-256, SHA-384 or SHA-512 integrity. It rejects workspace links, missing or ambiguous integrity and unsupported formats. The dependency check compares quarantined tarball bytes against the integrity of an exact installed path from the reviewed lockfile. Keep verification ahead of extraction or lifecycle hooks. Review package identities and download origins in the dependency acquisition process. A matching archive digest binds bytes to the trusted lockfile. [npm package-lock format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)

Both SBOM commands produce CycloneDX 1.6 JSON marked incomplete. Each npm component describes a declaration in the lockfile and preserves its archive integrity as metadata. The report omits download URLs. For other inputs, pass a JSON array of items with `type`, `name` and `version`, such as `[{"type":"platform","name":"Node.js","version":"22"}]`. Use image and runtime inventory tools for the installed OS packages, runtimes, actual dependency graph and transitive build inputs. Component names can be sensitive. Inspect the SBOM before distributing it. [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)

## Reusable CI examples

Copy [the GitHub workflow](ci.github.example.yml) into the caller's trusted workflow repository and call it from a protected release workflow. Include [the GitLab job](ci.gitlab.example.yml) from a trusted configuration and extend `.amqic_supply_verify` from a protected release pipeline. Both jobs fail closed unless the signed payload verifies and the bundled `bom.cdx.json` matches the regenerated lockfile report.

Provision an isolated Linux runner with Node.js 22, the reviewed `supply.mjs`, and the following protected environment variables or GitHub environment variables. Mount the trusted inputs and sealed artifacts read-only. Keep release signing permissions outside these verifier jobs. Exclude untrusted PR jobs and arbitrary repository builds from access to these runners.

| Variable | Trusted value |
| --- | --- |
| `AMQIC_SUPPLY_TOOL` | Absolute path to the reviewed verifier |
| `AMQIC_SUPPLY_PAYLOAD_DIR` | Absolute path to the sealed extracted payload |
| `AMQIC_SUPPLY_BINARY_POLICY` | Absolute path to the reviewed binary policy |
| `AMQIC_SUPPLY_INVENTORY` | Absolute path to the exact signed inventory bytes |
| `AMQIC_SUPPLY_SIGNATURE` | Absolute path to the raw detached Ed25519 signature |
| `AMQIC_SUPPLY_PUBLIC_KEY` | Absolute path to the externally trusted signer public key |
| `AMQIC_SUPPLY_SOURCE_COMMIT` | Full expected source commit from trusted configuration |

Run the tests with `node --test enterprise/supply/supply.test.mjs`. Fixtures use local test keys and synthetic packages. Apply the separate repository signature workflow when publishing the kit.
