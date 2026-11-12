# Release verification

Official releases bind their public files to one maintainer-signed SHA-256 registry named `SHA256SUMS`. The maintainer applies the post-quantum electronic signature to the final registry before publication. This source preparation creates the registry; the maintainer supplies its signature through the release process.

## Verification sequence

1. Obtain `SHA256SUMS` and its signature from the official release. Establish the trusted maintainer identity through [AMQIC verification](https://amqic.ai/pages/request-verification).
2. Validate the post-quantum signature of the exact registry using that verification service and the signing material supplied by the maintainer. A valid-looking text file or a downloaded checksum alone does not establish its origin.
3. Compare every downloaded file with its exact relative path and SHA-256 entry. On systems with GNU coreutils, run `sha256sum --check SHA256SUMS` from the release root.
4. Review the complete extracted file list against the registry. Unexpected files need investigation before running any code. The registry itself, detached signature material, and local Git metadata have separate roles as described below.
5. To check the public support addresses, verify the registry first, then compare the hash of `wallets.txt` with its entry. On Windows, `Get-FileHash -Algorithm SHA256 .\wallets.txt` displays the file hash for comparison.

Verification should use trusted local tooling. Run the checksum check before executing scripts supplied by an unverified download. If the registry signature, any file hash, file membership, or expected signer is inconsistent, stop and obtain a verified release.

## Registry scope

Each registry line contains a lowercase SHA-256, two spaces, and the root-relative file path. Entries are sorted by path. The registry covers all regular public source, documentation, configuration, test, license, and media files in that release, including `wallets.txt`.

`SHA256SUMS` excludes itself because a file cannot normally contain its own final hash. Its authenticity comes from the maintainer's signature. A detached signature file, conventionally `SHA256SUMS.sig`, is signature metadata and is also excluded from the payload registry. Local `.git` metadata is outside the public file payload. Any other supplied regular file must have a matching registry entry. The signature format and algorithm identifiers are determined by the maintainer's actual signing system.

Git attributes preserve the committed file bytes without automatic line-ending conversion. Tools that rewrite files, line endings, or archive contents change their hashes. Changes require a regenerated registry and a new registry signature. Validate each release independently.

## Interpretation

A valid signature and matching hashes establish that the checked bytes correspond to the authenticated registry. They do not establish that the code has no defects or that a deployment is configured securely. Consult [VALIDATION.md](VALIDATION.md) for executed tests and target-environment gaps, and [SECURITY.md](../SECURITY.md) to report a defect.
