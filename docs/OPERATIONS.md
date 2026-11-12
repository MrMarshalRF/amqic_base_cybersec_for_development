# Operations with secrets, backups, and dependencies

## Access boundary

Humans enter secrets in their own terminals. AI works with metadata and the sanitized result from a fixed consumer. An AI process with full access under the same user can read local files. Enforced separation requires a separate OS account or an external store with an independent issuance policy. The `scripts/protected_input.mjs` example implements a local AES-256-GCM record with restrictive Linux permissions. Application integration and authorization checks for the operation are implemented separately.

Do not send secrets in chat. Do not place them in the project's `.env`, Git, Dockerfile, Compose, argv, env, CLI output, logs, clipboard, screenshots, or source backups. Secret files require AES-256 in a verified store and key management outside the project. The local input example encrypts the record with a separate passphrase and serves as an integration starting point. Use it with real data only after defining the protected consumer and storage boundary.

## Ordinary files and backups

### Main procedure for Linux

1. Ensure that Node.js 22+ and Python 3 are installed from a trusted source. Prepare an immutable snapshot of the source files, a separate backup directory with permissions 0700, and a secure temporary-file directory. On filesystems with journaling and snapshots, deleting a file does not guarantee physical erasure. Use a protected encrypted volume or private tmpfs for temporary data.
2. A human runs the command in their own terminal. Replace the paths with agreed absolute paths. `app` and `public` are explicit inclusions within the snapshot.

```sh
node scripts/secure_backup.mjs create /srv/example/snapshot /backups/example.amqic app public
```

3. Enter a long random passphrase and repeat it. The script creates an intermediate tar.gz in a private temporary directory, encrypts it with AES-256-GCM, verifies the decrypted copy and every file, then removes only its own temporary directory. The final result is an encrypted `.amqic` file. Existing archives are not overwritten.
4. Test restoration into a new directory that does not exist. Store the password separately from the archive, for example in KeePassXC. After restoration, compare the result with the agreed snapshot before changing operational data.

```sh
node scripts/secure_backup.mjs restore /backups/example.amqic /restore-check/example-new
```

The main helper runs on Linux and refuses automated input. On Windows, a separate verified ACL procedure is required before using the low-level tools. The kit does not install one automatically.

### Low-level steps for maintainers

The `scripts/backup.py` script handles ordinary static files. It rejects links and special files, excludes common secret filenames, checks every file's SHA-256 and the archive's exact membership, and reads the entire gzip stream to EOF. Path ancestors are checked for symlinks and Windows reparse points before resolution and payload reads. On Windows, normalized or reserved filename components and native case aliases are refused; distinct ordinary Unicode names remain supported. Source and destination directories must stay under trusted, exclusive control during the operation. The maximum is 100000 files and 8 GiB of payload data. Empty directories, ACLs, owners, and executable bits are not preserved. Restoration creates files with permissions 0600 and directories with permissions 0700 on Unix. On Windows, configure and independently verify a restrictive ACL for the target directory beforehand. The script does not set Windows ACLs.

A human or the data owner prepares the inclusion list after reviewing its contents. Automatic exclusions do not recognize secrets in arbitrarily named files. Secret directories, configurations containing credentials, KDBX files, and key files must be excluded separately. Such information requires a separate encrypted backup process with its own authorization.

Run the following example from the kit root. Destination directories must already exist, be outside the source tree, and have a verified access boundary. The names are placeholders to replace with agreed absolute paths.

```sh
python3 scripts/backup.py create --root /srv/example/snapshot --include app --include public --output /secure-staging/example.tar.gz --allow-plaintext
python3 scripts/backup.py verify /secure-staging/example.tar.gz
```

The plaintext archive is a sensitive intermediate artifact. The final backup is encrypted with AES-256-GCM. A human runs the following commands in their own terminal and enters the password without echo.

```sh
node scripts/archive_crypto.mjs encrypt /secure-staging/example.tar.gz /backups/example.amqic
node scripts/archive_crypto.mjs decrypt /backups/example.amqic /secure-restore/example.tar.gz
python3 scripts/backup.py verify /secure-restore/example.tar.gz
python3 scripts/backup.py restore /secure-restore/example.tar.gz --target /restore-check/example-new
```

`archive_crypto.mjs` requires Node.js 22+ and uses built-in crypto without npm packages. Format v1 contains `AMQICENC1`, a random 16-byte salt, a 12-byte nonce, ciphertext, and a 16-byte GCM tag. The entire header is authenticated as AAD. The 256-bit key is derived using scrypt with N=32768, r=8, p=1 and a memory limit of 64 MiB. These parameters are fixed by the format version. Use a long random passphrase stored separately in a protected store. A weak password permits offline brute force.

Output is created exclusively. During decryption, plaintext bytes are temporarily written to a neighboring `.partial` file with Unix permissions 0600, and the final name appears only after tag verification. An incorrect password, modified header/data, or truncation does not publish the final plaintext file. The temporary file is removed after a normal handled error. If the process crashes, it may remain in the protected directory. System snapshots and physical media erasure require a separate policy. Windows also requires a previously verified directory ACL for encryption.

The source archive is not deleted automatically. First verify the encrypted copy by decrypting it, running a full `verify`, and testing restoration. Deleting a specific intermediate file requires a separate owner decision. The tools are not designed for writing into an untrusted directory or for concurrent hostile file substitution. The snapshot and operation directories must be closed to unrelated writers.

If restoration fails, the source backup is preserved and the partially created hidden `.restore-*` directory remains for analysis. The final name is published only after every written file has been verified. Publication without overwriting is supported on Linux and Windows. A retry uses a new directory. The script does not overwrite, delete old backups, or rotate them automatically. SHA-256 checks integrity. Record the backup's provenance authenticity in an external trusted journal or through a signature.

## Databases

Obtain a dump using the database system's native tool, matched to its version and consistency requirements. Test restoration into a separate empty database without operational integrations. Backing up files from a running PostgreSQL, MySQL, SQLite, or other database requires its own native snapshot/log mechanism. This script does not coordinate transactions or replace that mechanism.

## Destructive actions and step-up

Deleting backups, shortening retention, changing ACLs, issuing a key, and switching the operational application require separate confirmation bound to the exact objects and action. A trusted component with replay protection verifies an independent hardware key or OTP on another device. A code from the same store accessible to AI does not provide independence. The kit contains no universal verification component, so a human performs these steps. An AI script does not gain deletion authority from an authorization file or its own assessment.

## Dependency quarantine

The runnable example is in `infra/container/quarantine.compose.yaml`. Preparation of a separate volume, image pinning, and the sequence of separate fetch/inspect profiles are described in the [infrastructure instructions](INFRASTRUCTURE.md). AI uses the [dependency review skill](../skills/review-dependencies/SKILL.md). First reconcile these examples with your isolated environment and approved admission policy.

1. Record the exact name, version, URL, hash/signature, trusted key source, and license. A hash downloaded alongside a substituted package does not by itself authenticate the publisher. Verify the signature, trusted provenance/attestation, or hash through an independent trusted channel.
2. Download only into a separate quarantine using a separate downloader. For the network stage, allow the required addresses on an external firewall/proxy. Do not mount source code, secrets, an SSH agent, the Docker socket, a home directory, or operational volumes. Run the container unprivileged with resource limits and without host network.
3. Transfer the received bytes to an isolated static-review stage with `--network none`, read-only input, and separate disposable output. Check archive membership, paths, links, executable files, install/postinstall hooks, native extensions, lockfile changes, and vulnerabilities against a trusted database. Do not install, import, or run package scripts before the decision. The analyzer must also be pinned and verified. A container shares the host kernel; suspicious code requires an additional boundary, such as a separate VM.
4. AI assessment assists review. Admission is decided by an authorized human or a previously approved verifiable policy. Save the exact digest, provenance, and decision in an external journal. Promote only those bytes into a controlled registry/cache. Builds use an approved lockfile with lifecycle hooks disabled until separate authorization covers their execution.
5. After admission, build and verify a new image in a separate build environment without operational secrets. In `infra/container/compose.yaml`, pass the approved `APP_IMAGE_REPOSITORY` and `APP_IMAGE_SHA256`. The operational Compose runs the application and does not perform quarantine downloads. Changing a tag without checking the digest does not promote admitted bytes.

This describes the quarantine process. A network downloader, proxy, registry, and signing infrastructure are not installed automatically. Assign an owner and exact cleanup resources to each temporary environment beforehand. Preserve the report and approved hashes, then remove only the disposable resources owned by this operation after independent authorization of the required destructive steps.
