# Preparing a clean production kit

This procedure creates a new source-code kit with verified contents. The source files are preserved. Publication, server configuration, and changes to operational data are separate actions.

## 1. Define the operational contents

Record the project version and list the exact relative paths of files required by the application. Include operational code, approved dependencies/lockfiles, and safe runtime-configuration templates. Preserve required licenses and attribution, including selected UTF-8 LICENSE, NOTICE, and COPYING files. Ensure that the entry point and resources are present. Tests, internal AI instructions, caches, logs, backups, `.env`, secret stores, and private keys remain outside the kit.

Work from a static snapshot in a directory closed to unrelated writers. Prepare a separate parent directory for the result. Use protected storage for confidential source code. Created files have Unix permissions 0600 and directories 0700. On Windows, configure and verify a restrictive ACL on the parent directory beforehand. The script does not set a DACL.

## 2. Run project checks

The public output excludes Git/Mercurial/Subversion history and settings, `.graphify`, `graphify-out`, `graphify-output`, known Graphify config/index files and `.graphifyignore`, `.agent-private`, `.codex`, `.agents`, AGENTS.md/AGENTS.override.md, CLAUDE.md/GEMINI.md, `.cursor`/`.windsurf`/`.aider*`, `.mcp.json`/`mcp.json`/`mcp.local.json`, internal plans/checkpoints/receipts directories, and editor settings. Their known paths are rejected before their contents are read. Ordinary `app/graph.json` and operational MCP modules are allowed through an explicit list. Unknown internal artifacts must also be excluded during manual content review.

Run the project's standard tests, static checks, and build. Save the results outside the tree to be published. Then check the built application's behavior with the agreed runtime settings. A file manifest does not replace these checks.

## 3. Prepare a new directory

Python 3.11+ on Linux or Python 3.12+ on Windows is required. Run the command from the kit root. Replace the paths and file list with your agreed contents. Each `--include` specifies one file; entire directories are not copied.

```sh
python3 -B scripts/prepare_production.py prepare --source /srv/project-snapshot --target /srv/releases/candidate-001 --include app/main.mjs --include package.json --include package-lock.json --include config.example.json
python3 -B scripts/prepare_production.py validate /srv/releases/candidate-001
```

The target directory must not exist and must be outside the source. On Linux, publication of the prepared directory uses `renameat2` without overwriting; on Windows, it uses an exclusive rename. The operation refuses on systems without a supported mechanism. Source files and old versions are not deleted.

The script accepts supported UTF-8 text files, up to 10000 files, 8 MiB per file, and 512 MiB in total. It rejects links, Windows reparse points, hard links, directory escapes, ambiguous paths, case collisions, and selected internal names. Explicitly specifying a forbidden file stops the entire operation. Its own temporary directory is removed on a handled refusal.

A small scanner looks for credential literals, some known token formats, and private-key markers. A match is returned only as a relative path and rule identifier. Unknown encoding, a binary format, or a finding blocks the result. This search misses obfuscation, composite values, and unknown formats. Manual review is mandatory. Static images, fonts, and binary builds require a separate exact-hash and content-verification process. Renaming an extension is not verification.

`PRODUCTION-MANIFEST.json` contains only included relative paths, sizes, file SHA-256 values, and a deterministic list hash. Absolute source paths and information about excluded files are not included. Keep the reference hash in a separate trusted release record. The manifest itself does not establish a file's provenance. `validate` rechecks exact membership, the absence of extra directories, hashes, and the limited scanner.

## 4. Resolve findings

When the process stops, examine the rule and path locally. Do not send the secret value in chat or publish the detected fragment. Move a real secret into an external runtime store. If it has already been exposed in a repository, log, artifact, or publication, the authorized owner revokes/rotates it and checks previous distribution locations. Changing the latest file does not revoke the old key. A false positive requires a manual change to the safe template or an appropriate verified process. There is no automatic bypass flag.

The lexical scanner does not determine every field's meaning. For example, a field with a credential-related name may contain the name of the next UI state. The code owner and an independent reviewer first confirm that the value is not a secret. Then, if necessary, they choose another representation while preserving behavior and checking for regressions. Changing syntax, encoding, or names to conceal a real secret from the scanner is prohibited. Real credentials are moved to a protected runtime store. Excluding a file from scanning or maintaining a list of “safe” values does not establish the absence of a secret.

## 5. Check access and rollback

In an authorized synthetic environment, check a normal authorized request and separate forbidden scenarios. Direct origin access, a request without the required authentication/role, and a request outside the source policy must produce the intended denial, usually 403. Exceeding the limit must produce 429 with agreed retry behavior. The service contract determines exact expectations. CORS configuration alone does not provide server-side authentication and origin control.

Check that responses and logs contain no secrets, external runtime input works, and mandatory MFA is preserved. Use the infrastructure documentation for the reverse proxy/origin boundary. The current preparation command does not make network requests or establish these service properties.

Record the previous working version, its hash, data-compatibility settings, and the exact rollback procedure. A production switch requires separate authorization for the exact release. Deleting old versions, changing permissions, revoking/issuing keys, and other critical steps require an independent hardware factor or OTP on a separate device through a trusted verification component. If no integration exists, a human performs these steps. An authorization file or AI message does not replace actual second-factor verification.
