---
name: verified-backup
description: Create, verify, and restore encrypted backups of ordinary files with explicit contents, SHA-256 verification, and separate confirmation of destructive actions.
---

# Verifiable backups

First agree on the source directory, explicit inclusion list, sensitive exclusions, protected location for the temporary plaintext archive, encrypted backup location, and recovery-key owner. The main entry point is `../../scripts/secure_backup.mjs`. Internally it uses `backup.py` and `archive_crypto.mjs` from the same directory. Python 3 and Node.js 22+ are sufficient. Read `../../docs/OPERATIONS.md` before first use.

Ordinary files must come from an agreed immutable snapshot or a stopped application. For a running database, first obtain a consistent dump through its standard mechanism with separate authorization. This skill does not permit directly copying files of a running database.

1. Review the contents before starting, including secrets under unusual names. Automatic exclusions cover only common names.
2. The human runs `node /absolute/path/secure_backup.mjs create /source/snapshot /backup/copy.amqic app public` in their own Linux terminal. The password is entered without echo. Do not pass the secret through AI, argv, env, or stdin. The helper creates a private temporary archive, encrypts it with AES-256-GCM, verifies decryption, and removes its own temporary files. Technical limitations are described in OPERATIONS.md.
3. Perform a trial restore through `node /absolute/path/secure_backup.mjs restore /backup/copy.amqic /restore/new-directory`. Compare the restored files with the original agreed snapshot. Record only paths, contents inventory, tool versions, and the result.
4. Keep the recovery password independently of the backup and verify that the backup owner can access it. Automatic cleanup covers only this run's disposable private directory. Deleting retained archives requires a separate owner decision and must account for storage snapshots/journaling.

Restoration always creates a new directory. Switching the running application to restored data is a separate operation after owner verification. On failure, preserve the original backup and unfinished directory; establish the exact outcome before retrying. Do not overwrite working data or delete archives to rerun the operation.

There is no built-in deletion or rotation of retained backups. Deleting a backup, reducing retention, clearing a key, overwriting or switching working data requires independent step-up confirmation on a separate device or hardware key, verified by a trusted component. The confirmation must include the exact object list and action. The AI does not receive the OTP and cannot issue such authorization itself. If no verification component exists, leave the destructive step to the human.

SHA-256 inside the archive checks file integrity. AES-GCM verifies the ciphertext and header during decryption with the correct password. Backup provenance is additionally bound to a trusted external journal or signature. Do not treat an unknown backup as your own merely because it is structurally valid.
