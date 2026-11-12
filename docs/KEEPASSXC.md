# KeePassXC for developers

The name “KeePass version X” in this kit refers to KeePassXC. Install an appropriate current stable version from the official source and verify the distribution signature according to the developers' instructions. Record the version in your local operations record. [Official getting started guide](https://keepassxc.org/docs/KeePassXC_GettingStarted), [signature verification](https://keepassxc.org/verifying-signatures).

## Database and access

Create a KDBX 4 database and select Argon2id in the derivation settings. Tune opening time and memory on the weakest trusted device involved in recovery. Use a unique long passphrase. Select AES-256 for database content encryption. Exact field names depend on the application version. [KeePassXC user guide](https://keepassxc.org/docs/KeePassXC_UserGuide).

If needed, add a key file and keep it separate from the KDBX and its backups. Losing a required key file makes the database inaccessible. Arrange a separate protected recovery copy of the key file and verify the backup owner's access. Add supported hardware challenge-response, such as YubiKey/OnlyKey, according to project requirements. Prepare and test a backup device beforehand. A hardware factor can also cause loss of access without a recovery plan. [KeePassXC user guide](https://keepassxc.org/docs/KeePassXC_UserGuide).

## Backups and recovery

Copy the closed, consistent database to independently protected media and retain multiple generations. KDBX is already encrypted. An additional AES-256-GCM container is acceptable under the media policy, with separate password management. Store the key file and hardware factor independently. A human must test recovery in an isolated copy of KeePassXC. Do not open the database through an agent or save CSV/XML/HTML exports for verification. Such exports expose the entries. [KeePassXC user guide](https://keepassxc.org/docs/KeePassXC_UserGuide), [features and export description](https://keepassxc.org/docs/KeePassXC_GettingStarted).

## TOTP and critical operations

KeePassXC can store and generate TOTP. If the password and TOTP are accessible from the same unlocked database, compromise of that database exposes both. For deleting backups, changing permissions, issuing keys, and other critical operations, use a separate device or hardware factor verified by an independent component. Store recovery codes under a separate policy as well. [KeePassXC features](https://keepassxc.org/docs/KeePassXC_GettingStarted).

## AI integration

AI prepares metadata for the required operation. A human opens KeePassXC locally and passes the selected value only to a previously reviewed fixed consumer, through hidden terminal input or an isolated external-store integration. The consumer returns only a sanitized status. Do not use a password-printing CLI command, the clipboard, Auto-Type into an AI window, a screenshot, or a database export as an integration channel. Do not include secrets in shell history, argv, env, or logs.

`scripts/protected_input.mjs` demonstrates hidden terminal input on Linux and a separate encrypted local record. It does not read KDBX, verify the master password, or implement an application consumer. Its record is encrypted with AES-256-GCM using a separate passphrase. When AI has full access under the same user, a separate OS account or external store is required for enforced isolation. KeePassXC does not itself establish this boundary for an arbitrary agent process.
