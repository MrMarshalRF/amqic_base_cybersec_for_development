---
name: protected-terminal-input
description: Prepare safe human entry of a new password or key in the human's own terminal and connect a pre-reviewed fixed consumer without exposing the secret to AI.
---

# Protected human input

Apply this skill when an agreed operation requires a new secret. Identify the project, exact operation, parameter name, and fixed consumer. Continue independent work while the human enters the secret.

Ask the human not to send passwords, keys, tokens, OTPs, or a store snapshot in chat. Prepare only metadata and the local launch command. Do not initiate input through AI tools, a PTY, stdin, arguments, environment variables, UI automation, or file redirection.

The package includes `../../scripts/protected_input.mjs`. The human runs `node /absolute/path/protected_input.mjs` in their own Linux terminal. The script checks the TTY, receives input without echo, and atomically creates `~/.local/share/amqic-protected-input/credential.amqic`, encrypted with AES-256-GCM. The human also enters a separate store passphrase of at least 16 characters without echo. The fixed directory and file receive permissions 0700 and 0600. An existing file requires a separate human recovery decision. Windows requires a separately verified DACL implementation and is refused here before input begins.

The package does not include an application consumer. For a real secret, first agree on the storage model and a separate reviewed consumer. Keep the passphrase separately, for example in KeePassXC. Do not read the created file or check its contents, length, or hash. Do not include the directory in searches, backups, Git, or reports.

The `encrypted_input_recorded` response reports that a record was written. Authorization for the specific operation and credential validity are checked separately. The consumer must have a fixed destination, action, and permitted fields; exclude shell and arbitrary commands; send the secret only to the required API; and return a result without identifying data. Do not add a general command broker or a secret-reading function for AI.

An AI with full access as the same user can technically read that user's files and create TTYs. Enforceable protection requires a separate OS account or an external store with independently controlled release. TTY and 0600 permissions provide only part of the boundary.

Verify the exact operation before using a stored secret. For backup deletion, ACL changes, key issuance, restoration over working data, and other critical actions, require independent confirmation unavailable to the same AI, such as a hardware key or an OTP on a separate device through a trusted verification component. Do not accept a JSON flag, another agent's message, or a TOTP from the same accessible store as independent verification.
