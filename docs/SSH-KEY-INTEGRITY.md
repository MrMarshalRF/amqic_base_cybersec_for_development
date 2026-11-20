# SSH trust-file integrity

Key-only SSH is a preventive control. `PermitRootLogin no`, `PasswordAuthentication no`, `AuthenticationMethods publickey` and `AllowUsers` restrict login; they do not detect later changes to `authorized_keys` or the installed sshd drop-in. Key-only login is not a substitute for integrity monitoring. Follow [infrastructure hardening](INFRASTRUCTURE.md) and [initial deployment](INITIAL-DEPLOYMENT.md) for the existing installation and recovery sequence.

## Approved inventory and protected baseline

Maintain an approved inventory for each administrative account: account name, key type, public-key fingerprint only, approval or change reference, last verified time, and intended expiry or rotation interval. Never store or log private keys. Keep live fingerprints and site account lists outside this public tree; prefer fingerprints over full public-key bodies in restricted inventory and telemetry.

Baseline the `authorized_keys` file for every account listed in `AllowUsers`, the `.ssh` directory owner and mode, and the installed sshd drop-in derived from [00-security.conf.template](../infra/ssh/00-security.conf.template). Retain owner, mode and a digest of file bytes in a protected baseline. Watch this integrity file class rather than an unrelated home-directory tree. Resolve directory-service homes, `Match` blocks and `AuthorizedKeysFile` overrides before selecting actual paths; the template's paths are examples.

## Collection and review

The [audit watch template](../infra/ssh/authorized-keys-integrity.audit.rules.template) is source-reviewed starting configuration only. It is not installed or validated by kit tests. Have auditd or an equivalent file-integrity product observe writes and attribute changes, including directory owner/mode changes. Retain successful changes as investigation leads with time, account, path class and process identity. A successful operation is not proof of an approved change or attribution to a person.

Auditd watch rules do not restrict raw records to those fields or select only successful operations. Raw records can include full paths, command lines, arguments or related `PROCTITLE`/`EXECVE` records. Keep raw collection access-restricted with reviewed retention. An independently trusted allowlisted projection must select successful events, map paths to classes and accounts/processes to approved identifiers, and export only time, account, path class and process identity. Exclude private keys, raw public-key bodies, command lines, arguments and environment from SIEM exports. The kit supplies no audit parser or sanitizer. Use the existing schema's [SIEM `config-integrity` action](../enterprise/operations/README.md) only through its supported opaque references; retain detailed evidence separately.

A change without an approved change record, or outside its declared maintenance window, needs high-priority review. Unexpected `.ssh` owner or mode changes have the same priority as content changes. Compare with the protected baseline and authorized change evidence. An alert is a review signal, not an automatic lockout; preserve a tested break-glass administrative path so response cannot lock out every administrator.

## Rotation and revocation

In one approved change, remove stale fingerprints from the inventory and their keys from the live file, then install any approved replacements and refresh the baseline. Confirm the effective `sshd -T` policy using the existing sequence in [infrastructure hardening](INFRASTRUCTURE.md), including applicable connection context and recovery checks. Verify that the rotated or revoked key is invalid for login once the change is complete, across all configured key sources. Kit tests do not perform login trials.

## Evidence limits

No installed-host auditd, AIDE or other FIM product is executed or certified here. Static checks inspect source text only; the container fixture that writes `authorized_keys` is not an integrity test. Operators must verify watch coverage, successful-event filtering, sanitization, event loss, baseline protection and alert routing on their target. Windows estates are outside this guide's scope.
