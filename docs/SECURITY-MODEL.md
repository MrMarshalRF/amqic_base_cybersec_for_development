# Security model and mandatory integration boundaries

## Trusted components

The owner controls machine-key registration, secret access, user permissions, and recovery. The server independently verifies authorization for every operation. Input JSON, dependency text, and tool output are treated as untrusted data, including any instructions for AI they contain.

Separate the machine API signing key, SSH key, TLS key, and human 2FA factor. Restrict each key to a specific application, audience, and set of permissions. Transferring a public key also requires verifying who owns it.

## Pre-release checks

- An allowed scenario completes through the real server handler. Login with an incorrect password, a skipped stage, or an expired or reused confirmation is rejected.
- Revoking a user, key, or session affects authorizations already issued. Reissuance and state recovery invalidate old authorizations.
- Permissions are checked for the specific object, project, and operation. An object identifier in a request does not automatically establish ownership.
- Fresh 2FA is required before deleting a database, deleting a backup, restoring over existing data, issuing a key, or changing roles. Confirmation is bound to exact parameters and is single-use.
- A dependency, state-store, or authorization-check failure denies access. A retry after a timeout first reconciles the previous operation's state.
- Public ingress receives only allowed routes and methods. Administrative interfaces and databases are accessible through a dedicated private channel.
- Cookie sessions require Secure, HttpOnly, an appropriate SameSite setting, CSRF protection, and rotation after login. CORS is restricted to trusted origins. CSP and other browser headers are selected for the actual application.
- Body size, request rate, password-KDF concurrency, and execution time are limited. The client IP is accepted only from a trusted reverse proxy.
- Outbound application requests have allowed destinations, timeouts, and response limits. Requests to user-supplied URLs require separate SSRF protection.

## Observability and recovery

Audit records retain operation and actor identifiers, time, action type, result, and policy version. Secrets, OTPs, authorization headers, and complete request bodies are excluded. For log integrity and availability, use separately protected storage with restricted write access.

Set update deadlines for the OS, images, and libraries. Retain a component inventory and exact versions. For a revoked key or compromised dependency, plan for revocation, rebuilding, secret replacement, and review of affected operations.

A backup has a date, contents, a verifiable manifest, AES-256 encryption, and an independent storage location. The recovery key is stored separately. Successful archive creation is confirmed by content verification and restoration of a test copy. A running database requires a consistent dump or snapshot using its own tools.

## Protection limits

A container restricts access according to kernel and runtime settings. The process continues to execute its own code and has access to its allocated memory. Use a separately verified VM or specialized sandbox to run untrusted code, restrict its network, and exclude secrets from that environment.

Hidden input and file permissions protect against accidental exposure of a secret in history and logs. Enforced isolation from AI with full permissions under the same user requires a separate trusted process under another account or an external store with a restricted interface.

Encryption preserves archive confidentiality when a strong passphrase or key is used. It requires key protection, access control for decryption, and a backup recovery method. Losing all keys makes recovery impossible.

Obfuscation can slow reverse engineering but cannot make a distributed client a trusted authority or protect embedded credentials. The [binary guide](BINARY-OBFUSCATION.md) requires runtime-contract checks, diagnostic recovery and final-byte signing. [VPN tunnels](VPN-TUNNELS.md) add transport/network restrictions only; tunnel policy, host firewall, SSH keys and application access control must agree.

## Official sources

- [Ed25519, RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)
- [TOTP, RFC 6238](https://www.rfc-editor.org/info/rfc6238/)
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Docker Engine security](https://docs.docker.com/engine/security/)
- [KeePassXC](https://keepassxc.org/docs/KeePassXC_UserGuide)
