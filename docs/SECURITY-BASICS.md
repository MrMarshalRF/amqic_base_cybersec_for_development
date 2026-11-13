# Security basics, explained simply

This guide is for developers who are new to cybersecurity. Imagine that you are building a small website where visitors send a contact form and staff sign in to manage requests. The same ideas apply to many apps and APIs.

Security is a set of cooperating checks. A locked front door does not help if a window is open. Each section below explains one check, a simple example, and its limits. The linked guides contain the actual procedures and tested scope. This kit provides basic protection, not a guarantee that a system cannot be attacked.

## 1. Decide who may do what

**Authentication** asks who is signing in. **Authorization** asks what that person may do. They are different checks.

Example: a support employee can read assigned messages but cannot delete the entire database. Knowing the employee's identity is not permission to do everything.

The server must check permission on every protected action, even when the interface hides the button. A visitor can send a request without using your buttons. See the [authorization core](../reference/README.md).

## 2. Login stages, CAPTCHA and 2FA

A password is one way to prove identity. A time-based one-time password, or **TOTP**, adds a code from a separate authenticator. **2FA** means two different factors, not simply typing the same password twice.

Example: staff enter their login, password, CAPTCHA result and authenticator code. The server confirms each stage in order. The browser cannot skip straight to the final stage by hiding earlier screens.

CAPTCHA makes some automated abuse harder; it does not establish who the visitor is. 2FA reduces the value of a stolen password, but phishing, stolen sessions and unsafe recovery can still defeat the overall system. Recovery and device enrollment need protection too. See [login integration](../reference/README.md).

## 3. Fresh approval for a dangerous action

A successful login should not authorize every future destructive operation. Ask for a fresh second-factor check when the risk justifies it, and bind approval to the exact operation.

Example: approval to delete test record 42 is not approval to delete the production database. An expired or already used approval must not work again.

The real server verifies the factor. An AI message saying "approved" or a JSON field named `approved` is not proof. The app also needs a reliable operation record so a network retry does not repeat a deletion. See [sensitive operations](../reference/README.md).

## 4. Machine keys and SSH keys

Public-key cryptography uses two related pieces: a private key kept by its owner and a public key that other systems can use to verify proof from that owner.

Example: a deployment machine signs a request with its Ed25519 private key. The server checks it using the registered public key. The signature must cover the intended request, and old requests must not be reusable.

SSH can also use Ed25519 keys for administrator access. Machine API signatures and SSH are separate protocols: a key in one system does not automatically grant access to the other. Never send a private key to the server as proof or paste it into a chat. See [machine requests](../reference/README.md) and [initial deployment](INITIAL-DEPLOYMENT.md).

## 5. Keep passwords and other secrets out of source code

A secret is information such as a database password, API token or private key. Your application should obtain it through a protected runtime mechanism, not from public code.

Example: the code knows the name of a secret it needs; the deployment's secret manager provides its value to the authorized service. A sample configuration explains the setting without containing the real password.

The [protected-input skill](../skills/protected-terminal-input/SKILL.md) helps an operator enter secrets without echoing them. That does not make an all-powerful AI running as the same OS user unable to read the resulting files. Strong separation needs a separate trusted account, process boundary or external secret manager. See [operations](OPERATIONS.md).

## 6. Use a password manager carefully

KeePassXC stores passwords in an encrypted database. A strong master password and safely managed recovery materials help protect it.

Example: use a unique password for each service and keep the password database out of your Git repository. If you use a separate key file, losing both the recovery path and the required key can lock you out.

An unlocked password manager on a compromised computer cannot guarantee secrecy. Back up the database and protect its recovery method separately. See [KeePassXC](KEEPASSXC.md).

## 7. Encrypt and restore backups

A backup is a separate recoverable copy. Encryption makes its contents difficult to read without the right key. This kit uses AES-256-GCM for its encrypted archive workflow.

Example: if a disk fails, restore yesterday's backup into a test location and check that the needed records are actually present. A file called `backup.zip` is not proof that recovery works.

A running database needs its own consistent dump or snapshot; simply copying open files may produce an unusable backup. Keep the decryption key recoverable and separate from the backup. Deleting backups is a dangerous action with its own approval. See [backup operations](OPERATIONS.md).

## 8. HTTPS, proxying and direct-IP access

HTTPS protects communication with the named server and helps the browser verify its identity. A reverse proxy can stand in front of your application and enforce an additional access boundary.

Example: visitors use `https://your-owned-domain.example`, while the application listens only on an internal address. An unexpected hostname or direct request to the origin IP should not expose the application.

A proxy does not erase old DNS records or guarantee that nobody discovers the origin address. Protect the origin even if its address becomes known. Keep certificate and hostname checks; do not disable them to make a connection succeed. See [initial deployment](INITIAL-DEPLOYMENT.md).

## 9. Firewalls, accounts and closed ports

A firewall decides which network connections may reach a machine. An operating-system account decides what a process can do after it is running.

Example: allow the public web ports through the intended proxy path, but allow SSH only from approved administrative sources. Use a dedicated administrator account and verify key-based access before removing an old login method.

Nginx does not protect every port on a machine. SSH authentication belongs to SSH, and a firewall controls network reachability. Keep an independent recovery console so a mistaken rule does not lock you out. See [server setup](INITIAL-DEPLOYMENT.md).

## 10. Nginx routes, protected files and allowlists

A route is a URL path your server deliberately supports. An allowlist names the sources or actions you permit; everything else can be denied.

Example: the site serves its public homepage but refuses requests for `.env`, Git internals, database dumps or private configuration. A `403` response means the request is forbidden.

Even an allowed visitor should not read secret files. Headers claiming to contain a visitor's IP are trustworthy only when a specifically trusted proxy overwrites them. See [infrastructure](INFRASTRUCTURE.md).

## 11. Rate limits and 429 responses

A rate limit restricts how quickly a client can make requests. `429` means the client has exceeded a limit and should slow down according to the service's retry policy.

Example: a public page and an expensive API need different limits. Ten requests per minute might be sensible as an initial API example, but unusable for a busy application.

Tune limits for real traffic and shared IP addresses. A rate limit does not prove that an allowed request is authorized or harmless. See [Nginx limits](INFRASTRUCTURE.md).

## 12. CSP and safe browser output

A Content Security Policy, or **CSP**, tells the browser which kinds of scripts and resources the page permits.

Example: the page normally loads scripts from its own site. A stricter policy can block an unexpected inline script. Third-party CAPTCHA and other integrations need deliberate policy changes.

CSP is an extra layer, not permission to insert untrusted input as HTML. Use plain-text output or the correct escaping for the destination. Test error pages as well as successful pages. See [infrastructure](INFRASTRUCTURE.md) and [web input protection](WEB-INPUT-PROTECTION.md).

## 13. Personal-data form fields are data, not code

A form field can contain text that resembles SQL, HTML or a shell command. The safe design prevents that text from becoming an instruction.

Example: the database query is fixed, and the visitor's message is supplied separately as a bound value. A message saying `DROP TABLE` stays a message. When displaying it, the browser receives plain text rather than new HTML to execute.

Names, email addresses and phones also have field-specific format and size checks. Those checks do not replace safe database queries. Free-form text needs safe handling every time it is displayed, emailed or exported. See the [tested form module](../reference/pii-input.mjs) and [full explanation](WEB-INPUT-PROTECTION.md).

## 14. Containers reduce exposure

A container packages an application with an isolated view of some system resources. A non-root identity, limited permissions, restricted network, read-only code files and resource limits reduce what a compromised application can reach.

Example: a contact-form handler runs in a container that has no Docker control socket, cannot rewrite its own code, and can reach only the required database. It also uses the safe form handling from the previous section.

A container still executes code and shares the host kernel. Removing a shell does not make code execution impossible, and a container does not fix a SQL-injection bug. Untrusted code may require a stronger separate sandbox. See [container guidance](INFRASTRUCTURE.md).

## 15. VPN access for administrators

A VPN adds a protected network path between approved devices. WireSock is a Windows client for a WireGuard-compatible endpoint; Tailscale manages connections and policy between enrolled devices.

Example: an administrator reaches SSH through a private tunnel address, while strangers on the internet cannot reach that administrative path.

The firewall, SSH keys and application permissions still apply. A subnet router also needs correct forwarding and return routes; a router may hide the original client's address through NAT. A tunnel is not a guarantee of anonymity. See [VPN tunnels](VPN-TUNNELS.md).

## 16. Review dependencies and update supported versions

A dependency is someone else's code that your app uses. Downloading it can also bring install scripts and other executable content into your build.

Example: download an exact package into a controlled area, check its source/version and expected digest, inspect it without running it, then approve the exact object for the build. Use separate download and execution environments where needed.

AI can help review evidence but cannot guarantee that a package is safe. A checksum only proves that bytes match a reference, so the source of that reference matters. A newer version is not automatically compatible or vulnerability-free. See [dependency review](OPERATIONS.md) and [version checks](VERSIONS.md).

## 17. Binary obfuscation is a speed bump

Obfuscation changes a compiled program to make some analysis harder. Removing debug symbols reduces exposed diagnostic metadata, but is not the same as hiding the program's logic.

Example: ship a release binary without private debug files, while retaining matching symbols securely so your team can understand a crash. If you rename code elements, test features that discover them dynamically.

Do not embed a secret and assume that obfuscation protects it. Test the transformed binary and sign/hash the final bytes after transformations. See [binary protection](BINARY-OBFUSCATION.md).

## 18. Antivirus is another check

ClamAV can detect some known malicious content. Keep both its engine and detection database up to date.

Example: an uploaded file stays in private quarantine until required checks finish. A scan error or a file that could not be fully inspected is not automatically a clean result.

No antivirus catches everything. Do not expose its scanning daemon to the internet or automatically delete important data on a detection. See [ClamAV guidance](SERVICE-PROTECTION.md#clamav-on-a-server).

## 19. Redis can share short-lived security state

Several copies of an application may need to share counters and challenge records. Redis can provide that shared state quickly.

Example: three API replicas consult the same rate counter instead of each granting a client a separate allowance. Updates must be atomic so simultaneous requests do not bypass the check.

Protect Redis with private reachability, authentication/ACLs and TLS where required. Losing a replay marker through eviction or failover can weaken a check; plan for that failure. Redis is not automatically a secure secret store or a reliable record of completed destructive operations. See [Redis guidance](SERVICE-PROTECTION.md#redis-as-shared-security-state).

## 20. Request proof of work adds a cost

A proof-of-work challenge asks a client to do a bounded amount of computation before the server accepts selected expensive work.

Example: a gateway checks a short-lived puzzle bound to one request, consumes it once, then performs the usual authentication and permission checks. It also limits how often clients can ask for puzzles.

Powerful attackers can still compute solutions, and excessive difficulty harms legitimate users. Explain the computation, allow cancellation and provide a suitable accessible path. A solved puzzle does not make input safe or replace CAPTCHA, 2FA or container isolation. See [request admission](SERVICE-PROTECTION.md#request-proof-of-work-at-a-gateway).

## 21. Prepare a clean release

A development folder often contains files that do not belong in production: local settings, debug output, caches, secrets and test data.

Example: create a new release folder containing only approved application files and notices. Check the result without deleting your working source. A public source release can intentionally include tests and documentation that a running application does not need.

`.gitignore` helps avoid adding some files to Git, but does not remove old committed files or secrets from history. Rotate exposed credentials. See [production preparation](PRODUCTION.md).

## 22. Hashes, signatures and the file registry

A SHA-256 hash is a fingerprint of file bytes. A registry lists expected fingerprints and paths. A signature helps establish who approved that exact registry.

Example: first verify the maintainer's signature through the documented trusted method, then compare each downloaded file with the registry and look for unexpected extra files.

A malicious person could replace both a file and an unsigned checksum list. Matching hashes alone do not prove who made the files or that the code is safe. Changing any registered file requires a new hash and registry signature. See [release verification](RELEASE-VERIFICATION.md).

## 23. Publish a versioned GitHub release

A Git tag identifies a source snapshot. A GitHub release adds notes and downloadable artifacts to a tag.

Example: publish `v1.1.0` only after its source, archives, registry and signatures have been checked. Download the uploaded assets again and verify them instead of assuming an upload succeeded perfectly.

README explains use and limitations, SECURITY explains private vulnerability reporting, and LICENSE states the permission terms. Preserve third-party notices. Do not move a published version tag to different code as a quiet repair. See [GitHub releases](GITHUB-RELEASES.md).

## 24. Deploy, observe and be able to roll back

Deployment means installing and activating a specific release on a real target. It is different from uploading files to GitHub.

Example: verify the release, create a consistent recoverable backup, stage the new version, run approved migrations, switch traffic carefully, and check the real public/private request paths. Keep the previous working version available.

Rolling back a program does not necessarily roll back its database. Restoring an old database can lose newer records. Plan those decisions before the change, keep an operator available, and stop if acceptance checks fail. See [secure deployment](DEPLOYMENT.md).

## 25. Report vulnerabilities and interpret evidence honestly

If you find a weakness, report it privately through [SECURITY.md](../SECURITY.md) with a safe reproduction and no real credentials or personal data.

Example: "this specific test request bypassed this check on this version" is useful evidence. "No one can ever hack this" is not a test result.

The [validation record](VALIDATION.md) distinguishes executed tests from templates and untested production integration. [Operational threat data](../THREAT-DATA.md) describes observed requests and policy decisions from one deployment; those counts do not prove that every request was an intrusion or that another deployment has the same protection.

## 26. An external layer: Cloudflare and caching

Cloudflare can stand between visitors and your origin server. Its edge can filter some unwanted traffic and answer repeated requests for public files from a cache, so the origin does less work.

Example: many visitors can receive the same public logo from the cache. Each person's account page must remain private and must not be served to another visitor from a shared cache.

A DDoS attack tries to exhaust a resource using traffic from many sources: network capacity, connections or expensive application work. Edge protection and safe caching help at different stages, but the origin still needs closed bypass paths, safe code and appropriate limits. Not every traffic spike is an attack. See the [Cloudflare walkthrough](CLOUDFLARE-EDGE.md) for the mechanisms, safe cache exclusions and verification steps.

## 27. Keep incoming files away from primary storage

A new upload is untrusted. Receive it in a separate quarantine area that cannot overwrite application code, existing customer files or approved downloads.

Example: the upload receiver can write only to quarantine. A scanner checks an exact stable copy. A trusted promoter verifies that the approved bytes match before copying them into approved storage. The download service can read that approved storage but cannot write it.

Separate directories alone are weak isolation if the same process can freely modify both. Use separate volume/bucket permissions and service identities. A read-only scanner also does not stop the receiver from changing the source, so the final content must match the scan result. See [upload isolation](UPLOAD-ISOLATION.md).
