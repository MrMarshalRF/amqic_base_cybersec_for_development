# Infrastructure with restrictive defaults

These files are templates for a separate Linux server, prepared for manual deployment by the owner. The kit does not reconfigure the current computer or running servers. Start with a verified backup restoration and access through the provider's console. Set all domain, image, and account values explicitly. Do not permit missing settings or remove restrictions just to get the system running.

## 1. Prepare the application

The public container runs a single verified, statically linked Linux executable, `app`. It listens on `0.0.0.0:8080`, runs with UID/GID `65532`, writes logs to stdout/stderr, and writes temporary files to `/tmp`. The executable must match the server architecture and pass functional tests under these restrictions. Build and test it in a separate build process. Verify its provenance and SHA-256 before placing it in `infra/container/app`.

`infra/container/Dockerfile` uses `FROM scratch`. The final image contains no shell, interpreter, package manager, or external utilities. Build dependencies are not copied into the image. After building, inspect the image contents and record its digest in a trusted registry. Set `APP_IMAGE_REPOSITORY` and `APP_IMAGE_SHA256` in a separate local environment file with permissions `0600`. These are public image identifiers; do not put secrets there. The values do not include `@sha256:`; the template adds that part itself. Also set `APP_PRIVATE_SUBNET` and `APP_PRIVATE_IPV4`. Choose an unused RFC1918 subnet that does not overlap the LAN, VPN, or existing Docker networks, and an available application address within it. Before starting, compare `ip route` and `docker network inspect` with your addressing scheme. Deliver the image in advance using its verified digest; `pull_policy: never` prevents an unexpected download during startup.

```sh
docker compose --env-file /secure/app-image.env -p secured-app \
  -f infra/container/compose.yaml config --quiet
docker compose --env-file /secure/app-image.env -p secured-app \
  -f infra/container/compose.yaml up -d
```

The owner runs these commands only after reviewing the image, settings, and this guide. A missing digest stops preparation. Restrictions include an immutable root filesystem, a non-root UID, `cap_drop: ALL`, `no-new-privileges`, memory/CPU/PID limits, disabled core dumps, and a small `tmpfs` with `noexec,nosuid,nodev`. Docker must support the default seccomp profile. Do not add `unconfined`, `privileged`, host networking/PID/IPC, devices, the Docker socket, or bind mounts of host directories. [Docker Compose services](https://docs.docker.com/reference/compose-file/services/), [Docker seccomp](https://docs.docker.com/engine/security/seccomp/).

The application has no published ports. Only HTTPS/HTTP and explicitly allowed host SSH are accessible externally. The application is on a separate `internal` network with a fixed private IPv4 address. Host nginx connects to that address on port 8080. On the target Linux host, before enabling the site, verify that the address is reachable from the host and inaccessible externally. Docker Desktop places the bridge inside a VM, and routing from Windows/macOS differs. If the address is unreachable, stop deployment and prepare a suitable Linux host while preserving isolation. This network restricts external routing, but does not provide domain allowlists or isolate the container from every reachable host address or other members of its network. If outbound connections must be prohibited, configure verified filtering rules at the container network/host boundary, including IPv6. If specific external APIs are needed, use a separate controlled egress proxy with an exact destination allowlist. Do not connect the public application to a second shared network to obtain internet access. [Docker networks](https://docs.docker.com/reference/compose-file/networks/), [Docker bridge](https://docs.docker.com/engine/network/drivers/bridge/).

The container shares the host kernel. Removing the shell removes a ready-made command interpreter, but a vulnerable binary can execute its own code, make permitted system calls, and read its own memory. Default seccomp, a separate PID namespace, and the absence of `SYS_PTRACE`, core dumps, and host `/proc` reduce opportunities to read other processes. They do not prove that leakage is impossible. Keep the kernel and runtime updated. For a stronger boundary, use a separate VM or a separately verified gVisor/Kata configuration. This kit neither installs them nor verifies their protection.

## 2. Expose only the required HTTP routes

1. Set your own lowercase ASCII domain. The generator rejects IP addresses, line breaks, spaces, and configuration characters. For an IDN, first obtain its valid ASCII/Punycode form.
2. Review `infra/protected-paths.json`. This is the single URI list for enforced `403` responses, including private directories, configuration files, and their variants. Add project-specific private URIs.
3. List the exact public routes in `nginx.conf.template`. The example allows `/` and `/api/v1/status`. Authentication and MCP routes remain closed and are added only after the corresponding handlers are reviewed. Every route must retain application checks for authentication, authorization, method, and parameters. Expanding this to proxying through `location /` defeats the allowlist.
4. Generate a new file without overwriting the active one.

```sh
python3 infra/nginx/render.py --host your-owned-domain.example --upstream YOUR_PRIVATE_IPV4:8080 \
  --output /secure/nginx-candidate.conf
```

5. Place the certificate and key at `/etc/nginx/tls/fullchain.pem` and `/etc/nginx/tls/privkey.pem`. The private key must be accessible only to the process that needs to read it at startup. Keep it outside the project. Test the configuration with your installed nginx using `nginx -t -c /secure/nginx-candidate.conf`. After a successful check, apply the candidate through the server's standard mechanism and reload. Save the previous configuration for rollback.
6. Test a normal request to an allowed path, protected paths, an unknown Host, access by IP, and an SNI/Host mismatch. A protected path with the correct domain should return `403`. An invalid HTTP Host receives `421`; an unknown TLS SNI is rejected during the handshake. HTTP redirects only to the fixed configured HTTPS domain. [nginx server names](https://nginx.org/en/docs/http/server_names.html), [nginx TLS](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).

Matching uses the normalized `$uri`, without the query string. Case variants, descendants, suffixes introduced by a dot/semicolon/tilde, hidden segments, residual percent encoding, and backslashes are blocked. Common backup, key, and dump extensions, cloud/kube/docker credentials, service configurations, and VCS paths are also blocked. This policy may intentionally reject some legitimate unusual URIs. Do not address this by disabling checks globally. Repeated decoding and differences in application path handling require separate application tests. The two example public routes allow GET and HEAD only. New write operations require a separate reviewed route, authentication, and an explicit method allowlist. [nginx URI/location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location).

### Request rate limiting

The site uses a separate per-IP limit of `10r/s`. The paths `/api`, `/api/…`, `/mcp`, and `/mcp/…` share a separate per-IP limit of `10r/m`. Matching respects segment boundaries and case variants, so `/apiary` remains subject to the site limit. Both queues use `burst=9 nodelay`. A fresh IP can send up to ten virtually simultaneous requests; excess requests receive `429`. This is a leaky bucket algorithm, with capacity replenished gradually at the corresponding rate. [nginx limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html).

Requests for protected files, unknown routes, disallowed methods that reach the access phase, and HTTP redirects also pass through the limiter. A protected path normally receives `403`, or `429` after the limit is exhausted. Denial takes place in the access phase after the limiter. Each new terminal `location` must explicitly include exactly one `limit_req` for its category: site or API/MCP. Do not combine several limits with empty conditional keys in a shared context or replace denial with an early `return 403`. Category selection must happen before the limiter and preserve the original URI. The TLS handshake, HTTP parsing errors, and the TRACE method rejected by nginx core (`405`) occur before these handlers and require their own network limits.

The key is the actual TCP connection address, `$binary_remote_addr`. `X-Forwarded-For`, User-Agent, and Origin headers do not establish client identity or change the limit. When adding a CDN/load balancer, first separately configure trust only for verified proxy addresses and test header spoofing. Until this is configured, all clients of a proxy share its limit. Users behind a shared NAT also share one IP. Nginx state is local to the instance; independent servers require a separate solution for a shared limit. User-Agent names are not blocked wholesale; genuine and fake bots can send the same header.

The normal access log contains the address, method, status, and response size, without the URI or headers. `deny` and limiter diagnostics may contain the full URI, so the error log is set to `crit`. Critical errors may still contain request context. Restrict error log access, do not put secrets in URLs, and do not increase verbosity on a public server without a separate sensitive-data removal procedure.

Git, Graphify, instruction files, plans, receipts, and MCP configuration are internal project data. The registry explicitly blocks `/.git`, `/.graphify`, `/graphify-out`, `/graphify-output`, `/AGENTS.md`, `/AGENTS.override.md`, `/.mcp.json`, `/mcp.json`, `/plans`, and `/receipts`. Application `/mcp` routes retain a separate API policy and are opened only after handlers and access permissions are reviewed.

### CSP policy

The template sends an enforced `Content-Security-Policy` on normal HTTP responses and denial responses, including `403` and `429`. The policy starts with `default-src 'none'`, allows scripts, styles, images, fonts, connections, and the manifest only from the same origin, and prohibits iframe embedding, objects, base URI changes, media, and workers. Forms submit only to the same origin, and HTTP resources are upgraded to HTTPS. HSTS remains limited to HTTPS responses. Inline scripts, inline styles, `eval`, external CDNs, CAPTCHA, and widgets require a previously reviewed integration. [W3C CSP3, Working Draft](https://www.w3.org/TR/CSP3/).

For the initial profile, serve JS/CSS and other permitted resources from the same origin and add only reviewed public routes. Integrating an external API, WebSocket, CAPTCHA, or CDN requires exact allowed sources and verification of the corresponding directives. The application generates working nonces for each response and binds them to specific page elements. A fixed nonce and a value from `$request_id` are not used for this purpose. Inline resource hashes are bound to exact verified bytes. For such an integration, update the static nginx policy and application policy consistently on the required routes. The template preserves upstream CSP and adds its own baseline policy. The browser applies both together, retaining the application's stricter restrictions. Adding a nonce or external source only to the upstream policy does not relax the active nginx baseline policy. Copies of HSTS, Referrer-Policy, and X-Content-Type-Options are hidden through `proxy_hide_header` so that one verified layer sets these headers. Authentication and server-side access checks remain the application's responsibility. [nginx headers](https://nginx.org/en/docs/http/ngx_http_headers_module.html), [nginx proxy_hide_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header).

### Repeatable nginx testing

In the tested nginx 1.27 branch, adding any local `add_header` in `server` or `location` replaces the inherited header set. When changing the configuration, restate the entire required set through a shared include or explicit directives, and check CSP/other headers on `200`, `403`, and `429` responses. Retaining one new header does not itself retain the others.

Run `infra/nginx/test_nginx.py` on a separate machine with Docker, Python 3.11+, and OpenSSL. Obtain a trusted nginx image in advance and verify its exact local SHA-256 ID. The test accepts only that type of ID. It creates its own certificates for `kit.example.test`, a separate bridge, and a container with ports bound only to loopback. Its synthetic upstream returns fixed text. Production certificates and keys are not passed to the test. `--output` must point to a new directory. If OpenSSL is unavailable, `--tls-fixture` accepts a directory with pregenerated synthetic `fullchain.pem` and `privkey.pem` for this name.

```sh
python3 -B infra/nginx/test_nginx.py \
  --image sha256:REPLACE_WITH_VERIFIED_LOCAL_IMAGE_ID \
  --output .dev/nginx-regression-new
```

`report.json` records input SHA-256 hashes, the `nginx -t` result, `403/429` responses, allowed `200` responses, `308`/Host/SNI, recovery of the separate limits, absence of the test query string marker in stdout/stderr, and deletion of the exact container/network. This lab bridge is used only within the test; the public application retains its `internal` network with no published ports. On failure, examine the report and incomplete cleanup, fix the cause, and use a new directory. The test does not install the configuration on a server.

The configuration contains no `root` or `alias`. The host filesystem is not published. The protected URI list does not replace file access controls or anticipate new application aliases. For every new route, verify what actual data it returns, including query parameters. The application must not provide arbitrary file reads or administrative actions through the public `/`.

ACME HTTP-01 requires a separate `/.well-known/acme-challenge/` route. The current template blocks it. Use a verified DNS-01 process or a separately designed narrow exception with its own token directory, limited lifetime, and tests. Do not open all of `.well-known` or disable protected path checks. With strict SNI and direct access by IP, an HTTPS availability check also requires the correct name. Renew certificates with result verification and a safe reload.

## 3. Prepare SSH without losing access

The following sequence is for Debian/Ubuntu with OpenSSH, systemd, and UFW. First verify service names, paths, and active rules on the server itself. For another system, prepare an equivalent plan first. Keep the working first SSH session open throughout, and test the provider's recovery console in advance.

1. On your trusted computer, create an Ed25519 key with a passphrase using `ssh-keygen -t ed25519`. The private key stays on this computer. Transfer only the `.pub` to the server.
2. In the current administrative session, create a separate account, such as `deployadmin`, using `adduser deployadmin`. If it needs administrative privileges, add it to `sudo` using `usermod -aG sudo deployadmin`. Enter the local sudo password interactively. Do not include it in files, commands, or chat.
3. Create `/home/deployadmin/.ssh` with owner `deployadmin:deployadmin` and mode `0700`. Place the verified public key in `authorized_keys` with the same owner and mode `0600`. Do not copy the private key.
4. Open a second independent session with `ssh -i /path/to/private-key deployadmin@server`. Check `id` and, if required, `sudo -v`. Do not change SSH until this check succeeds.
5. Through the administrative session, save a private backup of the current `/etc/ssh` and `/etc/ufw` with root-only permissions, for example `umask 077; tar -czf /root/security-before.tar.gz /etc/ssh /etc/ufw`. Record the previous `systemctl status ssh` and `ufw status verbose` state. Do not publish the backup contents.
6. Substitute the verified account name for `@@ADMIN_USER@@` in `infra/ssh/00-security.conf.template`. Ensure that the name matches the successfully tested login. Install the file through the standard mechanism at `/etc/ssh/sshd_config.d/00-security.conf`, preserving existing settings. Check the `Include` order and all `Match` blocks. OpenSSH usually uses the first value obtained for a setting.
7. Run `sshd -t`, then `sshd -T -C user=deployadmin,host=server,addr=YOUR_CLIENT_IP`, and verify the effective values of `permitrootlogin no`, `passwordauthentication no`, `kbdinteractiveauthentication no`, `authenticationmethods publickey`, and `allowusers deployadmin`. Repeat the check for the administrative and root users if `Match` applies. Resolve any discrepancy at its configuration source before reloading.
8. Run `systemctl reload ssh`. Open another new key-based session and check sudo. Separately verify rejection of root login and password-only login. An already open session does not establish that the new settings work. [OpenSSH sshd_config](https://man.openbsd.org/sshd_config).

## 4. Restrict inbound traffic and test rollback

For initial deployment behind a proxy, use the separate [INITIAL-DEPLOYMENT.md](INITIAL-DEPLOYMENT.md) guide with a verifiable nftables candidate, a cloud firewall, and two nginx whitelist modes. The UFW example below applies to a host where UFW is the chosen manager. Managing the same boundaries through several managers simultaneously requires a separate compatibility check.

1. Before enabling UFW, determine the actual SSH port and the administrator's trusted external IP/CIDR, including IPv6. First add a narrow allowance, such as `ufw allow from YOUR_ADMIN_CIDR to any port YOUR_SSH_PORT proto tcp`. Substitute verified values; do not run commands with placeholders.
2. Add `ufw allow 80/tcp` and `ufw allow 443/tcp`, then `ufw default deny incoming`. Check all existing rules with `ufw status numbered`. Broad old allowances require a separate deliberate removal after narrow access has been verified.
3. Enable UFW with `ufw enable`, retaining the first SSH session and recovery console. Test a new SSH session and HTTPS from an allowed address. The application port `8080` must be inaccessible externally.
4. Docker manages its own routing rules. A UFW check alone does not prove that a published Docker port is closed. Preserve the absence of published application ports and check Docker rules, IPv6, and access from a separate client.
5. If new access fails, use the retained session or console to restore the exact previous files from the private backup, check `sshd -t`, reload the SSH configuration, and restore the previous UFW state. Before restoring, verify that the correct archive and target server are selected. Do not replace rollback with permanent access for all addresses or password/root login.

Outbound filtering requires a list of the server's actual dependencies, including DNS, time, updates, certificates, and backups. First compile this list and test the rules through the recovery console. The template does not automatically change host outbound rules.

## 5. Dependency quarantine

`infra/container/quarantine.compose.yaml` separates downloading from offline inspection. It uses a verified minimal Python 3.11 or newer image, specified through `PYTHON_IMAGE_REPOSITORY` and `PYTHON_IMAGE_SHA256` and delivered in advance by digest. The public application container does not contain such tooling. ZIP directory parsing is additionally bounded by container memory; a malformed archive may cause the inspector to fail or hit the memory limit and remains unapproved.

1. Choose a new unique Docker volume name for one inspection, set it in `QUARANTINE_VOLUME`, and create it with `docker volume create "$QUARANTINE_VOLUME"` in your own terminal. Do not use an existing volume name. The one-time `prepare` profile checks that the volume is empty and assigns UID/GID `65532:65532` with permissions `0700`. Only this preparation service runs with UID 0 and the single capability `CHOWN`, without networking or access to project data. Downloading and inspection run without root/capabilities. Reusing a volume with a previous or partial result is prohibited.
2. Obtain the expected `ARTIFACT_SHA256` through an independent trusted channel and an exact public HTTPS `ARTIFACT_URL` without tokens, a query string, a username, or a password. Values from the same source as an arbitrary downloaded archive do not themselves establish provenance.
3. Restrict outbound access from the download network to the required repository at an external egress gateway. Compose `fetch_egress` does not itself set a destination allowlist. Downloading uses TLS verification, disallows redirects, enforces a 64 MiB limit, and requires a hash. No install/lifecycle scripts are executed.

```sh
docker compose --env-file /secure/quarantine.env -p dependency-review \
  -f infra/container/quarantine.compose.yaml --profile prepare run --rm prepare
docker compose --env-file /secure/quarantine.env -p dependency-review \
  -f infra/container/quarantine.compose.yaml --profile fetch run --rm fetch
docker compose --env-file /secure/quarantine.env -p dependency-review \
  -f infra/container/quarantine.compose.yaml --profile inspect run --rm inspect
```

4. The offline stage uses `network_mode: none` and mounts the volume read-only. It verifies the hash, inventories ZIP/TAR/gzip-TAR without extraction or execution, and rejects dangerous paths, links, special files, and exceeded limits. Output contains file hashes and bounded text excerpts from manifests, licenses, and shell hooks as escaped JSON strings. The message `content-inventoried-ai-review-required` means that substantive review under `skills/review-dependencies/SKILL.md` is required. A matching hash does not establish safety.
5. For analysis, use a separate verified offline tool in an equally isolated process with a read-only volume. Do not open the artifact in a normal IDE/package manager with automatic plugins and hooks. Before transfer, record the exact hash and review result. Only explicitly approved bytes matching that hash may enter the trusted build. There is no automatic promotion to the application.

After inspection, stop only the containers belonging to that inspection and remove only its demonstrably separate temporary resources according to your retention policy. Keep a safe report, hash, and decision. Do not delete shared volumes or images.

## Source verification

The primary nginx, OpenSSH, and Docker guides were checked on November 12, 2026. Verify the applicability of specific parameters against the installed versions. The presence of an example does not establish installation or protection of a particular server.

The rate values are starting defaults. Tune API/MCP throughput, website throughput, and burst capacity to the actual workload and shared-IP/proxy policy, then rerun the checks. The Docker test harness bounds each CLI call to 30 seconds. Its cleanup records exact owned resources, attempts independent removal and absence checks, and retains `cleanup_pending` when the result is unknown. The daemon-free regression command is `python -B infra/nginx/test_harness.py`.
