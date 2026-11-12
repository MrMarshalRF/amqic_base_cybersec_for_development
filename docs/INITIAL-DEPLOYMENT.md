# Initial deployment behind a proxy

This procedure is intended to ensure that, from the first public launch, the origin accepts web traffic only through the selected proxy, while administrative access is restricted to separate trusted addresses. The templates prepare files. The owner makes DNS, cloud firewall, SSH, and network rule changes after review. Recovery access through the provider's console must work before changing the network.

## 1. Separate service roles

The registrar manages domain registration and DNS delegation. The authoritative DNS provider publishes records. The VPS provider hosts the origin server and usually offers its own network firewall. The HTTP proxy/CDN receives visitors' web requests and forwards them to the origin. Different companies may perform these roles.

Choose a proxy with the required HTTP/HTTPS capabilities, origin TLS verification, and origin access controls. For Cloudflare, the example procedure below uses proxied DNS records and the Full (strict) origin certificate verification mode. Obtain proxy network addresses from the selected provider's current official list and have the owner verify them. The kit includes no automatically trusted Cloudflare or other provider list. [Cloudflare origin protection](https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/).

In a private deployment record, save the official network list URL, the time it was retrieved in UTC, and the SHA-256 of the downloaded source file. After the generator normalizes the CIDRs, also save the SHA-256 of the resulting nginx/nftables policy file that you intend to apply. The source JSON policy hash appears in the nftables candidate's header. Before applying it and before every update, recheck the source, network membership, and hashes against the accepted candidate. A list from a previous deployment is not automatically considered current.

## 2. Restrict the network before publishing the origin

1. Create a cloud firewall/security group before connecting a new VPS to public service. Deny inbound traffic by default for IPv4 and IPv6.
2. Allow the actual SSH TCP port, usually `22`, only from your administrative CIDR or managed VPN/bastion addresses. Verify the administrator's current external address. Keep the provider's recovery console open.
3. Allow TCP `80` and `443` only from current, separately verified web proxy networks. If a particular operator needs direct access, include their exact CIDR through a separate deliberate decision. Access from the unrestricted internet is not required.
4. Keep all other inbound services closed. Do not publish application container ports externally. The database, Docker API, and administrative panels must listen on private interfaces or be accessible through a separate VPN.
5. Test the rules from the administrative connection and from an independent unauthorized address. Test IPv6 separately. Save the firewall configuration and the console rollback procedure.

Cloudflare's standard web proxy serves specific HTTP/HTTPS ports. It does not automatically carry SSH on `22`. Administrative SSH remains a separate connection through an allowed address, VPN, or bastion. [Cloudflare network ports](https://developers.cloudflare.com/fundamentals/reference/network-ports/).

## 3. Prepare SSH and origin TLS

Follow the verifiable sequence in [INFRASTRUCTURE.md](INFRASTRUCTURE.md) for a separate account, an Ed25519 key, a second SSH session, `sshd -t`, and checking the effective `sshd -T` settings. The selected user's `authorized_keys` must contain only the public part of the authorized key. `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, and `AllowUsers` enforce access on the SSH side. Nginx and DNS do not verify SSH keys.

Origin TLS uses a certificate for the exact domain and strict verification by the proxy. Do not disable certificate verification. To bind the origin more closely to a specific proxy/account, configure provider-supported origin authentication, such as mTLS/authenticated origin pull or a verified tunnel. A provider's shared CIDRs establish the network source, but serve many customers and do not by themselves prove that requests belong to your account. Application authentication continues to operate independently of this boundary.

## 4. Prepare the local ingress firewall

`infra/firewall/render.py` generates a separate `inet amqic_origin_guard` table. It preserves loopback, established/related connections, and required ICMP/IPv6 neighbor/MTU messages. New SSH connections are allowed only from `admin_cidrs`, HTTP/HTTPS only from `proxy_cidrs`, and all other inbound traffic is dropped. An address family without allowed CIDRs remains closed. This file does not configure outbound or forwarding traffic.

1. Copy `infra/firewall/policy.example.json` to a private local file outside the repository. Replace every placeholder. Set a separate SSH port and exact administrative/proxy CIDRs. The networks `0.0.0.0/0` and `::/0`, empty lists, and IPv4-mapped IPv6 entries are rejected.
2. Generate a new candidate.

```sh
python3 -B infra/firewall/render.py --policy /secure/origin-firewall.json \
  --output /secure/origin-firewall.nft
```

3. Before applying it, save the current rules, confirm that the console works, prepare an exact recovery plan, and check the file with `nft --check --file /secure/origin-firewall.nft`. Run this check in the target Linux environment with the required privileges. This step does not itself apply rules.
4. Ensure that a table named `amqic_origin_guard` does not already exist. The file uses `create table`, so adding an existing name again fails. Updating an existing table requires a separate reviewed change, rather than adding another copy of the rules.
5. Apply and persist the configuration through your system's standard mechanism after review. Keep the current SSH session open. Open a second session from an allowed address, verify web access through the proxy, rejection of unauthorized direct access, and IPv6. If a problem occurs, restore the exact previous state through the remaining session/console.

The file contains no `flush ruleset` and does not delete other tables. Other firewall managers may additionally block traffic allowed here. For one host, choose a managed UFW **or** native nftables approach; migrating from an existing manager requires a separate plan and compatibility check. For an initial VPS, this section replaces the UFW example in the main guide. [nftables manual](https://netfilter.org/projects/nftables/manpage.html).

Before applying it, confirm static addressing or separately verify DHCP and the provider service traffic required to obtain/renew an address. The template contains no special rules for initial DHCP configuration. Also check IPv6 router advertisements, neighbour discovery, and reconnection after a reboot. Updating an existing managed table must atomically change only `amqic_origin_guard`; this generator produces initial creation only and refuses to silently merge old rules.

Docker port publishing may use forwarding/NAT and bypass host-input rules. Preserve the kit's absence of published application ports, and check `docker ps`/`docker inspect` and external reachability. This template does not claim to filter arbitrary Docker forwarding chains.

## 5. Choose the nginx whitelist mode

The nginx whitelist supplements the cloud and local firewalls. Without `--allowlist`, the public policy of allowed routes remains in place. Passing `--allowlist` explicitly enables the restriction. An empty or invalid file stops generation, and the working file is not overwritten.

### Peer mode

Copy `infra/nginx/allowlist.peer.example.json`, fill in `peer_cidrs`, and specify `"mode": "peer"`. Nginx checks the address of the immediate TCP peer. Behind a CDN, that peer is a CDN node, so visitors passing through an allowed node pass the shared network boundary. To list specific end clients, use the next mode.

### Trusted-client mode

Copy `infra/nginx/allowlist.client.example.json`. Specify separate, non-overlapping `peer_cidrs` for trusted proxies and `client_cidrs` for allowed clients. Only an explicitly specified single header, either `CF-Connecting-IP` or `X-Real-IP`, is accepted. The selected proxy must overwrite it with the verified client address, removing the value from the visitor's original request. Confirm this in your proxy's settings and through a separate test.

The template configures `set_real_ip_from` for these networks only, disables recursive chain lookup, and checks both the original TCP peer through `$realip_remote_addr` and the restored client address through `$remote_addr`. A missing/invalid header or a composite comma-separated value does not grant access. An `X-Forwarded-For` supplied by an untrusted party does not establish trust. This mode requires an nginx build with `http_realip_module`; `nginx -t` detects a missing module. [nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html), [nginx geo](https://nginx.org/en/docs/http/ngx_http_geo_module.html).

In peer mode, limits are counted per TCP peer. In trusted-client mode, they are counted per restored client only after the trusted proxy is verified. A shared NAT still means a shared address. Protected files remain protected even for allowed clients. Whitelist denials pass through the existing limiter and receive `403` or `429`, including HTTP requests that would otherwise redirect to HTTPS.

```sh
python3 -B infra/nginx/render.py --host your-owned-domain.example \
  --upstream YOUR_PRIVATE_IPV4:8080 --allowlist /secure/nginx-allowlist.json \
  --output /secure/nginx-candidate.conf
```

Check the nginx CIDRs against the cloud firewall, origin authentication, and actual proxy addresses. Run `nginx -t` and test allowed/denied clients, header spoofing, protected URIs, limits, and CSP. Only then use the candidate in the server's standard change procedure.

## 6. Publish only proxied web access

Create the web DNS record with proxy mode enabled from the outset, if the provider supports it. Do not publish a temporary DNS-only origin record for initial testing. After delegating DNS, verify that the public answer for the web name contains proxy addresses and that the origin accepts web connections only from allowed networks and with the correct TLS/Host. Certificates can be prepared through a verified DNS-01 process without exposing the origin to the entire internet.

Separately check DNS-only subdomains, MX/SPF, mail servers, and other services using the same IP. They can reveal the origin address. Historical DNS records and third-party logs may retain previously published addresses. A proxy reduces direct reachability and ordinary disclosure of the web origin, but does not erase history or guarantee that the IP remains invisible. Even a discovered address must remain protected by the firewall and origin authentication. [Cloudflare exposed IP guidance](https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/exposed-ip-address/).
