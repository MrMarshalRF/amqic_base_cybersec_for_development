# Private administration with VPN tunnels

## Choose the access pattern

| Pattern | Suitable use | What you must operate |
| --- | --- | --- |
| WireGuard server and a WireSock Windows client | A small set of known administrators reaching one server or a routed private network | Peer keys, endpoint, UDP reachability, routes, firewall and revocation |
| Tailscale on each endpoint | Identity-managed access between workstations and servers across changing networks | Identity provider, device enrollment, restrictive access policy and device lifecycle |
| Tailscale subnet router | Access to devices that cannot run a client | A protected forwarding gateway, advertised/approved routes, destination policy and return-path/SNAT decisions |

Start with clients on both endpoints for private SSH/HTTPS administration. A subnet router or internet exit node is unnecessary for that arrangement. Keep public website ingress through its normal proxy and private administrative ingress as separate paths. These are templates, not changes applied to a real server or this workstation.

A VPN encrypts a network path; it does not make the endpoint trustworthy, remove the need for HTTPS, erase historical origin IP addresses, or authorize application actions. Preserve SSH public-key authentication, application sessions, MFA for sensitive operations, least privilege and recovery access. This guide assumes ordinary OpenSSH over the VPN. Tailscale SSH is a separate feature with different authorization and is not enabled here.

## Before changing access

Inventory OS versions, public endpoint, LAN/container/tunnel ranges, DNS, required users/devices, allowed destination ports and an independent provider/serial console. Check for overlapping ranges before choosing addresses. Save the current SSH, firewall, VPN and Nginx configurations privately and define an exact rollback. Keep the existing administrative session while testing a new one; an established session alone does not prove new connections work.

Install supported clients from the [WireGuard installation instructions](https://www.wireguard.com/install/), [WireSock Secure Connect](https://wiresock.net/documentation/wiresock-secure-connect/get-started), or [Tailscale installation guide](https://tailscale.com/docs/install/linux). Pin and record versions through the project's normal dependency process. Do not pipe an unreviewed downloaded script into a privileged shell. Check the current WireSock license for the intended business use.

## Method 1: WireGuard and WireSock

WireSock Secure Connect is a Windows WireGuard client, not a VPN server. Run a compatible WireGuard endpoint on the server. Each administrator/device needs a separate keypair and tunnel address; sharing one client private key prevents independent revocation. Generate and provision private keys locally through the human-controlled protected process. Exchange public keys only. Never paste private keys into chat or commit completed profiles.

These illustrative profiles are deliberately incomplete: replace placeholder keys locally and choose non-overlapping addresses. The server has tunnel address `10.77.0.1`; one Windows administrator has `10.77.0.2`. This permits direct access to the server only; it does not route the internet or another LAN.

Server `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY_FROM_PROTECTED_LOCAL_PROVISIONING>

[Peer]
PublicKey = <ADMIN_CLIENT_PUBLIC_KEY>
AllowedIPs = 10.77.0.2/32
```

Windows client profile:

```ini
[Interface]
Address = 10.77.0.2/32
PrivateKey = <CLIENT_PRIVATE_KEY_FROM_PROTECTED_LOCAL_PROVISIONING>

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = vpn.example.com:51820
AllowedIPs = 10.77.0.1/32
# Enable only when NAT mapping maintenance is needed:
# PersistentKeepalive = 25
```

`AllowedIPs` controls destination selection and peer source-address association; it does not replace the server's firewall or application permissions. On the server, assign only that client's tunnel addresses to that peer. Give additional peers distinct keys and `/32` addresses. Protect profiles and private keys with restrictive OS permissions/ACLs and an appropriate encrypted backup.

On Linux with `wg-quick`, after authorized provisioning and a reviewed firewall change:

```sh
sudo wg-quick up wg0
sudo wg show wg0
```

For a controlled disconnect, use `sudo wg-quick down wg0`. Configure boot activation through the distribution's service manager only after acceptance. Do not copy opaque `PostUp`/`PostDown` firewall hooks or add `SaveConfig=true` without understanding configuration rewrites. See [WireGuard quickstart](https://www.wireguard.com/quickstart/) and [wg-quick](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8).

In WireSock, import the locally protected client profile, select it and connect using the [documented GUI](https://wiresock.net/documentation/wiresock-secure-connect/connect.html). Verify a recent handshake and traffic counters on both ends before testing `ssh developer@10.77.0.1`. Do not disable SSH host-key checking; confirm the expected host key through an independent trusted channel.

### Optional per-application routing

WireSock supports additional selectors under `[Peer]`. For example, for a profile that only needs the Windows SSH client:

```ini
#@ws:AllowedApps = ssh
```

This line is a WireSock extension, not portable WireGuard access control. The selected application **and** destination must match `AllowedApps` and `AllowedIPs`. Prefer an exact reviewed executable path when needed. It is a client routing convenience, not proof of which person or process originated traffic. See [parameters](https://wiresock.net/documentation/wiresock-secure-connect/advanced-parameters.html) and [selector semantics](https://wiresock.net/documentation/guide/using-allowedips-and-allowedapps).

Do not replace the single-host route with `0.0.0.0/0` and `::/0` merely to reach SSH. Full-tunnel internet routing also requires forwarding, egress policy, NAT/return routes, DNS design and an IPv6 decision.

## Method 2: Tailscale on both endpoints

Install a supported Tailscale client on each authorized endpoint. On a Linux server, the interactive enrollment path is:

```sh
sudo tailscale up
tailscale status
tailscale ip -4
```

The first command provides an authentication URL for human approval. Do not put reusable auth keys in shell commands, source files or chat. Use the identity provider's MFA and the organization's enrollment/device-approval controls. The normal Windows GUI supports the equivalent sign-in flow. Record the actual device identity and address; do not invent or assume an address from the shared `100.64.0.0/10` range.

After enrollment, assign the server an authorized tag and use ordinary OpenSSH to its observed Tailscale address. Preserve this kit's `sshd` settings. Do not add `--ssh` casually: [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh) intercepts port 22 on the Tailscale address and has its own policy model.

### Restrict identity and destination

Adapt and validate this policy fragment in the tailnet's existing configuration. Replace sample identities; it is not a drop-in replacement for an organization's policy:

```json
{
  "groups": { "group:ops": ["operator@example.com"] },
  "tagOwners": { "tag:origin": ["group:ops"] },
  "grants": [
    { "src": ["group:ops"], "dst": ["tag:origin"], "ip": ["tcp:22", "tcp:443"] }
  ]
}
```

Apply `tag:origin` to the intended enrolled server through an authorized owner. Restrict who can assign that tag. Existing ACLs and grants are additive: a narrow grant does not cancel an old allow-all rule. Review the complete policy and remove/narrow unnecessary broad grants with the organization's approval. Test both permitted and denied identities and destination ports. This fragment does not grant port 80 redirects, arbitrary backend ports, or access to other tagged hosts' resources beyond the specified ports. See [grant syntax](https://tailscale.com/docs/reference/syntax/grants) and [grant semantics](https://tailscale.com/docs/features/access-control/grants/grants-explained).

Network rules distinguish identities/devices and ports, not HTTP paths or application roles. Continue enforcing the application's authorization and Nginx route policy. Review device/key expiry, offboarding and compromised-device revocation; a VPN session does not substitute for fresh step-up on a destructive action.

## Method 3: reach a private subnet

Use a dedicated, hardened Tailscale subnet router if the destination cannot run a client. Choose the precise non-overlapping subnet, enable required IP forwarding under change control, and implement deny-by-default forwarding rules. Then advertise only the intended route, for example:

```sh
sudo tailscale set --advertise-routes=10.77.20.0/24
```

This sets the node's advertised routes; preserve any other intentionally advertised routes in the new reviewed value. Approve the route in the admin console or a deliberately configured auto-approver, and separately grant only intended users/destinations/ports. Linux consuming clients may require `sudo tailscale set --accept-routes=true`; do not enable it indiscriminately on routing gateways. A route approval is not an access grant. Follow the [subnet-router guide](https://tailscale.com/docs/features/subnet-routers).

Subnet routing normally uses SNAT. The downstream service can see the router's LAN address, not the original client's Tailscale address. This affects Nginx allowlists, audit attribution and per-IP rate limits. Disabling SNAT on a supported Linux router requires an explicit return route to the original client ranges and corresponding firewall rules. Never disable it without verifying the complete path.

For WireGuard routed access, add the reviewed destination subnet to the client `AllowedIPs`, enable forwarding on the gateway, restrict forwarded destination ports, and provide return routes or an explicit SNAT design. These changes are unnecessary for direct host-to-host SSH. See Ubuntu's [peer-to-site guide](https://ubuntu.com/server/docs/how-to/wireguard-vpn/peer-to-site/).

An [exit node](https://tailscale.com/docs/features/exit-nodes) carries internet traffic and is distinct from a subnet router. It needs separate advertisement, approval, client selection and egress policy. Neither role provides a guarantee of anonymity or zero DNS leaks.

## Integrating this kit's firewall and Nginx

The shipped [nftables template](../infra/firewall/nftables.conf.template) is a starting policy for proxied web ingress and administrative TCP access. It does **not** open WireGuard UDP 51820 or provide a forwarding policy. Do not assume a tunnel works through the unmodified template or repurpose a web-proxy allowlist as a VPN permission.

For direct WireGuard, review the specific UDP listen port at the provider and host firewall. Separately allow the intended tunnel interface/source/destination and SSH/HTTPS ports. For Tailscale, reconcile its managed rules with this kit's input base chain: an earlier drop (the template uses priority `-10`) cannot be undone by a later accept. Inspect effective chain order and test fresh connections. Do not flush the complete ruleset, edit Tailscale-managed chains blindly, or allow every port on `tailscale0` as a shortcut. [nftables base-chain semantics](https://wiki.iptables.org/wiki-nftables/index.php/Configuring_chains) and [Tailscale firewall guidance](https://tailscale.com/docs/integrations/firewalls) describe the relevant boundaries.

Tailscale can use direct or relayed connections depending on network conditions. Preserve required control/relay connectivity and consult its [firewall ports](https://tailscale.com/docs/reference/faq/firewall-ports); do not open every inbound port to force a direct path. Record the observed direct/relay state when diagnosing latency.

For direct VPN-to-Nginx access, use the socket-peer allowlist model with the actual permitted VPN addresses and retain valid hostname/TLS checks. A request to a bare VPN IP can correctly fail Host/SNI validation: resolve your approved administrative hostname to the VPN address and use a certificate valid for that name. Do not relax Host validation to make the test pass.

Behind an actual trusted HTTP reverse proxy, use the separate [trusted-client model](INITIAL-DEPLOYMENT.md) with the exact trusted peer ranges. A NAT gateway is not a trusted source of client HTTP headers. Never grant access based on a user-supplied `X-Forwarded-For` header. Record the source Nginx actually sees and account for clients sharing SNAT when setting limits.

## Acceptance and recovery

Validate a recent handshake/device connection, intended routes, DNS, IPv4/IPv6 behavior and a fresh SSH connection with the correct key and host identity. Verify forbidden identities, ports, backend paths and external administrative access are denied. Test HTTPS, CSP and rate-limit behavior through the intended hostname. Confirm private routes remain private when the client disconnects and reconnects.

Check MTU/PMTU if handshakes succeed but larger transfers fail. Do not hard-code one MTU for every path; keep necessary ICMP error handling. Test DNS and browser DoH/proxy settings on the actual client. WireSock split-DNS and Tailscale DNS behavior differ; see [WireSock local-resource guidance](https://wiresock.net/documentation/guide/local-resources-unavailable.html) and [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale).

Only after a second tested session and working independent recovery should an authorized operator remove an old public management path. Revoke a lost device/peer, remove its allowed identity/routes, and verify fresh connections fail. Retain encrypted, access-controlled configuration backups. This guide is source-reviewed; it does not attest to a live tunnel or deploy a VPN configuration.
