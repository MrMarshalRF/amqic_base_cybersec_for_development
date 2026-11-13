# An external protection layer with Cloudflare

This example places Cloudflare in front of the website's existing origin protections. It is a second layer in the network path, not a security certification or a replacement for the application. No account settings or live traffic are changed by this guide.

The intended path is: **visitor → Cloudflare edge → restricted origin/Nginx → private application container → private data services**. Administrative VPN access has its own narrowly allowed path. The origin still enforces hostname/TLS checks, allowed routes, safe input handling, authentication, rate limits and least privilege.

## How DDoS works

Denial of service means making a service unavailable or too slow for legitimate users. A distributed attack uses many traffic sources. The sources may be compromised machines, coordinated clients, proxies or traffic from systems abused to reflect responses. Source count alone is not proof of an attack.

| Kind of pressure | What runs out | Simple example | Why one control is insufficient |
| --- | --- | --- | --- |
| Network volume, often discussed at layers 3/4 | Link capacity, packet-processing or connection capacity | More packets arrive than the network path can carry. | An application returning 429 cannot recover bandwidth already saturated upstream. |
| Connection/protocol state | Connection tables, TLS/HTTP processing, available workers | Many connections keep resources occupied. | A firewall rule, edge protocol handling and server time/resource limits address different stages. |
| Application requests, often layer 7 | CPU, database connections, storage, paid external calls | Many apparently valid searches hit an expensive uncached endpoint. | HTTPS encrypts the requests but does not make them cheap or authorized. |

Traffic spikes can also be legitimate, such as a popular news link. Distinguish abuse from real demand using request patterns, resource saturation, error rates and representative samples. One high request count, country or user agent does not by itself prove malicious intent.

Cloudflare can absorb/filter supported traffic at its edge before forwarding accepted requests to the origin. Caching can eliminate some origin work entirely. However, uncached requests still consume origin capacity, and a leaked directly reachable origin can bypass the edge. A web proxy also does not automatically protect every unrelated protocol or port on the origin machine. See [Cloudflare's DDoS overview](https://developers.cloudflare.com/ddos-protection/) and [HTTP DDoS protection](https://developers.cloudflare.com/ddos-protection/managed-rulesets/http/).

## 1. Inventory the application first

List public hostnames, assets, dynamic pages, APIs/MCP, uploads, WebSockets/streaming, login/account pages and private administration. Record which requests are personalized, change state, carry a cookie/token, or call expensive services. Identify legitimate machine clients that cannot complete browser challenges.

Choose the actual plan/features available to the zone and review current limits in official documentation. Managed WAF rules, custom rules, rate-limit capabilities, bot controls, logging and rule counts vary by product and plan. Do not assume an example setting is included in every account or that turning on a product proves it protects the complete application.

Prepare a rollback and independent administrative access before changing DNS, origin firewall or TLS. Record the last working rules and origin address privately. Never publish a production IP or token in a public walkthrough.

## 2. Proxy public web DNS and close the bypass

Enable proxying for the supported public web records, then verify public DNS and the actual HTTP path. A DNS-only record resolves to the origin and does not send web traffic through the same proxy protections. Review IPv6, alternate hostnames, old DNS records, mail/services sharing the IP and unintended published application ports.

At the provider and host firewall, restrict public origin web ingress to the current official Cloudflare source ranges and any separately justified service paths. Maintain IPv4 and IPv6 rules. Keep SSH private through the agreed VPN/administrative sources; adding Cloudflare web ranges is not an SSH authorization mechanism. Do not close the old management path before proving recovery and a new session.

Use the [official IP list](https://www.cloudflare.com/ips/) through a reviewed update process. Do not paste an old static list and forget it. Restrict actual origin ingress, not merely what your DNS publishes. Preserve the kit's [Nginx and firewall checks](INITIAL-DEPLOYMENT.md).

An IP allowlist identifies the proxy network, not necessarily your own zone or a specific visitor. Retain hostname/SNI checks and consider authenticated origin connections appropriate to the deployment. Review other public applications on the same host instead of assuming a single domain-level setting covers them.

## 3. Use verified TLS on both legs

Use Cloudflare **Full (strict)** with a valid matching origin certificate and correct origin configuration. The visitor-to-edge and edge-to-origin connections are separate TLS sessions. Do not rely on a mode that leaves the origin leg unencrypted or skip certificate validation as a troubleshooting shortcut. See [Full (strict)](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/).

An [Origin CA certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/) is intended for Cloudflare-to-origin trust. Ordinary browsers generally do not trust it for direct access. If administrators use a VPN hostname directly, provide a certificate and trust model valid for that path too; do not disable browser/SSH certificate or host checks.

[Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) adds client-certificate authentication on supported origin connections. Understand the selected certificate scope: a shared Cloudflare certificate proves a Cloudflare connection, not exclusive ownership of your zone. Stronger per-zone/custom arrangements have their own setup and availability. Do not claim account-specific authentication merely because a shared certificate is enabled.

## 4. Cache only content that is safe to share

A cache stores a response so later requests can be served without repeating origin work. It is useful for immutable public assets, but dangerous for personalized data if the cache key or rules mix users.

Example: `app.a1b2c3.js` can be shared by all visitors when it contains only public application code and its filename changes whenever the bytes change. A page showing one person's contact details cannot be shared with the next visitor.

| Request/response | Starting policy | Reason |
| --- | --- | --- |
| Fingerprinted public JS/CSS/images/fonts | Cache deliberately with a suitable TTL and correct content type | Same safe bytes for every visitor; new build uses a new URL. |
| Login, logout, account/admin pages and personal-data responses | Bypass shared caching; send appropriate no-store headers | Avoid serving session or personal data to another user. |
| Requests with session cookies or an Authorization header | Bypass by default until a separately reviewed policy proves sharing is safe | Identity-specific data must not be merged by a shared cache key. |
| API/MCP, POST/state-changing requests, streams and uploads | No generic “cache everything” rule | Authentication, method semantics, freshness and streaming require specific handling. |
| Public anonymous HTML | Review separately | It may be shareable, but template personalization, cookies, language and updates must be accounted for. |

For a genuinely public fingerprinted asset, an illustrative origin response is:

```http
Cache-Control: public, max-age=31536000, immutable
```

Only use such a long lifetime when URLs change with content and the data is safe for any viewer. Cache invalidation cannot reliably remove a previously delivered private response from every client.

For a personal-data response, an illustrative origin response is:

```http
Cache-Control: private, no-store
```

Also configure the relevant edge bypass rules. Cloudflare rule/settings combinations can alter how origin headers are handled, and an explicit edge cache override can defeat an intended origin policy. A header alone is not proof of the effective configuration. Review [default cache behavior](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/), [Cache-Control](https://developers.cloudflare.com/cache/concepts/cache-control/), and [Cache Rules](https://developers.cloudflare.com/cache/how-to/cache-rules/).

Create narrow public-asset cache rules, not a blanket rule for all URLs. Configure explicit bypasses for sensitive route families and identity-bearing requests. Cache Rules are stackable, and the last matching conflicting setting wins: a later eligibility/TTL rule can undo an earlier bypass. Inspect the complete effective rule order in the actual zone. Do not treat `Authorization`, `Vary`, `Set-Cookie`, or a custom cache key as a universal protection for personalized responses. Some cache configurations can store responses despite authentication or change cookie handling. Test the effective behavior rather than inferring it from a rule name.

### Prove cache separation

Test at least two independent synthetic users plus an unauthenticated client. Use separate cookie jars and requests through Cloudflare. Confirm no client's page/body/cookie appears in another client's response, and that login/account/API/MCP responses are not shared-cache hits.

For intended public assets, compare repeated requests using the returned `CF-Cache-Status`, `Age` where present, content bytes and origin logs. A cache miss on a first request may be normal; a hit on a personal-data response is a warning requiring investigation. Test query strings, cookies, locale and deployment URL changes relevant to your application. `CF-Cache-Status` is one observation, not proof that the response contains safe content.

Randomized URLs/query strings and expensive uncached endpoints can still generate origin work. Bound query complexity, database work, uploads and external calls in the application. Caching does not replace those limits.

## 5. Add WAF, bot handling and rate limits deliberately

Review the zone's available [WAF](https://developers.cloudflare.com/waf/) managed rules and custom-rule capabilities. Test expected browser and machine flows before enforcement. Use supported observation or staged rollout where available, keep a rollback, and tune narrowly scoped false positives with evidence. Do not globally skip protection for every request that sends a chosen header or user agent.

Apply separate rate policies to login, uploads, expensive APIs and other routes, with limits appropriate to their normal cost and shared-user traffic. Match the intended host/path/method and use only verified identity/request characteristics supported by the plan. A client-supplied header alone cannot establish trusted identity. Distributed edge rate limiting is approximate and can admit excess requests during detection/propagation; do not use it as an exact financial quota or single-use authorization check. Keep Nginx and application limits as additional layers and monitor their combined effect. See [rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/).

Interactive challenges may be appropriate for some browser traffic but break API/MCP clients, webhooks and automation. Provide a deliberately authenticated machine route/policy rather than expecting a server client to click CAPTCHA. Preserve application authentication, replay defenses and per-operation authorization. Browser challenges do not authenticate a person or prove a submitted field safe.

Cloudflare's DDoS controls, WAF and application rate limits act at different points and have different capabilities. A plan name or a single “enabled” toggle does not establish that every attack or origin resource is covered. Review current product scope and service limits rather than promising unlimited protection.

## 6. Restore client addresses only from trusted proxies

Nginx normally sees the Cloudflare connection's address. For client-level limits/logging, restore the visitor address only from the trusted proxy network using the configured real-IP mechanism. Accept `CF-Connecting-IP` only after the socket peer has been verified as an allowed proxy.

An attacker can send a header with the same name directly to a reachable origin. That header must not grant access or an exemption. Keep the kit's distinction between proxy peer and restored client and verify both paths. Never add all networks to `set_real_ip_from` to make a log display look right. See [restoring visitor IPs](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/) and the [trusted-client model](INITIAL-DEPLOYMENT.md).

Forwarding through a VPN gateway or NAT is a different path and can produce a different source address. Do not apply proxy-header trust to it without an actual authenticated, correctly configured HTTP proxy.

## 7. Acceptance, monitoring and incidents

Before closing the change, verify DNS/proxy status, both TLS legs, restricted origin reachability, allowed public routes, forbidden files, private administration, and restored client-IP behavior. Exercise normal browser login, personal-data forms and authenticated machine clients through the edge. Check cookies, redirects, CSP, request limits and sensitive cache bypasses.

Monitor edge blocks/challenges and origin request rates together with latency, errors, saturation and legitimate user reports. An edge-block count is a policy observation, not proof of a compromise or a count of successful attacks. Keep logs access-controlled and minimize personal data.

During an incident, use the prepared response procedure and current evidence. Escalate to the provider when appropriate. A global challenge or temporary route restriction can affect legitimate users; apply it deliberately and roll it back when no longer needed. Do not disable all protection or expose the origin publicly to work around a false positive. Do not perform unapproved load tests or attacks on real infrastructure.

The kit's [operational threat report](../THREAT-DATA.md) illustrates careful interpretation of real policy observations. It is not a benchmark or a promise that another Cloudflare zone will produce the same result. Record this deployment's actual settings, plan, dates, tests and remaining risks in its private operational documentation.
