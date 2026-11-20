# Fixed outbound HTTPS and local return routes

This Node.js 22/24 standard-library reference makes a real HTTPS GET using a host-authored endpoint catalog. Callers select an endpoint ID; they cannot supply a URL, host, method, path, query, body, credentials or headers. This adds a connect-time implementation beyond the agent-runtime reference's offline egress decision. It is a bounded IPv4 profile, not a universal SSRF solution or an OS network sandbox.

This application catalog is not host or container egress enforcement. A process can initiate connections outside the catalog; use the separate [host egress monitoring guide](../../docs/HOST-EGRESS-MONITORING.md) for default-deny network policy, approved destination classes and minimal decision telemetry at the host/container boundary. Neither document activates that deployment layer.

Trusted application startup can construct a client:

```js
import { createOutboundClient, createReturnRouteResolver } from './outbound.mjs';

const outbound = createOutboundClient({ endpoints: [{
  id: 'catalog', hostname: 'catalog.example.com', path: '/public/catalog',
  maxBytes: 65536, timeoutMs: 5000, contentType: 'application/json'
}] });
// Invoke only in an authorized deployment with its real, reviewed catalog:
// const bytes = await outbound.get('catalog');
const returnTo = createReturnRouteResolver([{ id: 'account', path: '/account' }]);
console.log(returnTo('account')); // /account
```

The example hostname is a placeholder. Merely importing this module and constructing a client performs no network operation. Run the fully synthetic executable example/test suite without network access:

```sh
node --test enterprise/outbound/outbound.test.mjs
```

At each call, a whole DNS answer list is obtained using `dns.lookup(host, {all:true, verbatim:true})`. Any unsafe answer denies the operation; an empty list or more than 32 answers also denies it. Only canonical IPv4 literals from the checked list can reach the request's lookup callback. The default `https.request` connects using that callback, preserving the original hostname for HTTP Host, SNI and normal certificate/hostname verification. There is no second DNS lookup between checking and connecting. It uses port 443, `rejectUnauthorized:true`, `family:4` and `agent:false`, with no pooled connections or application DNS cache. Direct `https.request` does not consume proxy environment variables. Do not replace it with a proxy-aware fetch wrapper or install a custom global transport hook.

The profile denies IPv6 and IPv4-mapped IPv6, private, loopback, link-local/metadata, carrier-grade NAT, multicast, reserved and documented special-use IPv4 ranges, including Azure's `168.63.129.16`. Some special-use blocks are intentionally rejected more broadly than their individual allocations. A hostname must be lowercase ASCII, non-IP, without wildcard or trailing dot. This intentionally excludes IDN input and IPv6-only services. Keep the special-use policy reviewed as deployment requirements and address registries change; a public IP classification alone is not authorization to contact a service.

Endpoint paths use a narrow canonical grammar: `/` and slash-separated ASCII letters, digits, `_` or `-`, optionally ending in `/`. Encoding, dot segments, backslashes, query strings, fragments and credentials have no representation. Endpoint records are copied at factory creation. The fixed request headers are Accept and identity Accept-Encoding; no credential injection API is implemented. If authentication is required, design and review a separate fixed trusted credential consumer rather than passing model-controlled headers to this API.

The absolute deadline starts before DNS and covers connection, TLS, headers and body, capped at ten seconds. Late DNS completion cannot create a request after timeout/abort. There are no retries or redirect following. Only status 200 and the configured JSON/plain-text media type are accepted. Compressed bodies are unsupported. Both declared and streamed sizes are bounded before buffering, up to 1 MiB, with at most 4096 chunks and an 8 KiB response-header limit. Request, response and owned socket are destroyed on failure, timeout and completion. Public errors expose only fixed messages/codes, never upstream errors, headers, certificates or body text. Successful bytes remain **untrusted data**: parse using a bounded schema, authorize their use, and escape output; do not execute them or treat them as agent instructions.

`createReturnRouteResolver` separately maps fixed IDs to canonical local application paths. Never take a caller URL and normalize it into a return path. The resolver returns only the exact startup snapshot, rejecting unknown IDs including prototype names. It makes no network/filesystem calls. This is not an OIDC `redirect_uri` validator; provider callback registration and exact OIDC redirect matching remain separate.

Both `resolve` and `request` are trusted **startup-only test adapters**, never request/model arguments. A malicious replacement can bypass transport security; protect code and startup configuration outside the agent's writable boundary. The shipped tests inject synthetic event streams, inspect pinned lookup/TLS options and exercise denial/timeout/cleanup behavior. They perform no DNS, socket, live-service, Docker or external integration test. Actual TLS/OS routing, egress firewall enforcement, trusted resolver behavior and upstream service authorization must be checked independently in the authorized deployment. Limit outbound access at the network boundary as an additional layer.
