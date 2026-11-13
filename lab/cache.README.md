# Synthetic reverse-proxy cache privacy lab

Run `node lab/cache-verify.mjs --output /absolute/external/new-cache-report.json`.
Node.js 22+ and Docker with the fixed local image below are required. The ALL lab
preparation step can fetch this exact digest; this individual verifier never
selects a mutable tag or downloads an alternative image.

`nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`

The verifier starts two actual Nginx containers on one dedicated internal Docker
network. One serves only synthetic responses; the other performs real proxy
caching. No host ports, real domains, account data, credentials or production
configuration are used. Fixed HTTP probes run inside the proxy container using
the image's `wget`. A/B strings are public fixture identifiers, not passwords.
Containers run as UID/GID 101 with a read-only root, dropped capabilities,
resource limits and a bounded tmpfs cache.

The assertions exercise:

- An anonymous fingerprinted public asset changes from `MISS` to `HIT`, with
  the same upstream request identity and an immutable public cache policy.
- Authorization and cookie requests bypass even an already warmed public
  asset. Alternating synthetic clients A/B receive only their own bodies and
  distinct upstream request identities.
- Personal and API routes bypass caching. Origin `private, no-store` responses
  and responses with `Set-Cookie` are never served from shared cache, including
  anonymous requests to otherwise cache-eligible fingerprinted paths.
- A forged client cache-status header cannot replace the proxy's status. The
  warmed anonymous entry remains anonymous after the personalized requests.

The public fixture deliberately varies its body for credentialed requests to
make incorrect cache sharing observable. This does not recommend personalized
content on public asset URLs. In production, public fingerprinted assets should
be invariant and private data should use separate routes.

An exclusive external JSON report contains source hashes, observed image ID and
Nginx version, named assertions, and cleanup results. The adjacent
`.resources.json` records launch intent, exact container/network IDs, observed
start times and lifecycle state. Exit 0 means all assertions and cleanup passed;
exit 1 means failure. Cleanup discovers only the exact random ownership label,
removes those containers/network, then requires successful empty listings.
Docker errors never count as absence. Keep failed reports for diagnosis.

This is a local generic Nginx reference, **not a Cloudflare deployment test**.
The report always marks `realCloudflare` as `vendor_not_tested`. It does not
establish CDN account rules, edge keys, tiered caching, public TLS, HTTP/2 or
HTTP/3, browser caching, stale/revalidation behavior, concurrency, or all `Vary`
cases. Normal Nginx processing of upstream cache headers is left enabled; only
the explicit scenarios above are measured. Configuration text alone cannot
establish a live provider's behavior.

See [HTTP Caching, RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html),
[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
(data-protection and configuration controls), and the kit's
[Cloudflare guide](../docs/CLOUDFLARE-EDGE.md) for deployment boundaries. Provider
configuration and its authorized verification remain separate work.
