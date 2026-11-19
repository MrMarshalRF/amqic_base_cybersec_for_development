# Nginx protocol-parser security and rollout

Reviewed on 19 November 2026. The upstream advisory lists Nginx OSS 1.30.7+ and 1.31.9+ as fixed for CVE-2026-123007 (HTTP/2 flow-control memory corruption) and CVE-2026-123633 (HTTP/2 use-after-free). The 18 November release also addresses HTTP/3, TLS request-body processing, resolver, mail and stream issues. Check each product against its vendor advisory and exact package revision. [Nginx security advisories](https://nginx.org/en/security_advisories.html) В· [Stable changelog](https://nginx.org/en/CHANGES-1.30)

## Inventory and exposure

Inventory every replica, ingress controller, appliance and bundled proxy that can receive untrusted traffic. Record distributor, full build, architecture, artifact digest, listeners, built HTTP/2 and HTTP/3 modules, effective protocol settings and process identities. Include the terminator binary/package in the host or image SBOM. Authenticate inventory through the deployment's trusted collector and protect raw diagnostics.

Record a target for every replica, including an offline replica that could return to service. Process identities must include host/container boot identity and start time so PID reuse cannot make an old worker look new.

The kit pins the official Nginx 1.30.7 Alpine image by digest. Its version and normal HTTP/TLS behavior are checked in the laboratory. Check distributor backports, NGINX Plus and forks against their own advisory dispositions. Older upstream version numbers can be fixed backports, while package-specific affected ranges may differ.

## Temporary protocol policy

The template sets `http2 off;` in the http context. Remove all legacy `listen ... http2` parameters and server-level enabling directives from the effective configuration. Legacy listeners can enable HTTP/2 despite a separate off directive. The explicit directive requires Nginx 1.25.1 or later and the HTTP/2 module. Validate the configuration with the matching patched binary. [HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html)

Keep QUIC listeners and UDP ingress closed. Verify active configuration and network publication independently. The template has no QUIC listeners and suppresses upstream Alt-Svc. Check protocol settings separately on visitor-to-CDN and CDN-to-origin connections, then confirm the protocol actually negotiated on the origin leg. [HTTP/3 module](https://nginx.org/en/docs/http/ngx_http_v3_module.html) В· [Cloudflare HTTP/2 to origin](https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/)

Disabling HTTP/2 reduces reachability for these two HTTP/2 flaws. Install the patched package for the broader security release. Raising worker_connections, WAF signatures, rate limits and CDN settings cannot establish that the parser is patched. Keep route, hostname, TLS, CSP and workload restrictions active through the change.

## Patch and verify

1. Open a change record. Capture affected replicas, exact vendor findings for relevant CVEs, configuration, artifact and recovery access. Confirm runtime SBOM coverage.
2. Procure the patched artifact through the approved supply-chain process. Set its exact digest and validate the candidate configuration with that binary.
3. Roll out through the deployment procedure. Verify permitted routes, methods, authentication, Host/SNI, certificates, CSP and sensitive-path denials.
4. Replace or drain old processes. A reload acknowledgement alone cannot establish that old workers exited. Long-lived connections may extend drain. Confirm every previous master and worker is absent and every new instance uses the intended artifact. Set shutdown timeouts through the deployment's availability policy.
5. Offer h2 and http/1.1 in benign TLS negotiation. Confirm http/1.1 under the restrictive policy and exercise a permitted request. Check HTTP/3/QUIC listeners and UDP ingress separately.
6. Preserve hashes and observations. Record missing replicas or unknown vendor builds as unresolved. Keep a patched or protocol-restricted rollback option and verify compatibility before switch-over.

For an exposed parser advisory, assign an incident owner immediately and record an exposure-based patch deadline. Prioritize isolation or protocol mitigation while preparing the patch. Exceptions require an owner, expiry and monitoring under the deployment's operations policy.

## Offline rollout gate

`enterprise/runtime/nginx-rollout.mjs` validates operator-prepared policy and inventory. It requires vendor findings for both HTTP/2 CVEs and any additional CVEs selected in the change, an exact artifact digest, replaced master and workers, prior-process absence and fresh protocol observations for each listed replica.

Vendor findings are trusted, reviewed server-side policy. An attacker-supplied statement that a build is fixed cannot supply that authority. The informational OSS version helper recognizes only the dated 1.30 and 1.31 release lines. The actual gate uses the exact reviewed vendor finding, allowing a documented backport with its distributor's build and reference.

Policy schema `amqic-nginx-policy/v1` contains `changeId`, `changeStartedAt`, `requiredAdvisories`, `expected` and `vendorFindings`. Each expected entry contains `workload`, `previousMaster`, `previousWorkers` and `artifactDigest`. A finding contains `vendor`, `product`, `build`, `architecture`, `cve`, `status` and an HTTPS `reference`.

Inventory schema `amqic-nginx-inventory/v1` contains the same `changeId`, `observedAt` and `observations`. Observations carry `workload`, `master`, `startedAt`, `workers`, `previousProcessesAbsent`, the four vendor/build identity fields, `artifactDigest`, `evidenceDigest` and `protocols`. Workers carry `instance` and `startedAt`. Protocol fields are `http2`, `http3`, `quicUdp` and `alpnHttp1`. The [synthetic tests](../enterprise/runtime/nginx-rollout.test.mjs) include a complete fixture.

Use UTC timestamps with milliseconds and opaque aliases in public evidence. Observations must be at most 24 hours old and made after the change started. This profile expects HTTP/2, HTTP/3 and QUIC false and ALPN HTTP/1.1 true. Validate input bytes and supply the resulting ETag:

```sh
node enterprise/runtime/nginx-rollout.mjs --plan policy.json inventory.json
node enterprise/runtime/nginx-rollout.mjs --verify policy.json inventory.json EXPECTED_ETAG
```

The result includes its input ETag, canonical output SHA-256 ETag and per-target outcomes. Exit 0 accepts the recorded rollout, exit 1 means unresolved targets, and exit 2 means invalid input or stale ETag. Retain exact input bytes and source revision. This offline tool evaluates supplied observations. The trusted collector must establish their authenticity and completeness.

## Detection and response

Alert on unexpected worker crashes, segmentation faults, repeated exits and restart growth. Correlate workload saturation, protocol at the termination point, deployments and error rates. Ensure worker-crash messages reach monitoring while keeping request logs minimal. Exclude authorization headers, cookies, bodies and raw opaque identifiers.

Unexpected proxy children, new files and outbound connections are investigation signals. Confirm configured helper roles and startup context, then review credential access and process trees. The [starting Falco rule](../enterprise/runtime/profiles/nginx-shell.falco.yaml) flags a successful direct shell child of an nginx process inside a container. Validate rule syntax and behavior against the installed Falco version and tune authorized helpers through your monitoring policy. This source-reviewed signal has no local kernel/Falco execution result. [Falco rules](https://falco.org/docs/reference/rules/)

Collect core dumps only through a private approved procedure. Dumps can contain credentials and application data. Restrict collection, access, retention and sharing. When compromise is suspected, isolate the instance, preserve necessary evidence, rebuild from verified artifacts and review accessible credentials through incident response.

## Verification and standards

The fixed baseline tests the offline rollout gate with synthetic records. The Nginx laboratory uses benign TLS/HTTP requests to verify protocol defaults, ALPN and the existing access controls. Required checks for an actual CDN, ingress, fork or rollout remain in the target environment.

These controls support NIST SP 800-53 Rev. 5 SI-2 (Flaw Remediation), CM-6 (Configuration Settings), CM-8 (System Component Inventory), SC-7 (Boundary Protection), SI-4 (System Monitoring) and IR-4 (Incident Handling). Use recorded evidence and operating scope for an assessment. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
