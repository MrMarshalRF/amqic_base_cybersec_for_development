# Defensive AI tool runtime reference

This optional Node.js 22/24 standard-library module admits structured tool requests to fixed, trusted handlers. It runs no shell, installs nothing, resolves no DNS and makes no network requests. It is a same-process reference guard, not an untrusted-code sandbox, process containment system, OAuth server or production approval service. See [the integration guide](../../docs/AI-AGENT-RUNTIME.md).

Run from the repository root:

```sh
node --test enterprise/agent-runtime/agent-runtime.test.mjs
```

## Executable synthetic integration

Save this example as `demo.mjs` in this directory and run `node enterprise/agent-runtime/demo.mjs` from the repository root. The handler operates only on synthetic in-memory data. The automatic approval callback is **TEST ONLY**; it demonstrates digest binding and supplies no human authentication or step-up approval. Do not expose adapters, session construction, revocation or policy compilation to model-generated code.

```js
import { compilePolicy, createSession } from './agent-runtime.mjs';

const catalog = {
  version: 1, maxCalls: 2, maxLifetimeMs: 60000,
  tools: {
    summarize: {
      args: { document: { type: 'string', values: ['synthetic-report'] } },
      requiresApproval: true, endpointIds: []
    }
  }
};
const identity = {
  sessionId: 'demoSession', tenantId: 'demoTenant',
  actorId: 'demoActor', generation: 'generationOne'
};
const session = createSession({
  compiledPolicy: compilePolicy(catalog, catalog), identity,
  handlers: { summarize: args => ({ summary: `Synthetic summary: ${args.document}` }) },
  now: () => Date.now(),
  audit: event => { console.log(JSON.stringify(event)); return true; },
  approve: async ({ digest, binding }) => {
    // TEST ONLY. A real trusted approval service must authenticate the approver,
    // show the exact binding, enforce its own freshness and return this digest.
    if (binding.request.tool !== 'summarize') throw new Error('Denied');
    return { digest };
  }
});
console.log(await session.dispatch({
  ...identity, requestId: 'demoRequest', tool: 'summarize',
  args: { document: 'synthetic-report' }
}));
session.revoke();
```

## Exact supported contracts

- `compilePolicy(policy, catalog)` snapshots and freezes a host-authored policy bounded by a trusted catalog. Both use the exact version-1 shape shown above. Every tool has `args`, `requiresApproval` and `endpointIds`. All argument fields are required; unknown keys deny. Supported field schemas are `{type:'string',values:[...]}`, `{type:'boolean',values:[...]}` and `{type:'integer',min,max}` with safe integers. No regex, arbitrary JSON Schema, executable conditions, optional fields or nested argument objects are accepted.
- `checkPolicyNarrowing(candidate, boundary)` returns `within_boundary`, `outside_boundary` or `unsupported_or_invalid`. It checks supported finite sets and integer ranges, subsets of tool/endpoint IDs, tighter call/lifetime limits and preservation of required approval. Identical argument names and types are required. This closed comparison is not an SMT solver or formal proof for general policy languages.
- `createSession({compiledPolicy,identity,handlers,approve,audit,now})` binds exact host-selected `sessionId`, `tenantId`, `actorId`, `generation`. Identity/request/tool IDs match `[A-Za-z][A-Za-z0-9_-]{0,63}`. Each dispatch takes exactly these identity fields plus `requestId`, `tool`, `args`. A model-provided approval flag denies. The model may send data requests only; it must have no same-process access to trusted JavaScript objects or adapters.
- The approval callback receives `{digest,binding}`; its answer must be exactly `{digest}` matching SHA-256 of canonical normalized session/request/policy/catalog/endpoint-ID/expiry data. Trusted approval must decide that exact binding; echoing any digest automatically is never real approval. The handler receives frozen `(args,{identity,requestId,digest,endpointIds})`. Only endpoint IDs are bound: hostname, path, credential reference, executable identity and MCP server/tool versions are not included automatically. The host must capture an immutable trusted endpoint-ID and handler/version mapping for each session, and handlers must enforce that mapping. A changed mapping requires revoking the old generation and creating a new session. Capturing a handler function cannot freeze mutable configuration in its closure. This module implements no executable/version attestation, MCP authentication or provider authorization.
- `audit` must durably accept each sanitized event and return exactly `true`. Only `reserved` and `dispatch` events with fixed metadata, tool/request/session IDs and digest are emitted: no arguments, result, credentials or raw adapter exceptions. Denial, approval decision, effect completion and result-reconciliation events are host responsibilities. The host must use opaque nonsecret IDs and protect the audit sink. The events are ordinary local JSON records, not an OCSF schema. A digest can reveal low-entropy values by guessing; do not use arguments for secrets. Approval receives arguments deliberately, so its interface must also be trusted.
- Calls and request IDs are consumed before awaiting audit/approval, including denied approvals, handler errors and unknown effects. Replay state is bounded by `maxCalls` (1–10000); lifetime is 1–86400000 ms. The host supplies authoritative nonnegative safe-integer time. Rollback or clock failure latches revocation. Expiry/revocation is rechecked after asynchronous approval and audit immediately before handler invocation. No automatic retries occur.

Keep `session.revoke()` under the trusted host's generation kill switch. For a new generation create a fresh session and revoke every old instance. RAM replay state and revocation cover only this object in this process, disappear on restart and do not coordinate replicas. Production needs atomic durable shared admission, trusted generation/revocation state, authenticated approvers, result reconciliation and handler-side authorization. An effect already started cannot be undone by later revocation; handlers need cancellation/transaction semantics where applicable. The guard does not impose a handler timeout or bound handler output, CPU, memory, network response size or provider cost. The host must enforce these independently.

## Optional offline egress plan

`checkEgress({url,method,endpoint,dnsAnswers})` accepts an endpoint with exactly `id`, `hostname`, `path`, `method`, `credentialRef`. It returns an immutable `plan_only` object or `{status:'denied'}`. Example input:

```js
{
  url: 'https://api.example.org/report', method: 'POST',
  endpoint: { id: 'reportApi', hostname: 'api.example.org', path: '/report',
    method: 'POST', credentialRef: 'reportCredential' },
  dnsAnswers: ['8.8.8.8'] // synthetic supplied resolver observation, no lookup
}
```

The host authors the endpoint and supplies **all** resolver answers. Only exact lowercase ASCII DNS names, HTTPS implicit port 443, `GET`/`POST` and simple canonical paths are supported. Explicit ports, userinfo, query, fragment, encoding, dot segments, duplicate slashes, alternate hosts, IPv4 literal hosts, Unicode and all IPv6 answers deny. Each address must be a canonical public IPv4 value; private, loopback, link-local, CGNAT, documentation, benchmarking, multicast/reserved and the Azure platform virtual IP deny. This deliberately narrow offline filter is not a complete provider-special-address registry or DNS binding guarantee.

The plan carries only a fixed credential reference ID, never a credential. It is **not an authorization token**. A real fixed transport must resolve again at connection time, validate every actual answer, pin the checked connection address, preserve the original hostname for TLS verification and SNI, reject every redirect, and apply separate OS/network egress restrictions. Model-supplied DNS answers or endpoint configuration cannot establish authorization. This module implements none of those transport, DNS, secret-store or OS integrations.
