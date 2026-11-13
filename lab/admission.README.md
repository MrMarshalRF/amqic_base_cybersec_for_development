# Bounded admission reference

`reference/admission.mjs` is an optional admission control example. It does not replace passwords, CAPTCHA, TOTP, session validation, authorization or request limits. It is not connected to the login controller. Deploying and sizing it requires a separate application decision.

Run synthetic tests on Node 22:

```sh
node --experimental-sqlite --test reference/admission.test.mjs
```

`createPowGate` needs a trusted random secret of at least 32 bytes, an atomic shared `store.consume(nonce, expires, now)` returning exactly `true` only for the first use, and a trusted server clock in seconds. Never take those inputs or the difficulty from an HTTP request. `issue({subject,audience,method,path,bodyHash})` returns a MAC-authenticated random challenge. Compute `bodyHash` as lowercase SHA-256 of the exact request bytes in a bounded HTTP adapter; derive subject and audience from trusted context. Verification binds every field, checks MAC before the proof, checks expiry and clock rollback, computes one hash, then consumes the nonce. Counters are canonical decimal unsigned 32-bit strings. Difficulty is bounded to 8–22 bits and lifetime to 1–300 seconds. Issuing challenges itself still needs rate limiting.

`solvePow` is an explicit bounded demonstration/client helper (maximum one million attempts). It is never called automatically by the verifier or on high server load. Test difficulty 8 is deliberately weak; this example makes no production cost recommendation. Device capabilities differ and proof of work is not proof of a person. A failed bounded solve may be retried by a client under application policy, never as unbounded server work.

Use `SqlitePowStore` with a protected persistent database path shared by all relevant processes for local durable replay control. The default `:memory:` store is only for isolated tests. A unique nonce insert in a write transaction arbitrates concurrent use. A stored clock guard rejects backwards observations; monitor clock health. Database replacement, restoring an older backup, a separate replica/store, secret compromise or loss of durability can weaken replay prevention. Failures deny access; consumption and an external application side effect are not one transaction. A consumed proof is not an exactly-once external operation and does not replace durable application idempotency.

`createRedisRateLimiter` optionally provides a fixed-window counter using one fixed Lua `INCR`/`PEXPIRE`/`PTTL` script. Host, port, prefix, limit, lifetime, timeout and optional ACL username/password are trusted configuration only. Pass credentials from an existing reviewed protected consumer, never from requests, CLI arguments or checked-in examples. `tlsOptions` accepts `ca`, `servername` and `minVersion`; certificate verification cannot be disabled. There is no general Redis command API. The limiter denies on connection, authentication, protocol, expiry or timeout errors without a retry. It does not implement PoW replay storage. Redis restart/eviction/replication failover can reset counters; durable distributed guarantees require an independently validated deployment. A timeout can occur after the counter increments.

For an already prepared, purpose-built synthetic Redis on loopback, run:

```sh
node --experimental-sqlite lab/redis-live.mjs
```

Set `AMQIC_REDIS_LAB_PORT` to the port of that purpose-built isolated service before running; there is no default target. It uses the public synthetic fixture password `synthetic-lab-only-password`, opens no public listener and creates no container. Never configure a production service with this password. It verifies authenticated access, eight concurrent attempts, two admissions, 2000 ms TTL metadata and expiry reset. Test keys use a random namespace and expire automatically. Exit code 2 with `NOT RUN` means the live integration was unavailable, never a pass. `run-lab.mjs --verify` supplies the isolated service automatically. Unit tests use isolated fake protocol peers and do not establish a real Redis integration pass.
