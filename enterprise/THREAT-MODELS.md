# Component threat models

Use the following assumptions when integrating the enterprise references. Define the actual deployment boundary and identify the owners of its identity, keys, storage, clocks and evidence.

| Component | Trust boundary and failure to prevent | Control and verification |
| --- | --- | --- |
| Policy and admission | Callers can send arbitrary input. Client-supplied tenant, roles, clocks and replay markers cannot supply authority. Failover can expose stale admission state. | Trusted authentication and resource binding, deny by default, atomic budget and replay state. Test exact scope, concurrency, primary loss and time rollback. Hold the service closed when durability is uncertain. |
| Cloud KMS | An authenticated workload may still select an unintended key or context. Rotation may strand earlier ciphertext. | Pin approved resources and versions, authorize in the service and provider, and bind scope to authenticated encryption. Test key substitution, old-key readability and provider failures. |
| Identity federation | Assertions enter the service from another trust domain. An issuer may identify subjects differently from another provider. | Pin tenant, provider, key trust, issuer and audience. Bind the response to a live one-time login transaction. Map roles from an allowlist. Evaluate account recovery, key rollover and revocation for each deployment. |
| SIEM and evidence | An exporter or collector can omit, reorder or truncate records. A mutable checkpoint allows a new chain to replace history. | Validate the chain against a trusted checkpoint and verify export digests. Protect collector credentials, track delivery, and record retention and deletion decisions. |
| Dependency changes | A pull request may introduce a vulnerable dependency or an unreviewed CI action. Published advisory information can lag. | Use pinned Actions and review updates. Use dependency review for supported graphs and scan the actual image and dependency inventory in deployment. Review evidence gaps before release. |

Recheck these assumptions after changes to queueing, federation, key providers, topology or logging. The sample tests establish behavior for their recorded fixtures.
