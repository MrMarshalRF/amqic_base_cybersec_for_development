# Enterprise security profile

This profile adds executable references to the public starter kit. The examples use synthetic identities and data. They are designed to be adapted to a service's own authorization, storage and deployment boundaries.

| Area | Entry point | Adoption check |
| --- | --- | --- |
| Policy, tenant scope and abuse control | [Policy guide](policy/README.md) | Authenticate the caller and bind the tenant from trusted identity. Keep the policy at the server boundary and use shared admission state in a distributed service. |
| Database isolation and tenant keys | [Database security](../docs/DATABASE-SECURITY.md), [PostgreSQL example](../infra/database/README.md), [Field encryption](../reference/field-encryption.README.md) | Test application authorization together with RLS under actual service principals. Provision distinct key identifiers and policies for the tenants that require them. |
| Audit and evidence | [Audit and evidence tools](evidence/README.md) | Preserve canonical report bytes, correlate events by request, verify an independently stored audit checkpoint and route the minimal event feed through the deployment's collector. |
| Supply chain | [Supply chain tools](supply/README.md) | Pin the allowed payload, verify its signed inventory with a trusted public key, and review build provenance separately. Generate an SBOM from the actual lockfile or a declared component list. |
| Short-lived credentials and key rotation | [Secrets and rotation](rotation/README.md) | Use workload identity, enforce provider scope and expiry, and verify rotation plus old-key decryption and revocation in the target environment. |
| Runtime and infrastructure | [Runtime hardening](runtime/README.md) | Inventory running JVMs and container runtimes. Verify the active security profile and workload identity after roll-out. |

## Distributed services, cloud keys and federation

| Integration | Entry point | Target verification |
| --- | --- | --- |
| Distributed admission | [PostgreSQL and Redis](distributed/README.md) | Verify primary fencing, replay retention, failover and datastore time against the target topology. |
| Cloud KMS | [AWS, Google Cloud and Azure adapters](cloud-kms/README.md) | Test workload credentials and resource-level permissions. Confirm rotation and decryption of existing data on each platform. |
| Federation | [Multi-provider identity](federation/README.md) | Validate provider keys, assertion audience and recipient, one-time state, and provisioning against the tenant's actual IdPs. |
| Operations and SIEM | [Playbooks and export](operations/README.md) | Verify authenticated delivery, checkpoint custody, retention and response drills. |

See the [component threat models](THREAT-MODELS.md) for the assumptions that keep these integrations valid.

## Collect evidence

Run the standard laboratory in a disposable local environment with its documented prerequisites. Pass its completed report and the exact repository root to the evidence exporter. The GitHub verification workflow checks the source inventory, runs the laboratory and uploads the generated JSON and Markdown. It includes a CycloneDX inventory of the declared lab images. The workflow also runs isolated PostgreSQL and Redis admission checks and includes their report as a separate file. The run diagnostics remain available from the workflow.

```sh
node scripts/verify.mjs --all --prepare --output /absolute/external/all-local.json
node enterprise/evidence/cli.mjs export /absolute/repository /absolute/external/all-local.json /absolute/external/control-evidence
```

Keep the exact source revision and report with the evidence. Follow the signing procedure in the evidence guide with a maintainer-controlled key. Keep assurance scope, environments, operator actions and collection times alongside the artifacts. Review missing prerequisites, skipped tests and externally scoped checks before relying on a control.

## Prepare an auditor handoff

| Evidence area | Example control mapping to confirm with the assessor | Additional deployment evidence |
| --- | --- | --- |
| Identity, authorization and isolation | SOC 2 CC6.1, ISO/IEC 27001:2022 Annex A 8.2 for privileged access, PCI DSS v4.0.1 requirement 7 for scoped access | Production identity and role assignment, review records, RLS configuration and tests for every applicable data path. |
| Security events and monitoring | SOC 2 CC7.2, ISO/IEC 27001:2022 Annex A 8.15 and 8.16, PCI DSS v4.0.1 requirement 10 | Retention, collector access, trusted checkpoint custody, time synchronization, alert tests and response records. |
| Release integrity and runtime updates | SOC 2 CC8.1, ISO/IEC 27001:2022 Annex A 8.32, PCI DSS v4.0.1 requirement 6 | Approved changes, builder identity, artifact authentication and evidence that the patched image or JVM is running. |

These mappings identify potential evidence for selected requirements. Applicability and effectiveness depend on system boundaries, the assessed period, people and procedures. Record the owner, scope, observation period, decision and gaps for each mapping. Confirm identifiers and requirements against the applicable official editions. [AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) · [ISO/IEC 27001](https://www.iso.org/standard/27001) · [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/)

## Agent runtime references

Use the [agent runtime reference](agent-runtime/README.md) for fixed tools, exact approval binding, supported policy narrowing, generation revocation and conservative offline egress plans. Its [deployment guide](../docs/AI-AGENT-RUNTIME.md) covers separate OS/sandbox enforcement, credentials, supply chain and emergency operations. This complements resource policy and distributed admission; it does not install an autonomous agent, network proxy or sandbox.

## Automated-probing references

The [probe-defense reference](probe-defense/README.md) supplies same-host atomic multi-dimension request admission, safe denial responses, an inert canary handler and a conservative security.txt generator. The [defense guide](../docs/AUTOMATED-PROBING-DEFENSE.md) connects these to existing origin, identity, database and incident controls. No offensive agent, live testing or automatic visitor retaliation is part of this profile.
