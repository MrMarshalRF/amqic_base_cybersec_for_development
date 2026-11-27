# Federated identity monitoring

Apply this source-reviewed procedure when a deployment uses a federated identity provider (IdP) or cloud tenant. It does not apply to a purely local password file. The [directory companion](DIRECTORY-IDENTITY-MONITORING.md) now adds manual directory, Kerberos and certificate review guidance. Directory collectors, Windows/domain hardening and deployed detection remain outside the implemented web references.

## Review changes

Assign an identity owner to review the provider's official audit logs and APIs at least daily and on each relevant alert; record any approved cadence adjustment and coverage gap. Compare changes with the approved application and workload inventory:

- New or changed consent grants and OAuth application permissions.
- New service principals or workload identities.
- New client secrets, certificates or access keys.
- Application-registration owner or publisher changes.
- Sign-ins that depart from an expected known-device or last-seen pattern. Treat these as investigation leads; this procedure is not a geofence product or proof of account compromise.

Bind reviews to the [federation contract](../enterprise/federation/README.md): tenant/provider identity, exact registered redirect URIs, audience and external-group-to-local-role mapping remain fixed and reviewed. A grant that widens scope requires change control; it must not silently enlarge local authorization. Preserve reviewed policy revisions and the contract's flow invalidation requirements when trust or credential configuration changes.

For workload identities used by the [cloud KMS adapters](../enterprise/cloud-kms/README.md), compare the identity and resource grants with their existing least-privilege configuration. This review adds no KMS permissions or provider scope. Follow the [probing playbook's identity guidance](AUTOMATED-PROBING-DEFENSE.md#primary-guidance-and-standards) without treating a framework name as evidence of malicious intent.

## Respond at the issuer

Confirm the change and its authorization with the identity owner. Preserve minimal case evidence, then revoke or disable an unexpected grant or credential at the issuer through the provider's approved procedure. Rotate remaining affected material and inspect owners and publishing access. Verify the resulting provider state and reconcile uncertain operations before retrying.

A local block does not revoke an upstream token. Review affected local sessions and role assignments through the adopting application's controls; federation's synthetic login tests do not establish deprovisioning or session revocation. Record the containment result and unresolved access separately.

## Record the review

Retain time, opaque tenant and actor references, change class, outcome and opaque case reference. For example, a consent-grant review can use documentation time `2026-11-20T00:00:00.000Z`, opaque references assigned by the operator and outcome `deny`, with details behind the restricted case. No real identity is needed in the public record.

Map consent or permission changes to [SIEM export](../enterprise/operations/README.md) category `identity`, action `consent-change`, signal class `identity-grant`. Map service-principal, workload-identity, credential, owner or publisher changes to action `principal-change` with the same category and signal class. The action records the coarse change class; keep finer details behind `caseRef`. Use the schema's existing timestamp, outcome and opaque reference fields; do not add directory attributes. Exclude tokens, assertion bodies, credential values and directory display names from public exports.

## Limits

The kit does not monitor Entra, Google or Okta in production. Operators must configure collection, alert delivery, permissions and coverage using their provider's official audit logs and APIs. This increment adds procedure and SIEM field support, not a provider connector. Existing synthetic federation tests do not exercise live consent catalogs or establish deployed detection quality.

## Credential velocity and breadth

Review cloud control-plane audit events per opaque credential, source, asset and bounded time window. Compare event rate, distinct services/actions and denied-call ratio with the identity's approved workload baseline. An unusual source and subsequent secret-store or audit-log access can strengthen a lead; no single rate threshold proves credential theft.

Register expected infrastructure-as-code, inventory, posture and backup runs with reviewed source/scope/expiry. A registered run with the same breadth and a high-rate single-action job are near matches. The [behavior specification](AGENTIC-ATTACK-DETECTION.md) and [offline fixture suite](../enterprise/detection/README.md) use synthetic event classes only, without cloud queries or credentials. Production baselines, provider completeness, pagination, latency and clock handling require target validation.

Record the anomaly review as `campaign` / `campaign-note` / `campaign-correlation`. Use `identity` / `principal-change` only for an actual principal or credential-state change. Confirm the finding with the identity owner; any revoke, disable or rotate action occurs at the issuer, and the evaluator performs none of those operations.

## Cloud control-plane context

Extend the private audit baseline beyond velocity. Review metadata-service access
by unexpected workloads, IAM/role-binding changes, unusual object-storage
inventory and Kubernetes API discovery. Normal bootstrap, workload-identity token
refresh, inventory and deployment traffic can produce similar observations;
metadata access alone is not evidence of credential theft.

Record trusted event and ingestion times, issuer/tenant, opaque principal and
resource scope, operation class, outcome, collector provenance, policy revision
and a protected change/engagement reference. Some metadata accesses are not
visible in control-plane logs: identify the host/proxy/workload source and its
coverage rather than inventing a missing audit event. Preserve pagination,
delivery delays and identity/key epochs when relating records.

For example, storage listing plus a role-binding change by an unexpected
principal can justify review. A deployment is a near match only when these exact
actions, resources, workload/source and times fall within its externally
approved scope, without unexplained privilege or integrity drift. An approved
identity alone cannot exempt unrelated changes. Another tenant or incomparable
clocks cannot establish a chain. Confirm actual effects separately from denied attempts.
Use campaign/campaign-note/campaign-correlation for the investigation; existing
identity/principal-change records describe actual supported principal-state
changes, not arbitrary directory or API-discovery records. The eight-family
evaluator's cloud-velocity fixture does not implement all of these new behaviors.
Revocation and rotation remain separately authorized issuer operations.
