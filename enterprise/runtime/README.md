# Java runtime inventory and deployment controls

The runtime gate compares a rollout record with an inventory of the JVM instances that actually serve the workload. It checks vendor, package, full build, architecture, replacement instance and deployed artifact digest. Keep both inputs under operator or CI control and retain the original evidence independently.

## Reverse proxy advisories

The [Nginx gate and response guide](../../docs/NGINX-EDGE-SECURITY.md) extends runtime evidence to proxies and ingress replicas. It checks exact vendor/CVE findings and artifact, master/worker replacement and restrictive protocol observations. Include the terminator binary/package in runtime inventory and SBOMs.

## Respond to a Java runtime advisory

CVE-2026-114938 affects the Java runtime. Review every deployed copy of the JVM, including bundled runtimes, worker images and dormant replicas that may be reactivated. Identify the running executable and version using approved host or container inventory. Use the vendor's security advisory for the exact distribution and package. Published versions may use distributor-specific backports. Sources checked on 18 November 2026: [Red Hat advisory RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018), [Amazon Linux security tracker](https://explore.alas.aws.amazon.com/CVE-2026-114938.html), [OpenJDK advisory index](https://openjdk.org/groups/vulnerability/advisories/).

1. Record all replicas, active process or pod instance identifiers, and the full runtime builds. Tie executable identity to the artifact actually running. On a Linux host, approved inventory can resolve the executable of a known process through `/proc/<pid>/exe`. In Kubernetes, record the workload and pod or container instance together with the actual image ID, per-platform artifact digest and installed distribution package metadata. Add the JDK to the image inventory as well as application libraries.
2. Select fixed builds according to distributor guidance. Rebuild images from the patched base, verify the new artifacts and replace the affected processes. Coordinate availability, probes and rollback through the normal change process. Prevent old replicas and scheduled jobs from reintroducing the affected image.
3. Capture post-change observations for the expected set. Use a stable instance key that includes start identity, such as container instance ID plus start time, or boot identity plus PID plus process start time for host workloads. Store a hash of an independently retained observation. Use fresh UTC timestamps and confirm service health with ordinary functional checks.
4. Review unusual JVM child processes, crashes, changes to executable files, permissions and outbound traffic in the relevant interval. Correlate host and application logs, keep restricted evidence, and follow your incident process for containment and remediation. The included Falco rule supplies a starting signal. Use your vendor's current guidance for any temporary mitigation and track its removal after patching.

## Run the offline check

Run this in CI or at change review after supplying authoritative local JSON:

```sh
node enterprise/runtime/java-inventory.mjs rollout-policy.json rollout-inventory.json
```

Policy schema `amqic-java-policy/v1` has the following fields alongside `schema`:

| Field | Value |
| --- | --- |
| `advisory` | A CVE identifier |
| `changeId` | Shared rollout identifier |
| `changeStartedAt` | Recorded UTC change start in ISO 8601 with milliseconds and a Z suffix |
| `expected` | Array of records with `workload`, `previousInstance` and `artifactDigest` |
| `vendorFindings` | Array of `vendor`, `package`, `build`, `architecture`, `status` and `reference` records. The status is `fixed`, `not-affected` or `affected`. Use the primary distributor HTTPS advisory as the reference. |

Inventory schema `amqic-java-inventory/v1` contains `schema`, the same `changeId`, `observedAt`, and an `observations` array. Each observation contains `workload`, `instance`, `startedAt`, `vendor`, `package`, `build`, `architecture`, `artifactDigest` and `evidenceDigest`. Give each replica its own stable workload key. Both digests use `sha256:<64 lowercase hexadecimal characters>`. Use safe opaque identifiers. Exclude local paths, command arguments, environment values, credentials and raw logs from public evidence.

Exit status 0 means all expected records agree with the policy. Status 1 means at least one expected workload needs investigation, such as a missing observation, an old instance, or an unknown build. Status 2 indicates invalid inputs. Observations are valid for at most 24 hours and must be at or after change start. Match exact vendor build strings to retain distributor backport semantics. The check trusts vendor disposition records and the collected observation. Validate their source and verify hashes against retained observations before using the result as evidence.

## Hardened example for Kubernetes

[The shared pod specification](helm/files/pod-spec.json) pins the Linux workload to a non-root UID and GID, uses a read-only root filesystem and bounded temporary workspace, drops all Linux capabilities and forbids privilege escalation. It disables service account token injection and selects the seccomp and AppArmor `RuntimeDefault` profiles explicitly. This uses profiles supplied by the runtime on eligible nodes. Verify AppArmor is enabled on selected hosts, confirm admission and enforcement with your current runtime, and test each image's filesystem and syscall requirements before deployment. [Kubernetes seccomp guide](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes AppArmor guide](https://kubernetes.io/docs/tutorials/security/apparmor/)

The Helm chart requires an approved digest-pinned Linux image compatible with UID 10001 and writable `/tmp`. Its NetworkPolicy supplies empty ingress and egress allow lists for the matching workloads. Require a CNI that enforces NetworkPolicy and account for Kubernetes node traffic exceptions. Review all matching policies because allow rules combine, then add only required directional flows such as approved DNS and application dependencies. Set image digest, resource limits and health probes for your service. [Kubernetes NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

The optional OpenTofu module provisions a dedicated namespace with versioned Restricted Pod Security Admission labels and namespace-wide default-deny NetworkPolicy. Provide an approved kubeconfig and explicit context. Review the provider lockfile and plan according to your team's change process. Operators deploy the chart separately into that namespace once its controls are in place. Helm templates, OpenTofu provider resolution, cluster admission and profile enforcement require target-side validation. [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) · [OpenTofu CLI](https://opentofu.org/docs/cli/)

## Runtime signals

[The Falco rule](profiles/java-shell.falco.yaml) alerts on successful direct child shell execution by a containerized process named `java`. It exports only process identifiers and names. Review legitimate shell use, engine and syscall capture support, dropped events and rule coverage before enabling alerts. Calibrate against benign workload behavior. Treat the alert as an investigation signal. [Falco rule reference](https://falco.org/docs/concepts/rules/basic-elements/)

## Local verification

```sh
node --test enterprise/runtime/runtime.test.mjs
```

The suite exercises the offline inventory gate with synthetic observations and checks constraints in the profile, chart template sources, namespace module and Falco rule. Host process collection, Helm and OpenTofu rendering, cluster deployment, kernel policy enforcement and Falco event capture need separately recorded validation.
