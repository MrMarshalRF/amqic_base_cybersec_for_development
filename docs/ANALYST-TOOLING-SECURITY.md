# Security for analyst tools handling untrusted files

## TL;DR

Keep both the analysis tool and its actual Java runtime patched. For operators
already using JADX, the reviewed minimum is **1.5.7**, checked on 26 November
2026. Confirm current official advisories before each rollout. This guide does
not require installing JADX or add it as a kit dependency.

## Where it helps

Use this checklist for analyst laptops, disposable review machines and CI jobs
that parse untrusted APK, XAPK or JAR files. Parsing and exporting are trust
boundaries: a patched decompiler does not make its input or exported project
trusted. This repository supplies guidance, not a decompiler, detector or
malware-analysis sandbox.

## Keep tool and runtime inventories separate

Record the following privately for each GUI, CLI, library integration and
leftover unpacked copy. Keep an inventory entry for disposable images too.

| Evidence | Example and acceptance condition |
| --- | --- |
| Tool identity | JADX version, official release URL, exact asset name and operator-computed SHA-256. Compare against an authenticated publisher checksum when available; a locally computed hash alone does not authenticate the publisher. |
| Runtime packaging | Record whether the selected asset bundles Java or uses a system installation. A patched system JDK does not replace an old bundled runtime. |
| Actual runtime | Record the selected Java executable/distribution, version and vendor patch evidence. A JADX upgrade does not patch a separately installed system JDK. Restart after replacement. |
| Isolation and output | Record the review environment, writable output directory, plugin/config locations, credential exclusions and network policy. |
| Disposition | Owner, review date, accepted artifact identity and remaining target checks. Keep sample content and sensitive host paths out of public reports. |

The official [1.5.7 release](https://github.com/skylot/jadx/releases/tag/v1.5.7)
updates bundled Java for the Java4Shell issue. Its
[packaging advisory](https://github.com/skylot/jadx/security/advisories/GHSA-mpx4-q2vm-vgfq)
references **JDK CVE-2026-114938**; it is not an additional CVE in JADX source.
Use the applicable Java vendor's fixed build evidence, including for no-JRE
packages. See the existing [Java runtime guide](../enterprise/runtime/README.md).

## Advisory-driven upgrade checklist

JADX 1.5.6 fixed the following three tool issues. The 1.5.7 floor also covers
the subsequent bundled-runtime update; 1.5.6 alone is insufficient for an old
bundled-JRE package.

| Official record | Boundary and required response |
| --- | --- |
| [CVE-2026-54684 / GHSA-gpvc-ccw7-744v](https://github.com/skylot/jadx/security/advisories/GHSA-gpvc-ccw7-744v) | XAPK path handling could write outside the intended directory and plant a plugin loaded on a subsequent launch. Upgrade affected 1.5.2–1.5.5 copies; review plugin/config integrity separately. |
| [CVE-2026-42049 / GHSA-w6f5-h4x4-rfpj](https://github.com/skylot/jadx/security/advisories/GHSA-w6f5-h4x4-rfpj) | Untrusted manifest values entered exported Gradle scripts. Opening/building the exported project is a separate execution boundary; keep it isolated after upgrading. |
| [CVE-2026-42447 / GHSA-jwv3-q635-w9m4](https://github.com/skylot/jadx/security/advisories/GHSA-jwv3-q635-w9m4) | GUI Summary HTML injection could cause outbound or local-service requests. Upgrade the GUI and restrict unnecessary network access in the review environment. |

Use the [official security advisories](https://github.com/skylot/jadx/security/advisories)
and [1.5.6 release notes](https://github.com/skylot/jadx/releases/tag/v1.5.6)
for affected ranges and fixes. Confirm installed artifact identity and runtime
patch level; do not open crafted samples to prove a patch. Library dependency
pins and separately installed GUI copies need their own inventory entries.

## Isolate input, output and execution

1. Process untrusted samples in a disposable VM with reviewed isolation, or a
   container whose host/kernel boundary and limitations have been assessed.
   Do not mount home directories, production source, SSH/cloud credentials,
   Docker sockets or the analyst's standing plugin/config directories.
2. Use a dedicated output directory separate from home, VCS checkouts and tool
   configuration. Do not launch from a directory that contains the persistent
   plugin path beneath it. Untrusted output must not become installed tooling.
3. Install plugins and scripts only from reviewed, pinned sources. Review
   unexpected plugin JARs or configuration changes before another launch;
   preserve evidence and rebuild the disposable environment when warranted.
4. Treat Gradle exports as untrusted executable projects. Do not let an IDE
   import or build them automatically on a privileged workstation. Review and
   build only inside the isolated environment with separately authorized
   dependency/network access.
5. Deny unnecessary egress and access to host/local administration services.
   A container's localhost differs from the host, but shared networking,
   mounted sockets and reachable host services still require explicit review.
6. Retain approved evidence, then revert/dispose of the exact owned environment
   under the operator's retention and cleanup policy. Shared folders, clipboard,
   device forwarding and hypervisor patching remain part of the boundary.

For example, an analyst receives an APK: record its private case identity, use a
reviewed disposable environment with no credentials, confirm both tool/runtime
patch evidence, export into its dedicated directory and review the export there.
Moving that export to a trusted IDE for an automatic Gradle build would cross
the boundary again.

## Monitoring and response

Baseline expected plugins, child processes, file writes and destinations.
Unexpected plugin/config changes, child shells, writes outside output, network
access or JVM crashes are investigation leads. Legitimate plugins and export
workflows can also cause such events; an alert is not attribution or proof of
compromise. Keep raw paths, sample content and collector evidence private.

If a session appears suspicious, stop using that environment, preserve approved
evidence, confirm tool/runtime identity and follow the
[incident-response playbooks](../enterprise/operations/README.md). Do not reopen the same sample on a
trusted desktop. Existing [runtime integrity](AGENT-RUNTIME-INTEGRITY.md) and
[host egress](HOST-EGRESS-MONITORING.md) procedures explain related boundaries;
they do not install a JADX collector.

## Standards and validation boundary

Selected relationships are NIST SP 800-53 Rev. 5 **CM-8** (inventory), **SI-2**
(flaw remediation), **AC-6** (least privilege), **SC-7** (boundary protection),
**SI-7** (integrity) and **SI-4** (monitoring), as mapped in
[SECURITY.md](../SECURITY.md). These are control relationships, not certification.
This guide is checked through source/link review, payload membership and
checksum integrity. No JADX execution, sample analysis, host sensor deployment,
containment effectiveness or vendor installation is verified by kit fixtures.
