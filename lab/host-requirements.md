# Host prerequisites and visible lab parameters

The host runs the fixed launcher; test services and privileged networking exercises run in disposable containers. Keep this distinction when adapting the examples. The lab does not configure a production machine for you.

## One POSIX command

From the repository on a Linux/macOS host with the prerequisites below:

```sh
sh lab/run.sh
```

The wrapper prepares only the fixed pinned laboratory images and runs the all-local checks. If no output path is supplied, it creates a private report directory under the host's temporary directory and prints its location. That directory is intentionally retained so the final protocol remains available.

Use `sh lab/run.sh --plan` to inspect the JSON plan without creating that directory or running services. Use `--no-prepare` to require already prepared images. For a chosen report location, use `sh lab/run.sh --output /private/reports/new-result.json`; its parent must exist, and the report/sidecars must not already exist. Windows users can use the direct Node command documented in [ALL-LAB.md](../docs/ALL-LAB.md).

## What the host needs

| Prerequisite | Why it is needed | Boundary |
| --- | --- | --- |
| Node.js 22+ | Fixed runner, API examples and browser driver | No global npm installation or AI API key is required. |
| Python 3.12+ | Cross-platform source, backup and configuration tests | The separate container additionally tests supported Linux Python versions. |
| Docker Engine/Desktop in Linux-container mode and Compose | Disposable services, private networks and OS namespaces | Docker access is privileged access to the host daemon; use a trusted workstation/runner. No socket is mounted into a public application. |
| Supported OpenSSL 3 | Temporary TLS certificates for actual Nginx tests | Selected as a child-process tool; the lab does not change host certificate stores or production certificates. |
| Installed Chromium/Chrome/Edge | Real browser tests of the supplied form | A new temporary browser profile is used; personal profiles are not opened. |
| Internet during explicit preparation | Digest-pinned images and date-frozen signed package metadata | Tests use synthetic local traffic. Preparation is not an unrestricted application egress policy. |
| Sufficient free disk/RAM | Tool images include compilers and test services | Check Docker capacity before preparation; the plan identifies required images. |

The wrapper does not run `sudo`, install host packages, change host firewall rules, edit SSH configuration, connect a host VPN, or read a password manager. A missing prerequisite remains an actionable non-success result; do not disable host security to hide it.

## Parameters are inspectable

| File | Parameters and purpose |
| --- | --- |
| [scenarios.json](scenarios.json) | Fixed scenarios, checks, prerequisites, standards, expected outcomes and external/manual boundaries. |
| [protocol.schema.json](protocol.schema.json) | Machine-readable plan/result structure and accepted status values. |
| [infra-fixtures/Dockerfile](infra-fixtures/Dockerfile) | Pinned base images and signed date-frozen Debian package sources for the test tool image. |
| [infra-verify.mjs](infra-verify.mjs) | Container-only accounts, network namespaces, limits, no host ports/mounts and exact cleanup. |
| [infra-fixtures/probes.py](infra-fixtures/probes.py) | Synthetic SSH, firewall, WireGuard, password-vault and binary checks. |
| [run-lab.mjs](run-lab.mjs) | Fixed scanner/Redis images, loopback-only dynamically allocated ports, memory/CPU/PID limits and cleanup. |
| [cache-fixtures](cache-fixtures) | Actual Nginx cache/bypass rules and the synthetic upstream; no real Cloudflare account. |
| [uploads.compose.yaml](../infra/container/uploads.compose.yaml) | Separate quarantine/verdict/clean volume mounts and UID/GID roles. |
| [Initial deployment](../docs/INITIAL-DEPLOYMENT.md) | How to choose real operator CIDRs, domain, upstream, SSH settings and recovery for a separately authorized target. |

Synthetic users, passwords, keys, private addresses and test domains are not values to copy into production. The lab generates temporary keys where required and uses only public synthetic data. In production, provision real keys through a protected process, choose non-overlapping networks, set real authorization rules, keep secrets external and validate the exact deployment.

## Capabilities and failure handling

Some OS exercises require kernel features such as network namespaces, nftables and WireGuard. `NET_ADMIN`/`NET_RAW` apply only to the dedicated lab containers. The lab does not request host networking, a privileged container or permission to load arbitrary host kernel modules. If a required feature is unavailable, the scenario must report that limitation instead of pretending to pass.

All local scenarios must finish and confirm required cleanup before the top-level result is accepted. Keep external/manual entries separate. If cleanup is uncertain, retain its private resource ledger and reconcile those exact resources; do not use a blanket Docker prune or delete unrelated data.
