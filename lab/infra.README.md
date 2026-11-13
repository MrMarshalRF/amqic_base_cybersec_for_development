# Isolated infrastructure verification

From the repository root, prepare dependencies and run all local checks:

```sh
node scripts/verify.mjs --all --prepare --output /absolute/external/new-all-report.json
```

To run only infrastructure after preparation:

```sh
node lab/infra-verify.mjs --output /absolute/external/new-infra-report.json
```

The Dockerfile pins official Python and Node image digests and signed Debian
snapshot repositories dated 2026-11-13. Preparation requires Internet access;
verification never installs dependencies. The report records the actual image ID,
recipe hash and installed package versions. Rebuilding is not claimed to produce
byte-identical image metadata.

The verifier creates an internal Docker network and three disposable containers,
with no host mounts, host networking, published ports, privileged mode or Docker
socket. `NET_ADMIN` and `NET_RAW` apply only inside their separate namespaces.
The created resource names, returned IDs, process/start identities and IPs are
persisted in the external `.resources.json` ledger before use. Containers and
network are removed by exact ID after ownership checks; cleanup is verified.
The dependency image is intentionally retained for subsequent runs.

Checks use only synthetic identities and files:

- The shipped SSH template configures a real `sshd`; valid key login succeeds,
  while another key, root login and password authentication fail.
- The shipped firewall renderer consumes a concrete lab policy. Its nftables
  rules are checked, installed and exercised with actual TCP connections from
  an allowed peer and an outside peer. Baseline reachability is checked first.
- Two kernel WireGuard devices exchange real traffic and a handshake, then
  peer removal must prevent traffic. Missing kernel support is reported as
  `unsupported`, never a successful test or an installed host VPN.
- The shipped terminal and backup regression suites run under both Linux
  Python 3.11 and 3.12, with real PTYs and the pinned Node binary. Windows-only
  cases remain separately identified by unittest's platform skips.
- A synthetic executable is split into release/debug files and exercised;
  a synthetic KeePassXC vault opens with its test password and rejects another.
- The shipped scratch Dockerfile packages a static synthetic probe. Its actual
  UID, capabilities, no-new-privileges, core limit, read-only root, writable
  temporary filesystem and absence of a shell/socket are checked. The temporary
  runtime image is removed after the probe.

JSON `ok`, `complete` and `status` require all checks and cleanup. Exit code 1
means failed, unsupported, missing prerequisites or incomplete cleanup; check
the report rather than assuming a missing capability is a pass. Failures retain
the external evidence. If Docker refuses or cannot confirm cleanup, the ledger
explicitly remains `cleanup_pending` and needs exact-resource reconciliation.
No production service, personal
password database, SSH configuration, firewall or VPN profile is changed.
