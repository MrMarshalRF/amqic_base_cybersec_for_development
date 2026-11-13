# Upload volume isolation lab

Run from this checkout with Node.js and a working Linux Docker engine:

```sh
node lab/upload-isolation-verify.mjs --output /absolute/external/new-upload-result.json
```

On Windows, use an absolute Windows path for `--output`. The output directory
must already exist, be outside this checkout, and neither the report nor its
`.resources.json` sidecar may exist. No host Python installation is required.
The reviewed image must already be available locally; the runner never pulls:

```text
python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
```

The runner expands the actual `infra/container/uploads.compose.yaml` using
`docker compose config --format json`, with synthetic image substitutions and
automatic `.env` loading disabled. It validates the resulting role users,
supplemental groups, mount directions and `nocopy` settings. It runs the exact
Compose prepare command on three new, exclusively named volumes, then executes
four small synthetic Python probes using the Compose role identities and mounts:

| Role | Required observation |
| --- | --- |
| Prepare | New empty volumes receive their role UID/GID and directory mode 0750 |
| Intake | Quarantine write produces mode 0640; clean and verdict paths absent |
| Scanner | Quarantine read succeeds, overwrite/create fail; verdict write succeeds |
| Promoter | Both inputs readable, overwrite/create fail; clean write succeeds |
| Media | Clean read succeeds, overwrite/create fail; both input paths absent |

All five temporary containers run without a network, with a read-only root
filesystem, all capabilities dropped (prepare adds only CHOWN), no-new-privileges,
resource limits and a temporary `/tmp`. No host bind mounts, real files, secrets,
application images, external scanners, host settings or existing volumes are used.
This is a Linux filesystem and mount-boundary test, not an application upload
pipeline, malware detection, ingress-network or production deployment test.

The JSON report contains `status`, `ok`, `complete`, named boolean checks,
Compose/runner source hashes and cleanup evidence. Success requires all seven
checks (`compose_contract`, `runtime_prepare`, `runtime_intake`,
`runtime_scanner`, `runtime_promoter`, `runtime_media`, `source_stable`) and
successful empty label-filtered container and volume listings after cleanup.
The exit code is zero only on complete success. Runtime failures produce a failed
report where possible; invalid output arguments fail before resource creation.

The private `.resources.json` sidecar records launch intentions and observed exact
container IDs/volume names. Keep it locally for recovery; publish only the
sanitized report. Cleanup discovers partial creates by the unique ownership label
and removes only this run's resources. A failed cleanup is `cleanup_pending`, not
success. Forced process termination or an unavailable Docker daemon can interrupt
cleanup; preserve the sidecar and reconcile those exact labeled resources before
starting another run. The script does not retry a create whose outcome is unknown.
