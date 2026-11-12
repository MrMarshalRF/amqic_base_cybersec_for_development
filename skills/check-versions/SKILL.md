---
name: check-versions
description: Check the currency of Node.js, Python, and supported npm/PyPI dependencies before release using official metadata or a verified dated snapshot, without automatic updates.
---

# Check versions before release

Read `../../docs/VERSIONS.md`. Use `../../scripts/check_versions.py` for bounded inventory and comparison. Keep reports outside the source tree and published package. The script does not install packages or run package scripts.

1. Agree on the target environment. Python is taken from the interpreter running the script; Node comes from a fixed system installation at an absolute path, with the `--version` argument. Project executables and PATH are not used. Lockfiles and requirements report declared versions; their correspondence to the installed server is checked separately. A user-supplied Node version passed through `--node-version` is marked as declared.
2. Run `inventory --project /absolute/project --output /private/inventory.json`. The project is assessed by default. Missing lockfiles, unsupported manifests, unpinned dependencies, and unknown transitive coverage remain gaps. `--scope runtime` is permitted for a separate check of the two language environments and does not complete the library review.
3. Review the inventory locally first. `check` without a source works offline and reports uncertainty. Network access requires `--online`. Public npm/PyPI names must additionally be listed through `--public-package npm:name` or `--public-package pypi:name`. Do not authorize transmission of private names. Private, local, and nonstandard-registry dependencies remain subject to separate review, even if their names are explicitly listed.
4. Use official metadata or `--snapshot` with a verified source and retrieval time. Do not present self-authored JSON as proof of provenance. A stale snapshot, error, unsupported version, or name/version mismatch leaves the check incomplete.
5. Consider `latest`, `latest_in_line`, `support`, `eol`, `withdrawn`, `deprecated`, and available advisories separately. A newer version does not prove security or authorize an update. The absence of PyPI vulnerability reports is limited by its coverage. For Node, Python, and npm, the script does not perform a complete advisory audit.

`currency_ready` applies only to the specified inventory and its completeness. `production_ready` is always false because release additionally requires security and compatibility reviews, tests, a build, and owner authorization. Do not change dependencies automatically. Before an agreed update, use a separate branch/candidate, the standard tests, and a rollback plan. Report errors and uncertainty as an unfinished check while preserving the data already obtained.
