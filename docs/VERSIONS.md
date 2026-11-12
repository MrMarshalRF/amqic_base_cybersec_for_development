# Checking versions before release

`scripts/check_versions.py` collects a limited inventory and compares versions with dated official metadata. It does not install or update packages, run npm/pip hooks, or modify source files.

## 1. Select the environment and scope

The Python running the script reports its own interpreter version. Node is checked with `--version` using an absolute path in a standard system installation outside the project being checked. The current directory and project PATH are not searched. On Windows, Program Files/nodejs is checked; on Unix, /usr/bin, /usr/local/bin, and /opt/homebrew/bin are checked. User-managed version managers may remain undetected. For a server, virtual environment, or another installation, run the check there or supply a separately established Node version through `--node-version`; this input is marked as declared. Entries in package-lock.json and requirements.txt also describe pinned configuration. They do not establish the actual installation.

By default, package-lock.json v2/v3 and simple `name==1.2.3` lines in requirements.txt are supported. npm entries include nested lockfile packages. A simple requirements.txt does not establish transitive coverage. Ranges, prerelease versions, extended PEP440 forms, local URLs, nonstandard registries, and other manifests require separate review. Supported comparison is limited to stable versions with two to four numeric components.

## 2. Save the inventory locally

```sh
python3 -B scripts/check_versions.py inventory --project /srv/project --output /private/version-inventory.json
```

Choose an output file that does not exist. The script refuses to overwrite existing reports. The inventory contains package names, versions, entry provenance, and coverage gaps. Private names may also be confidential, so store inventories and reports outside the tree to be published.

Use `--scope runtime` to check Node/Python separately. This mode does not check libraries. The kit's main helpers use Python/Node standard libraries. Whether a specific deployment matches this composition must still be checked separately.

## 3. Obtain dated information

Without `--online`, no network requests are made. The following procedure is suitable for the two language runtimes.

```sh
python3 -B scripts/check_versions.py inventory --project /srv/project --scope runtime --output /private/runtime-inventory.json
python3 -B scripts/check_versions.py check --inventory /private/runtime-inventory.json --online --save-snapshot /private/runtime-snapshot.json --output /private/runtime-report.json
```

For dependencies, first review the inventory locally. Additionally specify each public name authorized for transmission, for example `--public-package npm:express` or `--public-package pypi:requests`. Use names actually present in your inventory. `--online` alone does not authorize transmission of all discovered names. Private/local/nonstandard registries receive no network request even when listed this way. Do not enter registry tokens, passwords, or URLs containing credentials.

The network code uses only fixed HTTPS addresses, without redirects or environment proxy settings. Limits are 5 seconds per network wait, reduced according to the overall budget, 60 seconds for metadata collection, 64 requests, 5 MiB per response, and 32 MiB in total. Interrupting system DNS depends on the OS; this is a separate interpreter limitation. An error or exceeded limit is retained as uncertainty. Source code and project files are not sent to servers; a package name is sent over the network only after explicit approval.

An offline repeat uses the same inventory and saved snapshot.

```sh
python3 -B scripts/check_versions.py check --inventory /private/runtime-inventory.json --snapshot /private/runtime-snapshot.json --output /private/runtime-report-repeat.json
```

The default maximum source age is 24 hours. `--max-age-hours` changes this limit within 1–720 hours. This is a freshness limit, not proof of currency at the time of a future release. The snapshot is bound to the ecosystem, name, and version. A JSON file does not itself establish provenance; the owner separately verifies trust in a supplied snapshot.

## 4. Read the result

- `observed` and `version_origin` distinguish a measured runtime, a declared override, and a version from lockfile/requirements.
- `latest` shows the latest stable version in the available metadata. `latest_in_line` separately shows the current patch for the Node major or Python minor line. Runtime currency is compared within the selected line.
- `support` and `eol` show the language runtime's published policy. npm/PyPI have no common support policy; `not-published-by-registry` requires checking with the package author.
- `withdrawn` refers to a yanked PyPI release, and `deprecated` to an npm marker. Available PyPI advisories are listed by identifier. The script does not perform a complete vulnerability audit. `not_assessed` means a separate assessment is unfinished.
- `currency_ready` refers to the currency and coverage of the selected inventory. `production_ready` is always false. A new version or absence of advisories does not establish release security.

Exit code 0 means the limited currency check is ready. Code 2 means an update to consider, a coverage gap, an unknown state, or an error. For a project without a complete supported inventory, a positive check of two runtimes does not cover libraries. The owner decides on updates after assessing compatibility and security. Release requires standard tests, a build, access checks, and a rollback plan from [production-kit preparation](PRODUCTION.md).

## Sources

Node uses the official [release index](https://nodejs.org/dist/index.json) and [support schedule](https://github.com/nodejs/Release). Python uses the [release list](https://www.python.org/doc/versions/) and [branch status](https://devguide.python.org/versions/). npm obtains latest and exact-version metadata from registry.npmjs.org. PyPI uses exact-version JSON and the release list at pypi.org. The snapshot retains exact URLs, retrieval time, and response SHA-256. Unsupported official-page markup results in uncertainty.

For npm, `latest` corresponds to the publisher's tag of that name, rather than the highest version number across all tags. Compatibility of a new version with the current application is checked separately.
