# Releasing a project on GitHub

## Separate the three deliverables

1. **Source repository:** code, tests, public documentation, license notices and safe examples that developers need to inspect or rebuild the project.
2. **Release artifacts:** a reviewed source archive and/or platform binaries, their exact inventories, checksum registries, signatures and safe release notes.
3. **Production deployment:** installation and activation of one verified release in an explicitly authorized environment. Follow [DEPLOYMENT.md](DEPLOYMENT.md); publishing a GitHub release is not a deployment.

Public `AGENTS.md`, tests and build instructions can be intentional source content even though the [runtime preparation tool](PRODUCTION.md) excludes them from an application deployment. Do not use one exclusion list blindly for both deliverables. Keep local agent settings, credentials, production data, build caches, diagnostic mappings and private operational instructions outside both public source and release artifacts.

## Public documentation and licensing

| File or setting | What to include | What to avoid |
| --- | --- | --- |
| `README.md` | Intended audience, purpose, quick start, requirements, capabilities, limitations, links to security/validation/deployment, license and maintainer | Unsupported security claims, untested commands presented as verified, real credentials, local machine paths |
| `LICENSE` | The chosen license's complete standard text and the correct copyright notice | A license badge without license text, invented ownership or a promise that third-party material has the same license |
| Third-party notices | Required attribution, notices and license texts for distributed components/assets; review redistribution obligations | Assuming that public availability permits redistribution or that the repository license overrides dependencies |
| `SECURITY.md` | Private reporting channel, supported versions, response targets, disclosure process and scope | Promising guaranteed response times or claiming a bounty/certification that does not exist |
| Validation/build docs | Reproducible commands, exact tested versions/platforms, results and untested boundaries | Treating a passing unit test as a complete audit or deployed verification |
| `AGENTS.md` and skills | Portable contributor/automation guidance for this project | Personal tools, private policies, secrets and internal organization details |
| GitHub About | Accurate short description, project URL and relevant topics | Keyword stuffing, confidential topic names or unrelated claims |

This repository uses [MIT](../LICENSE). For your own project, choose a license you have authority to apply and preserve its required notices. SPDX provides the [MIT text and identifier](https://spdx.org/licenses/MIT.html); GitHub explains [repository licensing](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository). Review dependency and asset licenses separately. An SPDX identifier in package metadata does not replace a required notice in a distributed artifact.

GitHub topic names are public even when used by a private repository; keep them generic and non-sensitive. See [GitHub topics](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics).

Keep security contact details current. State response periods as targets if you cannot guarantee them. Link `SECURITY.md` from the README and release notes. Describe standards as requirement mappings or design references with scope and evidence, not as endorsements or certifications.

## Define and freeze the release contents

Review tracked and untracked files, staged changes, ignored output and Git history before making a repository public. `.gitignore` prevents some new accidental additions; it does not remove already tracked files or erase prior commits. For an exposed credential, revoke/rotate it and assess prior distribution. History repair requires a coordinated explicit plan; simply deleting the current file is insufficient.

Keep a candidate private until contents and release checks pass if that is your release policy. Make repository visibility changes only with explicit owner authorization: public access exposes the repository's accessible history, issues and releases, not merely the latest README.

Choose the exact file list and review every addition. Use explicit paths when staging changes; do not blanket-stage a workspace containing unrelated work. Record final versions, licenses, executable modes, supported targets and validation evidence. Freeze the candidate against concurrent writers before generating its registry.

For a source release, include public documentation and tests intentionally. For binary releases, retain required runtime resources and license notices but omit private debug symbols/maps unless the distribution format and intended recipient require them. Use a separate registry per archive/platform if their file sets differ, or a clearly documented common registry with unambiguous relative paths.

## Form a deterministic SHA-256 registry

Each line is a lowercase 64-character SHA-256, **two spaces**, and the case-sensitive path relative to the release root. Use `/` as the path separator and a stable sorted order. Hash raw file bytes; line-ending conversion changes the result. This project's `.gitattributes` preserves committed payload bytes, including mixed historical line endings.

Do not include `SHA256SUMS` in itself. Exclude only the specifically designated detached signature metadata, conventionally `SHA256SUMS.sig`. Include every other distributed payload file. For a source clone, `.git` is repository metadata outside the payload. Do not silently exclude new files because they are inconvenient to hash. Reject links, submodules and ambiguous paths unless your release format has a separately defined, verified representation for them.

A registry protects integrity only after you authenticate it. A malicious replacement can contain matching malicious hashes. Sign the final registry with the authorized signing identity, verify the signature through an independently trusted mechanism, and then verify payload hashes and exact membership. This project's maintainer uses [AMQIC verification](https://amqic.ai/pages/request-verification); a different project must document its own trust root and verification process rather than imply AMQIC signed it.

### Example generator for an approved Git index

Save this Python 3 example as a reviewed script **outside the release tree**. Run it from the Git repository root only after staging the explicitly approved payload. It hashes files in the index after confirming that their working bytes match the staged bytes. It fails on unresolved merges, symlinks/submodules, ambiguous names and changed files. Review untracked and ignored files separately: the index cannot tell whether an omitted file should have been distributed.

The command replaces the local candidate's `SHA256SUMS`; preserve previous releases separately and re-sign this new registry. Do not run it against an immutable published release directory.

```python
from pathlib import Path
import hashlib
import stat
import subprocess

root = Path.cwd().resolve()
git_root = subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True
).strip()
if Path(git_root).resolve() != root:
    raise SystemExit("Run from the repository root")

entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"])
rows = []
names = set()
for entry in entries.split(b"\0"):
    if not entry:
        continue
    metadata, raw_name = entry.split(b"\t", 1)
    mode, object_id, stage = metadata.decode("ascii").split()
    name = raw_name.decode("utf-8")
    if stage != "0" or mode not in {"100644", "100755"}:
        raise SystemExit("Unsupported index entry: " + name)
    if any(c in name for c in "\\\r\n\t") or name.startswith("/"):
        raise SystemExit("Ambiguous path")
    reserved = {"SHA256SUMS", "SHA256SUMS.sig"}
    if name.casefold() in {item.casefold() for item in reserved} and name not in reserved:
        raise SystemExit("Case-ambiguous registry name")
    if name in reserved:
        continue
    if name.casefold() in names:
        raise SystemExit("Case-ambiguous path")
    names.add(name.casefold())
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise SystemExit("Path escapes release root")
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit("Not a regular payload file: " + name)
    data = path.read_bytes()
    staged = subprocess.check_output(["git", "cat-file", "blob", object_id])
    if data != staged:
        raise SystemExit("Working bytes differ from staged bytes: " + name)
    rows.append((name, hashlib.sha256(data).hexdigest()))
if not rows:
    raise SystemExit("Empty payload")
target = root / "SHA256SUMS"
if target.is_symlink() or (target.exists() and not target.is_file()):
    raise SystemExit("Registry target must be a regular file")
target.write_bytes("".join(f"{digest}  {name}\n" for name, digest in sorted(rows)).encode("utf-8"))
print(f"Registered {len(rows)} payload files")
```

This is a source-registry example, not a complete release scanner, hostile-filesystem sandbox or binary packager. Use a private workspace with no concurrent writers and inspect ancestor directories for links/reparse points before running it. For a binary package, generate from that package's approved inventory instead of the source Git index. Preserve executable modes separately in the archive/build record; a file-content hash does not encode permissions.

## Sign, package and verify a readback

Run the affected tests on final candidate content. Generate the final registry, review its exact membership, and sign it with the maintainer-controlled process. Keep private signing keys outside Git, logs, build outputs and AI context. A detached signature file can accompany the registry; if verification lives in an external service, say so explicitly and explain how recipients authenticate the registry there.

Commit the accepted source changes and final registry together. Use an immutable tag for that commit, for example `v1.1.0`; choose versions according to the project's compatibility policy. A signed Git tag and an artifact/registry signature are different protections. Do not describe an unsigned tag as signed. Never move an already published version tag to different bytes to repair a release; issue a new version with clear notes.

Build or assemble archives with a reviewed packager that excludes local Git metadata, caches, secrets and private operational files. Inspect members before extraction and reject absolute paths, traversal, duplicate/case-colliding paths, unwanted links and unexpected files. Extract into a fresh directory and verify each file against the signed registry. Where GNU coreutils are available:

```sh
sha256sum --check SHA256SUMS
```

That command checks the listed files but does **not** reject extra files. Separately compare the full extracted regular-file set to the registry, allowing only the registry and its designated signature metadata as exceptions. Verify executable modes, required directories and platform signatures too. Hash each final archive if distributing an outer artifact checksum; do not create a circular registry that tries to hash an archive containing itself.

GitHub-generated source ZIP/TAR archives are convenient but are not the same object as an independently packaged binary release. Test their extracted payload against the registry rather than assuming a successful upload establishes byte identity. Avoid attributes that substitute or omit registered content from archives unless the registry explicitly matches that exported form.

## Publish through GitHub CLI

Authenticate through the normal browser/device flow. Never paste a GitHub token into a README, command argument, shell history or chat. Use an account/installation with only the permissions required for the destination repository. Verify the owner, repository, current visibility and intended commit first.

The following is a template. Replace `OWNER/REPO`, the version, paths and commit with the accepted values. Prepare a new release-notes file outside the public payload unless it is intentionally included and registered.

```sh
git tag -a v1.1.0 ACCEPTED_COMMIT -m "Release v1.1.0"
git push origin refs/tags/v1.1.0
gh release create v1.1.0 --repo OWNER/REPO --verify-tag --draft \
  --title "Project v1.1.0" --notes-file /private/release-notes.md
gh release upload v1.1.0 /private/artifacts/SHA256SUMS --repo OWNER/REPO
# Upload the reviewed source/binary archive and signature metadata, if supplied,
# with additional explicit paths using gh release upload.
gh release view v1.1.0 --repo OWNER/REPO
```

Push the accepted commit first if it is not already on the remote. Review the tag's target, not just its spelling. `--verify-tag` checks that the remote tag exists; it does not verify its signature or intended commit. Signed tags can be used when the project's verified signing setup supports them; do not improvise a new key during release.

Download all draft assets into a new empty directory using `gh release download ... --dir ...`. Compare downloaded digests to the accepted local files, then inspect/extract archives and repeat signature, hash and membership checks. Do not overwrite the local originals with downloaded copies. Only after acceptance, publish the draft with `gh release edit v1.1.0 --repo OWNER/REPO --draft=false`. Repository visibility remains a separate owner-controlled setting.

Creation, asset uploads and publication are separate requests. After a timeout or partial failure, inspect the existing draft, tag and asset list before retrying. Do not blindly recreate the release or use `--clobber`: replacing an asset can delete the previous object before the new upload succeeds. Reconcile identities and downloaded bytes first.

Use [GitHub's release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository) and the current [`gh release` reference](https://cli.github.com/manual/gh_release) for supported options. Consider [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) and tag/ruleset protection where available, with a process for uploading all intended assets before immutability takes effect. A configured immutable release locks its tag and assets on publication; do not claim that this setting is active without checking it. Do not overwrite a published signed artifact to make a failed check disappear.

## Maintain a changelog

Keep [CHANGELOG.md](../CHANGELOG.md) as the durable user-visible history. Record additions, changed behavior, fixes/removals and material validation limits for each version. Finalize the accepted version entry before generating and signing SHA256SUMS so the changelog is covered by the same registry. A prepared version heading is not proof of publication; the GitHub release page records the published state and timestamp. Do not edit signed release files afterward merely to change a status/date; later corrections belong in a new version.

## Release notes and final checks

State the release purpose, supported targets, notable changes and compatibility/migration requirements. Link verification instructions, SECURITY policy and validation results. Identify untested integrations and known limitations. Do not include confidential incident details, secrets or production logs. An initial baseline-security release should not promise complete protection or certified compliance.

Confirm the published tag/commit, asset names, downloaded hashes, signature verification path and expected visibility. Check README links and badges and the release page without relying solely on the maintainer's authenticated view. Record what was actually published and deployed separately. Keep signed previous releases and a recovery path; deleting them is a separate retention decision.
