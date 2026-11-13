---
name: obfuscate-binaries
description: Prepare and validate production binary obfuscation or symbol separation for authorized software, preserving runtime contracts, private diagnostics, artifact integrity and signing order.
---

# Prepare protected production binaries

Read [the binary guide](../../docs/BINARY-OBFUSCATION.md) and the target project's build/release instructions. Work only on the authorized application and target version. Distinguish symbol stripping, shrinking and actual obfuscation when choosing and reporting a method.

## Establish the task

Identify the executable format, OS/architecture/runtime, source revision, entry point, pinned toolchain and dependencies, public ABI, reflection/serialization/native bindings, platform signing, diagnostic storage and rollback requirements. Define the implementation details to make harder to inspect and the acceptable compatibility/performance budget. Keep server authorization and runtime secrets outside distributed clients. Do not treat obfuscation as protection for embedded credentials.

Select only the relevant guide recipe. GNU ELF debug separation does not apply unchanged to PE/Mach-O; Go linker metadata reduction is not an obfuscator; Android R8 requires the actual release variant and keep rules. Choose a third-party transformer only after its provenance, license and target compatibility are reviewed through the project's dependency workflow. Do not fetch unpinned tools or run arbitrary downloaded binaries.

## Build and verify

1. Preserve an unmodified baseline and create a separate private candidate directory. Do not overwrite source, old releases, signing keys or the baseline. Register any temporary environment and its cleanup owner under the project's normal workflow.
2. Run baseline checks. Apply narrowly scoped transformations with reviewed configuration. Preserve required imports/exports, externally referenced names, resources and security mitigations. Retain exact symbol files, name mappings and reproduction settings under restricted access. Exclude them from public output and container layers unless a reviewed distribution format requires otherwise; inspect Android AAB mapping metadata and approve the recipient before sharing the bundle.
3. Test the actual transformed artifact on each supported target: startup, authorized and denied operations, reflection, serialization, plugins/native interop, exceptions and diagnostic recovery. Compare relevant output and resource measurements to the baseline. Verify retained exports and final symbols with format-appropriate tools. Do not infer complete compatibility from size reduction or a hello-world test.
4. Complete transformations before signing; follow platform-specific signing/packaging order. Verify final platform signatures, then compute hashes of final distributables and prepare the exact release inventory. Any byte change invalidates previous file hashes and can invalidate signatures. Never reuse a signature for a changed registry.
5. Verify a readback and a rollback path. Report executed checks separately from templates and unavailable platforms. Stop the affected release if a compatibility, integrity, license, embedded-secret or diagnostic requirement fails. Do not disable scanners or hide a finding to obtain acceptance.

The kit's [production preparation tool](../../docs/PRODUCTION.md) accepts bounded UTF-8 source, not arbitrary binaries. Keep the binary review separate rather than renaming output or bypassing that tool. Use [release verification](../../docs/RELEASE-VERIFICATION.md) for the final registry. Building and preparing a candidate do not authorize publishing or deploying it; follow the user's actual release authority.

## Deliverable

Provide a safe report of the selected method and its limits, exact artifact hashes and versions, transformation/keep-rule scope, test and performance results, diagnostic-recovery evidence, signature status, inventory and rollback reference. Do not include secret values, private keys, private mappings, or internal machine paths in public documentation. Link applicable OWASP resilience goals and NIST SSDF process practices without claiming certification or that obfuscation closes an access-control vulnerability.
