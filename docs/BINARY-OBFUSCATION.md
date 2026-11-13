# Production binary obfuscation

## Purpose and limits

Obfuscation makes some forms of reverse engineering more expensive. Use it for an application you own or are authorized to transform, after deciding which intellectual property or implementation details merit this extra cost. A distributed client is controlled by its recipient: executable instructions and values needed at runtime remain observable. No obfuscator guarantees that a binary cannot be understood, modified, copied, or debugged.

Keep authorization and entitlement decisions on a trusted server. Do not embed production passwords, API secrets, private keys, or a universal decryption key in a binary and expect obfuscation to protect them. Obfuscation is not encryption, authentication, vulnerability remediation, or a software signature. It must not be used to hide malicious behavior, bypass scanners, disable security tools, or conceal a known secret exposure.

This guide separates three different operations:

| Operation | What changes | What it does not establish |
| --- | --- | --- |
| Symbol/debug separation | Debug sections and some symbol names are removed from the distributed artifact; diagnostic information is retained privately. | Program logic is not substantially disguised. Dynamic imports, exports, strings and machine instructions can remain visible. |
| Trimming, shrinking, optimization | Unused code/resources may be removed or transformed. | Smaller output is not evidence of secrecy, exploit resistance, or preserved reflection behavior. |
| Obfuscation | Names, strings, metadata or control flow are transformed, depending on the tool. | A recipient can still inspect execution. Compatibility and operational cost require measurement. |

The runnable native examples below demonstrate release hygiene, not a complete obfuscator. The managed-code examples describe actual name/transformation workflows with separate integration prerequisites. See [validation](VALIDATION.md) for the subset executed for this kit.

## Standards and evidence

| Reference | Relevant relationship | Boundary |
| --- | --- | --- |
| [OWASP MASVS-RESILIENCE](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE/) | Reverse-engineering and tampering resilience for mobile apps; use the relevant resilience goals to choose and evaluate obfuscation. | A mobile standard, not a blanket requirement for every web service or desktop binary. Applying one technique does not demonstrate MASVS compliance. |
| [OWASP MASTG](https://mas.owasp.org/MASTG/) | Platform-specific inspection of the delivered mobile artifact and resilience mechanisms. | Test the actual final artifact; the presence of an obfuscator in a build file is insufficient. |
| [NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) | PO.3: maintain toolchains; PO.4: define security checks; PW.6: configure compilation/build; PW.8: test executables; PS.2: release integrity; PS.3: archive releases. | These practices support the surrounding release process. SSDF does not mandate a particular obfuscator or certify this kit. |
| [OWASP ASVS and Top 10 mapping](OWASP-MAPPING.md) | Retain the kit's authentication, access-control and software-integrity requirements independently of obfuscation. | There is no claim that obfuscation closes a Top 10 category or establishes an ASVS level. |

## Release sequence

1. Record the source revision, target OS/architecture/runtime, licenses, compiler and transformation-tool versions, pinned dependency digests, and the threat model. Retain an unmodified baseline. Obtain tools through the [dependency inspection workflow](OPERATIONS.md), not an unpinned build-time download.
2. Run the normal tests and build. Configure supported compiler/linker hardening separately. Obfuscation does not substitute for mitigations such as ASLR, non-executable memory, stack protection, or control-flow protections where applicable.
3. Transform a candidate in a new private working directory. Preserve the baseline, required dynamic exports, plugin entry points, public ABI, serialization contracts, JNI/PInvoke bindings, reflection metadata, and license notices. Start with a narrow transformation scope and explicit keep rules.
4. Retain debug symbols, name mappings, exact configuration, tool versions and any reproducibility seed under restricted access. These may expose internal names and source paths; exclude them from public packages, container layers and generic build logs unless a reviewed distribution format requires them. Android AABs can bundle R8 mappings: inspect the actual archive and distinguish a store upload from an artifact shared publicly. Establish a retention policy and a way to find diagnostics by final artifact version/build ID.
5. Inspect and test the transformed candidate on each supported target. Test loading, integrations, error paths, startup, memory, CPU, size and crash symbolication. A matching hello-world output checks only that small example. Reflection, plugins, native bindings and serializers need their own integration tests.
6. Perform all byte-changing steps before final signing. The platform toolchain defines the exact ordering among binary transformation, bundle assembly, platform signing, notarization and packaging. Never run strip or an obfuscator on an already signed artifact. Verify the platform signature on the final output.
7. Hash final distributable bytes, build the exact inventory, sign its registry, verify a readback, and release only that inventory. Preserve the previous release and a tested rollback route. Every later change to a registered file requires a new registry and signature.

This kit's [prepare_production.py](../scripts/prepare_production.py) accepts bounded UTF-8 source files. It does not approve arbitrary binaries or transform them. Do not rename a binary or disable its scanner to pass it through that tool. Use a separate binary artifact review and final inventory alongside [production preparation](PRODUCTION.md).

## Example A: ELF debug separation on Linux

Prerequisites: a compatible C compiler and GNU binutils (`objcopy`, `strip`, `readelf`, `nm`), plus a Linux target on which the result can run. These commands use synthetic code, create a new directory, and do not overwrite an existing application. Execute them in a private parent directory. Debug files are intentionally not inside `release/`.

```sh
set -eu
umask 077
mkdir binary-demo
cd binary-demo
mkdir private release
cat > hello.c <<'EOF'
#include <stdio.h>
int main(void) {
    puts("AMQIC binary packaging demo");
    return 0;
}
EOF
cc -g -O2 hello.c -o private/app-baseline
cp private/app-baseline release/app
objcopy --only-keep-debug private/app-baseline private/app.debug
strip --strip-debug --strip-unneeded release/app
objcopy --add-gnu-debuglink=private/app.debug release/app
private/app-baseline > private/baseline-output.txt
release/app > private/candidate-output.txt
cmp private/baseline-output.txt private/candidate-output.txt
readelf --sections release/app
readelf --string-dump=.gnu_debuglink release/app
sha256sum release/app private/app.debug
```

The debug link stores a debug-file name and CRC, not a copy of the debug data. Configure the debugger or symbol server to locate the private file and verify symbolication of a controlled crash. Inspect `.debug_*`, `.symtab`, `.dynsym`, build IDs and exported symbols on your format rather than assuming `strip` removed everything. Required runtime symbols must remain. Do not apply this executable recipe blindly to relocatable objects, libraries with an external ABI, kernel modules, or a signed executable.

GNU documents [objcopy debug handling](https://sourceware.org/binutils/docs/binutils/objcopy.html), [strip](https://sourceware.org/binutils/docs/binutils/strip.html), and [GDB separate debug files](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html). Native Windows PE builds normally retain matching PDBs privately; macOS builds retain matching dSYM/UUID information and follow the Apple signing toolchain. ELF commands are not a portable PE or Mach-O recipe.

## Example B: Go release metadata reduction

Create this synthetic file as `hello.go` in a new private directory:

```go
package main

import "fmt"

func main() {
    fmt.Println("AMQIC binary packaging demo")
}
```

On PowerShell, from that directory:

```powershell
New-Item -ItemType Directory -Path private, release -ErrorAction Stop | Out-Null
go build -trimpath -o private/app-baseline.exe ./hello.go
if ($LASTEXITCODE -ne 0) { throw 'Baseline build failed' }
go build -trimpath -ldflags='-s -w' -o release/app.exe ./hello.go
if ($LASTEXITCODE -ne 0) { throw 'Candidate build failed' }
$baselineOutput = & ./private/app-baseline.exe
if ($LASTEXITCODE -ne 0) { throw 'Baseline execution failed' }
$candidateOutput = & ./release/app.exe
if ($LASTEXITCODE -ne 0) { throw 'Candidate execution failed' }
if ($baselineOutput -cne $candidateOutput) { throw 'Output mismatch' }
Get-FileHash -Algorithm SHA256 ./release/app.exe
```

`-trimpath` reduces recorded filesystem paths; linker `-s` omits the symbol table/debug information and implies `-w`. This is not full Go obfuscation: runtime metadata, strings and recoverable program structure may remain. Check [go build](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies) and [linker flags](https://pkg.go.dev/cmd/link). A production module also needs pinned modules, recorded build settings, target-specific tests and a private diagnostic baseline.

For actual Go name/literal transformations, [Garble v0.18.0](https://github.com/burrowers/garble/blob/v0.18.0/README.md) is an optional third-party build wrapper. This version requires Go 1.27 or later; the older Go version used for the metadata-reduction lab does not validate this tool. Select a reviewed release compatible with the pinned Go toolchain and install it in the controlled build environment. Do not install `@latest` during a release. For v0.18.0, after verifying that a module's import paths match the selected pattern, a build template is:

```sh
GOGARBLE='example.com/yourapp/internal' garble -literals build -trimpath -o release/app ./cmd/app
```

Replace that pattern and entry point with the actual module; an unmatched pattern does not protect the intended packages. Retain the exact Garble version, build inputs and any custom seed needed for reproduction and `garble reverse` trace recovery. Review its reflection behavior and diagnostic limitations; v0.18.0 does not support Go plugins. Literal transformation does not make a runtime secret safe. Do not select `-tiny` as a default: it removes panic/fatal diagnostics. Later versions can change package-selection behavior; use the documentation for the exact release. This template is not part of the standard-library-only kit and is not exercised by the Go metadata-reduction example.

## Example C: Android JVM bytecode with R8

R8 can shrink, optimize and rename Android application bytecode. For an existing Android application using a pinned, compatible Android Gradle Plugin below 9.3, the following Kotlin DSL belongs inside that app module's `android` block:

```kotlin
buildTypes {
    getByName("release") {
        isMinifyEnabled = true
        isShrinkResources = true
        proguardFiles(
            getDefaultProguardFile("proguard-android-optimize.txt"),
            "proguard-rules.pro"
        )
    }
}
```

For AGP 9.3 or newer, the current documented alternative inside the release build type is `optimization { enable = true }`, with default rules included by that DSL and custom `.keep` files under `src/<variant>/keepRules`. Do not mix version-specific configuration mechanically. Check the pinned plugin documentation before upgrading.

For the legacy configuration above, in `proguard-rules.pro`, preserve only the entry points your integration actually needs. For example, if a native or externally configured caller requires this exact class/member name:

```text
-keep class com.example.app.NativeBridge {
    public static native void initialize();
}
```

Replace the example with the real interface. This rule is not a universal JNI rule and does not cover every callback. Prefer library-supplied consumer rules where available. Overbroad `-keep class ** { *; }` can defeat the intended transformation; missing keep rules can break reflection, serialization, resource lookup or native calls. Exercise these paths in the actual release variant.

Build through the project's Gradle wrapper after reviewing its pinned distribution and dependencies. Retain `mapping.txt` for the exact release and prove that a synthetic obfuscated stack trace can be retraced before release. Subsequent builds overwrite the mapping; archive the correct one before rebuilding. Mappings can be bundled in AABs, so inspect archive membership and review the upload recipient before sharing a bundle. Measure the final APK/AAB and verify its signing configuration. See Android's [R8 optimization guide](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization), [keep rules](https://developer.android.com/topic/performance/app-optimization/keep-rules-overview), [troubleshooting](https://developer.android.com/topic/performance/app-optimization/troubleshoot-the-optimization), and [Retrace](https://developer.android.com/tools/retrace).

R8 requires a real Android project and is not a general ELF/PE transformer. The fragment above is an integration template, not a complete application or a claim of a tested Android release.

## .NET and other toolchains

.NET trimming and Native AOT can reduce deployed code or change its representation, but are not confidentiality guarantees. Dynamic assembly loading, reflection, serializers and native interop need explicit treatment. Follow Microsoft's [trimming guidance](https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/trim-self-contained) and [Native AOT limitations](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/). Resolve relevant analysis warnings rather than suppressing them to obtain a smaller artifact.

If you select a .NET obfuscator, evaluate it against the precise runtime, signing model, reflection use and platform support. Keep public contracts stable, retain rename mappings, test the transformed assembly through the real host, and follow toolchain-specific strong-name/Authenticode signing order. An assembly that compiles is not proof that its transformed version will load. This kit does not ship or endorse a universal .NET obfuscator configuration.

## Acceptance record

Record the baseline and final hashes, tool versions/digests, target and configuration, transformation scope, private symbol/mapping location, deterministic inputs or nondeterminism explanation, preserved exports/contracts, test commands/results, performance changes, signature verification, final inventory, and rollback version. Publish only the safe portion; do not publish private source paths, credentials, mappings, or secret material.

Reject a candidate if required integrations fail, source secrets remain embedded, security mitigations or signatures regress, diagnostics cannot be recovered, licensing is violated, or performance exceeds the agreed budget. A scanner false positive needs vendor-supported investigation and a known-good rebuild, not instructions to evade the scanner. The [AI skill](../skills/obfuscate-binaries/SKILL.md) turns this workflow into a bounded task.
