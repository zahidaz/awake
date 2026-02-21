# Verimatrix XTD

Verimatrix XTD (Extended Threat Defense) is a commercial application protection platform originally developed by **Inside Secure** (France). The XTD product line was acquired by **Guardsquare** (Belgium) in February 2026 for $8.5M, placing it under the same corporate umbrella as [DexGuard](dexguard.md) and [ProGuard](r8-proguard.md).

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Verimatrix (originally Inside Secure, now Guardsquare) |
| Origin | France (Aix-en-Provence) |
| Type | Commercial Protector/Obfuscator/RASP |
| Platforms | Android, iOS, Web (JavaScript frameworks) |
| Acquisition | Inside Secure acquired Verimatrix in 2019 for $143M, took Verimatrix name. XTD product line sold to Guardsquare in Feb 2026 for $8.5M |
| Current Owner | Guardsquare (Belgium) |

## History and Ownership

The lineage of this product is convoluted:

1. **Inside Secure** (France) developed the original application protection technology, including Whitebox 3.0 cryptography
2. **2019**: Inside Secure acquired Verimatrix Inc for $143M and rebranded the combined entity as Verimatrix
3. **Dec 2025 -- Feb 2026**: Verimatrix sold its XTD (app shielding), Code Protection, and Whitebox product lines to Guardsquare for $8.5M
4. **Feb 2026**: Guardsquare now owns DexGuard, ProGuard, and the former Verimatrix XTD suite

This consolidation means Guardsquare controls three distinct application protection products (DexGuard, XTD, ProGuard) and one white-box cryptography solution. Future product consolidation is likely -- redundant features between DexGuard and XTD will probably be merged, and the Verimatrix white-box crypto technology may be integrated into DexGuard's offering.

## Identification

### APKiD Detection

APKiD detects Verimatrix under its original Inside Secure branding:

```
protector : InsideSecure
```

APKiD issue #397 documents a false positive where zShield-protected applications were incorrectly flagged as InsideSecure. Verify detection by checking for the additional file artifacts below.

### File Artifacts

| Artifact | Description |
|----------|-------------|
| Native library | `libencryption_<arch>.so` (architecture-specific naming) |
| ProGuard/R8 rules | `-keep` rules referencing `com.insidesecure.core` package |
| Gradle plugin | `ApkdefenderPlugin.jar` in build configuration |
| SDK AAR | `vmx-xtd-sdk.aar` in project dependencies |

### ProGuard Keep Rules

Protected applications include keep rules for Verimatrix's runtime classes:

```
-keep class com.insidesecure.core.** { *; }
-keep class com.verimatrix.shield.** { *; }
```

The `com.insidesecure.core` package reference persists even after the Verimatrix rebranding, serving as a reliable identification marker.

## Build Integration

### Gradle Plugin

Verimatrix XTD integrates as a Gradle plugin through `ApkdefenderPlugin.jar`. The plugin adds protection tasks to the build pipeline:

```
apkprotectDebugRelease
apkprotectVariantRelease
```

These tasks run after APK/AAB assembly and apply the configured protection layers to the compiled binary.

### SDK Integration

The runtime SDK is distributed as `vmx-xtd-sdk.aar`, which applications include as a dependency. This AAR contains the runtime components needed for RASP checks, white-box crypto operations, and environmental detection.

### Cloud Portal

Verimatrix operated a cloud portal at `appshield.verimatrixcloud.net` for configuring protection policies and managing application builds. Following the Guardsquare acquisition, this infrastructure's future is uncertain.

### CI/CD Integration

GitHub Actions integration is available through the `Verimatrix/app-shield-protect` action, enabling automated protection in CI/CD pipelines.

## Protection Mechanisms

### Multi-Language Code Obfuscation

Verimatrix XTD applies obfuscation across multiple programming languages within a single application:

| Language | Obfuscation Support |
|----------|-------------------|
| Java | Full (bytecode transformation) |
| Kotlin | Full (bytecode transformation) |
| C/C++ | Native code obfuscation |
| Swift | iOS native obfuscation |
| JavaScript | Web/hybrid framework obfuscation |

### Control Flow Obfuscation

Transforms original control flow structures into flattened or opaque predicate-based patterns. Conditional branches are replaced with computed jumps, and loop structures are converted to state machines.

### Symbol Renaming

Class, method, and field names are replaced with meaningless identifiers. Unlike ProGuard/R8's simple sequential renaming (a, b, c), Verimatrix can apply more aggressive renaming patterns.

### String Obfuscation

String literals are replaced with runtime-computed values. Decryption routines are inlined at each use site rather than centralized, making batch decryption hooking harder than with [DexGuard](dexguard.md)'s pattern of centralized decryption classes.

### Arithmetic Obfuscation

Constant values and arithmetic operations are transformed into equivalent but more complex expressions. A simple integer comparison becomes a chain of bitwise operations and arithmetic that produces the same result.

### Code Encryption

Selected code sections are encrypted at rest and decrypted at runtime. This applies to both DEX bytecode and native code sections.

### Runtime Environmental Checks

| Check | Description |
|-------|-------------|
| Root detection | Detects su, Magisk, SuperSU, system partition modification |
| Emulator detection | Build properties, hardware fingerprinting |
| Debug detection | ptrace, TracerPid, JDWP |
| Hook detection | Frida, Xposed, Substrate |
| Clone detection | Multi-instance and app cloning |

### Binary Integrity Checks ("Superchecks")

Verimatrix implements what it calls "superchecks" -- integrity verification routines that validate the binary's structure at runtime. These checks go beyond simple hash verification, examining code section integrity, resource consistency, and native library state.

### Anti-Tamper

Detects modification of the APK structure, DEX bytecode, native libraries, and resources. Tampering triggers configurable responses.

### Anti-Debug

Multi-layer debugger detection covering both Java-level (JDWP) and native-level (ptrace, TracerPid) debuggers.

### Anti-Hook

Detects function hooking frameworks including Frida, Xposed, and Cydia Substrate through process memory inspection, loaded library scanning, and runtime class enumeration.

### Anti-Clone

Prevents application cloning and multi-instance execution by validating the installation context and package identity.

### Zero-Day Flags/Blockers

Verimatrix supports OTA-updatable detection rules. New threat signatures (root hiding tools, new Frida variants, novel hooking techniques) can be pushed to deployed applications without requiring a full app update. This is a significant defensive capability -- the protection adapts after deployment.

### Accessibility Abuse Detection

Detects when other applications are using Android's Accessibility Service to interact with the protected application. This counters overlay attacks and automated UI interaction from malware.

### RASP

Full Runtime Application Self-Protection suite combining the environmental checks, integrity verification, and threat response into a cohesive runtime defense layer.

## White-Box Cryptography

Verimatrix's white-box cryptography is the most technically significant component of the product suite. Originally developed as Inside Secure Whitebox 3.0, it is EMVCo certified for payment security.

### Design

White-box crypto transforms standard cryptographic algorithms so that keys are dissolved into the code itself. The key material does not exist as a discrete byte sequence at any point during execution -- it is mathematically distributed across lookup tables and code transformations. The implementation is algorithm-agnostic: the same white-box framework wraps multiple algorithms.

### Supported Algorithms

| Algorithm | Support |
|-----------|---------|
| AES | Encryption/decryption |
| AES-GCM | Authenticated encryption |
| 3DES | Legacy block cipher |
| RSA | Asymmetric operations |
| ECDSA | Signature verification |
| ECC | Elliptic curve operations |
| ECDH | Key exchange |
| HMAC | Message authentication |
| SHA family | Hashing |

### Security Properties

- Keys resist extraction through static reverse engineering
- Side-channel analysis (power analysis, electromagnetic emanation) is mitigated through algorithmic design
- Fault injection attacks (glitching) are detected and countered
- EMVCo certification validates resistance against a defined set of attack methodologies

### Reverse Engineering Implications

White-box crypto is the hardest component of Verimatrix to defeat. Unlike code obfuscation (which can be bypassed through dynamic analysis) or RASP checks (which can be hooked and disabled), white-box crypto is mathematically designed to resist key extraction. An attacker with full binary access and debugger control still cannot extract the key in a usable form.

Practical approaches against white-box crypto:

- **Differential fault analysis (DFA)**: Inject faults into the computation and analyze output differences to recover key bits. Requires significant expertise and per-implementation effort
- **Code lifting**: Extract the entire white-box implementation and use it as a black box without extracting the key. The implementation becomes an oracle that encrypts/decrypts on demand
- **API hooking**: Intercept inputs and outputs of the white-box function calls to capture plaintext data without breaking the crypto

## Framework Support

Verimatrix XTD supports protection of applications built with multiple frameworks:

| Framework | Protection Level |
|-----------|-----------------|
| Angular | JavaScript obfuscation |
| React | JavaScript obfuscation |
| React Native | JavaScript + native bridge protection |
| Vue | JavaScript obfuscation |
| Webpack | Bundle-level obfuscation |
| Xamarin | .NET/Mono + native protection |

This multi-framework support is particularly relevant for hybrid applications where JavaScript business logic needs protection alongside native components.

## Unpacking Methodology

Public bypass research for Verimatrix XTD is limited. The product has received less attention from the security research community compared to [DexGuard](dexguard.md) or [Chinese packers](tencent-legu.md).

### General Approach

1. Identify the protection layers present (APKiD, manual artifact inspection)
2. Bypass RASP checks using standard anti-detection Frida scripts
3. Dump decrypted DEX at runtime if code encryption is applied
4. For string obfuscation, hook at the use site rather than seeking centralized decryption methods
5. White-box crypto operations should be treated as black boxes -- intercept I/O rather than attempting key extraction

### White-Box Crypto

The white-box implementation is the primary barrier to complete analysis. Code lifting (extracting the white-box tables and reimplementing the encryption/decryption outside the app) is more practical than attempting key extraction. This approach works for cases where the goal is to replicate the app's cryptographic behavior rather than recover the raw key.

## Malware Usage

Verimatrix XTD has not been observed in malware samples. The commercial licensing model, cloud-based build integration, and enterprise sales process make it impractical for malware authors. The product is exclusively found in legitimate applications.

## Industry Usage

Verimatrix XTD is deployed across several verticals:

| Industry | Use Case |
|----------|----------|
| Media/streaming | DRM protection, content security |
| Gaming | Anti-cheat, asset protection |
| Fintech | Payment security, white-box crypto for key protection |
| Healthcare | Patient data protection, HIPAA compliance |
| Automotive | Connected car application security |

The media and streaming sector represents Verimatrix's historical core market, predating the Inside Secure acquisition.

## Guardsquare Acquisition Implications

The February 2026 acquisition creates several scenarios for reverse engineers to watch:

- **Product consolidation**: DexGuard and XTD have overlapping features (code obfuscation, RASP, anti-tampering). Guardsquare will likely merge the strongest components of each
- **White-box crypto in DexGuard**: Verimatrix's EMVCo-certified white-box crypto could be integrated into DexGuard, making DexGuard significantly harder to defeat for crypto-dependent analysis
- **Detection signature updates**: APKiD may need updated signatures as Guardsquare migrates XTD-protected apps to a unified product. The `protector : InsideSecure` signature may eventually disappear from new builds
- **Existing deployments**: Applications already protected with Verimatrix XTD will continue to show current artifacts until developers migrate to whatever Guardsquare's consolidated product becomes

## Comparison with Other Protectors

| Feature | Verimatrix XTD | [DexGuard](dexguard.md) | [DexProtector](dexprotector.md) | [zShield](zshield.md) |
|---------|---------------|---------|-------------|---------|
| White-box crypto | EMVCo certified, algorithm-agnostic | No | No | zKeyBox (separate) |
| Multi-language | Java, Kotlin, C/C++, JS, Swift | Java, Kotlin, native | Java, Kotlin, native | Java, Kotlin, native |
| Web framework support | Angular, React, Vue, Webpack | No | No | No |
| Code encryption | Yes | Yes (class encryption) | Yes | Yes (.szip) |
| OTA threat updates | Yes (zero-day flags) | No | No | No |
| Accessibility abuse detection | Yes | No | No | No |
| Build integration | Gradle plugin + cloud portal | Gradle plugin | CLI post-build | Build-time |
| Current owner | Guardsquare | Guardsquare | Licel | Zimperium |
| Public bypass research | Minimal | Extensive | Moderate | Limited (XXTEA only) |
| Malware adoption | None | Cracked versions | Rare | None |

## References

- [Verimatrix XTD App Shield](https://www.verimatrix.com/products/app-shield/)
- [Verimatrix Code Protection](https://www.verimatrix.com/products/code-protection/)
- [Verimatrix Whitebox Cryptography](https://www.verimatrix.com/products/whitebox/)
- [Guardsquare Acquires Verimatrix XTD](https://www.guardsquare.com/)
- [APKiD -- Android Application Identifier](https://github.com/rednaga/APKiD)
- [APKiD Issue #397 -- InsideSecure/zShield False Positive](https://github.com/rednaga/APKiD/issues/397)
- [Verimatrix GitHub Actions Integration](https://github.com/Verimatrix/app-shield-protect)
- [Inside Secure Whitebox 3.0 Documentation](https://www.verimatrix.com/)
- [EMVCo Security Evaluation](https://www.emvco.com/)
