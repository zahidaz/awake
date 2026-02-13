# Appdome

Appdome is a commercial no-code mobile security platform developed by **Appdome Inc** (USA/Israel). It operates as a cloud-based SaaS that applies protection to compiled APK/AAB binaries without requiring source code access. The platform uses a patented "Fusion" technology that merges microservice-based protection plugins into existing Android and iOS applications through a web portal or REST API.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Appdome Inc |
| Origin | Redwood City, California / Tel Aviv, Israel |
| Type | Commercial SaaS Protector (no-code, post-build) |
| Platforms | Android, iOS |
| Integration | Cloud portal upload, REST API, CI/CD plugins |
| Model | Per-app subscription licensing |

## How Fusion Works

Appdome's Fusion engine operates on compiled binaries rather than source code. The workflow:

1. Upload a compiled APK or AAB to the Appdome cloud portal (or submit via REST API)
2. The Fusion engine analyzes the binary structure -- frameworks, libraries, SDKs, native components
3. Selected protection plugins (microservice-based) are merged into the application
4. At least one additional `classes.dex` is injected containing the protection policy logic
5. The original `classes.dex` is modified to hook initialization and route through Appdome's protection layer
6. The secured binary is output for signing and distribution

The REST API enables CI/CD integration, allowing automated protection as part of build pipelines without manual portal interaction. Protection configuration is defined as a "Fusion Set" that specifies which plugins to apply.

## Identification

### APKiD Detection

APKiD identifies Appdome with the following signatures:

```
protector : Appdome
Appdome (dex)
```

### File Artifacts

| Artifact | Description |
|----------|-------------|
| Native library | `libloader.so` in `lib/arm64-v8a/` and `lib/armeabi-v7a/` |
| Additional DEX | Extra `classes.dex` file(s) containing protection policy |
| String references | Strings in `libloader.so` reference Appdome obfuscating compiler |
| Modified manifest | AndroidManifest.xml modified to route through Appdome initialization |

## Protection Mechanisms

### DEX Encryption (White Hat Android Packer)

Appdome encrypts DEX bytecode using what it markets as a "White Hat Android Packer." The original application code is encrypted and decrypted at runtime through the native `libloader.so` library.

### DEX and Control Flow Obfuscation

The "Dex Relocation" plugin applies multiple obfuscation layers:

- Call obfuscation -- indirect method invocations replace direct calls
- Function call modification -- original call sites are rewritten
- Dummy code injection -- non-functional code paths inserted to complicate static analysis
- Control flow flattening within protected methods

### Native Library Encryption

Native `.so` libraries bundled with the application are encrypted at rest and decrypted at load time through Appdome's native protection layer.

### SSL Pinning with Bypass Detection

Appdome implements certificate pinning that actively detects bypass attempts rather than simply failing silently. The pinning layer monitors for signs of MITM proxy interception and can trigger defensive responses when bypass tools are detected.

### Anti-Frida

Appdome's Frida detection covers multiple injection vectors:

| Detection Vector | Description |
|-----------------|-------------|
| frida-server | Detects standard frida-server process |
| Inject mode | Detects Frida injected via ptrace |
| Gadget mode | Detects FridaGadget.so loaded into the process |
| Custom modules | Scans for non-standard Frida modules |
| Objection | Detects Objection framework runtime |
| StrongR Frida | Detects recompiled Frida builds with modified signatures |

### Anti-Xposed

Detects the Xposed framework through class presence checks, stack trace inspection, and module enumeration.

### Root Detection

| Target | Detection |
|--------|-----------|
| Magisk | Binary presence, mount namespace analysis |
| MagiskHide | Detects hide list manipulation |
| Shamiko | Zygisk module detection |
| Zygisk | Module injection framework detection |
| SuperSU | su binary and package detection |
| RootCloak | Cloaking module detection |

### Emulator Detection

Identifies emulated environments through build properties, hardware fingerprinting, sensor availability, and telephony state analysis.

### Anti-Debugging

Monitors for debugger attachment via TracerPid checks, ptrace status, JDWP connection detection, and native debugger signatures.

### Anti-Tampering (OneShield)

Appdome's OneShield feature validates the integrity of the protected binary at runtime. It checks APK signatures, DEX checksums, and native library integrity. Tampering triggers configurable responses including immediate termination or silent reporting.

### Anti-Repackaging

Detects when the APK has been decompiled, modified, and rebuilt by verifying structural integrity beyond just the signing certificate.

### Malware and Overlay Detection

Detects malicious overlay attacks and identifies known malware patterns running alongside the protected application.

## Unpacking Methodology

No comprehensive public bypass tool exists for Appdome. The multi-layered detection model means each protection mechanism must be defeated individually.

### Primary Vector: Native Library Patching

The most documented approach targets native library detection routines:

1. Decompile the APK using apktool
2. Load `libloader.so` into Ghidra or IDA Pro
3. Locate Frida detection functions by searching for strings related to `/proc/net/unix`, `frida`, `gadget`, port 27042
4. Patch detection function return values to always return "safe" -- NOP the branch or force the return register
5. Rebuild and resign the APK

This approach is limited by OneShield integrity checks, which detect the patched native library. Defeating OneShield requires locating and patching the integrity verification routines as well, creating a chain of patches.

### Observed Bypass Attempts

XDA Forums discussions document scenarios where root hiding (MagiskHide/Shamiko) combined with developer mode restrictions and Frida concealment can get past initial checks, but the application crashes when attempting SSL pinning bypass. This confirms the layered detection model -- bypassing one layer exposes the next.

Progressive bypass is necessary: disable anti-debugging first, then anti-root, then anti-Frida, then SSL pinning, with each layer potentially requiring both Java and native level patches.

## Malware Usage

Appdome has not been observed protecting malware samples. The cloud-based SaaS model makes it impractical for malware authors:

- Requires account creation with identity verification
- All protected binaries pass through Appdome's cloud infrastructure
- Per-app licensing creates a cost barrier
- Cloud processing leaves an audit trail

## Industry Usage

Appdome is deployed primarily in industries requiring mobile app security compliance:

- Banking and financial services
- Fintech and mobile payments
- mCommerce and retail
- Trading platforms
- Healthcare applications

The no-code model appeals to organizations without dedicated mobile security engineering teams, allowing security teams to apply protection without modifying build pipelines or requiring developer involvement.

## Comparison with Other Protectors

| Feature | Appdome | [DexGuard](dexguard.md) | [DexProtector](dexprotector.md) | [Promon](promon.md) |
|---------|---------|---------|-------------|--------|
| Integration | Cloud SaaS (no-code) | Gradle plugin (source required) | CLI post-build | SDK integration |
| Source required | No | Yes | No | No |
| DEX encryption | Yes | Yes | Yes | No |
| Code virtualization | No | Optional | No | No |
| Anti-Frida | Multi-vector | Port + maps scanning | Yes | Yes |
| Root detection | Comprehensive | Comprehensive | Yes | Core feature |
| SSL pinning | With bypass detection | Native-level | Yes | Yes |
| Malware adoption | None | Cracked versions in malware | Rare | None |
| Unpacking difficulty | Medium-high (layered) | Medium (Frida hooks) | Medium-high | N/A (RASP) |

## References

- [Appdome Mobile Security Platform](https://www.appdome.com/)
- [Appdome Fusion Technical Overview](https://www.appdome.com/how-it-works/)
- [Appdome REST API Documentation](https://www.appdome.com/appdome-ci-cd/)
- [APKiD -- Android Application Identifier](https://github.com/rednaga/APKiD)
- [Appdome Anti-Frida Documentation](https://www.appdome.com/no-code-mobile-security/anti-frida-detection/)
- [Appdome OneShield Integrity Protection](https://www.appdome.com/no-code-mobile-security/mobile-app-integrity/)
