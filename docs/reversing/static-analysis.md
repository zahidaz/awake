# Static Analysis

Examining an APK without executing it. The first step in any Android reverse engineering workflow: extract the APK, read the manifest, decompile the code, and identify protections, permissions, and interesting code paths.

## Workflow

### 0. VirusTotal Triage

Before deep analysis, submit the sample to [VirusTotal](https://www.virustotal.com/) for multi-engine scanning. This provides an immediate overview:

```
Upload APK -> Check detection ratio -> Review vendor names -> Check "Details" tab
```

What to extract from VT results:

| Tab | What to Look For |
|-----|-----------------|
| Detection | Detection ratio, family names from ESET/Kaspersky/ThreatFabric, ignore generic "Trojan.Gen" verdicts |
| Details | Target SDK, signing certificate, embedded file types, APKiD results (packers/obfuscators) |
| Relations | Contacted domains/IPs (C2 infrastructure), downloaded files, embedded URLs |
| Behavior | Sandbox execution results: permissions requested, network connections, file system activity |
| Community | Researcher comments, YARA rule matches, tags |

Interpreting detection names: different engines name the same family differently. See [Naming Conventions](../malware/naming-conventions.md) for the full cross-vendor mapping. In practice, check ESET, Kaspersky, and Bitdefender names first as they have the most consistent Android family attribution.

If the APK is packed, the "Details" tab shows APKiD results revealing the packer. Detection counts may be lower for packed samples since engines scan the packer stub, not the actual payload.

For VT Intelligence users: search by `content:{hash}`, `imphash:`, or behavioral indicators like `behaviour_network:domain` to find related samples and track campaigns.

### 1. APK Extraction

Get the APK from the device:

```bash
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-XXX/base.apk
```

For split APKs (common on Android 5+):

```bash
adb shell pm path com.target.app
# Returns multiple paths: base.apk, split_config.*.apk
```

### 2. Manifest Review

The `AndroidManifest.xml` reveals the most about an app before looking at code:

```bash
apktool d base.apk -o output/
cat output/AndroidManifest.xml
```

What to look for:

| Element | Significance |
|---------|-------------|
| `<uses-permission>` | What data/capabilities the app requests |
| `<service>` with accessibility | Indicates potential device control capability |
| `<receiver>` for BOOT_COMPLETED | Persistence mechanism |
| `android:exported="true"` | Components accessible to other apps |
| `<provider>` without permission | Potentially exposed data |
| `taskAffinity` on activities | Possible task hijacking |
| `android:debuggable="true"` | Debug build, easier to instrument |
| `android:allowBackup="true"` | Data extractable via adb backup |
| Custom permissions | App-defined access controls |

### 3. Decompilation

**DEX to Java (readable but imperfect):**

```bash
jadx base.apk -d output_java/
```

[jadx](https://github.com/skylot/jadx) produces readable Java approximations. Works well for most unprotected apps. Struggles with heavy obfuscation or packed code.

**DEX to Smali (accurate but harder to read):**

```bash
apktool d base.apk -o output_smali/
```

[apktool](https://github.com/iBotPeaches/Apktool) disassembles to Smali (Dalvik assembly). Preserves all code structure. Required for patching.

### 4. Packer Identification

Run [APKiD](https://github.com/rednaga/APKiD) to identify protections:

```bash
apkid base.apk
```

Output reveals:

- Packer/protector used (Bangcle, Tencent, Virbox, DexProtector, etc.)
- Obfuscator (ProGuard, R8, Allatori, etc.)
- Anti-analysis techniques detected
- Compiler used

If the app is packed, static analysis of the DEX code shows only the packer stub. The real code is encrypted and only available at runtime. Move to [Dynamic Analysis](dynamic-analysis.md) or packer-specific unpacking techniques in [Packers](../packers/index.md).

### 5. String Extraction

Strings reveal C2 URLs, API endpoints, encryption keys, and debug messages:

```bash
strings base.apk | grep -i "http"
strings base.apk | grep -i "api"
```

In jadx, search across all decompiled sources for:

- URLs and IP addresses
- Hardcoded credentials or API keys
- Package names of target apps (for overlay malware)
- Packer-specific strings
- Base64-encoded blobs (may contain configuration)

### 6. Resource Analysis

Resources (`res/`) can contain:

| Resource | Contains |
|----------|----------|
| `res/xml/` | Network security config, accessibility config, file provider paths |
| `res/raw/` | Embedded files, encrypted payloads, configuration |
| `assets/` | Native libraries, packed DEX files, web content for overlays |
| `res/values/strings.xml` | Hardcoded strings, sometimes sensitive |

The network security config (`res/xml/network_security_config.xml`) reveals certificate pinning configuration and trusted CAs.

### 7. Native Code

If the APK contains `.so` files in `lib/`:

```bash
file lib/arm64-v8a/libnative.so
```

Native libraries may contain:

- Unpacking logic (common in packed apps)
- Anti-tampering checks
- Cryptographic operations
- JNI bridges to obfuscated functionality

Use Ghidra, IDA Pro, or Binary Ninja for native code analysis. Function names are often stripped, requiring pattern matching and dynamic analysis to map functionality.

## Family-Specific Static Analysis Notes

Different malware families present unique static analysis challenges. The table below maps families to their specific obstacles and recommended approaches:

| Family | Challenge | Approach |
|--------|-----------|----------|
| [FluHorse](../malware/families/fluhorse.md) | Business logic compiled as Dart AOT snapshot in `libapp.so`, not in DEX | Use [Blutter](https://github.com/nicksdevice/blutter) or [reFlutter](https://github.com/nicksdevice/reflutter) to analyze Dart snapshots. Standard DEX decompilers show only a thin Kotlin wrapper. |
| [SoumniBot](../malware/families/soumnibot.md) | Manifest obfuscation crashes jadx and apktool | Use Android OS itself as the parser (install on emulator, dump manifest via `adb shell dumpsys package`). Or patch the malformed ZIP entries manually. |
| [GodFather](../malware/families/godfather.md) v3 | `$JADXBLOCK` fields in class files + ZIP manipulation | Remove `$JADXBLOCK` annotations from DEX before feeding to jadx. Use alternative decompilers (Procyon, CFR) that may not honor this field. |
| [Mandrake](../malware/families/mandrake.md) | OLLVM-obfuscated native libraries | Use [D-810](https://github.com/nicksdevice/d-810) Ghidra plugin for OLLVM deobfuscation. Pair with [Frida Stalker](hooking.md) for runtime instruction tracing. |
| [Necro](../malware/families/necro.md) | Payload hidden in PNG steganography | Extract pixel data from downloaded PNGs, decode hidden DEX using the loader's algorithm. Check `BitmapFactory` usage patterns. |
| [Klopatra](../malware/families/klopatra.md) | Virbox packer virtualizes DEX into proprietary bytecode | Static analysis fails entirely for virtualized methods. Must use [dynamic analysis](dynamic-analysis.md) and hook the VM interpreter. See [Virbox](../packers/virbox.md). |
| [DexGuard](../packers/dexguard.md)-protected | String encryption, class encryption, resource encryption | Search for single-character class names (`o`, `oo`, `ooo`) with methods returning `String`. These are decryption stubs. |
| [Gigabud](../malware/families/gigabud.md) | Core logic in native `libstrategy.so` with Virbox packing | Analyze the Java layer for accessibility service registration, then trace native calls via Frida. |
| [Antidot](../malware/families/antidot.md) | Custom string encryption + gibberish class names | Identify the decryption method pattern and write a jadx script or Frida hook to bulk-decrypt all strings. |
| [Triada](../malware/families/triada.md) firmware variants | Malware code embedded in system framework | Compare system partition against known-good firmware images. Diff framework JARs and system apps. |

## Flutter/Dart Analysis

[FluHorse](../malware/families/fluhorse.md) and other Flutter-based malware require a different toolchain since business logic compiles to native code via Dart's AOT compiler rather than Dalvik bytecode:

| Tool | Purpose |
|------|---------|
| [Blutter](https://github.com/nicksdevice/blutter) | Dart AOT snapshot analyzer. Extracts class/method names and rebuilds Dart source from `libapp.so`. |
| [reFlutter](https://github.com/nicksdevice/reflutter) | Framework re-patching tool. Patches `libflutter.so` to enable SSL traffic interception and snapshot analysis. |
| [Doldrums](https://github.com/nicksdevice/doldrums) | Dart AOT snapshot parser for older Dart versions. |

The workflow: extract `libapp.so` from the APK, determine the Dart SDK version from `libflutter.so`, then use Blutter to parse the snapshot and recover function signatures and string references. [Fortinet published a detailed static reversing methodology](https://www.fortinet.com/blog/threat-research/fortinet-reverses-flutter-based-android-malware-fluhorse) at Virus Bulletin 2024.

## Tools

| Tool | Purpose |
|------|---------|
| [jadx](https://github.com/skylot/jadx) | DEX to Java decompiler, GUI and CLI |
| [apktool](https://github.com/iBotPeaches/Apktool) | APK disassembly/reassembly, Smali output |
| [APKiD](https://github.com/rednaga/APKiD) | Packer and obfuscator identification |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | Extract URLs, endpoints, secrets, and API keys from APKs |
| [Ghidra](https://ghidra-sre.org/) | Native code reverse engineering (free, NSA) |
| [dex2jar](https://github.com/pxb1988/dex2jar) | DEX to JAR conversion for use with Java decompilers |
| [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) | Multi-decompiler view (Procyon, CFR, FernFlower, jadx) |
| [JADX-GUI](https://github.com/skylot/jadx) | jadx with search, navigation, and deobfuscation features |

## Emerging Evasion Techniques

Beyond traditional packing and obfuscation, recent malware families have introduced novel techniques that specifically break static analysis assumptions:

### Manifest Obfuscation

[SoumniBot](../malware/families/soumnibot.md) (2024) exploits differences between how analysis tools and the Android OS parse `AndroidManifest.xml`. [Kaspersky documented three techniques](https://securelist.com/soumnibot-android-banker-obfuscates-app-manifest/112334/):

| Technique | Effect |
|-----------|--------|
| Invalid compression method | ZIP entry uses unknown compression value. Android defaults to uncompressed; jadx/apktool fail to parse. |
| Invalid manifest size | Declared size in ZIP header does not match actual size. Android ignores mismatch; tools crash or produce corrupt output. |
| Excessively long namespace strings | Hundreds of thousands of characters in XML namespace. Causes analysis tools to hang or run out of memory. |

### .NET MAUI Framework

[McAfee documented Android malware](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/) built entirely in C# using the .NET MAUI cross-platform framework. Core logic resides in blob binary files rather than DEX, meaning standard DEX decompilers (jadx, apktool) find no meaningful code. Multi-layer encryption (XOR + AES) further protects the actual payload.

### Steganographic Payloads

[Necro](../malware/families/necro.md) (2024) hides second-stage payloads inside PNG image files using [steganography](https://securelist.com/necro-trojan-is-back-on-google-play/113881/). The loader downloads what appears to be a standard image, extracts hidden data from pixel values, and loads it as a DEX payload. Network inspection sees an image download, not a malware fetch.

### ZIP Manipulation and JADX Blocking

[GodFather v3](../malware/families/godfather.md) (2025) combines multiple anti-decompilation layers: ZIP archive manipulation with invalid headers prevents standard archive tools from extracting the APK contents, deliberately malformed manifest entries crash parsers, and injected `$JADXBLOCK` fields in class files cause the jadx decompiler to skip those classes entirely. This layered approach targets the specific analysis toolchain most researchers rely on.

### OLLVM-Obfuscated Native Libraries

[Mandrake](../malware/families/mandrake.md) (2024) moved core malicious functionality from DEX into native libraries obfuscated with OLLVM (Obfuscator-LLVM), applying control flow flattening, string encryption, and bogus control flow. Standard native code analysis tools like Ghidra require significant manual effort to deobfuscate.

## Limitations

Static analysis fails when:

- The app is packed (encrypted DEX, loaded at runtime)
- Heavy obfuscation (ProGuard, R8, DexGuard, Allatori) makes code unreadable
- Native code handles critical logic
- Code is downloaded from C2 after installation
- Reflection is used to hide API calls
- Manifest is deliberately malformed to crash analysis tools ([SoumniBot](../malware/families/soumnibot.md))
- Non-DEX frameworks (.NET MAUI) bypass traditional decompilers
- Payloads hidden in images via steganography ([Necro](../malware/families/necro.md))
- ZIP manipulation and `$JADXBLOCK` fields disable jadx decompilation ([GodFather](../malware/families/godfather.md) v3)
- Commercial packers (Virbox) virtualize DEX into proprietary VM instructions ([Klopatra](../malware/families/klopatra.md))

In these cases, move to [Dynamic Analysis](dynamic-analysis.md) and [Hooking](hooking.md).
