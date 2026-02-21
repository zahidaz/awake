# Static Analysis

Examining an APK without executing it. The first step in any Android reverse engineering workflow: extract the APK, read the manifest, decompile the code, and identify protections, permissions, and interesting code paths.

!!! tip "Start with triage, not deep analysis"
    Before spending hours in jadx, run the sample through VirusTotal, APKiD, and a quick manifest review. Five minutes of triage prevents hours of wasted effort on already-documented families or heavily [packed](../packers/index.md) samples that require [dynamic analysis](dynamic-analysis.md) instead.

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

!!! tip "Low detection does not mean clean"
    A detection ratio of 2/60 does not mean the sample is benign. Packed samples routinely score under 5 detections because engines scan the packer stub, not the payload. Always proceed with manual analysis regardless of the detection count.

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
```

!!! tip "Reassemble split APKs before analysis"
    Split APKs distribute code and resources across multiple files. Use `bundletool build-apks` to reassemble them into a single universal APK, or pull all splits and analyze them together. Missing splits can mean missing DEX files, native libraries, or resources that contain the malicious payload.

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

#### Manifest Analysis Checklist

Work through this checklist for every sample. Each item maps to a specific class of malicious behavior.

**Exported Components**

Search for `android:exported="true"` across all `<activity>`, `<service>`, `<receiver>`, and `<provider>` tags. Any exported component is callable by other apps on the device. Malware exports components intentionally to receive commands from dropper apps or companion packages.

```bash
grep -n 'exported="true"' output/AndroidManifest.xml
```

!!! tip "Intent filters imply exported"
    On Android 12+ (API 31), any component with an `<intent-filter>` is implicitly exported unless `exported="false"` is set explicitly. Check intent filters that accept external intents -- these are entry points an attacker or dropper can invoke.

**Dangerous Application Flags**

| Flag | Risk |
|------|------|
| `android:debuggable="true"` | Allows `adb` to attach a debugger, JDWP access, and runtime inspection. Legitimate release builds never set this. |
| `android:allowBackup="true"` | Allows `adb backup` to extract application data including shared preferences, databases, and internal files. Malware uses this to exfiltrate data. |
| `android:usesCleartextTraffic="true"` | Permits unencrypted HTTP connections. C2 traffic may use cleartext to avoid certificate issues, making network interception trivial. |

**Service Declarations with Dangerous Bindings**

These service bindings grant the app powerful device control capabilities. Their presence in malware is a strong indicator of specific attack techniques:

| Permission | What It Grants | Related Attack |
|------------|---------------|----------------|
| `BIND_ACCESSIBILITY_SERVICE` | Full screen reading, gesture injection, UI interaction | [Accessibility Abuse](../attacks/accessibility-abuse.md) |
| `BIND_DEVICE_ADMIN` | Lock screen, wipe device, enforce policies, prevent uninstall | [Device Admin Abuse](../attacks/device-admin-abuse.md) |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Read all notifications including OTP codes and banking alerts | [Notification Listener Abuse](../attacks/notification-listener-abuse.md) |

```bash
grep -n 'BIND_ACCESSIBILITY_SERVICE\|BIND_DEVICE_ADMIN\|BIND_NOTIFICATION_LISTENER' output/AndroidManifest.xml
```

**Permission Declaration vs Usage**

Compare `<uses-permission>` declarations against actual API usage in the decompiled code. Malware sometimes declares permissions it does not use in the initial stage -- these are reserved for dynamically loaded payloads. Conversely, missing permission declarations for APIs the code calls indicate the app expects to run with elevated privileges (system app or root).

??? example "Extracting permissions for comparison"
    ```bash
    grep '<uses-permission' output/AndroidManifest.xml | sed 's/.*android:name="//' | sed 's/".*//' | sort > declared_permissions.txt

    grep -rn 'android.permission.' output_java/ | grep -oP 'android\.permission\.\w+' | sort -u > used_permissions.txt

    diff declared_permissions.txt used_permissions.txt
    ```
    Permissions that appear only in `declared_permissions.txt` may be reserved for second-stage payloads loaded at runtime.

**High-Value Permission Combinations**

Individual permissions tell you capabilities. Combinations reveal intent:

| Permission Combination | Likely Purpose |
|------------------------|---------------|
| `RECEIVE_SMS` + `READ_SMS` + `INTERNET` | SMS interception and exfiltration (OTP theft) |
| `BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` | Overlay attack capability (credential harvesting) |
| `READ_CONTACTS` + `READ_CALL_LOG` + `READ_SMS` + `INTERNET` | Full communication data harvesting |
| `CAMERA` + `RECORD_AUDIO` + `ACCESS_FINE_LOCATION` | Surveillance/stalkerware profile |
| `REQUEST_INSTALL_PACKAGES` + `INTERNET` | Dropper/downloader behavior |
| `BIND_DEVICE_ADMIN` + `BIND_ACCESSIBILITY_SERVICE` | Device takeover -- lock screen, wipe, persistence |
| `READ_PHONE_STATE` + `READ_PHONE_NUMBERS` + `INTERNET` | Device fingerprinting and tracking |
| `QUERY_ALL_PACKAGES` | App enumeration -- overlay malware scans for banking targets |

**Custom Permission Definitions**

Apps can define their own permissions. Look for `<permission>` declarations:

```bash
grep -n '<permission ' output/AndroidManifest.xml
```

| What to Check | Risk |
|---------------|------|
| `android:protectionLevel="normal"` | Any app can request this permission -- no real protection |
| `android:protectionLevel="dangerous"` | Requires user approval but any app can request it |
| `android:protectionLevel="signature"` | Only apps signed with the same key can hold it -- strong if the key is not compromised |
| Missing `protectionLevel` | Defaults to `normal` -- effectively unprotected |

**Network Security Config**

If `android:networkSecurityConfig` is declared in the `<application>` tag, inspect `res/xml/network_security_config.xml`:

??? example "Network security config analysis"
    | Element | Significance |
    |---------|-------------|
    | `<domain>` entries | Whitelisted domains -- potential C2 infrastructure |
    | `cleartextTrafficPermitted="true"` on specific domains | These domains use HTTP -- trivial to intercept |
    | `<pin-set>` | Certificate pinning -- will need bypass for traffic interception |
    | `<certificates src="user" />` | Trusts user-installed CAs -- makes interception easier |
    | `<certificates src="system" />` only | Does not trust user CAs -- requires Frida or system-level bypass |

!!! tip "Quick manifest dump without apktool"
    When apktool fails on malformed manifests (common with [SoumniBot](../malware/families/soumnibot.md)-style obfuscation), use `aapt` or install the APK on an emulator and dump via `adb shell dumpsys package com.target.app`.

### 3. Decompilation

#### Decompiler Comparison

| Tool | Strengths | Weaknesses | Best For |
|------|-----------|------------|----------|
| [JADX](https://github.com/skylot/jadx) | Best overall decompiler. Handles most samples, good GUI with search and navigation, active development, free | Struggles with heavy obfuscation, can be defeated by `$JADXBLOCK` fields and malformed DEX | First-pass decompilation of any APK |
| [JEB Pro](https://www.pnfsoftware.com/) | Best for obfuscated code. Interactive deobfuscation, scripting API, handles anti-decompilation tricks | Commercial (expensive license), slower for large apps | Heavily obfuscated malware, samples that defeat JADX |
| [Ghidra](https://ghidra-sre.org/) | Free, excellent native code analysis, extensible with plugins (D-810 for OLLVM), multi-architecture | Steeper learning curve, DEX support is secondary to native | `.so` library analysis, native unpackers, OLLVM-obfuscated code |
| [IDA Pro](https://hex-rays.com/) | Industry-standard native disassembler, best pseudocode output, largest plugin ecosystem | Commercial (very expensive), DEX support requires plugins | Production-grade native reversing, Virbox VM interpreter analysis |
| [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) | Simultaneous view from multiple decompilers (Procyon, CFR, FernFlower, JADX), good for comparing output | Heavier resource usage, less polished UI | Cross-referencing decompiler output when one fails |
| [apktool](https://github.com/iBotPeaches/Apktool) | Accurate Smali disassembly, resource extraction, APK repackaging, preserves all code structure | Smali is harder to read than Java, no high-level decompilation | Patching, resource extraction, Smali-level analysis |

!!! tip "Use multiple decompilers"
    No single decompiler handles every sample perfectly. Start with JADX for readability. If classes are missing or show errors, try JEB Pro or Bytecode Viewer with Procyon/CFR. For [GodFather](../malware/families/godfather.md) v3 samples with `$JADXBLOCK` fields, CFR and Procyon ignore the blocking annotation entirely.

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

#### JADX Deep Dive

jadx is the primary decompilation tool for Android static analysis. Knowing its advanced features significantly accelerates analysis of both clean and obfuscated samples.

**CLI Options for Batch Analysis**

??? example "Useful jadx CLI flags"
    ```bash
    jadx base.apk -d output/ \
      --deobf \
      --deobf-min 3 \
      --deobf-max 64 \
      --show-bad-code \
      --threads-count 4 \
      --export-gradle
    ```

    | Flag | Purpose |
    |------|---------|
    | `--deobf` | Enable class/method/field renaming for obfuscated code |
    | `--deobf-min 3` | Minimum alias length for deobfuscation renames |
    | `--deobf-max 64` | Maximum alias length |
    | `--show-bad-code` | Output code even when decompilation partially fails -- better than empty stubs |
    | `--threads-count 4` | Parallel decompilation for large APKs |
    | `--export-gradle` | Export as a Gradle project importable into Android Studio or IntelliJ |

**Dealing with Obfuscated Code**

When code is obfuscated (short class names like `a.b.c`, encrypted strings, flattened control flow):

1. **Enable deobfuscation**: `--deobf` assigns readable aliases based on class hierarchy and usage patterns
2. **Rename as you go**: In JADX-GUI, right-click any class/method/field and rename it (`n` shortcut). JADX propagates the rename across all references
3. **Follow the entry points**: Start from manifest-declared components (activities, services, receivers) and trace inward rather than reading bottom-up
4. **Identify string decryption stubs**: Obfuscated apps typically have one or two methods that all encrypted strings pass through. Find that method, understand the algorithm, and you unlock all strings

!!! warning "Do not trust class names in obfuscated code"
    Obfuscators rename classes to `a`, `b`, `c` etc., but some malware intentionally names classes to mislead -- a class called `GooglePlayServices` or `SecurityUpdate` may contain the actual malicious payload. Always verify by reading the code, not the name.

**Exporting to IDE for Large-Scale Analysis**

For complex samples with hundreds of classes, export to a Gradle project and analyze in Android Studio or IntelliJ:

```bash
jadx base.apk --export-gradle -d output_gradle/
```

Open the `output_gradle/` directory as a project in Android Studio. This gives you:

- Full IDE search with regex support across all decompiled sources
- Call hierarchy navigation (find all callers of a method)
- Type hierarchy (understand class inheritance chains)
- Refactoring tools for bulk renaming obfuscated symbols
- Structural search and replace for pattern matching across classes

!!! tip "Gradle export is the best approach for large obfuscated samples"
    When a sample has 500+ classes with single-letter names, JADX-GUI's navigation becomes unwieldy. Android Studio's "Find Usages", "Call Hierarchy", and "Go to Implementation" features make tracing obfuscated call chains far more efficient than scrolling through JADX-GUI tabs.

**jadx Scripting for Automated Analysis**

jadx supports scripting plugins for automating repetitive tasks like bulk string decryption:

??? example "jadx script to find potential string decryption stubs"
    ```java
    import jadx.core.dex.nodes.ClassNode;
    import jadx.core.dex.nodes.MethodNode;

    getDecompiler().getClasses().forEach(cls -> {
        cls.getMethods().forEach(method -> {
            if (method.getReturnType().toString().equals("Ljava/lang/String;")
                && method.getName().length() <= 2
                && method.getMethodInfo().getArgumentsTypes().size() >= 1) {
                log.info("Potential decryption stub: " + cls.getFullName() + "." + method.getName());
            }
        });
    });
    ```

This approach is especially valuable for [DexGuard](../packers/dexguard.md)-protected samples where hundreds of string decryption calls need to be resolved.

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

??? example "Interpreting APKiD output"
    ```
    [+] APKiD 2.1.5 :: from RedNaga :: rednaga.io
    [*] base.apk!classes.dex
     |-> compiler : r8
     |-> obfuscator : ProGuard/R8
    [*] base.apk!lib/arm64-v8a/libvdog.so
     |-> packer : Virbox
     |-> anti_vm : Detects virtual environments
     |-> anti_debug : Checks for debugging
    ```
    In this example, the DEX itself uses R8 obfuscation, but the presence of `libvdog.so` identified as Virbox means the real code is virtualized. The DEX decompilation will show only a stub loader.

**Manual Native Library Identification**

When APKiD does not recognize the protection, inspect native libraries manually:

```bash
ls -la lib/arm64-v8a/
file lib/arm64-v8a/*.so
strings lib/arm64-v8a/*.so | head -50
```

Known marker libraries and what they indicate:

| Library File | Packer |
|-------------|--------|
| `libvdog.so`, `libvirbox*.so` | [Virbox](../packers/virbox.md) |
| `libshella.so`, `libshellx.so` | [Tencent Legu](../packers/tencent-legu.md) |
| `libjiagu*.so` | [Qihoo 360](../packers/qihoo-360-jiagu.md) |
| `libdexguard.so` | [DexGuard](../packers/dexguard.md) |
| `libdexprotector*.so`, `libdpboot.so` | [DexProtector](../packers/dexprotector.md) |
| `libsecexe.so`, `libSecShell.so` | [Bangcle](../packers/bangcle.md) |
| `libcovault-appsec.so` | [AppSealing](../packers/appsealing.md) |

!!! tip "What to do when you detect a packer"
    If the app is packed, static analysis of the DEX code shows only the packer stub. The real code is encrypted and only available at runtime. Follow the [Analysis Decision Tree](../packers/index.md#analysis-decision-tree) to select the right unpacking approach, then move to [Dynamic Analysis](dynamic-analysis.md) or packer-specific unpacking techniques documented on each [Packer](../packers/index.md) page.

Also check the [Development Frameworks](frameworks/index.md) page at this stage. If the APK contains `libflutter.so`, `.dll` assemblies, or `assets/www/`, the framework determines the entire analysis approach -- standard DEX decompilation will produce no useful output for these frameworks.

### 5. String Analysis

Strings reveal C2 URLs, API endpoints, encryption keys, and debug messages.

#### Quick Extraction

```bash
strings base.apk | grep -i "http"
strings base.apk | grep -i "api"
```

#### JADX Search Patterns

In JADX-GUI, use `Navigation > Text Search` (or `Ctrl+Shift+F`) to search across all decompiled sources. The following patterns target the most common indicators:

**C2 URLs and Network Infrastructure**

```
https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
```

```
/api/
/gate/
/panel/
/bot/
```

!!! tip "Search for URL construction patterns"
    Malware authors rarely hardcode full C2 URLs as single strings. Look for string concatenation patterns like `"htt" + "ps://" + domain` or `StringBuilder` chains that assemble URLs at runtime. In JADX, search for partial URL fragments: `://`, `.php`, `.jsp`, `/gate`, `/panel`, `/bot`.

**API Keys and Credentials**

```
[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]
[Ss][Ee][Cc][Rr][Ee][Tt]
[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]
AIza
AKIA
```

**Target App Package Names (Overlay Malware)**

```
com.android.vending
com.google.android.gms
com.whatsapp
```

Banking trojans that perform [overlay attacks](../attacks/overlay-attacks.md) contain lists of targeted banking app package names. Search for arrays of strings matching the `com.` pattern.

**Cryptographic Constants**

```
AES
DES
RSA
Cipher.getInstance
SecretKeySpec
```

#### Encrypted String Identification

When strings are not readable in the decompiled output, the app likely uses string encryption. Common patterns to identify:

**Base64-Wrapped Encrypted Strings**

Look for long Base64 strings passed to decryption methods:

```java
String v0 = a.b.c.decrypt("dGhpcyBpcyBhIGJhc2U2NCBleGFtcGxl");
```

Search for `Base64.decode` calls combined with `Cipher` or custom decryption methods.

**Byte Array Initialization**

Encrypted strings often appear as byte arrays in the decompiled code:

```java
byte[] v0 = new byte[]{104, 116, 116, 112, 115, 58, 47, 47};
```

These are straightforward to decode. Convert the decimal values to ASCII.

??? example "Bulk decoding byte arrays with CyberChef"
    Copy the byte values and paste into [CyberChef](https://gchq.github.io/CyberChef/) with the "From Decimal" recipe. For hex arrays (`0x68, 0x74, 0x74, 0x70`), use "From Hex" instead.

**DexGuard String Encryption Pattern**

[DexGuard](../packers/dexguard.md)-protected apps have a recognizable pattern: single-character class names (`o`, `oo`, `ooo`) containing static methods that accept an `int` parameter and return a `String`. Every encrypted string in the app routes through one of these decryption stubs.

```java
String url = oo.o(1247);
String key = oo.o(1248);
```

!!! tip "Automating string decryption"
    For [Antidot](../malware/families/antidot.md), DexGuard, and similar encryption schemes, write a Frida script that hooks the decryption method and logs every call with its return value. This bulk-decrypts all strings at runtime without reversing the algorithm. See [Hooking](hooking.md) for Frida string interception patterns.

#### Grep Patterns for Bulk IoC Extraction

These patterns work against decompiled jadx output or `strings` output from the raw APK. Run them against the jadx output directory for best coverage.

??? example "URL, IP, and network infrastructure"
    ```bash
    grep -rEo 'https?://[a-zA-Z0-9./?=_&%-]+' output_java/

    grep -rEo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' output_java/

    grep -rEo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}' output_java/

    grep -rEi '(telegram\.org/bot|api\.telegram|t\.me/)' output_java/

    grep -rEi '\.(onion|bit|coin|lib|emc)' output_java/

    grep -rEi '(pastebin\.com|hastebin|ghostbin|rentry)' output_java/

    grep -rEi '(firebase|firebaseio\.com|googleapis\.com)' output_java/

    grep -rEi '(ngrok\.io|serveo\.net|localtunnel)' output_java/
    ```

??? example "API keys, secrets, and credentials"
    ```bash
    grep -rEi '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret)' output_java/

    grep -rEi '(password|passwd|pwd)\s*=' output_java/

    grep -rEo 'AIza[0-9A-Za-z_-]{35}' output_java/

    grep -rEo 'AKIA[0-9A-Z]{16}' output_java/

    grep -rEo 'ghp_[0-9a-zA-Z]{36}' output_java/
    ```

??? example "Crypto constants and encoded data"
    ```bash
    grep -rEi '(SecretKeySpec|Cipher\.getInstance|MessageDigest)' output_java/

    grep -rEo '"[A-Za-z0-9+/]{40,}={0,2}"' output_java/

    grep -rEi 'BEGIN (RSA |EC )?(PRIVATE|PUBLIC) KEY' output_java/
    ```

??? example "Target app package names (overlay malware)"
    ```bash
    grep -rEo 'com\.[a-z]+\.[a-z.]+' output_java/ | sort -u | head -100

    grep -rEi '(chase|wellsfargo|bankofamerica|citibank|paypal|venmo|cashapp|coinbase|binance|metamask)' output_java/
    ```

[APKLeaks](https://github.com/dwisiswant0/apkleaks) automates much of this extraction:

```bash
apkleaks -f base.apk
```

### 6. Resource Analysis

Resources (`res/`) can contain:

| Resource | Contains |
|----------|----------|
| `res/xml/` | Network security config, accessibility config, file provider paths |
| `res/raw/` | Embedded files, encrypted payloads, configuration |
| `assets/` | Native libraries, packed DEX files, web content for overlays |
| `res/values/strings.xml` | Hardcoded strings, sometimes sensitive |

The network security config (`res/xml/network_security_config.xml`) reveals certificate pinning configuration and trusted CAs.

!!! tip "Check assets for encrypted payloads"
    The `assets/` directory is the most common location for encrypted second-stage payloads. Look for files with high entropy, no recognizable file headers, or unusual extensions (`.dat`, `.bin`, `.enc`). Run `file` on every asset to identify embedded DEX, ELF, or ZIP files that the packer renamed.

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

!!! tip "Check JNI_OnLoad first"
    When analyzing native libraries, start with `JNI_OnLoad` -- this is called when the library loads and is where most malware registers its native methods dynamically. If native methods are registered via `RegisterNatives` rather than following the standard JNI naming convention, you need to trace the registration table to map Java method names to native function pointers.

??? example "Listing exported JNI functions"
    ```bash
    readelf -Ws lib/arm64-v8a/libnative.so | grep -i java
    nm -D lib/arm64-v8a/libnative.so | grep -i java
    ```
    If these commands return nothing, the library uses dynamic registration via `RegisterNatives` in `JNI_OnLoad`. Load it in Ghidra and search for cross-references to `RegisterNatives`.

## Family-Specific Static Analysis Notes

Different malware families present unique static analysis challenges. The table below maps families to their specific obstacles and recommended approaches:

| Family | Challenge | Approach |
|--------|-----------|----------|
| [FluHorse](../malware/families/fluhorse.md) | Business logic compiled as Dart AOT snapshot in `libapp.so`, not in DEX | Use [Blutter](https://github.com/worawit/blutter) or [reFlutter](https://github.com/Impact-I/reFlutter) to analyze Dart snapshots. Standard DEX decompilers show only a thin Kotlin wrapper. |
| [SoumniBot](../malware/families/soumnibot.md) | Manifest obfuscation crashes jadx and apktool | Use Android OS itself as the parser (install on emulator, dump manifest via `adb shell dumpsys package`). Or patch the malformed ZIP entries manually. |
| [GodFather](../malware/families/godfather.md) v3 | `$JADXBLOCK` fields in class files + ZIP manipulation | Remove `$JADXBLOCK` annotations from DEX before feeding to jadx. Use alternative decompilers (Procyon, CFR) that may not honor this field. |
| [Mandrake](../malware/families/mandrake.md) | OLLVM-obfuscated native libraries | Use [D-810](https://github.com/joydo/d810) Ghidra plugin for OLLVM deobfuscation. Pair with [Frida Stalker](hooking.md) for runtime instruction tracing. |
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
| [Blutter](https://github.com/worawit/blutter) | Dart AOT snapshot analyzer. Extracts class/method names and rebuilds Dart source from `libapp.so`. |
| [reFlutter](https://github.com/Impact-I/reFlutter) | Framework re-patching tool. Patches `libflutter.so` to enable SSL traffic interception and snapshot analysis. |
| [Doldrums](https://github.com/rscloura/Doldrums) | Dart AOT snapshot parser for older Dart versions. |

The workflow: extract `libapp.so` from the APK, determine the Dart SDK version from `libflutter.so`, then use Blutter to parse the snapshot and recover function signatures and string references. [Fortinet published a detailed static reversing methodology](https://www.fortinet.com/blog/threat-research/fortinet-reverses-flutter-based-android-malware-fluhorse) at Virus Bulletin 2024.

See [Development Frameworks](frameworks/index.md) for the full Flutter analysis methodology, other cross-platform framework identification, and framework-specific hooking strategies.

## YARA Rules for Android Malware

[YARA](https://virustotal.github.io/yara/) rules enable automated detection and classification of Android malware during static triage. Write rules that match structural patterns, string constants, and byte sequences unique to malware families or behaviors.

### Writing Effective Android YARA Rules

Android-specific considerations:

| Consideration | Details |
|---------------|---------|
| APK is a ZIP archive | YARA scans the raw ZIP bytes -- strings inside compressed entries may not match. Scan the unpacked APK directory or individual DEX files instead. |
| DEX file format | Target `classes.dex` directly. DEX header magic is `dex\n035\0` (or `036`, `037`, `038` for newer versions). |
| Multi-DEX | Large apps split code across `classes.dex`, `classes2.dex`, etc. Scan all DEX files. |
| Packed samples | YARA sees the packer stub, not the payload. Rules for packed malware should target packer signatures, not payload behavior. For packer identification patterns, see [Packers](../packers/index.md). |

### Rule Examples

??? example "Banking trojan detection rule"
    ```
    rule Android_BankingTrojan_Generic
    {
        meta:
            description = "Detects common Android banking trojan patterns"
            author = "AWAKE"
            date = "2025-01-01"
            target = "Android DEX"

        strings:
            $dex_magic = "dex\n03"

            $accessibility = "android/accessibilityservice/AccessibilityService"
            $overlay = "SYSTEM_ALERT_WINDOW"
            $sms_read = "android.permission.READ_SMS"
            $sms_receive = "android.permission.RECEIVE_SMS"

            $keylog = "AccessibilityEvent" ascii
            $inject = "webView" ascii nocase
            $screen_capture = "MediaProjection" ascii

            $target_chase = "com.chase.sig.android" ascii
            $target_boa = "com.infonow.bofa" ascii
            $target_wells = "com.wf.wellsfargomobile" ascii
            $target_paypal = "com.paypal.android.p2pmobile" ascii
            $target_coinbase = "com.coinbase.android" ascii

        condition:
            $dex_magic at 0 and
            $accessibility and
            ($overlay or ($sms_read and $sms_receive)) and
            any of ($keylog, $inject, $screen_capture) and
            2 of ($target_*)
    }
    ```

??? example "Dropper/loader detection rule"
    ```
    rule Android_Dropper_DynamicLoading
    {
        meta:
            description = "Detects Android droppers using dynamic DEX loading"
            author = "AWAKE"
            date = "2025-01-01"

        strings:
            $dex_magic = "dex\n03"

            $dexloader1 = "DexClassLoader" ascii
            $dexloader2 = "InMemoryDexClassLoader" ascii
            $dexloader3 = "PathClassLoader" ascii

            $crypto1 = "AES" ascii
            $crypto2 = "SecretKeySpec" ascii
            $crypto3 = "Cipher" ascii

            $reflect1 = "java/lang/reflect/Method" ascii
            $reflect2 = "getDeclaredMethod" ascii
            $reflect3 = "setAccessible" ascii

            $download1 = "URLConnection" ascii
            $download2 = "HttpURLConnection" ascii
            $download3 = "OkHttpClient" ascii

        condition:
            $dex_magic at 0 and
            any of ($dexloader*) and
            2 of ($crypto*) and
            any of ($reflect*) and
            any of ($download*)
    }
    ```

??? example "Packer identification rules"
    ```
    rule Android_Packer_Virbox
    {
        meta:
            description = "Identifies Virbox-packed Android samples"
            author = "AWAKE"

        strings:
            $virbox1 = "libvdog.so" ascii
            $virbox2 = "libvirbox" ascii
            $virbox3 = "senseShield" ascii nocase
            $virbox4 = "vboxjni" ascii

        condition:
            any of them
    }

    rule Android_Packer_TencentLegu
    {
        meta:
            description = "Identifies Tencent Legu-packed Android samples"
            author = "AWAKE"

        strings:
            $legu1 = "libshella.so" ascii
            $legu2 = "libshellx.so" ascii
            $legu3 = "com.tencent.StubShell" ascii
            $legu4 = "tencent_stub" ascii

        condition:
            any of them
    }

    rule Android_Packer_DexGuard
    {
        meta:
            description = "Identifies DexGuard-protected Android samples"
            author = "AWAKE"

        strings:
            $dg1 = "libdexguard.so" ascii
            $dg2 = "dexguard" ascii nocase
            $dg3 = "guardsquare" ascii nocase

        condition:
            any of them
    }
    ```

### Scanning Workflow

```bash
mkdir -p /tmp/yara_scan
unzip -o /path/to/base.apk -d /tmp/yara_scan/unpacked/
yara -r /path/to/android_rules.yar /tmp/yara_scan/unpacked/
```

!!! tip "Scan DEX files directly for best results"
    Scanning the raw APK (ZIP) misses strings inside compressed entries. Always unzip first and scan the extracted `classes*.dex` files and other assets individually.

For bulk scanning across a sample corpus:

```bash
find /malware/samples/ -name "classes*.dex" -exec yara /path/to/rules.yar {} \;
```

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
| [YARA](https://virustotal.github.io/yara/) | Pattern matching for malware classification and IoC detection |

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

!!! danger "Know when to stop"
    Recognize when static analysis is hitting a wall. Spending hours fighting a packer or obfuscator statically is almost always less efficient than switching to [dynamic analysis](dynamic-analysis.md) and dumping the decrypted code at runtime.

Static analysis fails when:

- The app is packed (encrypted DEX, loaded at runtime) -- see [Packers](../packers/index.md) for identification and unpacking
- Heavy obfuscation (ProGuard, R8, DexGuard, Allatori) makes code unreadable
- Native code handles critical logic
- Code is downloaded from C2 after installation
- Reflection is used to hide API calls
- Manifest is deliberately malformed to crash analysis tools ([SoumniBot](../malware/families/soumnibot.md))
- Non-DEX frameworks (.NET MAUI, Flutter, Xamarin) bypass traditional decompilers -- see [Development Frameworks](frameworks/index.md) for framework-specific toolchains
- Payloads hidden in images via steganography ([Necro](../malware/families/necro.md))
- ZIP manipulation and `$JADXBLOCK` fields disable jadx decompilation ([GodFather](../malware/families/godfather.md) v3)
- Commercial packers (Virbox) virtualize DEX into proprietary VM instructions ([Klopatra](../malware/families/klopatra.md))

!!! tip "Static analysis is a starting point, not the destination"
    Even when static analysis is blocked by packing or obfuscation, it still provides value. The manifest, resource files, native library names, and APKiD results all inform your dynamic analysis strategy. Spend 15-20 minutes on static triage before switching to runtime approaches -- it saves time by telling you exactly what to hook and where to look.

In these cases, move to [Dynamic Analysis](dynamic-analysis.md) and [Hooking](hooking.md).
