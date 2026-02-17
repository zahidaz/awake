# Anti-Analysis Techniques

Detecting and evading analysis environments, security tools, and human researchers. Nearly every modern Android banking trojan implements multiple layers of anti-analysis checks before executing any malicious behavior. The goal is simple: if the malware suspects it is being analyzed, it does nothing, resulting in a clean verdict from automated sandboxes and wasted hours for manual analysts.

See also: [Play Store Evasion](play-store-evasion.md), [Dynamic Code Loading](dynamic-code-loading.md), [Persistence Techniques](persistence-techniques.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1633](https://attack.mitre.org/techniques/T1633/) | Virtualization/Sandbox Evasion | Defense Evasion |
    | [T1633.001](https://attack.mitre.org/techniques/T1633/001/) | System Checks | Defense Evasion |
    | [T1627](https://attack.mitre.org/techniques/T1627/) | Execution Guardrails | Defense Evasion |
    | [T1627.001](https://attack.mitre.org/techniques/T1627/001/) | Geofencing | Defense Evasion |
    | [T1406](https://attack.mitre.org/techniques/T1406/) | Obfuscated Files or Information | Defense Evasion |
    | [T1628](https://attack.mitre.org/techniques/T1628/) | Hide Artifacts | Defense Evasion |
    | [T1630](https://attack.mitre.org/techniques/T1630/) | Indicator Removal on Host | Defense Evasion |
    | [T1629](https://attack.mitre.org/techniques/T1629/) | Impair Defenses | Defense Evasion |

    T1633 covers emulator/sandbox detection via build properties, telephony, sensors, and filesystem artifacts. T1627 covers execution guardrails including geofencing, delayed activation, and SIM checks. T1406 covers string encryption, packing, and code obfuscation. T1628/T1630 cover hiding the app icon, clearing logs, and removing forensic artifacts. T1629 covers disabling Play Protect and security tools.

## Emulator Detection

The most common first check. Emulators expose artifacts through build properties, hardware fingerprinting, telephony state, and sensor data that differ from physical devices.

### Build Property Checks

```java
private boolean isEmulator() {
    return Build.FINGERPRINT.contains("generic")
        || Build.MODEL.contains("google_sdk")
        || Build.MODEL.contains("Emulator")
        || Build.MODEL.contains("Android SDK built for x86")
        || Build.MANUFACTURER.contains("Genymotion")
        || Build.HARDWARE.contains("goldfish")
        || Build.HARDWARE.contains("ranchu")
        || Build.PRODUCT.contains("sdk_gphone")
        || Build.BOARD.contains("unknown")
        || Build.HOST.startsWith("Build");
}
```

Families like [Cerberus](../malware/families/cerberus.md), [Anatsa](../malware/families/anatsa.md), and [Hook](../malware/families/hook.md) check 10-20+ build properties. The check is trivial to implement but also trivial to bypass via Frida property spoofing on a physical device.

### Telephony Checks

| Check | Emulator Value | Real Device Value |
|-------|---------------|-------------------|
| `getDeviceId()` | `000000000000000` or null | Valid IMEI |
| `getSimSerialNumber()` | Empty or `89014103211118510720` | Valid ICCID |
| `getNetworkOperatorName()` | `Android` or empty | Carrier name |
| `getSimOperator()` | Empty | MCC+MNC code |
| `getLine1Number()` | `15555215554` (emulator default) | Real number or empty |
| `getSubscriberId()` | Empty | Valid IMSI |

### File System Artifacts

```java
private boolean checkEmulatorFiles() {
    String[] knownPaths = {
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/goldfish_pipe"
    };
    for (String path : knownPaths) {
        if (new File(path).exists()) return true;
    }
    return false;
}
```

### Sensor-Based Detection

[Trend Micro documented](https://www.trendmicro.com/en_us/research.html) malware using motion sensor data to distinguish real phones from emulators. BatterySaverMobi and Currency Converter (discovered on Play Store) checked accelerometer readings -- emulators return static or zero values because they don't simulate physical motion. The malware only activated its dropper payload after detecting non-zero accelerometer variance over time.

[SpinOk](../malware/families/spinok.md) SDK used gyroscope and magnetometer data as anti-emulation checks before activating its data harvesting across 193 apps with 451 million downloads.

### Hardware Property Checks

| Property | Emulator | Physical |
|----------|----------|----------|
| `BOARD` | `unknown`, `goldfish` | Device-specific |
| `BOOTLOADER` | `unknown` | Version string |
| `DEVICE` | `generic`, `generic_x86` | Device codename |
| `HARDWARE` | `goldfish`, `ranchu` | `qcom`, `exynos`, etc. |
| CPU ABI | `x86`, `x86_64` (common in AVDs) | `arm64-v8a` (most real devices) |
| Battery temperature | Static (usually 0) | Varies with use |
| Battery status | Always `CHARGING` | Varies |

## Root and Magisk Detection

Banking trojans detect rooted devices for two reasons: to avoid analysis environments (analysts use rooted devices), and to determine available exploitation paths.

### Common Root Checks

```java
private boolean isRooted() {
    String[] paths = {
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su"
    };
    for (String path : paths) {
        if (new File(path).exists()) return true;
    }
    try {
        Runtime.getRuntime().exec("su");
        return true;
    } catch (IOException e) {
        return false;
    }
    return false;
}
```

### Magisk Detection

| Technique | What It Detects | Bypass |
|-----------|----------------|--------|
| Check for `/sbin/.magisk`, `/data/adb/magisk` | Magisk installation directory | MagiskHide / Shamiko |
| Mount namespace inspection (`/proc/self/mounts`) | Magisk mount overlays | DenyList + Shamiko |
| Check `ro.boot.vbmeta.device_state` | Unlocked bootloader | Cannot spoof without re-locking |
| `PackageManager.getInstalledPackages()` for `com.topjohnwu.magisk` | Magisk Manager app | Randomize package name (built-in Magisk feature) |
| SELinux status (`getenforce`) | Permissive mode (common on rooted) | Enforce mode on properly configured root |

### SafetyNet / Play Integrity

Some malware checks [Play Integrity](../platform-abuse/play-integrity.md) attestation before executing, refusing to operate on devices that fail hardware attestation. This is unusual (most malware avoids Google APIs) but has been observed in families that want to ensure they are running on a real, unmodified device to maximize fraud success.

## Hooking Framework Detection

Hooking frameworks let analysts (and attackers) intercept function calls at runtime. Detecting them is a priority for both malware resisting analysis and protectors defending banking apps. The detection landscape has evolved significantly: early approaches targeted specific frameworks by name, while modern protectors use generic techniques that catch any inline hook regardless of the framework that placed it.

### Evolution

| Phase | Era | Approach | What It Catches |
|-------|-----|----------|----------------|
| 1 | 2017-2020 | Framework-specific signatures | Frida by name (`frida-agent` strings, port 27042, process name) |
| 2 | 2020-2022 | Evasion tools emerge | Renamed Frida binaries, Gadget injection, ZygiskFrida bypass phase-1 checks |
| 3 | 2022-present | Generic inline hook detection | Any framework: Frida, Dobby, ShadowHook, ByteHook, custom hooks |

The shift from phase 1 to phase 3 is the most important trend. Protectors that only check for `frida-agent` strings are trivially bypassed. Protectors that verify function prologue integrity catch everything.

### Hooking Frameworks

| Framework | Type | Footprint | Where It Shows Up |
|-----------|------|-----------|-------------------|
| [Frida](https://frida.re/) | Full instrumentation runtime | Heavy (JS engine, server process, agent library) | Primary RE tool, automated analysis pipelines |
| [Dobby](https://github.com/jmpews/Dobby) | Native inline hooking library | Minimal (~300 KB .so, no server, no ports) | Zygisk modules (PlayIntegrityFix, root hiding), game mods, malware |
| [ShadowHook](https://github.com/bytedance/android-inline-hook) | Native inline hooking (ByteDance) | Minimal | ByteDance apps internally, open-source adoption growing |
| [ByteHook](https://github.com/bytedance/bhook) | PLT/GOT hooking (ByteDance) | Minimal | PLT-level interception, less invasive than inline |
| [LSPlant](https://github.com/LSPosed/LSPlant) | ART Java method hooking | Minimal | LSPosed framework, Xposed module ecosystem |
| [Pine](https://github.com/canyie/pine) | ART Java method hooking | Minimal | Alternative to LSPlant for Java-level hooks |

Frida's detection surface is large: a server process, a full JavaScript runtime injected as a shared library, network ports, and characteristic strings in memory. Dobby and similar lightweight frameworks trade flexibility for stealth -- they compile as a small native library with no server, no JS engine, and no characteristic strings. The analyst controls the .so name. The only artifacts are modified function prologues and allocated trampoline memory pages.

### Frida-Specific Detection

| Technique | Implementation | Reliability |
|-----------|---------------|-------------|
| Default port scan | Connect to `localhost:27042` (frida-server default) | Low (easily changed) |
| `/proc/self/maps` scan | Search memory mappings for `frida-agent`, `frida-gadget` | Medium (bypassed by renaming) |
| Process enumeration | List running processes for `frida-server`, `frida-helper` | Medium (bypassed by renaming) |
| Named pipe detection | Check `/proc/self/fd/` for `linjector` pipes | Medium |
| `pthread` enumeration | Scan thread names for Frida-related strings (`gmain`, `gdbus`) | Medium-High |
| Library detection | Enumerate loaded libraries for Frida agent patterns | Medium |

These signature-based checks are the easiest to bypass: rename the binary, change the port, use [ZygiskFrida](https://github.com/lico-n/ZygiskFrida) to inject Frida Gadget via Zygisk instead of running a server. Patch `/proc/self/maps` reads via Frida itself to filter out Frida strings. [Shamiko](https://github.com/LSPosed/LSPosed.github.io) hides root and Frida artifacts from DenyList processes.

### Xposed / LSPosed Detection

| Technique | What It Detects |
|-----------|----------------|
| Stack trace inspection | `de.robv.android.xposed` in call stack |
| Class check | `XposedBridge` class loadable via reflection |
| `/proc/self/maps` | `XposedBridge.jar` mapped into process |
| Exception handler check | Xposed hooks modify exception handling chain |
| ART method structure | LSPlant modifies ART internal method structures; integrity checks on `ArtMethod` fields detect this |

[LSPosed](https://github.com/LSPosed/LSPosed) operates through Zygisk, making traditional Xposed detection (class names, JAR in maps) ineffective. Detection now requires checking ART internals for method structure modifications.

### Generic Inline Hook Detection

These techniques catch any framework that modifies native function code in memory, regardless of name or origin. This is where the arms race currently sits.

**Prologue integrity checking**: The protector stores hashes of the first 16-32 bytes of critical functions at initialization. Periodically (or before sensitive operations), it re-reads those bytes and compares. Any inline hook overwrites the prologue with a branch instruction, breaking the hash. This is the most reliable detection method.

```c
uint8_t expected_prologue[16] = { /* stored at build/init time */ };
uint8_t current_prologue[16];
memcpy(current_prologue, (void*)target_function, 16);
if (memcmp(expected_prologue, current_prologue, 16) != 0) {
    // Function has been hooked
}
```

**Anonymous executable memory scanning**: Inline hooking frameworks allocate executable memory pages for trampolines. These appear in `/proc/self/maps` as anonymous regions with execute permission (`r-xp` with no backing file). Normal processes have very few anonymous executable pages. A protector scanning for these can detect Dobby, Frida Interceptor, ShadowHook, and any other inline hook framework.

**Instruction pattern detection**: On ARM64, a Dobby hook replaces the function prologue with `LDR Xn, [PC, #offset]` followed by `BR Xn` (load absolute address, branch to it). Frida's Interceptor uses a similar pattern. Scanning function entry points for these characteristic instruction sequences detects hooks without knowing which framework placed them.

**`.text` section integrity**: Compare the in-memory `.text` section of loaded libraries against the on-disk copy. Any byte difference indicates patching. More expensive than prologue checking but catches hooks placed anywhere in a function, not just the entry point.

**Timing analysis**: A hooked function traverses the trampoline (relocated original instructions, jump back), adding nanoseconds of latency. Tight timing loops around sensitive functions can reveal the overhead, though this is noisy in practice.

### How Protectors Implement Detection

| Protector | Detection Approach |
|-----------|--------------------|
| [Promon SHIELD](../packers/promon.md) | RASP-focused. Runtime integrity checks on critical functions, environment fingerprinting. Primarily behavioral detection rather than signature scanning. |
| [Arxan (Digital.ai)](../packers/arxan.md) | Guard network: dozens of native guard functions that verify each other's integrity in a mesh. Hooking one guard triggers detection by others. Prologue integrity is checked across the guard network. |
| [LIAPP](../packers/liapp.md) | Aggressive multi-layer: Frida-specific signature checks, Magisk-aware root detection, and native function integrity verification. Server-side token validation adds a layer that client-side hooks cannot bypass. |
| [Appdome](../packers/appdome.md) | [Multi-vector framework detection](https://www.appdome.com/how-to/mobile-malware-prevention/android-malware-detection/detect-hooking-frameworks/): signature scanning for known frameworks, generic inline hook detection, memory map analysis. Covers Frida, Xposed, Dobby, and custom hooks. |
| [DexProtector](../packers/dexprotector.md) | Native bridge with integrity checks. Anti-Frida and anti-debug at the native layer. White-box crypto module (vTEE) adds cryptographic verification that hooks cannot fake without the key material. |

### Bypass Strategies

| Detection Type | Bypass Approach |
|----------------|-----------------|
| Frida-specific signatures | Rename binaries, change ports, use ZygiskFrida or Frida Gadget |
| `/proc/self/maps` scanning | Hook `fopen`/`fgets` to filter results, or use kernel-level hiding (Shamiko) |
| Prologue integrity | Frida Stalker (copies and instruments code blocks without modifying originals) |
| Anonymous RWX pages | Allocate trampolines in existing RX regions or use code-cave injection |
| `.text` integrity | Kernel-level hooking below the protector's visibility |
| Guard networks (Arxan) | Identify and patch all guards simultaneously, or hook the integrity check function itself |
| Timing analysis | Minimize trampoline overhead, add compensating delays |

The current state of the art: protectors layer multiple detection types so that bypassing one doesn't disable all. Analysts counter by combining Zygisk-based injection (avoids process-level artifacts), Frida Stalker (avoids prologue modification), and Shamiko (hides root and maps entries). Neither side has a decisive advantage.

## Debugger Detection

```java
private boolean isDebugged() {
    if (Debug.isDebuggerConnected()) return true;
    if (Debug.waitingForDebugger()) return true;

    try {
        BufferedReader reader = new BufferedReader(
            new FileReader("/proc/self/status"));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith("TracerPid:")) {
                int pid = Integer.parseInt(line.substring(10).trim());
                if (pid != 0) return true;
            }
        }
    } catch (Exception ignored) {}

    return false;
}
```

### Timing-Based Detection

Malware measures execution time of code blocks. Under a debugger or instrumentation framework, execution is significantly slower. [MITRE ATT&CK T1497.003](https://attack.mitre.org/techniques/T1497/003/) documents this as "Time Based Evasion."

```java
long start = SystemClock.uptimeMillis();
performDecoyComputation();
long elapsed = SystemClock.uptimeMillis() - start;
if (elapsed > THRESHOLD) {
    // Likely under instrumentation
}
```

## AV and Security App Detection

Malware checks for installed security apps to decide whether to activate. Some families disable Play Protect via [accessibility](accessibility-abuse.md) before proceeding.

### Package Name Checks

```java
private boolean hasSecurityApp() {
    String[] avPackages = {
        "com.avast.android.mobilesecurity",
        "com.eset.ems2.gp",
        "com.kaspersky.security.cloud",
        "com.bitdefender.security",
        "org.malwarebytes.antimalware",
        "com.symantec.mobilesecurity",
        "com.lookout",
        "com.zimperium.zips",
        "com.trendmicro.tmmspersonal",
        "com.drweb.pro"
    };
    PackageManager pm = getPackageManager();
    for (String pkg : avPackages) {
        try {
            pm.getPackageInfo(pkg, 0);
            return true;
        } catch (NameNotFoundException ignored) {}
    }
    return false;
}
```

### Play Protect Suppression

Multiple families use accessibility to disable Google Play Protect:

1. Open `Settings > Security > Google Play Protect`
2. Click the gear icon
3. Disable "Scan apps with Play Protect"
4. Confirm the dialog

[Anatsa](../malware/families/anatsa.md), [Cerberus](../malware/families/cerberus.md), [Hook](../malware/families/hook.md), and [Xenomorph](../malware/families/xenomorph.md) all implement this flow. See [Notification Suppression](notification-suppression.md) for how malware also suppresses Play Protect warnings.

## Geographic and Locale Checks

Malware avoids executing in researcher-common locales or countries where the operator has no targets. Covered in depth in [Play Store Evasion](play-store-evasion.md#geographic-targeting).

| Check | API | Spoofing Difficulty |
|-------|-----|-------------------|
| SIM country | `TelephonyManager.getSimCountryIso()` | High (requires physical SIM) |
| Network country | `TelephonyManager.getNetworkCountryIso()` | High (VPN doesn't change this) |
| IP geolocation | Server-side check | Medium (VPN changes IP) |
| System locale | `Locale.getDefault()` | Low (Settings change) |
| Timezone | `TimeZone.getDefault()` | Low (Settings change) |

[Anatsa](../malware/families/anatsa.md) campaigns specifically avoid Eastern European and Chinese IP ranges. [Mandrake](../malware/families/mandrake.md) used C2-side geofencing to avoid delivering payloads to non-target regions entirely.

## APK and Manifest Corruption

### Malformed ZIP Headers

[TrickMo](../malware/families/trickmo.md) uses malformed ZIP files combined with JSONPacker. The corrupted ZIP structure causes analysis tools (apktool, JADX, unzip) to fail or produce incomplete output, while the Android runtime tolerates the malformations and installs the APK normally. [Cleafy documented](https://www.cleafy.com/cleafy-labs/a-new-trickmo-saga-from-banking-trojan-to-victims-data-leak) this as a deliberate anti-analysis layer across 40+ variants.

### Manifest Corruption

[SoumniBot](../malware/families/soumnibot.md) injects malformed compression parameters into `AndroidManifest.xml`. Android's parser tolerates the corruption; analysis tools crash. [Kaspersky documented three specific techniques](https://securelist.com/soumnibot-android-trojan-evades-analysis/112296/): invalid compression method values, invalid manifest size declarations, and oversized namespace strings.

### Oversized DEX Headers

Some families pad DEX files with junk data that exceeds parser buffer sizes in analysis tools but is safely ignored by ART.

## Code-Level Obfuscation

| Technique | Effect | Families |
|-----------|--------|----------|
| String encryption | C2 URLs, package names encrypted at rest, decrypted at runtime | [Anatsa](../malware/families/anatsa.md) (DES), [Mandrake](../malware/families/mandrake.md), most families |
| Reflection-based API calls | Method names resolved via strings at runtime, invisible to static analysis | [Octo](../malware/families/octo.md), [Xenomorph](../malware/families/xenomorph.md) |
| Native code for sensitive ops | Key operations in `.so` libraries, harder to decompile | [Mandrake](../malware/families/mandrake.md) (OLLVM), [Octo2](../malware/families/octo.md) |
| Control flow flattening | Switch-based dispatch obscures actual execution order | Commercial packers, [DexGuard](../packers/dexguard.md) |
| Dead code injection | Junk methods/classes inflate the codebase | [Joker](../malware/families/joker.md), crypter outputs |
| Class/method renaming | `a.b.c.d()` instead of meaningful names | Nearly universal (ProGuard/R8 baseline) |
| Dynamic class loading | Payload classes loaded from encrypted assets or C2 at runtime | [Anatsa](../malware/families/anatsa.md), [Necro](../malware/families/necro.md), [SharkBot](../malware/families/sharkbot.md) |

### Domain Generation Algorithms

[Octo2](../malware/families/octo.md) introduced DGA-based C2 resolution, generating domain names algorithmically so that blocking individual domains is ineffective. The DGA seed and algorithm are embedded in a dynamically loaded native library, adding another analysis layer.

## Families by Anti-Analysis Depth

| Family | Emulator | Root/Magisk | Frida | Debugger | AV Check | Geo | Obfuscation |
|--------|:--------:|:-----------:|:-----:|:--------:|:--------:|:---:|:-----------:|
| [Anatsa](../malware/families/anatsa.md) | Yes | Yes | Yes | Yes | Yes | Yes | DES strings, native loader |
| [Mandrake](../malware/families/mandrake.md) | Yes | Yes | Yes | Yes | Yes | Yes | OLLVM native, multi-year dormancy |
| [Octo/Octo2](../malware/families/octo.md) | Yes | Yes | Yes | Yes | Yes | Yes | DGA, native library decryption |
| [Hook](../malware/families/hook.md) | Yes | Yes | Yes | Yes | Yes | Yes | Inherited from ERMAC lineage |
| [TrickMo](../malware/families/trickmo.md) | Yes | Minimal | No | No | Yes | Yes | Malformed ZIP, JSONPacker |
| [Cerberus](../malware/families/cerberus.md) | Yes | Yes | Yes | Yes | Yes | Yes | Play Protect disable |
| [SpyNote](../malware/families/spynote.md) | Yes | Yes | Yes | Yes | Yes | Minimal | Restricted settings bypass |
| [GodFather](../malware/families/godfather.md) | Yes | Yes | Yes | Yes | Yes | Yes | Multi-language targeting |

## Academic Research

| Paper | Year | Key Finding |
|-------|------|-------------|
| [A Comprehensive Survey on Android Anti-Reversing and Anti-Analysis](https://arxiv.org/abs/2408.11080) | 2024 | Systematic taxonomy of 32 anti-analysis subcategories across 5 major categories |
| [DroidMorph](https://arxiv.org/abs/2405.11876) | 2024 | 1,771 morphed variants achieved 51.4% detection rate, meaning half evaded all AV |
| [AVPASS](https://blackhat.com/docs/us-17/thursday/us-17-Jung-AVPASS-Leaking-And-Bypassing-Anitvirus-Detection-Model-Automatically.pdf) | 2017 | Leaked AV detection models to generate evasive variants; 56/58 AVs bypassed |

## Detection During Analysis

??? example "Static Indicators"

    - Multiple `Build.*` property checks concentrated in a single method
    - `/proc/self/maps` or `/proc/self/status` file reads
    - Hardcoded AV package name strings
    - `TelephonyManager` calls not related to app functionality
    - Native library with OLLVM indicators (flattened control flow)
    - Encrypted string arrays with runtime decryption routines

??? example "Dynamic Indicators"

    - App silently exits or shows benign behavior in emulator but activates on physical device
    - Delayed C2 contact (hours/days after install)
    - Port scanning on localhost (Frida detection)
    - Rapid file existence checks across `/dev/`, `/system/`, `/sbin/`
    - `getInstalledPackages()` called early in app lifecycle
