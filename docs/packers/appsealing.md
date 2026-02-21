# AppSealing

AppSealing is a cloud-based SaaS application protection platform developed by **INKA Entworks** (South Korea). It provides DEX encryption, native library protection, and anti-cheat detection through a web console where developers upload APKs and receive protected builds. The SaaS delivery model means no local tooling or build integration is required, distinguishing it from source-level protectors like [DexGuard](dexguard.md).

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | INKA Entworks |
| Origin | South Korea |
| Type | Commercial SaaS Packer/Protector |
| Platforms | Android, iOS, Hybrid (Unity, Unreal, Cocos2d) |
| Delivery | Cloud-based (upload APK, receive protected build) |
| Market | Korean banking, gaming, enterprise apps |
| Website | [appsealing.com](https://www.appsealing.com) |

## Identification

### APKiD Detection

APKiD identifies AppSealing with:

```
packer : appsealing
```

### File Artifacts

| Artifact | Description |
|----------|-------------|
| `libcovault-appsec.so` | Primary native security library |
| `AppSealingZygote` | Bootstrap class that initializes protection before app launch |
| `assets/AppSealing/` | Directory containing encrypted payloads and configuration |
| `sealed1.dex` | Encrypted DEX payload |
| `aws_classes.dex` | AppSealing wrapper DEX containing loader classes |
| `api.appsealing.com` | API endpoint for license verification and configuration |

### AppSealing Asset Directory

The `assets/AppSealing/` directory contains a set of numbered and lettered files:

| File | Purpose |
|------|---------|
| `1` | Primary encrypted payload |
| `11` | Secondary payload data |
| `a1` | Architecture-specific native data |
| `a3` | Architecture-specific native data (alternate) |
| `aslc` | AppSealing license configuration |
| `hr` | Hash/integrity reference data |
| `s1` | Sealed configuration block |
| `s3` | Sealed configuration block (alternate) |
| `si` | Sealing information metadata |
| `x1` | Executable payload (primary arch) |
| `x3` | Executable payload (alternate arch) |

The naming scheme uses single characters and short codes rather than descriptive names. The numeric pairs (1/11, s1/s3, x1/x3, a1/a3) correspond to different architecture targets or protection layers.

## Protection Mechanisms

### DEX Encryption

AppSealing encrypts application DEX files and decrypts them at runtime through the native `libcovault-appsec.so` library. Supports:

- **Selective DEX encryption** -- individual classes or packages can be marked for encryption
- **ODEX protection** -- prevents caching of decrypted optimized DEX
- **Multi-DEX support** -- handles apps with multiple DEX files

The encrypted DEX is stored as `sealed1.dex` and loaded through a custom class loader initialized by `AppSealingZygote`.

### SO File Encryption

Native `.so` libraries are encrypted within the APK and decrypted at load time. This prevents static extraction and analysis of JNI code.

### DLL Encryption (Unity)

For Unity-based games, AppSealing encrypts `libil2cpp.so` and Mono assemblies (`.dll` files). This is a targeted feature for the gaming market where IL2CPP reverse engineering is a primary threat.

### Anti-Debugging

Detects ptrace-based debuggers, JDWP connections, and common debugging tools. The native security component uses `kill`, `signal`, and `alarm` syscalls to terminate the process when debugging is detected. Patching or hooking these three functions at the native level prevents the crash-on-detection behavior.

### Anti-Decompile

Inserts invalid bytecode sequences and malformed headers that cause decompilers (JADX, JEB, Procyon) to fail on protected classes. This is a static analysis impediment only and does not affect runtime execution.

### Root and Emulator Detection

Checks for:

- `su` binary presence and known root management apps
- Magisk artifacts (though detection is basic compared to [DexProtector](dexprotector.md) or [Promon](promon.md))
- Emulator indicators via Build properties and hardware fingerprints
- Common emulator packages (Genymotion, BlueStacks, Nox)

### Cheat Tool Detection

Targets game modification tools:

- GameGuardian memory editor
- Lucky Patcher
- Xposed framework
- Frida (basic port check)
- Speed hack tools (Cheat Engine mobile variants)

### Repackaging Prevention

Signature verification against the original signing certificate. Detects APK modification by comparing checksums of critical components.

## Weaknesses

### String Encryption

AppSealing's string encryption is weak. Encrypted strings in the native layer use simple transformations that are easily reversible through static analysis of `libcovault-appsec.so`. This contrasts with [DexGuard](dexguard.md)'s polymorphic per-build string encryption or [DexProtector](dexprotector.md)'s white-box key derivation.

### Detection Bypass Surface

The detection methods rely on predictable check patterns. The native security component's use of `kill`, `signal`, and `alarm` for enforcement means that hooking these three libc functions neutralizes the entire crash-on-detection mechanism in one pass:

```javascript
var kill = Module.findExportByName("libc.so", "kill");
Interceptor.attach(kill, {
    onEnter: function(args) {
        console.log("Blocked kill(" + args[0] + ", " + args[1] + ")");
        args[0] = ptr(0);
    }
});

var signal_func = Module.findExportByName("libc.so", "signal");
Interceptor.attach(signal_func, {
    onEnter: function(args) {
        console.log("Blocked signal(" + args[0] + ")");
    },
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

var alarm = Module.findExportByName("libc.so", "alarm");
Interceptor.attach(alarm, {
    onEnter: function(args) {
        console.log("Blocked alarm(" + args[0] + ")");
        args[0] = ptr(0);
    }
});
```

### Java-Side Message Box Bypass

AppSealing displays a Java-side dialog when it detects a hostile environment (root, hook, cheat tool). This dialog can be suppressed via Xposed hooks on `AlertDialog.Builder` or by hooking the specific AppSealing callback class, allowing the app to continue running on detected devices.

## Unpacking Methodology

### AppPealing Xposed Module

[AppPealing](https://codeberg.org/pufferffish/apppealing) is a purpose-built Xposed module that:

- Disables cheat tool detection checks
- Dumps encrypted DEX files after decryption
- Decrypts sealed DEX payloads from the `assets/AppSealing/` directory
- Patches the `AppSealingZygote` initialization to skip integrity checks

This is the most targeted public tool for AppSealing bypass. Install via LSPosed, scope to the target app, and the module handles DEX extraction automatically.

### Appsealing-Reversal

[Appsealing-Reversal](https://github.com/ARandomPerson7/Appsealing-Reversal) provides a full analysis of the AppSealing protection scheme, including:

- Detailed breakdown of the native library initialization flow
- Identification of all check points and enforcement mechanisms
- Bypass strategies for each protection layer
- Documentation of the asset file format and encryption scheme

### frida-dexdump

Standard [frida-dexdump](https://github.com/hluwa/frida-dexdump) works for DEX recovery from AppSealing-protected apps:

```
frida-dexdump -FU
```

After the app initializes and `AppSealingZygote` decrypts the sealed DEX into memory, frida-dexdump scans for DEX magic bytes and dumps all loaded DEX files. Filter the output by size to separate application DEX from framework and AppSealing wrapper DEX.

### Combined Frida Bypass

A combined approach using Frida to neutralize all protection layers simultaneously:

```javascript
Java.perform(function() {
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(code) {
        console.log("Blocked System.exit(" + code + ")");
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exit.implementation = function(code) {
        console.log("Blocked Runtime.exit(" + code + ")");
    };
});

["kill", "signal", "alarm"].forEach(function(fname) {
    var func = Module.findExportByName("libc.so", fname);
    if (func) {
        Interceptor.attach(func, {
            onEnter: function(args) {
                console.log("Neutralized " + fname);
                args[0] = ptr(0);
            }
        });
    }
});
```

Use with `frida -f` in spawn mode to inject before `AppSealingZygote` initializes. Once the protection checks are neutralized, attach frida-dexdump to dump the decrypted DEX.

## Comparison with Other Protectors

| Feature | AppSealing | [DexGuard](dexguard.md) | [DexProtector](dexprotector.md) | [Chinese Packers](tencent-legu.md) |
|---------|------------|----------|--------------|----------------|
| Delivery model | SaaS (upload APK) | Gradle plugin (source required) | Post-build CLI | SaaS / CLI |
| DEX encryption | Yes (selective) | Yes (class-level) | Yes | Yes (whole DEX) |
| String encryption | Weak | Strong (polymorphic) | Strong (white-box) | Basic XOR |
| Code virtualization | No | Optional | Hide Access | No |
| Anti-Frida | Basic (port check) | Comprehensive | Comprehensive | Basic |
| Anti-root | Moderate | Comprehensive | Comprehensive | Basic |
| Unity/game support | Yes (dedicated) | No | Limited | No |
| Unpacking difficulty | Low-Medium | Medium-Hard | Medium-Hard | Easy-Medium |
| Public bypass tools | Yes (AppPealing, Appsealing-Reversal) | Limited | Limited | Yes (generic DEX dump) |

AppSealing occupies a similar market position to [Chinese packers](tencent-legu.md) in terms of protection strength but targets the Korean and international SaaS market. Its protections are substantially weaker than [DexGuard](dexguard.md) or [DexProtector](dexprotector.md), and the existence of dedicated bypass tools (AppPealing) makes it one of the easier commercial protectors to defeat.

## Industry Usage

AppSealing is primarily deployed in:

- **Korean banking apps** -- financial institutions using AppSealing as part of compliance requirements
- **Unity and Unreal games** -- anti-cheat and anti-tamper for mobile games, particularly Korean game publishers
- **Enterprise applications** -- corporate apps requiring basic IP protection without build pipeline changes

The SaaS model makes it attractive for organizations without dedicated mobile security engineering teams. Upload the APK, configure protection options via the web console, and download the protected build.

## Analyst Workflow

```
1. Run APKiD -> confirm "packer : appsealing"
2. Check for libcovault-appsec.so and assets/AppSealing/ directory
3. Install on rooted device with LSPosed + AppPealing module
4. Launch app -> AppPealing dumps decrypted DEX automatically
5. Alternative: Frida spawn mode with kill/signal/alarm hooks + frida-dexdump
6. Decompile dumped DEX with JADX
7. If Unity game: extract and analyze decrypted libil2cpp.so with IL2CPPDumper
```

## References

- [AppSealing Official](https://www.appsealing.com)
- [APKiD -- Packer Detection](https://github.com/rednaga/APKiD)
- [AppPealing Xposed Module](https://codeberg.org/pufferffish/apppealing)
- [Appsealing-Reversal -- Full Bypass Analysis](https://github.com/ARandomPerson7/Appsealing-Reversal)
- [frida-dexdump -- Automated DEX Dumping](https://github.com/hluwa/frida-dexdump)
- [INKA Entworks](https://www.inka.co.kr)
