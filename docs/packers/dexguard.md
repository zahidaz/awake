# DexGuard

DexGuard is a commercial Android app protection tool developed by **Guardsquare** (Belgium). It extends ProGuard/R8 with encryption, tamper detection, and environmental checks. The most commonly encountered commercial protector in Android malware analysis due to its effectiveness and availability.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Guardsquare |
| Origin | Belgium |
| Type | Commercial Packer/Protector/Obfuscator |
| Platforms | Android |
| Companion | AppSweep (security testing) |
| Relationship | Guardsquare also maintains ProGuard (open-source) and contributes to R8 |

## Build Integration

DexGuard operates as a **Gradle plugin** that runs at build time, requiring access to the application source code. This is a fundamental architectural difference from post-build protectors like [DexProtector](dexprotector.md), which operate on compiled APK/AAB artifacts without source access.

### Configuration Files

DexGuard uses two primary configuration files in the project root:

- `dexguard-project.txt` -- project-wide protection settings applied to all build variants
- `dexguard-release.txt` -- release-specific settings (typically stronger protection, applied only to release builds)

These files use the same syntax as ProGuard/R8 rules with additional DexGuard-specific directives:

```
-encryptstrings class com.target.app.**
-encryptclasses class com.target.app.core.**
-accessthroughreflection class com.target.app.crypto.** { *; }
-encryptassetfiles assets/config.json
-detectemulators com.target.app.SecurityCallback
-detectroot com.target.app.SecurityCallback
-detecthookingframeworks com.target.app.SecurityCallback
```

### ProGuard/R8 Relationship

DexGuard extends the ProGuard rule format. Any valid ProGuard configuration works inside DexGuard config files. DexGuard adds encryption and RASP directives on top of the standard obfuscation rules. Projects migrating from ProGuard to DexGuard can keep their existing `-keep` rules and layer DexGuard-specific protections incrementally.

Because DexGuard replaces ProGuard/R8 in the build pipeline rather than running alongside it, the two cannot be used simultaneously. The Gradle plugin intercepts the compilation step where R8 would normally run.

### Contrast with Post-Build Tools

| Aspect | DexGuard (Build-Time) | [DexProtector](dexprotector.md) (Post-Build) |
|--------|----------------------|----------------------------------------------|
| Source required | Yes | No |
| Integration point | Gradle plugin | Command-line tool on compiled APK |
| Polymorphism | Per-build variation (different keys, names) | Deterministic output |
| Configuration | ProGuard-compatible rule files | Standalone configuration |
| CI/CD fit | Native Gradle task | Additional build step |
| Malware use case | Requires cracked plugin + build environment | Can protect any existing APK |

The build-time integration is why cracked DexGuard versions are more complex to deploy than post-build tools. The attacker needs a functional Gradle environment with the DexGuard plugin correctly registered, not just a command-line wrapper.

## Identification

### APKiD Detection

APKiD identifies DexGuard with signatures like:

```
anti_disassembly : DexGuard (string encryption)
anti_vm : DexGuard (emulator check)
packer : DexGuard
obfuscator : DexGuard
```

### File Artifacts

| Artifact | Description |
|----------|-------------|
| String encoding classes | Classes with names like `o`, `oo`, `ooo` containing string decryption methods |
| Asset files | Encrypted DEX payloads in `assets/` with non-standard extensions |
| Native libraries | `libdexguard.so` or obfuscated native stubs |
| Class names | Aggressive single-character naming across all packages |
| Reflection-heavy initialization | Application class with extensive reflection in `attachBaseContext` |

### Distinguishing from ProGuard/R8

ProGuard/R8 only performs name obfuscation and dead code removal. DexGuard adds:

- String encryption (strings are decrypted at runtime via method calls)
- Class encryption (entire classes encrypted, loaded dynamically)
- Resource encryption
- Asset encryption
- Native code obfuscation
- Anti-tampering checks
- Environmental checks (root, debug, emulator)

If decompiled code shows method calls returning strings rather than string literals, it is likely DexGuard string encryption.

## Protection Mechanisms

### String Encryption

Replaces string literals with method calls that decrypt at runtime:

```java
String url = ooo.o("encrypted_bytes_here");
```

The decryption method uses XOR, AES, or custom algorithms. Keys may be derived from class names, method signatures, or hardcoded values.

### Class Encryption

Selected classes are encrypted and stored in assets or resources. At runtime, a custom class loader decrypts and loads them. This defeats static analysis of protected classes entirely.

### Resource and Asset Encryption

Layout XML files, strings, and assets can be encrypted. Decryption happens transparently through a patched `AssetManager` or resource loading hook.

### Code Virtualization

Critical methods can be converted to a proprietary bytecode format executed by an embedded interpreter. Similar to [Virbox](virbox.md) DEX virtualization but with a different instruction set.

### Tamper Detection

- APK signature verification against expected certificate
- DEX file checksum validation
- Native library integrity checks
- Response: crash, silent data corruption, or delayed termination

### Environmental Checks

| Check | Detection Method |
|-------|-----------------|
| Root | su binary, Magisk, SuperSU, system partition state |
| Emulator | Build properties, hardware sensors, telephony state |
| Debugger | TracerPid, JDWP, ptrace status |
| Frida | Port 27042, frida-agent in /proc/maps, named pipes |
| Xposed | XposedBridge class presence, stack trace inspection |

### Polymorphic Builds

Each DexGuard build produces a structurally unique output. Encryption keys, obfuscated class names, string decryption routines, and control flow transformations all vary between builds of the same application. Two APKs built from identical source with identical DexGuard configuration will have different bytecode.

This is DexGuard's most significant defensive property. A Frida script written to hook string decryption in build A will fail on build B because the decryption class name, method signature, and key derivation have all changed. Attackers must re-analyze each build individually. Automated tooling that relies on fixed class names or method patterns breaks across versions.

For malware analysis, this means samples from different campaigns or distribution waves require separate unpacking effort even when the underlying malware is identical. Contrast this with [DexProtector](dexprotector.md) or [Chinese packers](tencent-legu.md), where a single unpacking script transfers across all protected samples.

### Certificate Pinning

DexGuard includes a built-in SSL/TLS certificate pinning implementation that operates at the native layer, independent of OkHttp's `CertificatePinner` or Android's `NetworkSecurityConfig`. The pinning configuration is specified in the DexGuard config file and compiled into the protection layer at build time.

This means standard pinning bypass approaches that target OkHttp or `TrustManager` may be insufficient. The native-level pinning check runs before or alongside Java-layer networking, and a complete bypass requires hooking both layers. Objection's `android sslpinning disable` covers common Java-level patterns but may miss DexGuard's native implementation.

### Native Code Obfuscation

DexGuard protects JNI code in addition to DEX bytecode. Native libraries linked to the project can receive:

- Function-level control flow flattening
- String encryption within native code
- Symbol stripping beyond standard `strip`
- Arithmetic obfuscation of constants

This protection applies to the developer's own native code, not just DexGuard's runtime libraries. When analyzing a DexGuard-protected app that includes JNI components, expect obfuscated native functions that resist standard Ghidra/IDA analysis patterns.

### Reflection API Obfuscation

DexGuard encrypts reflection calls (`Class.forName()`, `Method.invoke()`, field access) so that the target class and method names are not visible in the bytecode. Instead of a plaintext string like `"com.target.SensitiveClass"`, the reflection target is resolved through the same encrypted string pipeline used for regular string encryption.

In decompiled output, this appears as:

```java
Class cls = Class.forName(ooo.o(new byte[]{...}));
Method m = cls.getDeclaredMethod(oo.o(new byte[]{...}), paramTypes);
m.invoke(instance, args);
```

Hooking the string decryption methods captures these reflection targets alongside other decrypted strings, revealing the hidden class and method references in one pass.

## Unpacking Methodology

### Frida-Based String Decryption

Hook the string decryption methods to log all decrypted strings:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.match(/^[o]+$/)) {
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        if (method.getReturnType().getName() === "java.lang.String") {
                            var methodName = method.getName();
                            cls[methodName].overload("[B").implementation = function(arr) {
                                var result = this[methodName](arr);
                                console.log(className + "." + methodName + " -> " + result);
                                return result;
                            };
                        }
                    });
                } catch(e) {}
            }
        },
        onComplete: function() {}
    });
});
```

### DEX Dumping

For class-encrypted builds, dump the decrypted DEX from memory after the class loader has processed it. See [Dynamic Analysis](../reversing/dynamic-analysis.md) for DEX dumping techniques.

### Class Loader Hook for Encrypted Classes

When DexGuard uses class encryption, the encrypted payload is decrypted and loaded through a custom `ClassLoader`. Hooking `ClassLoader.loadClass` and `DexFile` operations captures classes as they are decrypted:

```javascript
Java.perform(function() {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function(name, resolve) {
        var result = this.loadClass(name, resolve);
        console.log("loadClass: " + name);
        return result;
    };

    var DexFile = Java.use("dalvik.system.DexFile");
    DexFile.loadDex.overload("java.lang.String", "java.lang.String", "int").implementation = function(src, out, flags) {
        console.log("DexFile.loadDex src=" + src + " out=" + out);
        return this.loadDex(src, out, flags);
    };
});
```

This reveals the sequence of dynamically loaded classes and the file paths where decrypted DEX files are temporarily written before loading.

### Environmental Check Bypass (Combined)

DexGuard runs root, emulator, and debugger checks early in the initialization sequence. A combined bypass script handles all three vectors in a single Frida session:

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

var fopen = Module.findExportByName("libc.so", "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && (this.path.indexOf("/su") !== -1 ||
            this.path.indexOf("magisk") !== -1 ||
            this.path.indexOf("supersu") !== -1)) {
            retval.replace(ptr(0));
        }
    }
});

var prop_get = Module.findExportByName("libc.so", "__system_property_get");
Interceptor.attach(prop_get, {
    onEnter: function(args) {
        this.name = args[0].readUtf8String();
        this.value = args[1];
    },
    onLeave: function(retval) {
        if (this.name === "ro.debuggable") {
            this.value.writeUtf8String("0");
        }
        if (this.name === "ro.hardware") {
            this.value.writeUtf8String("qcom");
        }
        if (this.name === "ro.product.model") {
            this.value.writeUtf8String("SM-G998B");
        }
    }
});

var connect = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connect, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        if (port === 27042) {
            args[1] = ptr(0);
        }
    }
});
```

This script blocks process termination, spoofs system properties to hide emulator and root indicators, blocks `su`/Magisk file access, and prevents Frida port detection. Use with `frida -f` in spawn mode for early injection.

### Certificate Pinning Bypass

For DexGuard's native-level certificate pinning, a layered approach covers both Java and native implementations:

```javascript
Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.checkTrustedRecursive.implementation = function() {
        return Java.use("java.util.ArrayList").$new();
    };

    try {
        var DGPinning = Java.use("com.guardsquare.dexguard.runtime.net.SSLPinning");
        DGPinning.checkServerTrusted.implementation = function() {};
    } catch(e) {}
});

var SSL_CTX_set_custom_verify = Module.findExportByName("libssl.so", "SSL_CTX_set_custom_verify");
if (SSL_CTX_set_custom_verify) {
    Interceptor.attach(SSL_CTX_set_custom_verify, {
        onEnter: function(args) {
            args[2] = ptr(0);
        }
    });
}
```

The DexGuard pinning class name varies across builds due to polymorphism. The `com.guardsquare.dexguard.runtime.net.SSLPinning` path works for some builds but may need adjustment. [reFrida](https://github.com/zahidaz/refrida) includes SSL pinning bypass snippets that cover multiple DexGuard patterns through class enumeration rather than hardcoded names.

### JADX + Frida Combined Workflow

The most effective DexGuard analysis combines static and dynamic approaches to reconstruct a readable APK:

```
1. Open the APK in JADX -> identify string decryption classes and encrypted assets
2. Spawn the app with Frida, hook string decryption methods
3. Exercise all app functionality -> collect decrypted strings
4. Run frida-dexdump to capture all loaded DEX files from memory
5. Replace the original classes.dex with the dumped DEX files
6. Open the reconstructed APK in JADX
7. Use the Frida string log as a lookup table to annotate JADX output
8. For remaining encrypted strings, call the decryption method directly via Frida RPC
```

For step 8, Frida RPC allows calling DexGuard decryption functions on demand:

```javascript
rpc.exports = {
    decrypt: function(className, methodName, hexBytes) {
        var result = null;
        Java.perform(function() {
            var cls = Java.use(className);
            var bytes = Java.array("byte", hexBytes.match(/.{2}/g).map(function(b) {
                return parseInt(b, 16);
            }));
            result = cls[methodName](bytes);
        });
        return result;
    }
};
```

### Automated DEX Dumping with frida-dexdump

[frida-dexdump](https://github.com/hluwa/frida-dexdump) automates the process of scanning process memory for DEX headers and dumping all loaded DEX files. For DexGuard-protected apps, run it after the app has fully initialized to ensure all encrypted classes have been loaded:

```
frida-dexdump -FU
```

The `-F` flag attaches to the foreground app and `-U` targets a USB-connected device. The tool produces multiple DEX files in the current directory. Some will be framework DEX files -- filter by size and content to identify the application-specific ones. Load the dumped DEX files into JADX for analysis without DexGuard's encryption layer.

### Bypass Environmental Checks

Hook and return false for all detection methods. Objection's `android sslpinning disable` and `android root disable` handle common DexGuard patterns.

## Malware Usage

DexGuard is less commonly seen in malware than Chinese packers (Bangcle, Tencent Legu, Qihoo 360) due to its commercial licensing model. However, cracked or leaked versions have appeared in:

- Banking trojans targeting European institutions
- Samples where the original app was legitimately DexGuard-protected and then repackaged with malicious code
- High-value targeted campaigns where operators invest in professional tools

The protector is more commonly encountered when analyzing legitimate banking and financial apps (the defensive side) rather than the malware itself.

### Known Family Usage

| Family | Usage Context |
|--------|---------------|
| [Anatsa](../malware/families/anatsa.md) | DexGuard-protected droppers on Google Play. String encryption conceals C2 URLs and ATS configuration. |
| [Xenomorph](../malware/families/xenomorph.md) | v3 samples used DexGuard for string and class encryption. ATS scripting engine encrypted behind class loader. |
| [Medusa](../malware/families/medusa.md) | Some MaaS builds distributed with DexGuard protection to affiliates. |
| [Chameleon](../malware/families/chameleon.md) | Earlier variants used DexGuard-style string encryption (potentially cracked version). |

## Versions and Evolution

### Versioning

DexGuard's version numbering tracks closely with ProGuard releases, since DexGuard is built on top of the ProGuard codebase. Major DexGuard versions correspond to the ProGuard version they extend. Guardsquare releases updates quarterly, adding new detection vectors and obfuscation techniques in each cycle.

### Cracked Versions in the Wild

Cracked DexGuard copies circulate on underground forums and Telegram channels, primarily versions from 2018--2021. These leaked builds are the primary source of DexGuard-protected malware, since legitimate licensing requires a direct Guardsquare contract.

Key differences between cracked and current versions:

| Aspect | Cracked (Leaked) | Current (Licensed) |
|--------|-------------------|---------------------|
| Polymorphism | Missing or limited -- builds produce similar output | Full per-build variation |
| Detection vectors | Older checks (no modern Frida/Magisk detection) | Continuously updated detection |
| String encryption | Basic XOR patterns | Advanced multi-layer encryption |
| Config format | Older directive syntax | Extended directives for new features |
| Gradle compatibility | Often locked to older Gradle/AGP versions | Supports current Android build toolchain |

For malware analysts, this distinction matters. Samples using cracked DexGuard are significantly easier to unpack because the obfuscation is weaker and patterns are consistent across samples built with the same leaked version. If a Frida hook works on one sample from a cracked build, it likely works on others from the same version.

### Evolution of Detection Capabilities

DexGuard's environmental detection has expanded over time:

- **Pre-2019**: Basic root checks (`su` binary, known package names), ptrace-based debugger detection
- **2019--2020**: Added Magisk detection, Frida port scanning, Xposed class inspection
- **2021--2022**: Added Magisk module detection, frida-gadget in maps detection, named pipe scanning
- **2023+**: Added MagiskHide/Shamiko detection, Frida stalker detection, multiple frida-server signature checks, zygisk module awareness

Older cracked versions lack the later detection layers entirely, which is why samples built with leaked DexGuard often run without issues on rooted devices with modern Frida setups.

## Analyst Workflow

Step-by-step approach for DexGuard-protected samples:

```
1. Run APKiD -> confirm DexGuard detection
2. Open in jadx -> look for o/oo/ooo classes with byte[] -> String methods
3. Install on device/emulator
4. Attach Frida, hook string decryption classes (script above)
5. Run the app -> capture all decrypted strings (C2 URLs, API keys, target app list)
6. If class encryption present -> use frida-dexdump to dump loaded DEX
7. Decompile dumped DEX normally
8. For environmental checks -> use Objection or custom Frida hooks to bypass
```

For legitimate app analysis (banking app security assessment), the same unpacking approach applies. The key difference is that legitimate apps typically have more layers of protection active simultaneously, including tamper detection that may need hooking before the target functionality is reachable.

## Advanced Analysis Techniques

### Identifying DexGuard Version from Build Artifacts

Cracked DexGuard builds leave version-specific fingerprints:

| Indicator | How to Check |
|-----------|-------------|
| String decryption class count | Older versions (pre-2020): 1-2 classes. Newer: 3+ with delegation chains |
| Encryption algorithm | v8.x: XOR-based. v9.x+: AES with CBC mode. Identifiable by key schedule in bytecode |
| Native library name | `libdexguard.so` in older, obfuscated names in v9+ |
| ProGuard rule compatibility | Cracked versions often tied to specific AGP/Gradle ranges |
| Detection callback pattern | Pre-2021: direct `System.exit`. Post-2021: delayed callback through registered handler |

To fingerprint programmatically, decompile with JADX and count the number of single-character class names with `byte[]` to `String` methods. Cross-reference with known cracked version distribution dates from underground forum timestamps.

### Automated String Decryption Pipeline

For batch analysis across multiple DexGuard-protected samples:

```javascript
rpc.exports = {
    decryptAll: function() {
        var results = {};
        Java.perform(function() {
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (!className.match(/^[a-z]{1,3}(\.[a-z]{1,3})*$/)) return;
                    try {
                        var cls = Java.use(className);
                        var methods = cls.class.getDeclaredMethods();
                        methods.forEach(function(method) {
                            if (method.getReturnType().getName() !== "java.lang.String") return;
                            var params = method.getParameterTypes();
                            if (params.length !== 1) return;
                            if (params[0].getName() !== "[B") return;
                            var methodName = method.getName();
                            var original = cls[methodName].overload("[B");
                            cls[methodName].overload("[B").implementation = function(arr) {
                                var result = original.call(this, arr);
                                if (!results[className]) results[className] = [];
                                results[className].push(result.toString());
                                return result;
                            };
                        });
                    } catch(e) {}
                },
                onComplete: function() {}
            });
        });
        return results;
    },

    getResults: function() {
        return JSON.stringify(this._results || {});
    }
};
```

Drive this from a Python script using `frida.get_usb_device().attach(pid)` to batch-process multiple APKs. Export results as JSON for IOC extraction.

### Breaking Native SSL Pinning Without Known Class Names

DexGuard's polymorphism means the SSL pinning class name changes per build. Instead of targeting a known class, hook at the OpenSSL level:

```javascript
var SSL_CTX_set_verify = Module.findExportByName("libssl.so", "SSL_CTX_set_verify");
if (SSL_CTX_set_verify) {
    Interceptor.attach(SSL_CTX_set_verify, {
        onEnter: function(args) {
            args[1] = ptr(0);
            args[2] = ptr(0);
        }
    });
}

var SSL_set_verify = Module.findExportByName("libssl.so", "SSL_set_verify");
if (SSL_set_verify) {
    Interceptor.attach(SSL_set_verify, {
        onEnter: function(args) {
            args[1] = ptr(0);
            args[2] = ptr(0);
        }
    });
}

var X509_verify_cert = Module.findExportByName("libcrypto.so", "X509_verify_cert");
if (X509_verify_cert) {
    Interceptor.attach(X509_verify_cert, {
        onLeave: function(retval) {
            retval.replace(1);
        }
    });
}
```

This bypasses all certificate verification regardless of whether DexGuard's pinning uses Java-level `TrustManager`, native BoringSSL callbacks, or custom verification. Combined with installing a CA certificate in the system trust store (via Magisk module [MagiskTrustUserCerts](https://github.com/NVISOsecurity/MagiskTrustUserCerts)), this provides complete HTTPS interception.

For DexGuard builds that also pin at the Java `HttpsURLConnection` or OkHttp level, add [reFrida](https://github.com/zahidaz/refrida) SSL pinning bypass snippets which enumerate all `TrustManager` implementations dynamically rather than targeting hardcoded class names.

## Comparison with Other Protectors

| Feature | DexGuard | [Virbox](virbox.md) | [Chinese Packers](tencent-legu.md) |
|---------|----------|--------|----------------|
| String encryption | AES/XOR with method-level keys | VM-based, part of virtualization | Basic XOR in native layer |
| Class encryption | Custom class loader | Full DEX virtualization | DEX-in-assets encryption |
| Code virtualization | Optional, limited methods | Core feature, full DEX | Not available |
| Anti-debug | Comprehensive (ptrace, JDWP, Frida) | Moderate (ptrace, debug flags) | Basic (ptrace) |
| Unpacking difficulty | Medium (Frida hooks effective) | High (VM interpretation needed) | Low (standard DEX dump) |
| Cost to attacker | High (commercial, cracked copies rare) | Medium (Chinese market pricing) | Free |

## References

- [Guardsquare DexGuard](https://www.guardsquare.com/dexguard)
- [Guardsquare Blog -- Mobile Application Protection](https://www.guardsquare.com/blog)
- [APKiD DexGuard Signatures](https://github.com/rednaga/APKiD)
- [ThreatFabric -- Android Banking Trojan Reports](https://www.threatfabric.com/blogs)
- [frida-dexdump -- Automated DEX Dumping](https://github.com/hluwa/frida-dexdump)
- [reFrida -- Frida Script Collection](https://github.com/zahidaz/refrida)
- [Guardsquare -- DexGuard vs ProGuard Comparison](https://www.guardsquare.com/proguard-vs-dexguard)
- [OWASP MASTG -- Android Reverse Engineering](https://mas.owasp.org/MASTG/)
- [Objection -- Runtime Mobile Exploration](https://github.com/sensepost/objection)
