# DexProtector

DexProtector is a commercial Android and iOS application protector developed by **Licel**. It applies encryption, obfuscation, and native bridging at the bytecode and native levels, combined with a full RASP (Runtime Application Self-Protection) suite. Unlike obfuscation-focused tools such as [DexGuard](dexguard.md), DexProtector's core strength is its layered runtime protection and asset encryption via vtable hooking in `libandroidfw.so`. EMVCo-certified for six consecutive years, it is primarily deployed in mobile payments, banking, and fintech applications.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Licel |
| Origin | United States (Los Angeles HQ, London office) |
| Type | Commercial Packer/Protector/RASP |
| Platforms | Android (4.4+), iOS (11.0+), Apple Watch |
| Certifications | EMVCo SBMP SPT (6 consecutive years), PCI MPoC compliant |
| Scale | 12+ billion downloads across 85 countries |
| Website | [licelus.com](https://licelus.com/products/dexprotector) |

## Identification

### APKiD Detection

APKiD identifies DexProtector through native library naming patterns and asset file signatures:

```
packer : DexProtector
obfuscator : DexProtector
```

The primary detection regex matches native libraries across architectures:

```
/lib\/(arm.*|x86.*)\/libdexprotector\.[A-Za-z0-9.]{2,16}\.so/
```

### File Artifacts

| Artifact | Description |
|----------|-------------|
| `libdexprotector.XX.so` | Main protection library (XX = version digits) |
| `libdexprotector_h.so` | Alternate library naming |
| `libdpboot.so` | Bootstrap loader, loaded first via `System.loadLibrary("dpboot")` |
| `libdp.so` | Key generation and asset vtable hooking library |
| `assets/dp.mp3` | Encrypted index file mapping method/field indexes to hidden targets |
| `assets/dp.arm.so.dat` | Encrypted native payload (ARM generic) |
| `assets/dp.arm-v7.so.dat` | Encrypted native payload (ARMv7) |
| `assets/dp.arm-v8.so.dat` | Encrypted native payload (ARMv8/ARM64) |
| `assets/dp.x86.so.dat` | Encrypted native payload (x86) |
| `META-INF/MANIFEST.MF` | Contains `Protected-By: <version> DexProtector (<date>)` |
| `dexpro-build.properties` | Build metadata with version, detection flags configuration |

### DexProtector for AIDE Variant

A variant targeting AIDE (Android IDE) uses distinct artifacts:

| Artifact | Description |
|----------|-------------|
| `assets/classes.dex.dat` | Encrypted DEX payload |
| `assets/eprotect.dat` | Protection configuration data |
| `assets/dp-lib/dp.kotlin-v1.lua.mph` | Kotlin-specific protection library |

### Version Identification

The `META-INF/MANIFEST.MF` entry reveals the exact DexProtector version:

```
Protected-By: 12.3.19 DexProtector (20211214)
```

The `dexpro-build.properties` file contains build configuration:

```
build.version_name=: 1.5 (Beta)
build.version_code=: 15
reverse.detection=true
hooks.detection=true
device.detection=true
signature.detection=true
```

## Protection Mechanisms

### Native Library Loading Chain

DexProtector uses a multi-stage native library loading sequence during `attachBaseContext`:

```
Application.attachBaseContext()
  └─ System.loadLibrary("dpboot")     → loads libdpboot.so
       └─ JNI: loadLibrary("dexprotector") → loads libdexprotector.so
            └─ Custom ELF loader           → decrypts and maps final payload
                 └─ libdp.so               → master key generation + vtable hooking
```

Each stage handles a specific responsibility: `libdpboot.so` bootstraps the chain, `libdexprotector.so` acts as a custom ELF loader that decrypts the protected payload into memory, and `libdp.so` generates the 32-byte master key used to derive all subkeys for asset decryption.

### Asset Encryption and VTable Hooking

DexProtector's most distinctive technique is intercepting Android's native asset loading at the framework level. During initialization, `libdp.so` modifies the vtable of `android::_FileAsset` inside `libandroidfw.so`, replacing virtual function pointers to intercept all asset read operations.

When the application accesses any encrypted asset file, DexProtector's intercepted vtable entries decrypt and decompress the content on the fly. The decryption key and nonce are distributed across the file header and a subkey derived from the 32-byte master key. This provides transparent decryption -- the Java layer receives plaintext without any awareness of the encryption layer.

### Class and DEX Encryption

Entire DEX files or selected classes are encrypted and stored within the APK. At runtime, the native layer decrypts the DEX payload and loads it through a custom class loader. On ART, the decrypted output may be written as `.odex` or `.dat` files temporarily before loading.

### String Encryption

String literals are replaced with native bridge calls that accept an encrypted index parameter. DexProtector uses strong cryptographic algorithms with dynamic keys derived from multiple runtime parameters, making key extraction from static analysis infeasible. White-box cryptography protects the key material from memory inspection.

### Hide Access (Method/Field Virtualization)

When a method call or field access requires protection, DexProtector replaces the instruction with a call to a native bridge function:

```java
LibLiveNetTV.i(0x42, arg1, arg2);
```

The first parameter is an index resolved against the decrypted `assets/dp.mp3` file, which maps indexes to the actual methods or fields. This native `invokedynamic` engine hides the call graph entirely from static analysis tools like JADX and Ghidra.

### Resource and Asset Encryption

Layout XML files, drawables, raw resources, and arbitrary assets are encrypted within the APK. Decryption is handled transparently through the vtable-hooked `AssetManager`, meaning the application code accesses resources normally while DexProtector handles decryption at the native layer.

### Native Code Protection

- ELF section encryption (`.text` section of `.so` files)
- JNI bridge obfuscation
- Symbol stripping and import/export hiding
- Native library encryption with architecture-specific `.dat` payloads

### Anti-Debugging

| Technique | Detection Method |
|-----------|-----------------|
| ptrace | Self-attachment to block external debuggers |
| TracerPid | `/proc/self/status` monitoring |
| Debugger detection | IDA Pro, GDB, JEB, LLDB process signatures |
| JDWP | Java Debug Wire Protocol state inspection |
| Debug flags | `android:debuggable` manifest attribute checks |

### Anti-Tampering

DexProtector applies encryption-based integrity controls with context-sensitive keys calculated dynamically at runtime. Tampering with any protected component invalidates the derived keys, causing decryption to produce garbage rather than triggering an explicit check-and-fail pattern. This design makes patching significantly harder than simple signature verification bypasses.

Additional integrity checks include:

- APK certificate verification
- DEX file hash validation
- Native library content checks
- File integrity verification across APK contents

### Anti-Hooking and Anti-Instrumentation

| Target | Detection Method |
|--------|-----------------|
| Frida | Port 27042 scanning, `frida-agent` in `/proc/maps`, named pipe detection |
| Xposed | `XposedBridge` class presence, stack trace inspection |
| Substrate | Library injection detection |
| SO injection | `/proc/self/maps` monitoring for unexpected libraries |

### Root and Environment Detection

| Check | Method |
|-------|--------|
| Root | `su` binary, Magisk, SuperSU, system partition integrity |
| Emulator | Build properties, hardware characteristics, telephony state |
| Multi-parallel | App cloning and dual-space environment detection |
| Custom firmware | ROM fingerprinting, bootloader state |

### Certificate Pinning (Communication Hardening)

DexProtector provides built-in public key pinning and Certificate Transparency enforcement, blocking MITM proxies and ensuring data flows only to legitimate endpoints. This operates independently of application-level pinning implementations like OkHttp's `CertificatePinner`.

### vTEE CryptoModule (White-Box Cryptography)

The Licel vTEE (Virtual Trusted Execution Environment) is a software-based secure enclave running inside the application process. Unlike hardware TEEs, it creates a logically isolated execution environment through white-box cryptography. The CryptoModule:

- Protects cryptographic key material from memory dumps
- Provides secure storage with device-binding
- Handles AES, RSA, and other operations within the white-box implementation
- Prevents key extraction even with full memory access and debugger control

## Unpacking Methodology

### RASP Bypass as Prerequisite

DexProtector's RASP checks run before the application fully initializes. If Frida, root, or an emulator is detected, the app terminates immediately. Bypassing these checks is the first step in any analysis.

Spawn the application with Frida in spawn mode and hook early:

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
```

### Hooking the Unlink Call

DexProtector deletes decrypted temporary files after loading. Hooking the native `unlink` syscall prevents cleanup, leaving decrypted DEX and `.odex` files on disk:

```javascript
Interceptor.attach(Module.findExportByName(null, "unlink"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        console.log("unlink: " + path);
    },
    onLeave: function(retval) {
        retval.replace(0);
    }
});
```

Returning 0 tricks the process into believing the deletion succeeded while the decrypted files remain accessible at the logged paths.

### DEX Dumping from Memory

Intercept `android_dlopen_ext` to detect when DexProtector loads its decrypted payload, then dump DEX files from memory:

```javascript
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        console.log("dlopen: " + this.path);
    }
});
```

Tools like [frida-dexdump](https://github.com/hluwa/frida-dexdump) scan process memory for DEX magic bytes (`dex\n035\0`) and dump all loaded DEX files after DexProtector has completed its decryption routine.

### Native Bridge Index Extraction

To recover the hidden call graph, hook the native bridge function and log all index-to-method resolutions:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var cls = Java.use(className);
                var methods = cls.class.getDeclaredMethods();
                methods.forEach(function(method) {
                    if (method.toString().indexOf("native") !== -1) {
                        console.log("Native bridge: " + className + "." + method.getName());
                    }
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});
```

### dp.mp3 Decryption

The `assets/dp.mp3` file contains the encrypted mapping between native bridge indexes and actual method/field targets. After the app initializes, this file is decrypted in memory. Dumping the decrypted content from the process memory reveals the full method resolution table, restoring the original call graph.

### Step-by-Step Walkthrough

Complete DexProtector unpacking workflow targeting the native bridge and vtable hooking:

**Step 1: Identify the protection version.** Check `META-INF/MANIFEST.MF` for `Protected-By:` and `dexpro-build.properties` for detection flags. This determines which bypass techniques are needed.

**Step 2: Bypass RASP.** Use spawn mode (`frida -f com.target.app -U`) to inject before DexProtector initializes. Block `System.exit` and `Runtime.exit` as shown above. If the app still crashes, hook `Process.killProcess`:

```javascript
Java.perform(function() {
    var Process = Java.use("android.os.Process");
    Process.killProcess.implementation = function(pid) {
        console.log("Blocked killProcess(" + pid + ")");
    };
});
```

**Step 3: Prevent file cleanup.** Hook `unlink` and `remove` to preserve decrypted temporary files:

```javascript
["unlink", "remove"].forEach(function(fname) {
    Interceptor.attach(Module.findExportByName("libc.so", fname), {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (path && (path.indexOf(".dex") !== -1 || path.indexOf(".odex") !== -1 ||
                path.indexOf(".dat") !== -1)) {
                console.log("[blocked " + fname + "] " + path);
                this.block = true;
            }
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(0);
        }
    });
});
```

**Step 4: Extract the master key.** The 32-byte master key in `libdp.so` is derived during initialization. Hook the key derivation by intercepting AES key schedule operations:

```javascript
var AES_set_encrypt_key = Module.findExportByName("libdp.so", "AES_set_encrypt_key");
if (AES_set_encrypt_key) {
    Interceptor.attach(AES_set_encrypt_key, {
        onEnter: function(args) {
            var keyLen = args[1].toInt32();
            console.log("[AES key] length=" + keyLen + " key=" +
                args[0].readByteArray(keyLen / 8));
        }
    });
}
```

If symbols are stripped, search for the AES S-box constant (`0x63, 0x7c, 0x77, 0x7b`) in the loaded `libdp.so` memory to locate the encryption routines via pattern scanning.

**Step 5: Dump the dp.mp3 mapping table.** After the app initializes, `dp.mp3` is decrypted in memory. Scan process memory for the decrypted mapping structure:

```javascript
Process.enumerateRanges("r--").forEach(function(range) {
    try {
        var buf = range.base.readByteArray(Math.min(range.size, 0x10000));
        var view = new Uint8Array(buf);
        if (view[0] === 0x00 && view[1] === 0x00 && view[4] !== 0x00) {
            var f = new File("/data/local/tmp/dp_dump_" +
                range.base.toString() + ".bin", "wb");
            f.write(range.base.readByteArray(range.size));
            f.close();
            console.log("Dumped " + range.size + " bytes from " + range.base);
        }
    } catch(e) {}
});
```

**Step 6: Rebuild call graph.** With the dp.mp3 mapping and native bridge hooks, reconstruct which indexes resolve to which methods. The [Romain Thomas analysis](https://www.romainthomas.fr/post/26-01-dexprotector/) documents the index structure in detail.

### vTEE Key Extraction

DexProtector's vTEE CryptoModule uses [white-box cryptography](https://en.wikipedia.org/wiki/White-box_cryptography) to protect key material. The keys are embedded in lookup tables that encode the cryptographic operations. Extracting keys requires:

**Differential Fault Analysis (DFA):** Inject faults into the white-box AES implementation by modifying intermediate values. [Bos et al. (2016)](https://eprint.iacr.org/2015/753) demonstrated that DFA can extract AES keys from white-box implementations in minutes. Apply this by using Frida to corrupt specific memory addresses during encryption rounds and analyzing the faulty ciphertexts.

**Differential Computation Analysis (DCA):** Treat the white-box implementation as a black box and apply side-channel analysis techniques. Record memory access traces during encryption, then apply DPA-style statistical analysis to extract key bytes. The [SideChannelMarvels/Deadpool](https://github.com/SideChannelMarvels/Deadpool) project provides tools for this approach.

**Practical limitations:** Licel has hardened vTEE against known white-box attacks in recent versions. Counter-measures include internal encodings, table splitting, and perturbation tables. No public break of current vTEE versions has been published. For practical analysis, bypassing the vTEE entirely (hooking the plaintext before/after encryption) is more reliable than attempting key extraction.

## Comparison with DexGuard

| Aspect | DexProtector | [DexGuard](dexguard.md) |
|--------|-------------|---------|
| Vendor | Licel | Guardsquare |
| Platform | Android + iOS | Android (iXGuard for iOS) |
| Primary strength | RASP + asset encryption via vtable hooking | Polymorphic code obfuscation |
| Build integration | Post-build (no source code required) | Build-time (Gradle plugin, requires source) |
| Obfuscation approach | Native bridge hiding + encryption | Bytecode-level transformation + encryption |
| Polymorphism | No per-build variation | Each build produces different obfuscation |
| ProGuard/R8 relationship | Compatible as additional layer | Extends ProGuard directly |
| White-box crypto | Yes (vTEE CryptoModule) | No |
| Code virtualization | Hide Access (native bridge) | Optional VM interpreter |
| EMVCo certification | Yes (6 consecutive years) | No |
| Scalability of attacks | Breaking one instance enables attacks on all protected apps | Polymorphism forces per-build analysis |

The fundamental architectural difference: DexGuard integrates at build time and applies polymorphic transformations, meaning each build produces unique obfuscation patterns. DexProtector operates post-build on the compiled artifact, which means its protection mechanisms are structurally consistent across all protected applications. Successfully reverse engineering DexProtector's native layer for one application provides transferable knowledge to all DexProtector-protected apps.

## Malware Usage

DexProtector is less frequently observed in malware than [DexGuard](dexguard.md) or [Chinese packers](chinese-packers.md), but its commercial availability has led to documented abuse.

### Known Campaigns

| Campaign | Details |
|----------|---------|
| Anubis QR Scanner droppers | Private Anubis variant distributed via Google Play QR scanner/reader apps (Feb 2020 -- Mar 2021). DexProtector obfuscated the dropper code. Resulted in 30,000+ infections targeting 200+ banking apps and later expanded to 1,200+ targets. |
| BankBot Google Play campaigns | Sophisticated BankBot campaigns used DexProtector on Play Store droppers. ThreatFabric noted attackers "took the time and effort to buy and integrate DexProtector," indicating higher technical investment than typical campaigns. |

### Usage Pattern

Malware authors who adopt DexProtector typically demonstrate higher operational sophistication. The commercial licensing cost and integration effort filter out lower-tier operators. When DexProtector appears in malware, it usually protects a dropper component distributed through official app stores rather than the final payload itself.

## Analyst Workflow

```
1. Run APKiD -> check for DexProtector detection
2. Inspect assets/ -> look for dp.mp3, dp.arm-v7.so.dat, dp.arm-v8.so.dat
3. Check META-INF/MANIFEST.MF -> "Protected-By" header reveals version
4. Check for dexpro-build.properties -> detection flag configuration
5. Install on physical device (emulator likely blocked)
6. Spawn with Frida (spawn mode) -> hook System.exit early
7. Hook unlink() -> prevent cleanup of decrypted files
8. Run frida-dexdump -> capture decrypted DEX from memory
9. Decompile dumped DEX with JADX
10. For hidden method calls -> hook native bridge functions, log index resolutions
11. For asset decryption -> dump dp.mp3 contents after init completes
```

## Comparison with Other Protectors

| Feature | DexProtector | [DexGuard](dexguard.md) | [Virbox](virbox.md) | [Chinese Packers](chinese-packers.md) |
|---------|-------------|---------|--------|----------------|
| String encryption | White-box crypto, dynamic keys | AES/XOR with method-level keys | VM-based | Basic XOR in native layer |
| DEX encryption | Native bridge + vtable asset hooking | Custom class loader | Full DEX virtualization | DEX-in-assets encryption |
| Code virtualization | Hide Access (native invokedynamic) | Optional VM interpreter | Core feature, full DEX | Not available |
| Asset encryption | vtable hooking in libandroidfw.so | Patched AssetManager | N/A | N/A |
| Anti-debug | Comprehensive (ptrace, JDWP, Frida, Xposed) | Comprehensive | Moderate | Basic (ptrace) |
| RASP | Core feature, app-terminating | Partial | Partial | None |
| White-box crypto | Yes (vTEE CryptoModule) | No | No | No |
| Post-build protection | Yes (no source required) | No (build-time integration) | Yes | Yes |
| Unpacking difficulty | Medium-Hard | Medium | Expert (VM) | Easy-Medium |

## References

- [Licel DexProtector](https://licelus.com/products/dexprotector)
- [DexProtector Documentation](https://licelus.com/products/dexprotector/docs/android/introduction-to-dexprotector)
- [A Glimpse Into DexProtector -- Romain Thomas](https://www.romainthomas.fr/post/26-01-dexprotector/)
- [APKiD DexProtector Signatures](https://github.com/rednaga/APKiD)
- [Android_Dump_Dex -- Frida-based DexProtector dumper](https://github.com/Alexjr2/Android_Dump_Dex)
- [DexProtector EMVCo Certification](https://www.prnewswire.com/news-releases/dexprotector-achieves-emvco-approval-for-5th-consecutive-year-302378869.html)
- [SGSecure DexProtector Analysis](https://medium.com/@dazzleworth13/sgsecure-app-is-using-dexprotector-part-1-84a7aa371644)
- [ThreatFabric -- Anubis QR Scanner Campaigns](https://www.threatfabric.com/blogs/the-rage-of-android-banking-trojans)
- [ThreatFabric -- BankBot Google Play Campaigns](https://www.threatfabric.com/blogs/sophisticated-google-play-bankbot-trojan-campaigns)
