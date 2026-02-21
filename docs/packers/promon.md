# Promon SHIELD

Promon SHIELD is a commercial RASP (Runtime Application Self-Protection) solution developed by **Promon** (Oslo, Norway). Unlike traditional packers that encrypt DEX bytecode, SHIELD focuses on runtime integrity checks, environment detection, and anti-tampering. It is the dominant mobile app protection solution in European banking, reportedly used by over 50% of leading European financial institutions.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Promon AS |
| Origin | Oslo, Norway |
| Type | Commercial RASP / Application Shielding |
| Platforms | Android, iOS, Desktop (Windows, macOS) |
| Products | SHIELD for Mobile, SHIELD for Desktop, SDK Protection, IP Protection Pro |
| Founded | 2006 |

## RASP vs Packer

Promon SHIELD operates fundamentally differently from packers like [DexGuard](dexguard.md) or [Virbox](virbox.md).

| Aspect | RASP (Promon SHIELD) | Packer (DexGuard, Virbox) |
|--------|----------------------|---------------------------|
| Primary function | Runtime environment monitoring | Code transformation and encryption |
| DEX encryption | No | Yes |
| String encryption | No (externalizes to native layer) | Yes (inline decryption methods) |
| Code virtualization | No | Yes (Virbox), optional (DexGuard) |
| Anti-debugging | Core feature | Secondary feature |
| Root/hook detection | Core feature | Secondary feature |
| Overlay protection | Yes | No |
| Screen capture blocking | Yes | No |
| Integration model | Injected native library + config | Build-time transformation |

SHIELD wraps an application by injecting a native library that loads before anything else in the process. The library performs all checks at the native level, making Java-layer bypasses insufficient. The app's own code remains largely unmodified -- the protection is external rather than woven into the bytecode.

## Identification

### APKiD Detection

APKiD detects Promon SHIELD through ELF segment analysis of native libraries:

```
packer : Promon Shield
```

Detection is segment-based rather than filename-based, since library names are randomized in newer versions.

### File Artifacts

| Artifact | Description |
|----------|-------------|
| Native library | Randomized name (e.g., `libenhefoocjfcl.so`, `libniiblkgocjbb.so`). Legacy versions used `libshield.so` or `libshield.XXXXXXXX.so` |
| Config file | `config-encrypt.txt` in assets -- encrypted configuration consumed by the native library |
| Mapping file | `pbi.bin` in assets -- encrypted mapping data |
| Architecture | Typically `arm64-v8a`, may include `armeabi-v7a` and `x86` |
| Library size | Noticeably large compared to typical app native libraries |

### Java-Side Indicators

Promon SHIELD externalizes strings and class initialization to native methods. A bridge class (obfuscated name, e.g., `C6539Z`) exposes two native methods:

```java
native String m1788a(int i);
native void m1787a(Class cls, int i);
```

The first retrieves strings by index from the native layer. The second initializes classes by ID. The library name itself is XOR-encrypted before being passed to `System.loadLibrary()`.

If decompiled code shows string retrieval through indexed native calls rather than inline string literals or Java-based decryption methods, it is likely Promon SHIELD.

### Distinguishing from Other Protectors

- **No DEX encryption**: classes.dex is readable in JADX (strings are missing, but structure is intact)
- **No `o`/`oo`/`ooo` decryption classes**: unlike [DexGuard](dexguard.md), there are no Java string decryption stubs
- **Single large native library**: unlike Chinese packers that have recognizable library names (`libjiagu.so`, `libshella.so`)
- **OLLVM-obfuscated native code**: the native library uses Obfuscator-LLVM with control flow flattening

## Protection Mechanisms

### Native Library Lifecycle

1. `.init_array` constructor executes before `JNI_OnLoad`
2. Constructor unpacks the encrypted `.text` section and resolves imports dynamically via `dlsym()` and direct syscalls (`SVC 0`)
3. Configuration is decrypted from `config-encrypt.txt`
4. Environment checks begin immediately
5. If checks pass, the app's original code proceeds normally

### Anti-Debugging

**Process isolation via ptrace lock:**

1. `fork()` creates a child process
2. Parent calls `prctl(PR_SET_PTRACER)` to restrict tracing to the child only
3. Child attaches to parent via `ptrace(PTRACE_ATTACH)`
4. `prctl(PR_SET_DUMPABLE, false)` blocks external debuggers

This prevents any other process from attaching a debugger to the protected app. The child process acts as a watchdog.

**JDWP disablement:**

Patches `art::JDWP::JdwpState::HandlePacket()` at the ART runtime level to kill Java debugging entirely. This goes beyond checking `ro.debuggable` -- it neutralizes the debug protocol handler in-process.

### Root Detection

Checks over 20 system properties and file paths:

| Category | Examples |
|----------|----------|
| System properties | `ro.debuggable`, `ro.secure`, `persist.sys.root_access`, `service.adb.root` |
| Su binaries | `/system/xbin/su`, `/system/bin/su`, `/sbin/su` |
| Magisk artifacts | `/data/adb/magisk/magisk`, `/data/data/com.topjohnwu.magisk` |
| SuperSU artifacts | `/init.supersu.rc`, SuperSU package paths |
| Other root tools | Kingroot paths, root management app packages |

Directory watches via `inotify_add_watch()` monitor `/bin`, `/system/bin`, `/system/xbin`, and `/vendor/bin` for changes -- detecting root tools installed after the app starts.

### Hooking Framework Detection

| Framework | Detection Method |
|-----------|-----------------|
| Frida | Scans `/proc/self/maps` for `libFridaGadget.so`, checks memory page integrity |
| Xposed | Looks for `libxposed_art.so` in memory, checks for `art::mirror::ArtMethod::EnableXposedHook()` export symbol |
| Cydia Substrate | Scans for `libsubstrate.so` and `libsubstrate-dvm.so` in loaded libraries |
| Memory patching | Validates memory page contents -- modifications trigger process termination |

### Emulator Detection

Checks system properties that leak virtual hardware:

- `ro.kernel.qemu` (QEMU-based emulators)
- `ro.hardware` (goldfish, ranchu)
- Device manufacturer, model, and hardware strings
- ChromeOS and virtual machine indicators
- Telephony state anomalies
- Hardware sensor availability

### Repackaging Detection

1. Opens the installed `base.apk` directly via `openat()` syscall (bypasses Java file APIs)
2. Parses the APK signing block to extract signing certificates
3. Compares against expected certificate embedded in the native library
4. Verifies `libshield.so` checksum before proceeding with other checks

The syscall-based file access makes it harder to intercept with standard Java hooks.

### Overlay Detection

Detects if another application draws over the protected app's window. Prevents [tapjacking](../attacks/tapjacking.md) and phishing overlays that attempt to capture user input. The app can block interaction, alert the user, or terminate when an overlay is detected.

### Screen Capture Prevention

Blocks screenshots, screen recordings, and screen mirroring of the protected app. Uses `FLAG_SECURE` and additional native-level enforcement to prevent data leakage through screen capture.

### Dynamic Imports and Syscalls

The native library avoids standard libc imports for security-critical operations. Functions resolved at runtime via `dlsym()` or invoked through direct `SVC 0` syscalls include:

```
ptrace, prctl, fork, execl, __system_property_get,
dlopen, dladdr, inotify_init, inotify_add_watch,
eventfd, dl_iterate_phdr, openat, read, write, mmap
```

Direct syscalls bypass any LD_PRELOAD or linker-level hooking.

### Native Code Obfuscation

The SHIELD library itself is protected with:

- **OLLVM control flow flattening**: function CFGs are destroyed and replaced with dispatcher-based execution
- **Packed .text section**: encrypted at rest, unpacked by `.init_array` constructor at load time
- **No readable string table**: strings resolved dynamically
- **Stripped symbols**: no exported function names beyond JNI entry points

## Unpacking Methodology

### Frida-Based String Index Enumeration

Since SHIELD externalizes all strings to native methods accessed by index, you can brute-force the index space to reconstruct the string table:

```javascript
Java.perform(function() {
    var bridge = Java.use("com.target.app.C6539Z");
    for (var i = 0; i < 5000; i++) {
        try {
            var s = bridge.m1788a(i);
            if (s !== null && s.length > 0) {
                console.log("idx " + i + " -> " + s);
            }
        } catch(e) {}
    }
});
```

The bridge class name and method name will differ per app -- locate them by searching for classes with native methods that take a single `int` parameter and return `String`.

### Bypassing ptrace Lock

The fork-and-attach pattern can be defeated by:

1. **Patching the native library**: NOP out the `fork()` and `ptrace()` calls in the unpacked `.text` section
2. **Early Frida injection**: attach Frida before the native library's `.init_array` runs by spawning with `frida -f` and hooking `android_dlopen_ext` to intercept the library load
3. **Hooking `fork()`**: return 0 (pretend to be the child) or -1 (pretend fork failed) to prevent the watchdog process from starting

### Bypassing Root Detection

```javascript
Java.perform(function() {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            throw Java.use("java.io.IOException").$new("not found");
        }
        return this.exec(cmd);
    };
});
```

For native-level checks, intercept `__system_property_get` via `Interceptor.attach`:

```javascript
var prop_get = Module.findExportByName(null, "__system_property_get");
Interceptor.attach(prop_get, {
    onEnter: function(args) {
        this.name = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.name === "ro.debuggable" || this.name === "ro.secure") {
            args[1].writeUtf8String("0");
        }
    }
});
```

### Bypassing Repackaging Detection

The `promon-reversal` project demonstrates that APK signature verification can be bypassed by:

1. Extracting the original signing certificate from the native library's embedded data
2. Hooking the certificate comparison at the native level
3. Returning the expected certificate when SHIELD performs its check

### Native Library Patching

For persistent bypass (lab environment):

```
1. Extract the APK
2. Identify the SHIELD library (randomized name, largest .so in lib/)
3. Load in Ghidra/IDA -> locate .init_array entry point
4. Trace from init_array through the unpacking routine
5. Dump the unpacked .text section at runtime
6. Patch detection routines (NOP out fork/ptrace/property checks)
7. Replace the library, resign the APK
8. Install with signature verification bypass (Frida hook or debug certificate)
```

This approach requires re-bypassing the repackaging check since the modified library will fail its own integrity verification.

### Magisk-Based Approach

MagiskHide (deprecated) or Shamiko/Zygisk-based hiding can prevent SHIELD from seeing root artifacts in the filesystem and process list. Combined with a Frida server renamed and running on a non-default port, this avoids the most common detection vectors.

## Banking App Context

Promon SHIELD is the primary protection for European banking and financial apps. During mobile penetration tests of banking applications, SHIELD is the most frequently encountered defense layer.

Key considerations for pentesters:

| Aspect | Detail |
|--------|--------|
| Prevalence | Over 50% of top European banks reportedly use Promon SHIELD |
| Typical deployment | Combined with certificate pinning, obfuscation (often R8/ProGuard), and server-side fraud detection |
| Response behavior | Configurable per customer -- may silently report, block functionality, or force-close the app |
| Multi-layered | Banks often stack SHIELD with DexGuard or proprietary obfuscation |
| Server reporting | Detection events may be reported server-side, potentially flagging the tester's device or account |

When assessing a SHIELD-protected banking app, disable telemetry reporting hooks early to avoid triggering server-side fraud alerts during testing.

## Comparison with Other Protectors

| Feature | Promon SHIELD | [DexGuard](dexguard.md) | [Virbox](virbox.md) | [Chinese Packers](tencent-legu.md) |
|---------|---------------|----------|--------|----------------|
| Primary approach | RASP (runtime checks) | Code transformation | DEX virtualization | DEX encryption |
| DEX encryption | No | Yes | Yes (VM-based) | Yes |
| String protection | Native externalization | AES/XOR decryption | VM-based | Native layer XOR |
| Anti-debugging | Comprehensive (ptrace lock, JDWP patch) | Comprehensive | Moderate | Basic |
| Root detection | Comprehensive (20+ checks, inotify) | Moderate | Moderate | Basic |
| Overlay protection | Yes | No | No | No |
| Screen capture block | Yes | No | No | No |
| Hooking detection | Frida, Xposed, Substrate, memory integrity | Frida, Xposed | ptrace, debug flags | ptrace |
| Bypass difficulty | Medium-High (native-heavy) | Medium (Frida hooks effective) | High (VM interpretation) | Low (DEX dump) |
| Typical customers | European banks, fintech | Enterprise, some malware | Chinese market, some malware | Chinese market, malware |

## Analyst Workflow

```
1. Run APKiD -> confirm "Promon Shield" detection on the native library
2. Open in JADX -> note intact class structure but missing string literals
3. Locate the bridge class with native int->String methods
4. Spawn app with Frida (-f flag to attach early)
5. Hook android_dlopen_ext to intercept SHIELD library loading
6. Enumerate string indices via the bridge class native method
7. Hook fork() and ptrace() to disable the anti-debug watchdog
8. Hook __system_property_get to feed clean values for root checks
9. If repackaging needed -> bypass certificate verification at native level
10. For SSL pinning -> standard Frida SSL pinning bypass after RASP is neutralized
```

The critical difference from packer analysis: there is no DEX to unpack. The app code is already readable. The challenge is getting the app to run in an instrumented environment, not recovering hidden code.

## References

- [Promon SHIELD for Mobile](https://promon.io/products/shield-mobile)
- [Promon SHIELD 7.0 Release](https://promon.io/security-news/new-promon-shield-7.0-september-2024)
- [promon-reversal -- Analysis and PoC Bypass](https://github.com/KiFilterFiberContext/promon-reversal)
- [APKiD Promon Detection (Issue #267)](https://github.com/rednaga/APKiD/issues/267)
- [APKiD Promon SHIELD at 34C3 (Issue #72)](https://github.com/rednaga/APKiD/issues/72)
- [Honey, I Shrunk Your App Security (DIMVA 2018)](https://obfuscator.re/nomorp-paper-dimva2018.pdf)
- [APKiD -- Android Application Identifier](https://github.com/rednaga/APKiD)
