# Hooking

Intercepting function calls at runtime to read arguments, modify return values, or replace functionality entirely. Frida is the standard tool for Android hooking. Xposed provides a framework-level alternative.

## Frida

[Frida](https://frida.re/) injects a JavaScript engine into the target process. Scripts can hook any Java method, native function, or system call.

### Setup

```bash
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"

pip install frida-tools
```

### Basic Java Hooking

Intercept a Java method, read arguments, modify return value:

```javascript
Java.perform(function() {
    var targetClass = Java.use("com.target.app.LoginActivity");

    targetClass.checkPassword.implementation = function(password) {
        console.log("Password entered: " + password);
        var result = this.checkPassword(password);
        console.log("Result: " + result);
        return true;
    };
});
```

### Hooking Overloaded Methods

When a method has multiple signatures:

```javascript
targetClass.send.overload("java.lang.String", "int").implementation = function(msg, code) {
    console.log("send(" + msg + ", " + code + ")");
    return this.send(msg, code);
};
```

### Hooking Constructors

```javascript
targetClass.$init.overload("java.lang.String").implementation = function(param) {
    console.log("Constructor called with: " + param);
    this.$init(param);
};
```

### Native Function Hooking

Hook native (C/C++) functions in shared libraries:

```javascript
Interceptor.attach(Module.findExportByName("libnative.so", "decrypt"), {
    onEnter: function(args) {
        console.log("decrypt called");
        console.log("arg0: " + Memory.readUtf8String(args[0]));
    },
    onLeave: function(retval) {
        console.log("returned: " + Memory.readUtf8String(retval));
    }
});
```

## Common Hooking Tasks

### SSL Pinning Bypass

The most frequent use case. Multiple approaches depending on the pinning implementation:

```javascript
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
        console.log("Bypassing pin for: " + hostname);
    };
});
```

For comprehensive pinning bypass, [Objection](https://github.com/sensepost/objection) automates this:

```bash
objection -g com.target.app explore
android sslpinning disable
```

### Root Detection Bypass

Hook root check methods to return false. The example below covers basic RootBeer checks, but production malware uses multi-layered detection (file checks, property reads, native library probes). [8kSec's advanced root detection bypass guide](https://8ksec.io/advanced-root-detection-bypass-techniques/) covers sophisticated detection mechanisms and Frida-based bypasses beyond basic library hooks:

```javascript
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        console.log("Root check bypassed");
        return false;
    };
});
```

### Emulator Detection Bypass

```javascript
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.PRODUCT.value = "walleye";
    Build.HARDWARE.value = "walleye";
});
```

### Crypto Key Extraction

Hook encryption functions to dump keys and plaintext:

```javascript
Java.perform(function() {
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
        console.log("Algorithm: " + algorithm);
        console.log("Key: " + bytesToHex(keyBytes));
        return this.$init(keyBytes, algorithm);
    };

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("Cipher input: " + bytesToHex(input));
        var result = this.doFinal(input);
        console.log("Cipher output: " + bytesToHex(result));
        return result;
    };
});
```

### DEX Loading Interception

Capture dynamically loaded DEX files (packed apps):

```javascript
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libraryPath, parent) {
        console.log("Loading DEX: " + dexPath);
        this.$init(dexPath, optimizedDir, libraryPath, parent);
    };

    var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buf, loader) {
        console.log("In-memory DEX loaded, size: " + buf.remaining());
        var bytes = new Uint8Array(buf.remaining());
        var file = new File("/data/local/tmp/dumped_" + Date.now() + ".dex", "wb");
        file.write(bytes.buffer);
        file.flush();
        file.close();
        this.$init(buf, loader);
    };
});
```

## Advanced Frida: Memory Operations

Beyond hooking functions, Frida provides direct memory manipulation APIs for native-level analysis. [8kSec's memory operations series](https://8ksec.io/advanced-frida-usage-part-7-frida-memory-operations/) covers the full API:

| API | Purpose |
|-----|---------|
| `Memory.scan()` / `Memory.scanSync()` | Scan process memory for byte patterns |
| `Memory.alloc()` | Allocate memory in the target process |
| `Memory.copy()` / `Memory.dup()` | Copy and duplicate memory regions |
| `Memory.protect()` | Change memory page permissions (RWX) |
| `Memory.patchCode()` | Patch executable code at runtime |

[8kSec's Frida Stalker guide](https://8ksec.io/advanced-frida-usage-part-10-instruction-tracing-using-frida-stalker/) covers instruction-level tracing using Stalker APIs, enabling real-time observation of code execution at the assembly level. This is particularly useful for analyzing obfuscated native code in families like [Mandrake](../malware/families/mandrake.md) that use OLLVM.

## Anti-Frida Detection and Bypass

Malware actively detects Frida to prevent dynamic analysis. Understanding each detection vector is necessary to bypass them.

### Detection Techniques

| Detection Method | Indicator | Implementation |
|-----------------|-----------|----------------|
| Port scanning | TCP port 27042 (default frida-server port) | Socket connect to localhost:27042, if open assume Frida is present |
| Process name | "frida-server" in process list | Read `/proc/*/cmdline` or `ps` output looking for "frida" |
| Memory maps scanning | "frida" strings in `/proc/self/maps` | Open `/proc/self/maps` and scan for "frida-agent", "frida-gadget", or "frida-server" |
| Named pipes | Frida's linjector pipe names | Enumerate `/proc/self/fd/` for pipes matching "linjector" pattern |
| Loaded libraries | `frida-agent*.so` in memory | `dlopen` enumeration or `/proc/self/maps` check for frida-agent shared objects |
| pthread_create hooking | Thread creation patterns | Frida spawns threads during injection -- detect abnormal thread count or thread naming patterns |
| D-Bus protocol detection | Frida's internal D-Bus communication | Send D-Bus `AUTH` message to suspected Frida port and check for a valid reply |
| Inline hook detection | Modified function prologues | Read the first bytes of commonly hooked functions (like `open`, `strcmp`) and compare against known-good prologues |

### `/proc/self/maps` Scanning (Most Common)

The most widespread Frida detection reads `/proc/self/maps` line by line, searching for Frida-related strings. Malware typically runs this in a background thread on a timer:

```javascript
Java.perform(function() {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("maps") !== -1 || cmd.indexOf("frida") !== -1) {
            console.log("Blocked maps/frida scan: " + cmd);
            return this.exec("echo");
        }
        return this.exec(cmd);
    };
});
```

For native-level maps scanning, hook `libc.so` `open` and filter `/proc/self/maps` access:

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path && path.indexOf("/proc/self/maps") !== -1) {
            this.shouldBlock = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldBlock) {
            retval.replace(-1);
        }
    }
});
```

### D-Bus Protocol Detection

Some malware sends a raw D-Bus `AUTH` handshake to suspected Frida ports. If Frida responds, the app terminates:

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        var sockAddr = args[1];
        var port = (Memory.readU8(sockAddr.add(2)) << 8) | Memory.readU8(sockAddr.add(3));
        if (port === 27042) {
            console.log("Blocked connect to Frida port");
            this.shouldBlock = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldBlock) {
            retval.replace(-1);
        }
    }
});
```

### Bypass Strategies

| Strategy | How | Trade-offs |
|----------|-----|------------|
| Rename frida-server | `cp frida-server fs-15.x` and run the renamed binary | Simple but only evades name-based detection |
| Non-default port | `frida-server -l 0.0.0.0:1234` | Defeats port 27042 scanning only |
| Frida Gadget injection | Embed `frida-gadget.so` directly into the APK's lib folder | No frida-server process, survives process name checks |
| Hook detection functions | Intercept `open()`, `fopen()`, `access()` calls targeting `/proc/self/maps` | Comprehensive but can be detected by syscall-level checks |
| Magisk + Shamiko | Use [Shamiko](https://github.com/LSPosed/LSPosed.github.io) to hide root and Frida from process | Hides at zygote level, effective against most checks |
| Stalker-based tracing | Use Frida Stalker instead of Interceptor to avoid inline hook artifacts | Slower but undetectable by prologue checking |
| Kernel-level hiding | Custom kernel module to filter `/proc/self/maps` entries | Most thorough, requires custom kernel |
| Patch detection out | Remove Frida detection entirely from the APK (see [Patching](patching.md)) | Permanent fix, avoids the cat-and-mouse entirely |

### Frida Gadget (Rootless Injection)

When root is unavailable or frida-server is detected, inject Frida Gadget directly into the APK:

```bash
apktool d target.apk -o target_patched/
cp frida-gadget-16.x.x-android-arm64.so target_patched/lib/arm64-v8a/libfrida-gadget.so
```

Add a `System.loadLibrary` call in the main activity's Smali to load the gadget at startup:

```smali
const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

Reassemble, sign, and install. The app loads Frida Gadget on launch without needing frida-server.

## Xposed Framework

Xposed operates at the ART (Android Runtime) level, replacing method entry points in the runtime's internal method table. When a hooked method is called, ART redirects execution to the Xposed callback before (or instead of) the original implementation.

[LSPosed](https://github.com/LSPosed/LSPosed) is the modern Xposed implementation for Android 8.1+, installed as a Magisk module. It uses Riru or Zygisk to inject into the zygote process, which means hooks are active from the moment an app process is forked.

### How ART Method Hooking Works

Xposed replaces the `entry_point_from_quick_compiled_code` field in ART's `ArtMethod` struct. When the VM calls a hooked method, it jumps to Xposed's trampoline instead of the original compiled code. The trampoline invokes registered callbacks, then optionally calls the original method.

This is fundamentally different from Frida's approach: Frida injects into a running process and patches code in memory, while Xposed modifies the runtime's method dispatch table at process creation time.

### LSPosed Module Structure

An Xposed module is an Android app with a `xposed_init` file declaring the entry class:

```java
public class HookModule implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.target.malware")) return;

        XposedHelpers.findAndHookMethod(
            "com.target.malware.SecurityCheck",
            lpparam.classLoader,
            "isRooted",
            new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return false;
                }
            }
        );
    }
}
```

For before/after hooks instead of full replacement:

```java
XposedHelpers.findAndHookMethod(
    "javax.crypto.Cipher",
    lpparam.classLoader,
    "doFinal",
    byte[].class,
    new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            byte[] input = (byte[]) param.args[0];
            XposedBridge.log("Cipher.doFinal input: " + bytesToHex(input));
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            byte[] output = (byte[]) param.getResult();
            XposedBridge.log("Cipher.doFinal output: " + bytesToHex(output));
        }
    }
);
```

### Frida vs. Xposed

| Aspect | Frida | Xposed / LSPosed |
|--------|-------|-------------------|
| Hook timing | Attaches to running process | Active from process creation (zygote fork) |
| Persistence | Script must be re-run each session | Hooks survive app restarts and reboots |
| Iteration speed | Instant -- edit JS script, re-attach | Requires module rebuild and device reboot |
| Module changes | Immediate | Requires reboot (or soft reboot via LSPosed manager) |
| Language | JavaScript (with Java.perform bridge) | Java / Kotlin |
| Root requirement | Yes (frida-server) or Gadget injection | Yes (Magisk + LSPosed) |
| Detection surface | Detectable via port, maps, thread artifacts | Lower profile -- no separate server process |
| Native hooks | Full support (Interceptor, Stalker) | Limited -- primarily targets Java/ART methods |
| Interactive exploration | REPL, live scripting, object inspection | No REPL -- compile, install, reboot cycle |
| Best for | Dynamic exploration, one-off analysis | Persistent monitoring, long-running malware observation |

Xposed is particularly useful when analyzing malware that actively detects Frida, since LSPosed hooks leave fewer artifacts. It is also preferable for long-running observation sessions where restarting Frida scripts is impractical.

## Family-Specific Hooking

Certain malware families require targeted hooks to extract key data:

| Family | What to Hook | Purpose |
|--------|-------------|---------|
| [Cerberus](../malware/families/cerberus.md) lineage | `javax.crypto.Cipher.doFinal` | Decrypt C2 communication and overlay inject URLs |
| [GodFather](../malware/families/godfather.md) v3 | VirtualApp framework APIs | Intercept virtualized banking app interactions |
| [Anatsa](../malware/families/anatsa.md) | AccessibilityService.onAccessibilityEvent | Observe ATS command sequence |
| [Mandrake](../malware/families/mandrake.md) | OLLVM-protected native functions via Stalker | Trace obfuscated control flow |
| [SharkBot](../malware/families/sharkbot.md) | DGA algorithm function | Predict future C2 domains |
| [Vultur](../malware/families/vultur.md) | AlphaVNC initialization | Capture screen streaming setup |
| [SpyNote](../malware/families/spynote.md) | Socket/DataOutputStream | Intercept RAT command protocol |
| [Necro](../malware/families/necro.md) | BitmapFactory + pixel extraction | Capture steganographic payload |
| [Gigabud](../malware/families/gigabud.md) | `libstrategy.so` native functions | Intercept UI interaction commands |
| [BTMOB RAT](../malware/families/btmob.md) | WebView `loadUrl` / `evaluateJavascript` | Capture injected phishing pages |
| [LightSpy](../malware/families/lightspy.md) | Plugin loader + `light2.db` SQLite | Intercept plugin download and C2 config |
| [FluHorse](../malware/families/fluhorse.md) | Dart FFI bridge in `libapp.so` | Hook the Dart-to-native boundary for credential interception |
| [Rafel RAT](../malware/families/rafelrat.md) | `DevicePolicyManager` + `Cipher.doFinal` | Intercept admin commands and ransomware encryption |
| [KoSpy](../malware/families/kospy.md) | Firebase Firestore `getDocument` | Capture C2 configuration delivery |
| All packed families | DexClassLoader, InMemoryDexClassLoader | Dump decrypted DEX payload |

### Accessibility Service Monitoring

For families using accessibility-based ATS, hook the accessibility service to observe the full fraud sequence:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var cls = Java.use(className);
                if (cls.class.getSuperclass() &&
                    cls.class.getSuperclass().getName() === "android.accessibilityservice.AccessibilityService") {
                    cls.onAccessibilityEvent.implementation = function(event) {
                        console.log("[A11y] " + event.getEventType() + " pkg=" + event.getPackageName() + " text=" + event.getText());
                        this.onAccessibilityEvent(event);
                    };
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
});
```

## reFrida

[reFrida](https://github.com/zahidaz/refrida) is a browser-based Frida IDE that replaces the typical workflow of editing scripts in a text editor and running them via CLI. It connects to a running frida-server and provides a full development environment in the browser.

Key capabilities:

- **Monaco editor** with Frida API autocompletion, syntax highlighting, and inline documentation
- **Visual interceptor builder** -- select a class and method from a tree view, and reFrida generates the hook code automatically. Useful for quickly building hooks without memorizing overload signatures.
- **Built-in disassembler** -- disassemble native functions directly from the browser, navigate to cross-references, and set hooks on specific instructions
- **Memory search** -- scan process memory for strings, byte patterns, or values with a visual interface (wraps `Memory.scan` with result highlighting)
- **Stalker integration** -- configure and run Stalker traces with visual output of executed basic blocks and call graphs
- **Script management** -- save, load, and organize scripts per target application

reFrida is particularly effective for malware analysis workflows where you need to rapidly iterate on hooks, inspect memory regions, and trace native code execution without switching between multiple terminal sessions.

## Task-Oriented Hooking Strategies

Beyond family-specific hooks, certain analysis goals map to standard hook points regardless of the malware family:

| Analysis Goal | What to Hook | Why |
|---------------|-------------|-----|
| Intercept overlay injection | `WindowManager.addView`, `WindowManager.LayoutParams` | Banking trojans overlay fake login screens on top of legitimate apps |
| Capture C2 traffic | `OkHttpClient.newCall`, `HttpURLConnection.connect`, `URL.openConnection` | Intercept HTTP-based C2 before SSL encryption |
| Extract encryption keys | `SecretKeySpec.$init`, `Cipher.doFinal`, `Mac.doFinal` | Dump keys and plaintext at the crypto API boundary |
| Monitor SMS exfiltration | `SmsManager.sendTextMessage`, `SmsManager.sendMultipartTextMessage` | Catch outbound SMS used for OTP forwarding or premium abuse |
| Track file system activity | `File.$init`, `FileOutputStream.write`, `SharedPreferences.edit` | Observe config drops, payload writes, and preference changes |
| Capture screen recording | `MediaProjection.createVirtualDisplay`, `ImageReader.acquireLatestImage` | Detect VNC/screen streaming setup used by RAT families |
| Monitor accessibility abuse | `AccessibilityService.onAccessibilityEvent`, `performAction`, `performGlobalAction` | Observe ATS commands (clicks, scrolls, gestures) during automated fraud |
| Intercept dynamic loading | `DexClassLoader.$init`, `InMemoryDexClassLoader.$init`, `ClassLoader.loadClass` | Capture unpacked or stage-2 payloads at load time |
| Track permission abuse | `DevicePolicyManager.lockNow`, `DevicePolicyManager.resetPassword` | Detect device admin abuse (screen lock, wipe threats) |
| DNS/domain resolution | `InetAddress.getByName`, `InetAddress.getAllByName` | Capture DGA output or C2 domain resolution |
| WebView injection | `WebView.loadUrl`, `WebView.evaluateJavascript`, `WebViewClient.shouldInterceptRequest` | Intercept injected phishing pages and JavaScript payloads |
| Clipboard theft | `ClipboardManager.setPrimaryClip`, `ClipboardManager.getPrimaryClip` | Detect clipboard monitoring for crypto wallet address swapping |

## Tools

| Tool | Purpose |
|------|---------|
| [Frida](https://frida.re/) | Runtime instrumentation |
| [reFrida](https://github.com/zahidaz/refrida) | Browser-based Frida IDE with visual interceptor builder, disassembler, and Stalker integration |
| [Objection](https://github.com/sensepost/objection) | Frida-powered automation (SSL bypass, root bypass, etc.) |
| [LSPosed](https://github.com/LSPosed/LSPosed) | Xposed framework for modern Android |
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Dump DEX from memory via Frida |
| [r2frida](https://github.com/nowsecure/r2frida) | Radare2 + Frida integration |
| [medusa](https://github.com/Ch0pin/medusa) | Extensible Frida wrapper for common hooking tasks |

## SSL Pinning: Current State

Google now recommends against SSL pinning in Android security best practices. [8kSec's analysis](https://8ksec.io/why-you-should-remove-ssl-pinning-from-your-mobile-apps-in-2025/) covers why: pinning is trivially bypassed with Frida, creates maintenance burden, and provides minimal security benefit for most threat models since the Android platform's certificate transparency and Play Integrity checks provide stronger guarantees. For malware analysis, pinning bypass remains a routine first step (see SSL Pinning Bypass above).
