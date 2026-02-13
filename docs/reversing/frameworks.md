# Development Frameworks

Identifying which development framework built an Android app determines the entire reverse engineering approach. Each framework stores code in different formats, requires different decompilation tools, and presents different hooking surfaces. An app built with Flutter has zero useful DEX code; a Cordova app has all its logic in plaintext JavaScript. Misidentifying the framework wastes hours applying the wrong toolchain.

## Framework Identification

The fastest way to identify a framework is to unzip the APK and check for indicator files and native libraries.

| Framework | File Indicators | Native Libraries | Package/Class Markers |
|-----------|----------------|-------------------|----------------------|
| React Native | `assets/index.android.bundle` | `libjsc.so` (JavaScriptCore) or `libhermes.so` (Hermes) | `com.facebook.react.*` classes in DEX |
| Flutter | `assets/flutter_assets/kernel_blob.bin` (debug) | `libflutter.so`, `libapp.so` | `io.flutter.*` in DEX (thin bootstrap only) |
| Xamarin | `assemblies/*.dll` in APK root or `assets/` | `libmonosgen-2.0.so`, `libxamarin-app.so` | `mono.MonoRuntimeProvider` in DEX |
| Cordova / Ionic | `assets/www/index.html`, `assets/www/cordova.js` | None framework-specific | `org.apache.cordova.*` classes |
| Capacitor | `assets/public/index.html` | None framework-specific | `com.getcapacitor.*` classes |
| Unity (Mono) | `assets/bin/Data/Managed/*.dll` | `libmono.so`, `libunity.so` | `com.unity3d.player.UnityPlayer` |
| Unity (IL2CPP) | `assets/bin/Data/Managed/Metadata/global-metadata.dat` | `libil2cpp.so`, `libunity.so` | `com.unity3d.player.UnityPlayer` |
| NativeScript | `assets/app/bundle.js` or `assets/app/*.js` | `libNativeScript.so` | `org.nativescript.*` classes |
| Kotlin Multiplatform | No unique file indicators | None framework-specific | Standard Kotlin classes in DEX, shared module naming patterns |
| Qt for Android | `assets/--Updated-files/` or `assets/*.rcc` | `libQt5Core_*.so`, `libQt6Core_*.so` | `org.qtproject.qt5.*` or `org.qtproject.qt.*` |
| Corona / Solar2D | `assets/resource.car` | `libcorona.so`, `liblua.so` | `com.ansca.corona.*` classes |
| Cocos2d-x | `assets/res/`, `assets/src/*.lua` or `assets/script/` | `libcocos2dlua.so` or `libcocos2djs.so` | `org.cocos2dx.*` classes |

## Framework Detection Script

Shell-based detection by examining APK contents:

```bash
unzip -l target.apk > /tmp/apk_contents.txt

if grep -q "assets/index.android.bundle" /tmp/apk_contents.txt; then
    if grep -q "libhermes.so" /tmp/apk_contents.txt; then
        echo "React Native (Hermes engine)"
    else
        echo "React Native (JavaScriptCore)"
    fi
elif grep -q "libflutter.so" /tmp/apk_contents.txt; then
    echo "Flutter"
elif grep -q "assemblies/" /tmp/apk_contents.txt; then
    echo "Xamarin / .NET MAUI"
elif grep -q "assets/www/cordova.js" /tmp/apk_contents.txt; then
    echo "Cordova / Ionic"
elif grep -q "assets/public/index.html" /tmp/apk_contents.txt; then
    echo "Capacitor"
elif grep -q "libil2cpp.so" /tmp/apk_contents.txt; then
    echo "Unity (IL2CPP)"
elif grep -q "libmono.so" /tmp/apk_contents.txt && grep -q "libunity.so" /tmp/apk_contents.txt; then
    echo "Unity (Mono)"
elif grep -q "libNativeScript.so" /tmp/apk_contents.txt; then
    echo "NativeScript"
elif grep -q "libQt5Core" /tmp/apk_contents.txt || grep -q "libQt6Core" /tmp/apk_contents.txt; then
    echo "Qt for Android"
elif grep -q "libcorona.so" /tmp/apk_contents.txt; then
    echo "Corona / Solar2D"
elif grep -q "libcocos2d" /tmp/apk_contents.txt; then
    echo "Cocos2d-x"
else
    echo "Native Android (Java/Kotlin)"
fi
```

Frida-based runtime detection:

```javascript
Java.perform(function() {
    var dominated = false;

    try {
        Java.use("com.facebook.react.ReactActivity");
        send("Framework: React Native");
        dominated = true;
    } catch(e) {}

    try {
        Java.use("io.flutter.embedding.engine.FlutterEngine");
        send("Framework: Flutter");
        dominated = true;
    } catch(e) {}

    try {
        Java.use("mono.MonoRuntimeProvider");
        send("Framework: Xamarin");
        dominated = true;
    } catch(e) {}

    try {
        Java.use("org.apache.cordova.CordovaActivity");
        send("Framework: Cordova");
        dominated = true;
    } catch(e) {}

    try {
        Java.use("com.unity3d.player.UnityPlayer");
        send("Framework: Unity");
        dominated = true;
    } catch(e) {}

    if (!dominated) {
        send("Framework: Native Android");
    }
});
```

## Framework-Specific Analysis

### React Native

**Architecture:** JavaScript bundle (`assets/index.android.bundle`) executes on either JavaScriptCore (JSC) or the Hermes engine. The DEX layer contains only the React Native bridge and native module registrations. All business logic lives in JavaScript.

**Identifying the JS engine:**

| Engine | Indicator | Bundle Format |
|--------|-----------|---------------|
| Hermes | `libhermes.so` in `lib/` | Binary `.hbc` (Hermes bytecode) |
| JavaScriptCore | `libjsc.so` in `lib/` | Plain JavaScript (minified) |

**Hermes bytecode analysis:**

Hermes compiles JavaScript to `.hbc` bytecode for faster startup. The bundle at `assets/index.android.bundle` contains a Hermes binary header (magic bytes `c6 1f bc 03`). Tools for decompilation:

| Tool | Purpose |
|------|---------|
| [hbctool](https://github.com/nicksdevice/nicksdevice) | Disassemble/reassemble Hermes bytecode |
| [hermes-dec](https://github.com/nicksdevice/nicksdevice) | Decompile Hermes bytecode back to readable JavaScript |
| [jadx](https://github.com/nicksdevice/nicksdevice) | Useless for app logic -- only shows bridge code |

**Non-Hermes (JSC) analysis:**

The bundle is standard JavaScript, possibly minified with Metro bundler. Extract and beautify:

```bash
unzip -o target.apk assets/index.android.bundle -d /tmp/
npx js-beautify /tmp/assets/index.android.bundle > /tmp/bundle_readable.js
```

Search the beautified bundle for API endpoints, hardcoded secrets, and authentication logic. The entire application state machine is in this single file.

**Obfuscation:** Jscrambler is the most common commercial obfuscator for React Native bundles. It applies control flow flattening, string encoding, and dead code injection to the JavaScript. Metro's built-in minification only removes whitespace and shortens variable names.

**Hooking strategy:**

Standard Frida Java hooks only reach the bridge layer, not the application logic. For Hermes apps, hook the native Hermes runtime functions:

```javascript
var hermesInternal = Module.findExportByName("libhermes.so", "_ZN8facebook6hermes15HermesRuntimeD1Ev");
if (hermesInternal) {
    send("Hermes runtime detected");
}

Interceptor.attach(Module.findExportByName("libhermes.so", "nativeCallSyncHook"), {
    onEnter: function(args) {
        send("Native bridge call intercepted");
    }
});
```

**SSL pinning bypass:** If the app uses `react-native-ssl-pinning` or a custom native TrustManager, standard Java-layer OkHttp hooks work. If pinning is implemented in the JavaScript layer via a custom fetch wrapper, patch the bundle directly or hook the native HTTP module.

**Malware context:** React Native enables rapid cross-platform deployment of phishing apps. Threat actors build a single phishing interface and deploy to both Android and iOS simultaneously. The JS bundle often contains hardcoded C2 URLs and phishing target lists.

### Flutter

**Architecture:** Dart source compiles ahead-of-time (AOT) to native ARM machine code, stored in `libapp.so`. The Flutter engine (`libflutter.so`) provides the runtime. Zero application logic exists in the DEX layer -- the DEX code is a thin Kotlin/Java wrapper that bootstraps the Flutter engine.

**Build modes and their artifacts:**

| Mode | `libapp.so` | `kernel_blob.bin` | Reversibility |
|------|-------------|-------------------|---------------|
| Debug | Not present | Present (Dart kernel snapshot) | Easier -- snapshot contains type info |
| Profile | AOT snapshot | Not present | Moderate |
| Release | AOT snapshot (stripped) | Not present | Hardest -- symbols stripped |

**Toolchain:**

| Tool | Purpose |
|------|---------|
| [blutter](https://github.com/nicksdevice/blutter) | Best current tool. Parses Dart AOT snapshots, recovers class/method names, field types, and string references from `libapp.so` |
| [reFlutter](https://github.com/nicksdevice/reflutter) | Patches `libflutter.so` to enable SSL traffic interception and snapshot extraction |
| [Doldrums](https://github.com/nicksdevice/doldrums) | Older Dart snapshot parser, supports limited Dart SDK versions |

**Analysis workflow:**

1. Extract `libapp.so` and `libflutter.so` from the APK
2. Determine the Dart SDK version from `libflutter.so` strings (search for `Dart SDK version:`)
3. Run blutter against `libapp.so` with the matching SDK version
4. blutter outputs recovered class hierarchies, method signatures with offsets, and string literals
5. Import blutter's output into Ghidra/IDA to annotate the native binary with Dart symbol names

**SSL pinning bypass:** Flutter does not use the Android system certificate store. It bundles BoringSSL directly into `libflutter.so` and performs certificate verification internally. Standard Java-layer Frida hooks have zero effect. Bypass methods:

| Method | Approach |
|--------|----------|
| reFlutter | Patches `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so` to always return valid |
| Binary patch | Use Ghidra to locate the verification function in `libflutter.so` and NOP out the check |
| Frida native hook | Hook the BoringSSL verification function at runtime |

```javascript
var flutter = Module.findBaseAddress("libflutter.so");
var verify = Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain");
if (verify) {
    Interceptor.replace(verify, new NativeCallback(function() {
        return 1;
    }, "int", []));
}
```

**Hooking Dart functions:** Since Dart compiles to native code, hooking requires targeting native function addresses extracted by blutter:

```javascript
var libapp = Module.findBaseAddress("libapp.so");
var targetMethodOffset = 0x1a3f40;
Interceptor.attach(libapp.add(targetMethodOffset), {
    onEnter: function(args) {
        send("Dart method called at offset " + targetMethodOffset.toString(16));
    }
});
```

**Malware context:** [FluHorse](../malware/families/fluhorse.md) is the primary Flutter-based malware family. It targets banking credentials by mimicking legitimate financial apps. The Dart AOT compilation provides inherent obfuscation since standard Android RE tools (jadx, apktool) produce no useful output.

### Xamarin

**Architecture:** C# source compiles to Common Intermediate Language (IL) and runs on the Mono runtime (Xamarin classic) or is AOT-compiled (.NET MAUI). Two distinct modes require different analysis approaches.

**Mono mode (assemblies visible):**

The APK contains `assemblies/*.dll` files with standard .NET IL code. These DLLs decompile to near-source-quality C# using .NET decompilers:

| Tool | Purpose |
|------|---------|
| [dnSpy](https://github.com/nicksdevice/nicksdevice) | .NET debugger and decompiler, best for interactive analysis |
| [ILSpy](https://github.com/nicksdevice/nicksdevice) | Open-source .NET decompiler |
| [dotPeek](https://www.jetbrains.com/decompiler/) | JetBrains .NET decompiler |

```bash
unzip target.apk assemblies/* -d /tmp/xamarin_out/
```

Open the extracted DLLs in dnSpy. The decompiled C# is typically cleaner than jadx output from DEX, with full type information, method signatures, and string literals preserved.

**AOT mode (.NET MAUI):**

Newer .NET MAUI apps may AOT-compile assemblies into native code, eliminating the readable IL. In this case, the `assemblies/` directory contains stripped binaries or blob files that resist standard decompilation. [McAfee documented malware using this technique](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/) to evade detection, with additional XOR and AES encryption layers on the payloads.

**SSL pinning bypass:**

```javascript
Java.perform(function() {
    var ServerCertificateValidation = Java.use("Mono.Net.Security.MobileTlsProvider");
    if (ServerCertificateValidation) {
        send("Xamarin Mono TLS provider found");
    }
});
```

For Mono-mode apps, the most effective approach is to patch the DLL directly: decompile with dnSpy, modify the certificate validation callback to always return `true`, save the modified DLL, repackage the APK.

**Hooking:** Frida can hook Mono runtime internals:

```javascript
var monoJitRuntimeInvoke = Module.findExportByName("libmonosgen-2.0.so", "mono_jit_runtime_invoke");
if (monoJitRuntimeInvoke) {
    Interceptor.attach(monoJitRuntimeInvoke, {
        onEnter: function(args) {
            var methodName = Memory.readUtf8String(Memory.readPointer(args[0].add(8)));
            send("Mono invoke: " + methodName);
        }
    });
}
```

**Where to look:** Ignore the DEX entirely. All application logic is in `assemblies/*.dll`. The DEX contains only the Mono runtime bootstrap and Android activity stubs.

### Cordova / Ionic / Capacitor

**Architecture:** Standard web application (HTML, CSS, JavaScript) running inside an Android WebView. Native device APIs are accessed through JavaScript bridge plugins.

**Code location:** All application logic lives in `assets/www/` (Cordova/Ionic) or `assets/public/` (Capacitor). Unzip the APK and the entire application source is readable:

```bash
unzip target.apk assets/www/* -d /tmp/cordova_out/
```

**Analysis:** Open `index.html` in a browser or text editor. JavaScript files are typically minified but not compiled. Apply `js-beautify` or use browser dev tools to read the code. Search for:

- API endpoints and C2 URLs
- Hardcoded credentials and tokens
- Data exfiltration logic
- Plugin bridge calls to native functionality

**Plugin analysis:** Cordova plugins bridge JavaScript to native Android APIs. Examine `plugins/` for installed plugins and their Java implementations:

| Plugin Type | Security Relevance |
|-------------|-------------------|
| Camera plugins | Photo capture and exfiltration |
| File plugins | File system access |
| HTTP plugins | Network communication, potential SSL pinning |
| Device plugins | IMEI, phone number, device info collection |
| SMS/Contact plugins | Data harvesting |

**SSL pinning bypass:** Usually implemented via `cordova-plugin-advanced-http` or a custom Java plugin wrapping OkHttp. Standard Java-layer Frida hooks work:

```javascript
Java.perform(function() {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        handler.proceed();
    };
});
```

**Hooking:** Modify the JavaScript files directly in the APK, or hook the WebView's JavaScript bridge at runtime:

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        send("WebView loading: " + url);
        this.loadUrl(url);
    };

    WebView.evaluateJavascript.implementation = function(script, callback) {
        send("JS injection: " + script.substring(0, 200));
        this.evaluateJavascript(script, callback);
    };
});
```

**Security posture:** Weakest framework from a reverse engineering perspective. All code is visible, the WebView introduces browser-level attack surface, and JavaScript bridge calls can be intercepted trivially. No compilation barrier exists.

**Malware context:** [SpyLoan](../malware/families/spyloan.md) apps frequently use Cordova or web frameworks to rapidly build predatory lending UIs that harvest contacts, photos, and device data. The web-based architecture allows quick iteration and cross-platform deployment.

### Unity (Game Engine)

**Architecture:** Unity supports two scripting backends with radically different reversibility.

**Mono backend:**

C# scripts compile to IL and are stored as standard .NET DLLs in `assets/bin/Data/Managed/`. Primary target: `Assembly-CSharp.dll` contains all game scripts.

```bash
unzip target.apk "assets/bin/Data/Managed/*" -d /tmp/unity_mono/
```

Open `Assembly-CSharp.dll` in dnSpy or ILSpy. The decompiled C# is near-source quality with full class hierarchies, method bodies, and string literals. This is the easiest Unity configuration to reverse.

**IL2CPP backend:**

C# compiles to C++ which then compiles to native ARM code in `libil2cpp.so`. The IL is gone. However, `global-metadata.dat` preserves all class names, method signatures, field names, and string literals as metadata.

**IL2CPP analysis workflow:**

1. Extract `libil2cpp.so` and `assets/bin/Data/Managed/Metadata/global-metadata.dat`
2. Run [Il2CppDumper](https://github.com/nicksdevice/nicksdevice) with both files as input
3. Il2CppDumper produces `dump.cs` (C# stubs with method addresses) and `script.json` (Ghidra/IDA import script)
4. Import the generated script into Ghidra or IDA to annotate `libil2cpp.so` with recovered symbol names
5. Analyze the annotated native code with full class/method context

| Tool | Purpose |
|------|---------|
| [Il2CppDumper](https://github.com/nicksdevice/nicksdevice) | Extract metadata and generate C# stubs with native addresses |
| [Cpp2IL](https://github.com/nicksdevice/nicksdevice) | Alternative to Il2CppDumper, supports newer Unity versions |
| [dnSpy](https://github.com/nicksdevice/nicksdevice) | Decompile Mono-backend DLLs |
| [GameGuardian](https://gameguardian.net/) | Runtime memory editing for game state manipulation |

**Hooking:**

For Mono backend, hook via the Mono runtime. For IL2CPP, use native function addresses from Il2CppDumper output:

```javascript
var il2cpp = Module.findBaseAddress("libil2cpp.so");
var targetAddress = il2cpp.add(0x7A3B20);
Interceptor.attach(targetAddress, {
    onEnter: function(args) {
        send("IL2CPP method called");
    },
    onLeave: function(retval) {
        send("Return value: " + retval);
    }
});
```

**Anti-cheat:** Many Unity games deploy additional protection layers:

| Protection | Effect on RE |
|------------|-------------|
| GameGuard | Kernel-level anti-tamper, blocks debuggers and memory editors |
| EasyAntiCheat | Process integrity checks, blocks injection |
| Custom obfuscation | String encryption, control flow obfuscation in IL2CPP output |
| Metadata encryption | Encrypted `global-metadata.dat`, requires runtime decryption before Il2CppDumper works |

For encrypted `global-metadata.dat`, hook the metadata loading function at runtime and dump the decrypted buffer before Il2CppDumper analysis.

**Malware context:** [Goldoson](../malware/families/goldoson.md) SDK was discovered embedded in over 60 legitimate Unity-based games on the Play Store. The malicious SDK collected device data, installed apps, and Wi-Fi/Bluetooth connected device information. The SDK hid within the game's legitimate native library dependencies.

### NativeScript

**Architecture:** JavaScript or TypeScript code runs on the V8 engine with direct bindings to all native Android APIs. Unlike Cordova, there is no WebView -- V8 executes JavaScript that calls Android APIs directly through generated bindings.

**Code location:** Application bundles are in `assets/app/`. Extract and analyze as JavaScript:

```bash
unzip target.apk "assets/app/*" -d /tmp/nativescript_out/
```

**Security implication:** NativeScript's direct API bindings mean JavaScript code can call any Android API without requiring a native plugin. A NativeScript app can access contacts, SMS, camera, file system, and network directly from JavaScript. This makes malicious capabilities harder to gate behind plugin installation compared to Cordova.

**Analysis approach:** Similar to React Native. Beautify and read the JavaScript bundles. Search for Android API calls made through the `android.` namespace in JavaScript. Hook V8 execution or the Java bridge layer with Frida.

### Kotlin Multiplatform (KMP)

**Architecture:** Shared Kotlin code compiles to JVM bytecode and runs on the standard Android runtime alongside platform-specific Kotlin/Java code. The shared module produces regular `.class` files that end up in the DEX.

**Analysis:** Standard JADX decompilation works. The shared code appears as normal Kotlin classes in the DEX output. Look for the `expect`/`actual` pattern where shared module declarations have platform-specific implementations.

**No special tooling required.** KMP apps are analyzed identically to native Android apps. The shared business logic, networking, and data layers are all visible in DEX. This is the most RE-friendly cross-platform framework since it compiles to the same bytecode as native Kotlin.

### Qt for Android

**Architecture:** C++ application using Qt framework, compiled to native ARM code in `libQt*.so` libraries. The Java layer is a thin wrapper (`QtActivity`) that bootstraps the Qt runtime.

**Analysis:** All application logic is in native C++ libraries. Requires Ghidra or IDA for analysis. Qt's signal/slot mechanism creates indirect call chains that complicate static analysis. String literals are often in Qt resource files (`.qrc` compiled into binaries).

**Hooking:** Hook native Qt functions via Frida's Interceptor. Target `QNetworkAccessManager` for HTTP traffic interception, `QSslSocket` for SSL bypass.

### Corona / Solar2D

**Architecture:** Lua scripting engine (`liblua.so`) with a Corona runtime (`libcorona.so`). Game logic is written in Lua and stored in `assets/`.

**Analysis:** Extract Lua scripts from the APK. Corona may compile Lua to bytecode (`.lu` files), which can be decompiled with `unluac` or `luadec`. String searches in Lua bytecode remain effective since Lua bytecode preserves string constants.

### Cocos2d-x

**Architecture:** C++ game engine with optional Lua or JavaScript scripting. Native C++ code in `libcocos2dlua.so` or `libcocos2djs.so`.

**Lua variant:** Lua scripts in `assets/src/` may be compiled to bytecode. Extract and decompile with standard Lua tools. Some games encrypt Lua scripts with XOR or custom encryption before packaging.

**JavaScript variant:** JavaScript source in `assets/script/`. Extract and beautify. V8 or SpiderMonkey engine handles execution.

**C++ variant:** All logic in native `libcocos2d*.so`. Requires Ghidra/IDA analysis with Cocos2d-x type information.

## SSL Pinning Bypass by Framework

| Framework | Pinning Location | Bypass Method | Tool |
|-----------|-----------------|---------------|------|
| React Native | JS layer or native TrustManager | Patch bundle or Java-layer Frida hook | Frida, bundle patching |
| Flutter | BoringSSL compiled into `libflutter.so` | Patch `ssl_crypto_x509_session_verify_cert_chain` | [reFlutter](https://github.com/nicksdevice/reflutter), Ghidra binary patch |
| Xamarin | Mono `ServicePointManager` or `MobileTlsProvider` | Patch the .dll or Frida mono runtime hook | dnSpy, Frida |
| Cordova / Ionic | Java plugin (OkHttp) or `WebViewClient` | Standard Java-layer Frida hooks | Frida, [Objection](https://github.com/sensepost/objection) |
| Unity (Mono) | C# `UnityWebRequest` or embedded OkHttp | Patch `Assembly-CSharp.dll` or Java-layer hook | dnSpy, Frida |
| Unity (IL2CPP) | Native compiled cert check | Il2CppDumper to locate function, Frida native hook | Il2CppDumper, Frida |
| NativeScript | V8 bridge to Java TrustManager | Java-layer Frida hooks | Frida |
| Qt | `QSslSocket` in native `libQt5Network.so` | Native Frida hook on SSL verification function | Frida, Ghidra |
| Native Android | OkHttp `CertificatePinner`, `TrustManager`, network security config | Standard Java-layer Frida hooks | Frida, [Objection](https://github.com/sensepost/objection) |

## Hooking Strategy by Framework

| Framework | Frida Approach | Hook Target | Effectiveness |
|-----------|---------------|-------------|---------------|
| React Native (JSC) | Java bridge hooks + JS bundle patching | `com.facebook.react.bridge.*` classes, native module calls | Moderate -- bridge hooks capture cross-boundary calls, full logic requires bundle reading |
| React Native (Hermes) | Native hooks on `libhermes.so` | Hermes runtime functions, `nativeCallSyncHook` | Limited -- Hermes internals are complex, bundle decompilation preferred |
| Flutter | Native hooks on `libapp.so` at offsets from blutter | Dart function addresses recovered by blutter | Moderate -- requires blutter output for meaningful offsets |
| Xamarin | Mono runtime hooks or DLL patching | `mono_jit_runtime_invoke`, individual .NET methods via Mono API | High -- Mono runtime exposes rich hooking surface |
| Cordova / Ionic | WebView hooks + direct JS modification | `WebView.loadUrl`, `evaluateJavascript`, JS bridge | High -- all code is JavaScript, trivially modifiable |
| Unity (Mono) | Mono runtime hooks | `Assembly-CSharp.dll` methods via Mono API | High -- same as Xamarin Mono |
| Unity (IL2CPP) | Native hooks at Il2CppDumper offsets | C++ compiled method addresses from metadata dump | Moderate -- requires Il2CppDumper preprocessing |
| NativeScript | V8 bridge hooks + JS patching | Java bridge layer, native API bindings | Moderate -- similar to React Native approach |
| Kotlin Multiplatform | Standard Java hooks | Regular Java/Kotlin methods in DEX | High -- identical to native app hooking |
| Qt | Native hooks on Qt libraries | `QNetworkAccessManager`, `QSslSocket`, application-specific functions | Low -- dense C++ with Qt abstractions, requires significant Ghidra analysis |

## Malware Use of Frameworks

| Framework | Known Malware | Motivation |
|-----------|--------------|------------|
| Flutter | [FluHorse](../malware/families/fluhorse.md) | AOT compilation provides inherent obfuscation, jadx produces no output, cross-platform targeting |
| React Native | Phishing campaigns, fake banking apps | Rapid cross-platform development, single codebase for Android and iOS phishing |
| Cordova / Ionic | [SpyLoan](../malware/families/spyloan.md), predatory lending apps | Fastest development cycle, web developer skills sufficient, easy to rebrand |
| Unity | [Goldoson](../malware/families/goldoson.md) SDK in legitimate games | SDK embedding in popular games provides massive install base |
| .NET MAUI | Data theft campaigns ([McAfee report](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/)) | C# logic stored in blob files evades DEX-based scanning engines |
| Native (Java/Kotlin) | Majority of banking trojans: [Cerberus](../malware/families/cerberus.md), [GodFather](../malware/families/godfather.md), [Anatsa](../malware/families/anatsa.md), [Octo](../malware/families/octo.md), [Hook](../malware/families/hook.md), [Vultur](../malware/families/vultur.md) | Full Android API access, mature obfuscation/packing ecosystem, largest developer pool |

Framework choice correlates with threat actor sophistication. Banking trojan operators with years of experience prefer native Android for maximum control and access to commercial packers. Less sophisticated actors building phishing or data harvesting campaigns choose web-based frameworks (Cordova, React Native) for speed. Flutter adoption by malware authors is increasing as its AOT compilation provides a free obfuscation layer that defeats the standard jadx-based analysis pipeline.

## Reverse Engineering Difficulty Ranking

From easiest to hardest for a reverse engineer:

| Rank | Framework | Why |
|------|-----------|-----|
| 1 | Cordova / Ionic / Capacitor | All code is readable JavaScript in `assets/www/` |
| 2 | Xamarin (Mono) | .NET DLLs decompile to near-source C# |
| 3 | Unity (Mono) | Same as Xamarin -- .NET DLLs in `assets/bin/Data/Managed/` |
| 4 | Kotlin Multiplatform | Standard DEX, analyzed with jadx like any native app |
| 5 | NativeScript | JavaScript bundles, similar to React Native |
| 6 | React Native (JSC) | Minified but readable JavaScript bundle |
| 7 | React Native (Hermes) | Requires Hermes bytecode decompilation |
| 8 | Corona / Solar2D | Lua bytecode decompilation, sometimes encrypted |
| 9 | Unity (IL2CPP) | Requires Il2CppDumper + Ghidra, but metadata preserves symbols |
| 10 | Flutter | AOT-compiled Dart with stripped symbols, requires blutter |
| 11 | Qt for Android | Pure native C++ with Qt abstractions, minimal metadata |

## Tools Summary

| Tool | Framework Target | Purpose |
|------|-----------------|---------|
| [jadx](https://github.com/skylot/jadx) | Native Android, KMP | DEX to Java decompilation |
| [dnSpy](https://github.com/nicksdevice/nicksdevice) / [ILSpy](https://github.com/nicksdevice/nicksdevice) | Xamarin, Unity (Mono) | .NET IL decompilation to C# |
| [blutter](https://github.com/nicksdevice/blutter) | Flutter | Dart AOT snapshot analysis, symbol recovery |
| [reFlutter](https://github.com/nicksdevice/reflutter) | Flutter | SSL bypass and snapshot extraction via `libflutter.so` patching |
| [Il2CppDumper](https://github.com/nicksdevice/nicksdevice) | Unity (IL2CPP) | Extract metadata from `global-metadata.dat`, generate C# stubs |
| [Cpp2IL](https://github.com/nicksdevice/nicksdevice) | Unity (IL2CPP) | Alternative IL2CPP analyzer, supports newer Unity versions |
| [hbctool](https://github.com/nicksdevice/nicksdevice) | React Native (Hermes) | Hermes bytecode disassembly and reassembly |
| [hermes-dec](https://github.com/nicksdevice/nicksdevice) | React Native (Hermes) | Hermes bytecode decompilation to JavaScript |
| [js-beautify](https://github.com/nicksdevice/nicksdevice) | React Native (JSC), Cordova, NativeScript | JavaScript formatting and deobfuscation |
| [Frida](https://frida.re/) | All frameworks | Runtime instrumentation and hooking |
| [Ghidra](https://ghidra-sre.org/) | Flutter, Unity (IL2CPP), Qt, native libs | Native ARM code analysis |
| [unluac](https://github.com/nicksdevice/nicksdevice) | Corona/Solar2D, Cocos2d-x (Lua) | Lua bytecode decompilation |
