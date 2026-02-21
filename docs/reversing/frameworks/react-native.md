# React Native

React Native apps run JavaScript (or Hermes bytecode) on an embedded engine, with a thin Java/Kotlin shell handling Android lifecycle events and a bridge (or JSI layer) connecting JS to native platform APIs. All business logic typically resides in a single bundled file -- `assets/index.android.bundle` -- making it the primary reverse engineering target. The framework is Meta's open-source mobile SDK and powers a significant share of cross-platform Android applications.

## Architecture

### Old Architecture (Bridge)

React Native's original design uses three threads connected by an asynchronous JSON bridge:

| Thread | Role |
|--------|------|
| **Main (UI)** | Android native UI rendering, touch events |
| **JS** | Runs the JavaScript engine (JSC or Hermes), executes app logic |
| **Shadow** | Yoga layout engine, computes UI tree diffs |

JavaScript calls native modules by serializing messages as JSON over the bridge. Native modules respond the same way. Every cross-boundary call passes through `com.facebook.react.bridge.CatalystInstanceImpl`, which is the central dispatch point for bridge messages.

### New Architecture (JSI / Bridgeless)

Since React Native 0.76 (October 2024), the New Architecture is enabled by default. It replaces the asynchronous JSON bridge with the JavaScript Interface (JSI), a C++ layer allowing synchronous, direct calls between JavaScript and native code.

| Component | Purpose |
|-----------|---------|
| **JSI** | C++ interface enabling JS to hold direct references to native objects -- no serialization overhead |
| **TurboModules** | Lazy-loaded native modules accessed via JSI instead of the bridge registry |
| **Fabric** | New rendering system using a C++ shadow tree, supports concurrent rendering |
| **Codegen** | Generates type-safe C++ bindings from JS specs at build time |

For reverse engineering, the New Architecture means fewer JSON-serialized messages to intercept on the bridge and more direct C++ calls. Hooking strategy shifts from Java bridge interception toward native-level instrumentation of `libjsi.so` and TurboModule entry points.

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/index.android.bundle` | JS bundle (plaintext or Hermes bytecode) |
| `libjsc.so` | JavaScriptCore engine (older apps) |
| `libhermes.so` | Hermes engine (default since RN 0.70) |
| `libhermes_executor.so` | Hermes execution bridge |
| `libjsi.so` | JSI runtime (New Architecture) |
| `com.facebook.react.*` | Package prefix in DEX classes |
| `com.facebook.react.ReactActivity` | Main activity superclass |

Quick check:

```bash
unzip -l target.apk | grep -E "(index\.android\.bundle|libhermes|libjsc|libjsi)"
```

## JavaScript Engines

### JavaScriptCore (JSC)

Older React Native apps (pre-0.70 default, still optional) use Apple's JavaScriptCore engine compiled for Android. The bundle at `assets/index.android.bundle` is a plaintext JavaScript file -- minified, but fully readable.

Extraction is trivial:

```bash
unzip target.apk assets/index.android.bundle -d extracted/
```

The extracted file is standard JavaScript. Run it through a beautifier (`js-beautify`, Prettier) and search for string literals, API endpoints, hardcoded secrets, and authentication logic directly.

### Hermes

Hermes is Meta's custom JS engine, purpose-built for React Native. It compiles JavaScript to Hermes Bytecode (HBC) at build time, producing a binary blob rather than plaintext JS. Hermes has been the default engine since React Native 0.70.

#### HBC File Format

The Hermes bytecode format starts with a distinctive header:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0x00 | 8 bytes | Magic | `c6 1f bc 03 c1 03 19 1f` (little-endian: `0x1F1903C103BC1FC6`) |
| 0x08 | 4 bytes | Bytecode version | Version number (e.g., 84, 89, 90, 93, 94, 95, 96) |
| 0x0C | 20 bytes | SHA1 hash | Source hash for integrity |
| 0x20 | 4 bytes | File length | Total bytecode file size |
| 0x24 | 4 bytes | Global code index | Entry point function ID |

Identification with `file` or `xxd`:

```bash
file assets/index.android.bundle
xxd -l 32 assets/index.android.bundle
```

If the first bytes match the magic above, the bundle is Hermes bytecode. The `file` utility on Linux recognizes it and reports the Hermes version (e.g., "Hermes JavaScript bytecode, version 94").

!!! warning "Version Fragmentation"
    The HBC format version changes across Hermes releases. Tools must support the specific version in the target APK. A tool built for HBC v84 will not parse v96 bundles. Always check the version field before choosing a decompiler.

#### HBC Internal Structure

After the header, the file contains:

- **Function header table** -- metadata for each function (parameter count, register count, bytecode offset)
- **String table** -- all string literals indexed by ID
- **String storage** -- raw bytes for the string table entries
- **Bytecode segments** -- per-function instruction sequences
- **Regular expression table** -- compiled regex patterns
- **CommonJS module table** -- module resolution metadata

The bytecode uses a register-based VM with typed instructions. Each function operates on its own register frame.

## Code Location & Extraction

### JSC Bundle

```bash
unzip target.apk assets/index.android.bundle -d out/
npx prettier --write out/assets/index.android.bundle
```

The output is human-readable JavaScript. Search for API endpoints, credentials, cryptographic keys, and business logic directly.

### Hermes Bundle

Extract the HBC file the same way, then use specialized tooling to decompile:

=== "hermes-dec"

    ```bash
    pip install hermes-dec
    hermes-dec --hasm assets/index.android.bundle -o disassembly/
    hermes-dec --decompile assets/index.android.bundle -o decompiled.js
    ```

    [hermes-dec](https://github.com/P1sec/hermes-dec) (P1 Security) produces both disassembly and a pseudo-JavaScript decompilation. The decompiler output uses registers (`r0`, `r1`) and label-based jumps rather than structured control flow, but string references and function calls are resolved.

=== "hbctool"

    ```bash
    pip install hbctool
    hbctool disasm assets/index.android.bundle output_dir/
    ```

    [hbctool](https://github.com/bongtrop/hbctool) disassembles to a textual Hermes assembly format and supports reassembly -- enabling binary patching of the bytecode. Modify the disassembly, reassemble with `hbctool asm`, and repackage the APK.

=== "hermes_rs"

    [hermes_rs](https://github.com/Pilfer/hermes_rs) is a Rust-based disassembler and assembler supporting HBC versions 89, 90, 93, 94, 95, and 96. Useful when `hermes-dec` or `hbctool` lag behind the latest Hermes version.

### String Extraction Shortcut

Even without full decompilation, dumping strings from an HBC file reveals API endpoints, error messages, and logic hints:

```bash
strings assets/index.android.bundle | grep -iE "(api|http|token|key|secret|password|login)"
```

## Analysis Tools & Workflow

| Tool | Purpose | Hermes Support |
|------|---------|---------------|
| [hermes-dec](https://github.com/P1sec/hermes-dec) | Disassembly + decompilation of HBC | Multi-version |
| [hbctool](https://github.com/bongtrop/hbctool) | Disassembly, patching, reassembly | Up to v90 (forks for v96) |
| [hermes_rs](https://github.com/Pilfer/hermes_rs) | Rust disassembler/assembler | v89-96 |
| [jadx](https://github.com/skylot/jadx) | DEX decompilation (Java shell only) | N/A |
| [Frida](https://frida.re/) | Runtime hooking | All versions |
| [Ghidra](https://ghidra-sre.org/) | Native analysis of `libhermes.so` | N/A |

### Recommended Workflow

1. **Unzip APK** and identify engine (`libhermes.so` vs `libjsc.so`)
2. **Extract bundle** from `assets/index.android.bundle`
3. **Check HBC version** (`xxd -l 12` or `file`)
4. **Decompile** with hermes-dec or format/beautify if JSC plaintext
5. **Search** decompiled output for API endpoints, auth logic, hardcoded keys
6. **Hook at runtime** with Frida for dynamic values (tokens, decrypted data)
7. **Patch bundle** with hbctool if behavior modification is needed

## SSL Pinning Bypass

React Native SSL pinning typically operates at the Java layer, using OkHttp's `CertificatePinner` or a custom `TrustManager`. Standard Android SSL bypass scripts work because the pinning lives in the Java HTTP client, not in the JS engine.

```javascript
Java.perform(function() {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, certs) {
        console.log("[SSL] Bypassed pin for: " + host);
    };

    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[SSL] Bypassed TrustManager for: " + host);
        return untrustedChain;
    };
});
```

Some apps implement pinning in JS using libraries like `react-native-ssl-pinning` or `rn-fetch-blob` with cert checks. For these, patch the JS bundle directly:

1. Decompile with hbctool
2. Locate the pinning check function
3. Patch the comparison to always pass
4. Reassemble and repackage

## Hooking Strategy

### Bridge Interception (Old Architecture)

The central hook target for bridge-based apps is `CatalystInstanceImpl`, which routes all JS-to-native calls:

```javascript
Java.perform(function() {
    var CatalystInstance = Java.use("com.facebook.react.bridge.CatalystInstanceImpl");

    CatalystInstance.jniCallJSFunction.implementation = function(module, method, args) {
        console.log("[Bridge] " + module + "." + method + " args=" + args);
        this.jniCallJSFunction(module, method, args);
    };
});
```

### Native Module Interception

React Native native modules register as Java classes inheriting `ReactContextBaseJavaModule`. Hook specific modules to intercept their functionality:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("com.facebook.react") !== -1 && className.indexOf("Module") !== -1) {
                console.log("[RN Module] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

### JS Context Injection

Inject arbitrary JavaScript into the React Native runtime by hooking the bundle loader:

```javascript
Java.perform(function() {
    var CatalystInstance = Java.use("com.facebook.react.bridge.CatalystInstanceImpl");

    CatalystInstance.loadScriptFromAssets.implementation = function(assetManager, assetURL, loadSynchronously) {
        console.log("[RN] Loading bundle: " + assetURL);
        this.loadScriptFromAssets(assetManager, assetURL, loadSynchronously);
        this.loadScriptFromFile("/data/local/tmp/inject.js", "inject.js", false);
    };
});
```

This loads a custom script file into the same JS context after the main bundle, giving full access to the app's JavaScript environment.

### Hermes Native Hooking

For Hermes-specific instrumentation, hook the Hermes runtime directly:

```javascript
var hermesModule = Process.findModuleByName("libhermes.so");
if (hermesModule) {
    var exports = hermesModule.enumerateExports();
    exports.forEach(function(exp) {
        if (exp.name.indexOf("nativeCallSyncHook") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[Hermes] nativeCallSyncHook called");
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

### TurboModule Hooking (New Architecture)

For apps using the New Architecture, TurboModules are accessed through JSI rather than the bridge. Hook the C++ binding layer:

```javascript
var jsiModule = Process.findModuleByName("libjsi.so");
if (jsiModule) {
    jsiModule.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("call") !== -1 && exp.type === "function") {
            console.log("[JSI] " + exp.name + " @ " + exp.address);
        }
    });
}
```

## Expo and OTA Updates

[Expo](https://expo.dev/) is a popular React Native development framework that adds its own layer of abstraction. Expo apps have distinct characteristics relevant to reverse engineering and malware analysis.

### Identification

| Indicator | Location |
|-----------|----------|
| `expo.modules.*` packages | DEX classes |
| `EXPO_UPDATES_CHECK_ON_LAUNCH` | AndroidManifest metadata |
| `EXPO_UPDATE_URL` pointing to `u.expo.dev` | AndroidManifest metadata |
| Custom native modules under `expo.modules.*` | DEX (classes7.dex or later in multi-DEX builds) |

### OTA Code Updates

Expo's update system allows developers to push JavaScript bundle updates directly to installed apps without going through the Play Store. This is configured in the manifest:

```xml
<meta-data android:name="expo.modules.updates.ENABLED" android:value="true" />
<meta-data android:name="EXPO_UPDATES_CHECK_ON_LAUNCH" android:value="ALWAYS" />
<meta-data android:name="EXPO_UPDATES_LAUNCH_WAIT_MS" android:value="0" />
<meta-data android:name="EXPO_UPDATE_URL" android:value="https://u.expo.dev/<project-id>" />
```

When `CHECK_ON_LAUNCH` is `ALWAYS` and `LAUNCH_WAIT_MS` is `0`, the app checks for and applies updates at every launch with no delay. This allows pushing arbitrary JavaScript code to all installed instances without user approval or Play Store review.

From a malware perspective: an app that passes Play Store review as benign can receive a malicious JavaScript update post-publication. The update mechanism is legitimate Expo infrastructure, making it difficult to distinguish from normal app updates.

### Custom Native Expo Modules

Expo apps can include custom native modules that run outside the JavaScript context. These are implemented as Java/Kotlin classes under `expo.modules.*` and have direct access to Android APIs. Common patterns in malicious or aggressive apps:

| Module Purpose | Android APIs Used |
|---------------|-------------------|
| GPS tracking | `LocationManager`, `FusedLocationProviderClient`, foreground service with WakeLock |
| Clock tampering detection | GPS-derived time + NTP queries to `time.google.com`, `pool.ntp.org` |
| Background data sync | Foreground service with `dataSync` type, SQLite buffer, chunked uploads |
| Push-triggered actions | FCM receiver launching native services with deep link routing |

These modules bypass the JavaScript layer entirely, so analyzing only the JS bundle misses their functionality. Full analysis requires decompiling the DEX and examining the `expo.modules.*` package hierarchy.

## Obfuscation & Anti-Analysis

### Hermes Bytecode (Default Protection)

The move to Hermes provides baseline obfuscation. The bundle is no longer plaintext JS but compiled bytecode. This defeats casual `grep`/`strings` analysis of the full logic, though string literals remain extractable.

### Jscrambler

[Jscrambler](https://jscrambler.com/) is the most common commercial obfuscation layer for React Native. It integrates as a Metro bundler plugin and transforms the JavaScript before Hermes compilation.

Jscrambler transformations include:

| Transformation | Effect |
|---------------|--------|
| Control flow flattening | Replaces structured code with switch-based dispatch |
| String encoding | Encodes string literals, decodes at runtime via helper functions |
| Dead code injection | Adds unreachable code paths to inflate analysis surface |
| Self-defending | Crashes or loops if the code is reformatted/beautified |
| Domain lock | Binds execution to specific bundle hashes or environments |
| Anti-tampering | Detects modifications to the bundle and terminates |

When Jscrambler is applied before Hermes compilation, the obfuscation is baked into the bytecode. Decompiling with hermes-dec produces the obfuscated logic, not the original source.

### Metro Bundler Plugins

Open-source alternatives to Jscrambler use the Metro bundler's transform pipeline:

- [obfuscator-io-metro-plugin](https://github.com/whoami-shubham/obfuscator-io-metro-plugin) -- wraps [javascript-obfuscator](https://obfuscator.io/) as a Metro transformer
- `react-native-obfuscating-transformer` -- basic identifier mangling

These produce weaker obfuscation than Jscrambler but still complicate static analysis.

### ProGuard / R8

The Java/Kotlin shell code runs through [R8/ProGuard](../../packers/r8-proguard.md) during release builds, minifying class and method names in the DEX layer. This affects the native module names but not the JS bundle content.

## Malware Context

React Native is used in malware campaigns that prioritize rapid cross-platform development over deep Android API access. The framework appeals to threat actors who need to quickly clone legitimate app UIs for phishing.

| Use Case | Details |
|----------|---------|
| Fake banking apps | Clone legitimate banking interfaces using React Native's component system, harvest credentials via fake login forms |
| [Phishing campaigns](../../attacks/phishing-techniques.md) | Rapid deployment of convincing app replicas across Android and iOS from a single codebase |
| [SpyLoan](../../malware/families/spyloan.md) predatory lending | Some SpyLoan-category apps use web frameworks (Cordova, React Native) for fast iteration on phishing UIs |
| Credential harvesters | Simple apps that display a WebView or RN form, POST stolen data to a C2 endpoint |

React Native malware is typically unsophisticated compared to native banking trojans. The apps lack [accessibility abuse](../../attacks/accessibility-abuse.md), [overlay injection](../../attacks/overlay-attacks.md), or [ATS capabilities](../../attacks/automated-transfer-systems.md) found in families like [Cerberus](../../malware/families/cerberus.md) or [GodFather](../../malware/families/godfather.md). Their value to threat actors is speed of development and cross-platform reach, not evasion depth.

!!! info "ESET Classification"
    ESET's research on Android banking malware distinguishes between "sophisticated trojans" (native, multi-stage, ATS-equipped) and "fake banking apps" (simple credential stealers). React Native malware falls squarely in the latter category, relying on social engineering rather than technical exploitation.

## RE Difficulty Assessment

| Aspect | JSC Engine | Hermes Engine |
|--------|-----------|---------------|
| Code format | Plaintext JavaScript | Hermes bytecode (HBC) |
| Readability | High -- minified but beautifiable | Low -- requires decompilation |
| String extraction | Trivial | Trivial (strings in HBC string table) |
| Control flow recovery | Full | Partial (hermes-dec uses labels/jumps) |
| Patching | Edit JS directly | Disassemble, patch, reassemble with hbctool |
| Obfuscation ceiling | Jscrambler, javascript-obfuscator | Same tools applied pre-compilation |
| Overall difficulty | **Easy** (rank 13/28) | **Moderate** (rank 16/28) |

The Java/Kotlin shell is a thin wrapper with minimal logic -- focus analysis on the JS bundle. For Hermes apps, the main bottleneck is decompiler maturity: hermes-dec produces readable output for straightforward code but struggles with complex control flow and heavily obfuscated bundles. Cross-reference decompiled output with runtime Frida hooks to fill gaps.

## References

- [hermes-dec -- P1 Security](https://github.com/P1sec/hermes-dec)
- [hbctool -- bongtrop](https://github.com/bongtrop/hbctool)
- [hermes_rs -- Pilfer](https://github.com/Pilfer/hermes_rs)
- [Hermes Design Documentation](https://github.com/facebook/hermes/blob/main/doc/Design.md)
- [Hooking React Native Applications with Frida -- BeDefended](https://newsroom.bedefended.com/hooking-react-native-applications-with-frida/)
- [Reverse Engineering and Instrumenting React Native Apps -- Pilfer](https://pilfer.github.io/mobile-reverse-engineering/react-native/reverse-engineering-and-instrumenting-react-native-apps/)
- [Understanding and Modifying the Hermes Bytecode -- Payatu](https://payatu.com/blog/understanding-modifying-hermes-bytecode/)
- [P1 Security hermes-dec release blog](https://www.p1sec.com/blog/releasing-hermes-dec-an-open-source-disassembler-and-decompiler-for-the-react-native-hermes-bytecode)
- [OWASP MASTG: hermes-dec](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0104/)
- [React Native New Architecture](https://reactnative.dev/architecture/landing-page)
