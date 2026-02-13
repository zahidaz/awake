# NativeScript

NativeScript apps embed a JavaScript engine (V8 on Android) that has direct bindings to the full Android SDK -- no WebView, no bridge serialization. JavaScript calls translate to native API invocations through runtime-generated bindings, giving NativeScript apps near-native capability while keeping all business logic in JavaScript or TypeScript bundles. The framework is open-source under the Apache 2.0 license and maintained by OpenJS Foundation (formerly Telerik/Progress).

## Architecture

### Runtime

NativeScript on Android embeds Google's V8 engine inside a custom runtime (`libNativeScript.so`). At startup, the runtime generates metadata that maps every Android SDK class, method, and field to a JavaScript-accessible prototype. This means JS code can call `android.content.Intent` or `javax.crypto.Cipher` directly without any plugin or bridge layer.

| Component | Role |
|-----------|------|
| **V8 Engine** | Executes JavaScript/TypeScript (compiled to JS) at runtime |
| **libNativeScript.so** | Native library hosting V8, metadata access, and the JS-to-Java binding layer |
| **Android Runtime Metadata** | Pre-generated mappings of the entire Android SDK, stored in `assets/metadata/` |
| **Webpack Bundle** | Application code bundled into `assets/app/bundle.js` (and related chunks) |

### JS-to-Native Call Path

When JavaScript invokes a native Android API, the call flows through:

1. JS function call in V8 context
2. V8 binding layer in `libNativeScript.so` resolves the call against metadata
3. JNI call from native code into the Android Java/Kotlin layer
4. Android framework executes the request and returns the result back through JNI to V8

This direct binding model means there is no serialized bridge (unlike React Native's old architecture). Every Android API is available from JavaScript without writing native plugins.

### Build & Bundle Process

NativeScript uses Webpack to bundle application code at build time:

1. TypeScript compiles to JavaScript
2. Webpack bundles all JS into `bundle.js` (and optionally `vendor.js` for framework code)
3. The bundle, metadata, and `libNativeScript.so` are packaged into the APK
4. At runtime, V8 loads and executes the bundle directly

## Identification

| Indicator | Location |
|-----------|----------|
| `libNativeScript.so` | `lib/<arch>/libNativeScript.so` in the APK |
| `assets/app/bundle.js` | Webpack-bundled application JavaScript |
| `assets/app/vendor.js` | Framework and dependency code (when chunk splitting is enabled) |
| `assets/app/runtime.js` | Webpack runtime loader |
| `assets/metadata/` | Android SDK metadata tree used by the runtime |
| `org.nativescript.*` | Package prefix in DEX classes |
| `com.tns.Runtime` | Main NativeScript runtime class |
| `com.tns.NativeScriptActivity` | Default activity superclass |

Quick check:

```bash
unzip -l target.apk | grep -iE "(libNativeScript|assets/app/bundle|com/tns|metadata)"
```

Confirm by looking for the runtime entry point in the manifest:

```bash
aapt dump xmltree target.apk AndroidManifest.xml | grep -i "nativescript\|com.tns"
```

## Code Location & Extraction

All application logic lives in the `assets/app/` directory:

```bash
unzip target.apk "assets/app/*" -d extracted/
```

Key files after extraction:

| File | Contents |
|------|----------|
| `bundle.js` | Application business logic, routes, API calls, auth flows |
| `vendor.js` | NativeScript framework code, third-party libraries |
| `runtime.js` | Webpack module loader |
| `package.json` | App metadata (name, version, main entry point) |
| `assets/app/fonts/` | Custom fonts bundled with the app |

The JavaScript bundles are plaintext -- Webpack-minified but not compiled to bytecode. NativeScript does not use a custom bytecode format like Hermes. V8 compiles the JS at runtime from source.

## Analysis

### Bundle Beautification

Since the bundles are standard JavaScript, beautification gives near-readable output:

```bash
npx prettier --write extracted/assets/app/bundle.js
```

### Webpack Module Recovery

NativeScript apps use Webpack's module system. The bundle contains a module map where each module is a function keyed by a numeric or string ID. After beautification, search for the Webpack bootstrap:

```bash
grep -n "__webpack_require__" extracted/assets/app/bundle.js | head -20
```

Each module boundary starts with a function signature like `function(module, exports, __webpack_require__)` or the arrow-function equivalent. Identify modules of interest by searching for string literals:

```bash
grep -n "api\|http\|login\|token\|secret\|password\|encrypt" extracted/assets/app/bundle.js
```

### Metadata Analysis

The `assets/metadata/` directory contains a tree structure mirroring the Android SDK package hierarchy. This reveals which native APIs the app uses:

```bash
ls extracted/assets/metadata/
find extracted/assets/metadata/ -name "*.bin" | head -20
```

### Native Library Analysis

Load `libNativeScript.so` in Ghidra or IDA for deeper analysis of the V8 embedding layer:

```bash
unzip target.apk "lib/arm64-v8a/libNativeScript.so" -d extracted/
```

Look for exported symbols related to the binding layer:

```bash
readelf -Ws extracted/lib/arm64-v8a/libNativeScript.so | grep -i "CallJava\|GetJavaField\|Runtime"
```

### Recommended Workflow

1. **Unzip APK** and confirm NativeScript (`libNativeScript.so`, `assets/app/bundle.js`)
2. **Extract** `assets/app/` contents
3. **Beautify** `bundle.js` and `vendor.js` with Prettier or js-beautify
4. **Search** for API endpoints, hardcoded credentials, auth logic, crypto keys
5. **Map Webpack modules** to understand application structure
6. **Hook at runtime** with Frida for dynamic secrets (tokens, decrypted payloads)
7. **Patch bundle** directly (edit JS, repackage APK) for behavior modification

## Hooking Strategy

### Java-Layer Hooks

Since NativeScript calls Android APIs through JNI, standard Java-layer Frida hooks work for intercepting any native Android functionality the app uses:

```javascript
Java.perform(function() {
    var HttpURL = Java.use("java.net.HttpURLConnection");
    HttpURL.setRequestProperty.implementation = function(key, value) {
        console.log("[HTTP Header] " + key + ": " + value);
        this.setRequestProperty(key, value);
    };
});
```

### NativeScript Runtime Hooks

Hook the NativeScript runtime class to intercept framework-level operations:

```javascript
Java.perform(function() {
    var Runtime = Java.use("com.tns.Runtime");

    Runtime.runScript.overload("java.io.File").implementation = function(file) {
        console.log("[NS] runScript: " + file.getAbsolutePath());
        return this.runScript(file);
    };
});
```

### V8 Native Hooks

Intercept V8 function calls at the native layer by hooking `libNativeScript.so`:

```javascript
var nsModule = Process.findModuleByName("libNativeScript.so");
if (nsModule) {
    nsModule.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("CallJavaMethod") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[V8->Java] " + exp.name);
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

### Enumerating Loaded Modules

Discover which NativeScript and application classes are loaded:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("com.tns") !== -1 || className.indexOf("org.nativescript") !== -1) {
                console.log("[NS Class] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

### JS Bundle Patching

Because bundles are plaintext JavaScript, direct patching is the simplest modification approach:

1. Extract `assets/app/bundle.js`
2. Beautify and locate the target function
3. Edit the JavaScript directly
4. Repackage the APK with the modified bundle
5. Re-sign and install

```bash
npx prettier --write bundle.js
```

After editing:

```bash
cd extracted && zip -r ../modified.apk . && cd ..
apksigner sign --ks keystore.jks modified.apk
```

## SSL Pinning Bypass

NativeScript apps that implement SSL pinning typically do so at the Java layer using standard Android HTTP clients (OkHttp, HttpsURLConnection) or through the `nativescript-https` plugin, which wraps OkHttp's `CertificatePinner`. Standard Android SSL bypass techniques apply directly.

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

Some apps use the `nativescript-ssl-pinning` plugin which performs certificate checks in JavaScript. For these, patch the pinning logic directly in `bundle.js` -- locate the certificate comparison function and force it to return a passing result.

## Obfuscation

### Webpack Minification (Default)

All production NativeScript builds run through Webpack, which applies:

- **Identifier mangling** -- local variable and function names reduced to single characters
- **Tree shaking** -- unused code elimination
- **Module concatenation** -- inlined modules reduce function call overhead

This is the baseline for every release build. The output is minified but structurally intact -- beautification recovers readable control flow.

### JavaScript Obfuscators

Developers can integrate JS obfuscation tools into the Webpack pipeline:

| Tool | Technique |
|------|-----------|
| [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) | Control flow flattening, string encoding, dead code injection |
| [Jscrambler](https://jscrambler.com/) | Commercial -- self-defending code, domain locking, anti-tampering |
| [terser](https://github.com/terser/terser) | Advanced minification with mangling (default in Webpack 5) |

Jscrambler is the most aggressive option and the hardest to reverse. It transforms code before Webpack bundling, embedding runtime integrity checks that crash the app if the bundle is modified.

### ProGuard / R8

The Java/Kotlin shell code (NativeScript runtime, custom native modules) passes through R8/ProGuard during release builds. This affects class and method names in the DEX layer but has no impact on the JavaScript bundles.

### Practical Impact

Most NativeScript apps in the wild rely only on Webpack minification. The JS bundle is readable after beautification. Apps with Jscrambler or javascript-obfuscator are uncommon but require significantly more effort -- dynamic analysis with Frida becomes the primary approach.

## Analysis Tools

| Tool | Purpose |
|------|---------|
| [jadx](https://github.com/skylot/jadx) | DEX decompilation for the Java shell and runtime classes |
| [Frida](https://frida.re/) | Runtime hooking at both Java and native layers |
| [Ghidra](https://ghidra-sre.org/) | Native analysis of `libNativeScript.so` and V8 internals |
| [Prettier](https://prettier.io/) | JavaScript beautification |
| [source-map](https://www.npmjs.com/package/source-map) | Parse source maps if included (debug builds) |
| [webpack-bundle-analyzer](https://github.com/webpack-contrib/webpack-bundle-analyzer) | Visualize module composition of the bundle |

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Plaintext JavaScript (Webpack-minified) |
| Readability | High -- beautification yields readable code |
| String extraction | Trivial -- standard `grep`/`strings` on JS bundles |
| Control flow recovery | Full -- no bytecode compilation step |
| Patching | Easy -- edit JS directly, repackage APK |
| Native API visibility | High -- metadata tree reveals all Android API usage |
| Obfuscation ceiling | Jscrambler (rare), javascript-obfuscator (uncommon) |
| Overall difficulty | **Easy** |

NativeScript apps are among the easiest cross-platform frameworks to reverse engineer. The JavaScript bundles are plaintext, the Android API metadata is fully enumerable, and standard Java-layer hooks intercept all native calls. The primary analysis target is always `assets/app/bundle.js`.

## References

- [NativeScript Android Runtime -- NativeScript](https://github.com/NativeScript/android)
- [NativeScript Documentation](https://docs.nativescript.org/)
- [V8 JavaScript Engine](https://v8.dev/)
- [NativeScript Webpack -- NativeScript](https://github.com/NativeScript/nativescript-dev-webpack)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [jadx -- Android DEX Decompiler](https://github.com/skylot/jadx)
- [Ghidra -- NSA Reverse Engineering Framework](https://ghidra-sre.org/)
