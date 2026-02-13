# Cordova / Ionic / Capacitor

Cordova, Ionic, and Capacitor are WebView-based frameworks that package HTML, CSS, and JavaScript as native Android apps. The entire application UI and logic runs inside a `WebView`, with a plugin bridge exposing native device APIs (camera, contacts, filesystem) to JavaScript. All three share this fundamental architecture, making them the easiest cross-platform framework family to reverse engineer -- the app's source code ships as plaintext web assets inside the APK. These frameworks are heavily used in [SpyLoan](../../malware/families/spyloan.md) predatory lending campaigns due to the rapid development cycle they enable.

## Architecture

### Core Design

Every Cordova-family app follows the same pattern: a thin Java/Kotlin shell launches an Android `WebView` that loads the app's web content from local assets. Native functionality is exposed through a plugin bridge that serializes messages between JavaScript and Java.

| Component | Role |
|-----------|------|
| **WebView** | `android.webkit.WebView` instance rendering the HTML/CSS/JS app |
| **Web Assets** | HTML, CSS, JavaScript files bundled in the APK |
| **Plugin Bridge** | Message-passing layer between JS and native Java plugin classes |
| **Plugins** | Java classes exposing native APIs (camera, GPS, contacts, file) to JS |
| **Config** | `config.xml` (Cordova) or `capacitor.config.json` (Capacitor) defining app metadata and plugin settings |

### Cordova

Apache Cordova is the original WebView wrapper. The JavaScript bridge uses `cordova.exec()` to dispatch calls from JS to native plugin classes. Each plugin call is serialized as a JSON message containing the service name, action, and arguments, sent through `CordovaBridge.jsExec()` on the Java side. The `CordovaWebView` class manages the embedded `WebView` and routes bridge traffic.

Key Java classes:

| Class | Purpose |
|-------|---------|
| `org.apache.cordova.CordovaActivity` | Main activity, initializes the WebView |
| `org.apache.cordova.CordovaWebView` | WebView wrapper managing plugins and bridge |
| `org.apache.cordova.CordovaBridge` | JS-to-native message dispatcher |
| `org.apache.cordova.CordovaPlugin` | Base class for all native plugins |
| `org.apache.cordova.PluginManager` | Registry that loads and routes to plugin instances |

### Ionic

Ionic is a UI framework layered on top of Cordova (or Capacitor). It provides Angular/React/Vue components styled to match native platform UIs. From a reverse engineering perspective, Ionic adds no new native layer -- it is purely a JavaScript/TypeScript framework. The underlying engine is still Cordova or Capacitor. Ionic apps are identifiable by the `ionic.config.json` metadata and the `@ionic` package references in the bundled JavaScript.

### Capacitor

Capacitor is Ionic's successor to Cordova as a native runtime. It was built by the Ionic team to replace Cordova's aging plugin architecture. Key differences from Cordova:

| Aspect | Cordova | Capacitor |
|--------|---------|-----------|
| Web asset directory | `assets/www/` | `assets/public/` |
| Config file | `config.xml` | `capacitor.config.json` or `capacitor.config.ts` |
| Plugin config | `cordova_plugins.js` + `config.xml` | `capacitor.plugins.json` |
| Bridge class | `CordovaBridge` | `com.getcapacitor.Bridge` |
| Activity base | `CordovaActivity` | `com.getcapacitor.BridgeActivity` |
| Plugin base | `CordovaPlugin` | `com.getcapacitor.Plugin` |
| Native project | Generated, not version-controlled | Native project is a first-class source artifact |
| Plugin calls | `cordova.exec(success, error, service, action, args)` | `Capacitor.Plugins.PluginName.method()` returning Promises |

Capacitor's `Bridge` class is the central dispatch point. It maintains a `PluginHandle` registry mapping plugin names to Java class instances. JS calls arrive via `WebView.postMessage()` and are routed through `MessageHandler` to the target plugin method annotated with `@PluginMethod`.

## Identification

| Indicator | Framework | Location |
|-----------|-----------|----------|
| `assets/www/` directory | Cordova / Ionic (Cordova) | APK root |
| `assets/public/` directory | Capacitor | APK root |
| `cordova.js` | Cordova | `assets/www/cordova.js` |
| `cordova_plugins.js` | Cordova | `assets/www/cordova_plugins.js` |
| `config.xml` with `<widget>` root | Cordova | `res/xml/config.xml` |
| `capacitor.config.json` | Capacitor | `assets/public/capacitor.config.json` or `assets/capacitor.config.json` |
| `capacitor.plugins.json` | Capacitor | `assets/capacitor.plugins.json` |
| `org.apache.cordova.*` | Cordova | DEX classes |
| `com.getcapacitor.*` | Capacitor | DEX classes |
| `@ionic/core` in JS bundles | Ionic | `assets/www/` or `assets/public/` JS files |

Quick check:

```bash
unzip -l target.apk | grep -E "(assets/www/|assets/public/|cordova\.js|capacitor\.config)"
```

## Code Location

All application logic resides in the web asset directory as plaintext files:

```
assets/www/                    (Cordova)
  index.html
  cordova.js
  cordova_plugins.js
  js/
    app.js
    controllers/
    services/
  css/
  plugins/
    cordova-plugin-camera/
    cordova-plugin-contacts/

assets/public/                 (Capacitor)
  index.html
  main.XXXXX.js
  polyfills.XXXXX.js
  capacitor.config.json
```

For Cordova apps, `cordova_plugins.js` is the manifest listing every installed plugin, its JavaScript file, and the native class it maps to. This file is the starting point for understanding what native capabilities the app uses.

For modern Ionic/Capacitor apps using Angular or React, the JavaScript is bundled by webpack or esbuild into chunked files (`main.XXXXX.js`, `vendor.XXXXX.js`). These are minified but remain plaintext JavaScript -- no compilation step like Hermes bytecode.

Native plugin Java classes are compiled into the DEX and decompilable with [jadx](https://github.com/skylot/jadx). These handle the actual Android API calls that the JavaScript bridge dispatches to.

## Analysis Workflow

### 1. Extract and Inventory

```bash
unzip target.apk -d extracted/
ls extracted/assets/www/
```

### 2. Parse the Plugin Manifest

For Cordova apps, `cordova_plugins.js` contains a JSON array of every plugin:

```bash
cat extracted/assets/www/cordova_plugins.js
```

This reveals the installed plugins and their native class mappings. Each entry contains:

- `id` -- plugin identifier (e.g., `cordova-plugin-camera`)
- `file` -- path to the JS shim
- `pluginId` -- npm package name
- `clobbers` -- JS namespace the plugin occupies (e.g., `navigator.camera`)

### 3. Read Application JavaScript

```bash
npx prettier --write extracted/assets/www/js/app.js
```

The beautified JavaScript is fully readable application source code. Search for:

- API endpoints and hardcoded URLs
- Authentication tokens, API keys, secrets
- Business logic and data handling
- C2 endpoints in malicious apps
- Data exfiltration routines

### 4. Map Plugin Usage

Cross-reference the `cordova_plugins.js` manifest with actual usage in the app JavaScript. Sensitive plugins to flag:

| Plugin | Concern |
|--------|---------|
| `cordova-plugin-contacts` | Contact list exfiltration |
| `cordova-plugin-camera` | Photo capture, document harvesting |
| `cordova-plugin-file` | Filesystem access, data staging |
| `cordova-plugin-geolocation` | Location tracking |
| `cordova-plugin-sms` | SMS read/send capabilities |
| `cordova-plugin-device` | Device fingerprinting |
| `cordova-plugin-media-capture` | Audio/video recording |
| `cordova-plugin-sms-receive` | Passive SMS interception |

### 5. Decompile Native Plugin Code

```bash
jadx -d jadx_out/ target.apk
```

Examine plugin Java classes for native operations that the JS shims invoke. Look for raw Android API calls that go beyond what the standard plugin interface exposes -- custom plugins frequently embed additional data collection.

## Hooking Strategy

### WebView.loadUrl Interception

Intercept all content loaded into the WebView:

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");

    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        console.log("[WebView] loadUrl: " + url);
        this.loadUrl(url);
    };

    WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, headers) {
        console.log("[WebView] loadUrl: " + url + " headers: " + headers);
        this.loadUrl(url, headers);
    };
});
```

### evaluateJavascript Injection

Inject JavaScript into the running WebView context:

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");

    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log("[WebView] evaluateJavascript: " + script.substring(0, 200));
        this.evaluateJavascript(script, callback);
    };
});
```

### Cordova Bridge Interception

Hook the Cordova bridge to see all JS-to-native plugin calls:

```javascript
Java.perform(function() {
    var CordovaBridge = Java.use("org.apache.cordova.CordovaBridge");

    CordovaBridge.jsExec.implementation = function(bridgeSecret, service, action, callbackId, arguments) {
        console.log("[Cordova] " + service + "." + action + " args=" + arguments);
        return this.jsExec(bridgeSecret, service, action, callbackId, arguments);
    };
});
```

### Capacitor Bridge Interception

Hook Capacitor's message handler:

```javascript
Java.perform(function() {
    var MessageHandler = Java.use("com.getcapacitor.MessageHandler");

    MessageHandler.postMessage.implementation = function(message) {
        console.log("[Capacitor] postMessage: " + message);
        this.postMessage(message);
    };
});
```

### Direct JS Modification

The simplest approach for Cordova apps: edit the JavaScript files directly in the extracted APK, repackage, and resign. No decompilation or bytecode patching needed.

```bash
unzip target.apk -d repack/
vi repack/assets/www/js/app.js
cd repack && zip -r ../modified.apk . && cd ..
zipalign -v 4 modified.apk aligned.apk
apksigner sign --ks debug.keystore aligned.apk
```

This is the most direct patching path of any Android framework -- the source code is shipped as-is.

## SSL Pinning

SSL pinning in Cordova/Capacitor apps operates at the Java layer, typically through one of these mechanisms:

### OkHttp Plugin Pinning

Many Cordova apps use `cordova-plugin-advanced-http` which wraps OkHttp. Pinning is configured in Java:

```javascript
Java.perform(function() {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, certs) {
        console.log("[SSL] Bypassed pin for: " + host);
    };
});
```

### WebViewClient Certificate Override

Some apps implement pinning by overriding `WebViewClient.onReceivedSslError`:

```javascript
Java.perform(function() {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        handler.proceed();
    };
});
```

### JS-Layer Pinning

Rare, but some apps implement certificate checks in JavaScript using `cordova-plugin-advanced-http`'s pinning API. For these, patch the JS directly -- locate the `setSSLCertMode` call and change the mode from `pinned` to `nocheck`, or remove the pinning configuration entirely from the web assets.

## Obfuscation

### JavaScript Minification

Most Cordova/Ionic apps ship with minified but not obfuscated JavaScript. The build toolchain (webpack, esbuild, Vite) produces minified bundles that are trivially beautifiable:

```bash
npx prettier --write extracted/assets/www/js/app.js
```

Variable names are shortened but string literals, API endpoints, and logic flow remain intact.

### Webpack Source Maps

Development builds sometimes ship with source maps (`.map` files) that fully reconstruct the original TypeScript/JavaScript with original variable names and file structure:

```bash
find extracted/assets/ -name "*.map"
```

If present, source maps eliminate any reversing effort entirely.

### Ionic AppFlow Obfuscation

Ionic's commercial platform (AppFlow) offers optional JavaScript obfuscation as a build step. This applies [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) transformations:

- String encoding via helper functions
- Control flow flattening
- Dead code injection
- Identifier mangling beyond standard minification

The obfuscation is JavaScript-level only. Standard deobfuscation techniques apply -- community tools like [webcrack](https://github.com/j4k0xb/webcrack) and manual AST analysis work against these transforms.

### ProGuard / R8

The Java plugin layer runs through [R8/ProGuard](../../packers/r8-proguard.md) in release builds, renaming Java classes and methods. This affects only the native plugin code in DEX, not the JavaScript assets.

## Malware Context

Cordova and Ionic are the most common frameworks in [SpyLoan](../../malware/families/spyloan.md) predatory lending campaigns. The WebView architecture enables rapid cloning of legitimate financial app UIs using standard web development skills, without any Android-specific expertise.

| Use Case | Details |
|----------|---------|
| [SpyLoan](../../malware/families/spyloan.md) predatory lending | Majority of SpyLoan apps use Cordova/Ionic for rapid deployment of loan application UIs that harvest contacts, photos, SMS, and location data |
| Credential phishing | WebView-based apps displaying fake login forms for banking or government services, POSTing credentials to C2 servers |
| Data harvesting | Cordova plugin ecosystem provides ready-made access to contacts, SMS, camera, and storage via simple JS calls |
| [Phishing campaigns](../../attacks/phishing-techniques.md) | Quick production of convincing app replicas from a single HTML/CSS/JS codebase |

### SpyLoan Pattern

The typical SpyLoan Cordova app follows a consistent pattern:

1. Legitimate-looking loan application UI built with Ionic components
2. `cordova-plugin-contacts` harvests the full contact list during "reference verification"
3. `cordova-plugin-camera` captures selfies and ID documents during "KYC verification"
4. `cordova-plugin-geolocation` tracks location during "credit assessment"
5. Custom plugins or `cordova-plugin-file` stage and exfiltrate data to remote servers
6. Collected data is later used to harass and extort borrowers who default

The JavaScript source is fully readable, making it straightforward to document the data flow from UI forms through plugin calls to C2 exfiltration endpoints.

!!! info "Framework Prevalence in SpyLoan"
    McAfee's 2024 SpyLoan analysis and ESET's research on predatory fintech apps consistently identify Cordova/Ionic as the dominant framework in this threat category. The low development barrier and cross-platform deployment make it the preferred tool for operators mass-producing lending apps across Latin America, Southeast Asia, and Africa.

## Capacitor-Specific Analysis

### Asset Location

Capacitor apps store web assets in `assets/public/` instead of `assets/www/`:

```bash
ls extracted/assets/public/
```

### Bridge Architecture

Capacitor's bridge is more structured than Cordova's. The `com.getcapacitor.Bridge` class maintains a typed plugin registry. Each plugin is a Java class extending `com.getcapacitor.Plugin` with methods annotated `@PluginMethod`:

```bash
jadx -d out/ target.apk
grep -r "@PluginMethod" out/ --include="*.java"
```

This lists every native method callable from JavaScript, providing a direct map of the app's native attack surface.

### Capacitor Plugins

Capacitor uses a different plugin namespace. Common plugins to examine:

| Plugin | Package |
|--------|---------|
| Camera | `@capacitor/camera` |
| Filesystem | `@capacitor/filesystem` |
| Geolocation | `@capacitor/geolocation` |
| Device | `@capacitor/device` |
| HTTP | `@capacitor/http` (bypasses CORS) |
| Preferences | `@capacitor/preferences` (local key-value storage) |

The `@capacitor/http` plugin is notable -- it makes HTTP requests from the native layer rather than the WebView, bypassing CORS restrictions and making network interception via WebView hooks insufficient. Use OkHttp/HttpURLConnection hooks instead to capture this traffic.

### Live Reload Detection

Capacitor supports live reload during development, where the WebView connects to a remote dev server instead of loading local assets. Some apps accidentally ship with this enabled:

```bash
cat extracted/assets/capacitor.config.json | grep -i "server"
```

A `server.url` field pointing to an IP address or `localhost` indicates a misconfigured build that loads code from a remote source -- a potential hijack vector if the address is attacker-reachable.

## RE Difficulty Assessment

| Aspect | Cordova | Capacitor |
|--------|---------|-----------|
| Code format | Plaintext JS/HTML/CSS | Plaintext JS/HTML/CSS |
| Readability | High -- standard web source | High -- standard web source |
| String extraction | Trivial | Trivial |
| Control flow recovery | Full | Full |
| Patching | Edit JS files directly | Edit JS files directly |
| Obfuscation ceiling | JS obfuscation tools, Ionic AppFlow | JS obfuscation tools |
| Overall difficulty | **Very Easy** | **Very Easy** |

Cordova-family apps are the simplest Android apps to reverse engineer. The source code ships as plaintext web assets. No decompilation, disassembly, or bytecode analysis is needed -- the app is its own source code. The only complicating factor is JavaScript obfuscation, which is uncommon in this ecosystem and weaker than native-level protections. Focus analysis on the web assets directory and `cordova_plugins.js` manifest.

## References

- [Apache Cordova Documentation](https://cordova.apache.org/docs/en/latest/)
- [Capacitor Documentation](https://capacitorjs.com/docs)
- [Ionic Framework](https://ionicframework.com/)
- [jadx -- Android DEX Decompiler](https://github.com/skylot/jadx)
- [Frida](https://frida.re/)
- [McAfee SpyLoan Research](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/spyloan-a-global-threat-exploiting-social-engineering/)
- [ESET Predatory Fintech Research](https://www.welivesecurity.com/en/eset-research/beware-predatory-fintech-loan-sharks-use-android-apps-reach-new-depths/)
- [OWASP Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)
- [WebView Exploitation](../../attacks/webview-exploitation.md)
