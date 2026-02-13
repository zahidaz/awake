# Titanium (Appcelerator)

Titanium apps run JavaScript on a V8 engine embedded in a native Android shell, with the Kroll bridge translating JS calls into native Android API invocations. All application logic resides as JavaScript files inside `assets/Resources/`, making them the primary reverse engineering target. Appcelerator Titanium was a popular cross-platform framework from roughly 2010--2018; its usage has declined sharply, but legacy apps and some malware samples still surface in the wild. The project was acquired by Axway and eventually discontinued, though the open-source SDK remains on GitHub.

## Architecture

### Runtime Components

| Component | Role |
|-----------|------|
| **V8 Engine** | Executes JavaScript application code on Android |
| **Kroll Bridge** | Bidirectional proxy layer connecting JS objects to native Java classes |
| **Titanium Modules** | Java classes exposing Android APIs (camera, contacts, filesystem) to JS |
| **Proxy Objects** | Java-side representations of JS objects, managed by Kroll's reference system |

When a Titanium app calls `Ti.Network.createHTTPClient()`, the Kroll bridge maps the JS call to `org.appcelerator.titanium.TiHTTPClient` on the Java side. Every `Ti.*` namespace maps to a corresponding Java proxy class registered through Kroll's module system.

### Execution Flow

1. Android activity launches via `org.appcelerator.titanium.TiApplication`
2. V8 engine initializes through `libkroll-v8.so`
3. Kroll loads and registers all Titanium module proxies
4. V8 evaluates `app.js` from `assets/Resources/`
5. JS execution drives the app, with Kroll routing API calls to native Java classes

### Native Libraries

| Library | Purpose |
|---------|---------|
| `libkroll-v8.so` | V8 JavaScript engine with Kroll binding layer |
| `libtitanium.so` | Core Titanium runtime native code |
| `libtiverify.so` | License verification (present in some builds) |
| `libstlport_shared.so` | C++ standard library dependency |

## Identification

| Indicator | Location |
|-----------|----------|
| `libkroll-v8.so` | `lib/<arch>/` directory |
| `libtitanium.so` | `lib/<arch>/` directory |
| `org.appcelerator.titanium.*` | DEX class hierarchy |
| `org.appcelerator.kroll.*` | Kroll bridge classes in DEX |
| `assets/Resources/` | Directory containing JS source files |
| `assets/Resources/app.js` | Application entry point |
| `tiapp.xml` | Titanium project configuration (sometimes in assets) |

Quick check:

```bash
unzip -l target.apk | grep -E "(libkroll|libtitanium|Resources/app\.js|tiapp\.xml)"
```

Manifest inspection:

```bash
aapt dump xmltree target.apk AndroidManifest.xml | grep -i appcelerator
```

## Code Location & Extraction

### JavaScript Source Files

Titanium stores application code as plaintext JavaScript files in `assets/Resources/`. Unlike React Native's single-bundle approach, Titanium preserves the developer's file structure.

```bash
unzip target.apk "assets/Resources/*" -d extracted/
find extracted/assets/Resources/ -name "*.js" | head -20
```

Typical file structure inside `assets/Resources/`:

```
assets/Resources/
├── app.js
├── ui/
│   ├── login.js
│   ├── dashboard.js
│   └── settings.js
├── lib/
│   ├── api.js
│   ├── crypto.js
│   └── storage.js
└── alloy/
    ├── controllers/
    ├── models/
    └── styles/
```

### Alloy Framework

Many Titanium apps use the Alloy MVC framework, which compiles XML views, TSS styles, and controller JS into standard Titanium JS files at build time. The compiled output lands in `assets/Resources/alloy/` and is fully readable JavaScript.

```bash
find extracted/assets/Resources/alloy/controllers/ -name "*.js"
```

### Precompiled V8 Snapshots

Some Titanium builds precompile JavaScript into V8 snapshots or bytecode to improve startup time. In these cases, `assets/Resources/` contains `.jsb` (JavaScript binary) files instead of plaintext `.js`.

```bash
file extracted/assets/Resources/app.jsb
xxd -l 16 extracted/assets/Resources/app.jsb
```

V8 snapshots are version-specific and significantly harder to reverse. If plaintext JS is absent, check for mixed deployments where some files are compiled and others remain as source.

## Analysis

### Plaintext JS (Common Case)

Most Titanium apps ship unobfuscated JavaScript. Analysis is straightforward:

```bash
grep -rn "Ti.Network\|Ti.API\|Titanium.Network\|httpClient" extracted/assets/Resources/
grep -rn "password\|token\|secret\|api_key\|apiKey" extracted/assets/Resources/
grep -rn "https\?://" extracted/assets/Resources/ | grep -v "appcelerator.com"
```

### Key Patterns to Search

| Pattern | Significance |
|---------|-------------|
| `Ti.Network.createHTTPClient` | Network requests -- extract endpoints |
| `Ti.App.Properties.setString` | Local data storage -- look for credentials |
| `Ti.Database.open` | SQLite database access |
| `Ti.Filesystem` | File operations on device |
| `Ti.Contacts` | Contact harvesting |
| `Ti.Geolocation` | Location tracking |
| `Ti.Media.showCamera` | Camera access |

### V8 Bytecode Analysis

For precompiled `.jsb` files, options are limited:

```bash
strings extracted/assets/Resources/app.jsb | grep -iE "(http|api|token|key|password)"
```

V8 bytecode does not have mature open-source decompilers comparable to Hermes tooling. Focus on string extraction and runtime hooking when encountering compiled bundles.

## Hooking Strategy

### Java-Layer Kroll Intercepts

The Kroll bridge is the chokepoint for all JS-to-native communication. Hook proxy method invocations to monitor API calls:

```javascript
Java.perform(function() {
    var KrollProxy = Java.use("org.appcelerator.kroll.KrollProxy");
    KrollProxy.fireEvent.overload("java.lang.String", "org.appcelerator.kroll.KrollDict").implementation = function(event, data) {
        console.log("[Kroll] Event: " + event + " Data: " + data);
        return this.fireEvent(event, data);
    };
});
```

### HTTP Request Interception

```javascript
Java.perform(function() {
    var TiHTTPClient = Java.use("ti.modules.titanium.network.TiHTTPClient");
    TiHTTPClient.open.overload("java.lang.String", "java.lang.String").implementation = function(method, url) {
        console.log("[HTTP] " + method + " " + url);
        return this.open(method, url);
    };
});
```

### V8 Native Hooks

Hook V8 script evaluation to intercept JS code loading:

```javascript
var krollModule = Process.findModuleByName("libkroll-v8.so");
if (krollModule) {
    krollModule.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("Script") !== -1 && exp.name.indexOf("Compile") !== -1) {
            console.log("[V8] " + exp.name + " @ " + exp.address);
        }
    });
}
```

### Module Registration Monitoring

```javascript
Java.perform(function() {
    var KrollModule = Java.use("org.appcelerator.kroll.KrollModule");
    KrollModule.onAppCreate.implementation = function(app) {
        console.log("[Module] " + this.getClass().getName() + " registered");
        return this.onAppCreate(app);
    };
});
```

## SSL Pinning Bypass

Titanium's HTTP stack wraps Java's `HttpURLConnection` or Apache HTTP client through `TiHTTPClient`. SSL pinning, when present, operates at the Java layer:

```javascript
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustAllManager = Java.registerClass({
        name: "com.bypass.TrustAll",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var trustManagers = Java.array("javax.net.ssl.TrustManager", [TrustAllManager.$new()]);
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagers, null);
    SSLContext.setDefault(sslContext);
});
```

Some Titanium apps implement certificate checks in JavaScript via `Ti.Network.HTTPClient.validatesSecureCertificate`. Patch this by modifying the JS source directly in `assets/Resources/` before repackaging.

## Malware Context

Titanium was used in phishing campaigns during its peak popularity (2012--2016). The framework's appeal to threat actors was rapid cross-platform UI cloning with native-looking results.

| Use Case | Details |
|----------|---------|
| Fake banking apps | Titanium's native UI components produced convincing banking clones that were harder to distinguish from native apps than WebView-based phishing |
| Credential harvesting | Simple apps using `Ti.Network.createHTTPClient` to POST stolen credentials to attacker infrastructure |
| Data exfiltration | Access to contacts (`Ti.Contacts`), location (`Ti.Geolocation`), and device info through Titanium's cross-platform APIs |
| Adware wrappers | Apps wrapping advertising SDKs with minimal legitimate functionality |

Modern malware rarely uses Titanium due to the framework's decline. Encountering a Titanium-based sample today likely indicates either a legacy app or an actor reusing older tooling.

## RE Difficulty Assessment

| Aspect | Plaintext JS | Precompiled V8 |
|--------|-------------|----------------|
| Code format | JavaScript source files | V8 bytecode snapshots |
| Readability | High -- usually unminified | Low -- no mature decompilers |
| String extraction | Trivial | Trivial via `strings` |
| File structure | Preserved from source project | Flat binary blobs |
| Patching | Edit JS, repackage | Requires bytecode manipulation |
| Overall difficulty | **Very Easy** | **Moderate** |

Titanium apps with plaintext JavaScript are among the easiest Android targets to reverse engineer. The preserved file structure, readable code, and well-defined Kroll bridge make both static and dynamic analysis straightforward. The primary challenge arises only with precompiled V8 builds, which are uncommon.

## References

- [Titanium SDK Source -- tidev](https://github.com/tidev/titanium-sdk)
- [Kroll Bridge Architecture -- Appcelerator Wiki (archived)](https://web.archive.org/web/2020/https://wiki.appcelerator.org/display/guides2/Kroll)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [jadx -- Android DEX Decompiler](https://github.com/skylot/jadx)
