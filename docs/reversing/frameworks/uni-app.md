# uni-app (DCloud)

uni-app is a Vue.js-based cross-platform framework developed by DCloud, a Chinese company. Apps built with uni-app run JavaScript inside a WebView or use a native rendering engine (based on Weex) depending on the build configuration. The framework dominates the Chinese Android app ecosystem and is the most common framework behind Chinese-market phishing, gambling, and grey-market financial apps. All business logic lives in JavaScript/Vue bundles packaged under `assets/apps/` inside the APK, making it the primary reverse engineering target.

## Architecture

### Runtime Modes

uni-app supports two rendering modes that fundamentally change the app's runtime behavior:

| Mode | Engine | Description |
|------|--------|-------------|
| **WebView** | Android WebView (Chromium) | Vue components render as HTML/CSS inside a system WebView -- identical to a Cordova-style app |
| **Native Rendering** | Weex-based engine | Vue components compile to native UI widgets via a bridge layer, similar to React Native |

Most uni-app APKs in the wild use WebView mode. Native rendering (marketed as "uni-app x" or "nvue") is less common and requires explicit per-page opt-in by the developer.

### Component Stack

| Layer | Component |
|-------|-----------|
| **JavaScript** | Vue.js 2/3 application code, uni-app runtime, plugin APIs |
| **Bridge** | DCloud bridge layer (`io.dcloud.feature.*`) connecting JS to Android APIs |
| **Rendering** | Android WebView or Weex native renderer |
| **Native Shell** | DCloud SDK (`io.dcloud.*`), handles lifecycle, permissions, plugin loading |

The DCloud bridge exposes device APIs (camera, GPS, contacts, file system) to JavaScript through a message-passing interface. JavaScript calls `uni.*` APIs, which serialize through the bridge to Java-side handlers in `io.dcloud.feature.*` classes.

### DCloud Plus Plugins

uni-app uses a plugin system called "Plus" (HTML5+) that provides native capability wrappers. Each plugin registers as a Java class under `io.dcloud.feature.*` and exposes methods callable from JavaScript via `plus.*` or `uni.*` APIs.

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/apps/__UNI__XXXXXXX/` | App bundle directory (hex app ID) |
| `assets/data/dcloud_control.json` | DCloud runtime configuration |
| `assets/data/dcloud_error.html` | DCloud error page |
| `assets/data/dcloud_properties.xml` | DCloud properties |
| `io.dcloud.*` | Package prefix in DEX classes |
| `io.dcloud.PandoraEntry` | Main entry point activity |
| `io.dcloud.PandoraEntryActivity` | Alternative entry point |
| `DCUniMP` or `DCloudApplication` | Application class names |

Quick check:

```bash
unzip -l target.apk | grep -E "(dcloud|io\.dcloud|assets/apps/)"
```

Manifest inspection:

```bash
aapt dump xmltree target.apk AndroidManifest.xml | grep -i dcloud
```

### App ID Format

Every uni-app project gets a unique ID in the format `__UNI__XXXXXXX` (7 hex characters). This ID appears as the directory name under `assets/apps/` and in `dcloud_control.json`. It maps to the app's registration on DCloud's developer portal.

## Code Location & Extraction

### Bundle Structure

```
assets/
  apps/
    __UNI__XXXXXXX/
      www/
        app-config.js
        app-service.js
        manifest.json
        pages/
          index/
            index.js
          login/
            login.js
        static/
        uni_modules/
  data/
    dcloud_control.json
    dcloud_error.html
```

The `app-service.js` file is the main application bundle -- a single concatenated JavaScript file containing all Vue component logic, route definitions, API calls, and business rules.

### Extraction

```bash
unzip target.apk "assets/apps/*" -d extracted/
unzip target.apk "assets/data/*" -d extracted/
```

### JavaScript Analysis

The extracted JavaScript is minified but not bytecode-compiled. Standard beautification makes it readable:

```bash
npx prettier --write extracted/assets/apps/__UNI__*/www/app-service.js
npx prettier --write extracted/assets/apps/__UNI__*/www/app-config.js
```

Search for high-value targets:

```bash
grep -rniE "(api|http|token|secret|password|login|encrypt|decrypt|key)" extracted/assets/apps/
```

### Configuration Files

`manifest.json` in the app bundle directory contains app metadata, permissions, and SDK configuration. `dcloud_control.json` in `assets/data/` specifies the runtime version and app ID. Parse both with `python3 -m json.tool`.

## Analysis Workflow

1. **Unzip APK** and confirm DCloud indicators (`io.dcloud.*`, `assets/apps/`)
2. **Extract** all files from `assets/apps/` and `assets/data/`
3. **Beautify** `app-service.js` -- this is the primary analysis target
4. **Parse** `manifest.json` for permissions, API keys, third-party SDK configs
5. **Search** for API endpoints, hardcoded credentials, encryption keys
6. **Map** `uni.*` / `plus.*` API calls to understand what device capabilities the app uses
7. **Hook** at runtime with Frida to capture dynamic values

### API Call Mapping

uni-app JavaScript uses `uni.*` APIs for platform features. Key APIs to search for:

| API Call | Capability |
|----------|-----------|
| `uni.request` | HTTP requests -- reveals C2 endpoints |
| `uni.uploadFile` | File exfiltration |
| `uni.getLocation` | GPS tracking |
| `uni.getSystemInfo` | Device fingerprinting |
| `uni.setStorage` / `uni.getStorage` | Local data persistence |
| `uni.makePhoneCall` | Phone call initiation |
| `uni.sendSmsMessage` | SMS sending (via plus plugin) |
| `plus.contacts` | Contact list access |
| `plus.camera` | Camera access |
| `plus.io` | File system access |

## Hooking Strategy

### WebView Interception

For WebView-mode apps, hook the WebView bridge to intercept all JS-to-native communication:

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");

    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        console.log("[WebView] loadUrl: " + url);
        this.loadUrl(url);
    };

    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log("[WebView] evaluateJavascript: " + script.substring(0, 200));
        this.evaluateJavascript(script, callback);
    };
});
```

### DCloud Bridge Interception

Hook the DCloud bridge layer to capture all native API calls from JavaScript:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("io.dcloud.feature") !== -1) {
                console.log("[DCloud Feature] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

### Network Request Interception

Capture HTTP requests made through `uni.request`:

```javascript
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[Network] " + this.toString());
        return this.openConnection();
    };
});
```

### JavaScript Injection

Inject JavaScript into the WebView to intercept `uni.*` calls at the JS layer:

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        this.loadUrl(url);
        var payload = "javascript:void((function(){var orig=uni.request;uni.request=function(o){console.log(JSON.stringify(o));return orig(o);}})())";
        this.loadUrl(payload);
    };
});
```

## Malware Context

uni-app is the framework of choice for Chinese-origin Android malware campaigns, particularly those targeting financial fraud and data harvesting.

| Use Case | Details |
|----------|---------|
| Gambling apps | Illegal gambling platforms distributed outside Google Play, rapid iteration on game UIs using Vue components |
| Phishing campaigns | Fake banking and payment apps mimicking Alipay, WeChat Pay, and Chinese bank interfaces |
| Loan fraud | Predatory lending apps collecting contacts, photos, and location data for extortion |
| Cryptoscams | Fake cryptocurrency trading platforms with fabricated balances and withdrawal locks |
| Data harvesters | Apps requesting excessive permissions, exfiltrating contacts, SMS, and call logs via `plus.*` APIs |

### Chinese Ecosystem Dominance

uni-app is overwhelmingly distributed through Chinese app stores (Huawei AppGallery, Xiaomi GetApps, Tencent MyApp, Baidu Mobile Assistant) rather than Google Play. APKs are also sideloaded via WeChat/QQ links and landing pages. This distribution model makes them harder to track through standard Western threat intelligence feeds.

### Detection Patterns

Common indicators of malicious uni-app samples:

- Heavy use of `plus.contacts`, `plus.camera`, `plus.io` for data collection
- API endpoints pointing to recently registered domains or IP addresses
- Obfuscated C2 URLs constructed by string concatenation in `app-service.js`
- Permission requests disproportionate to stated app functionality
- Multiple app IDs cycling through the same C2 infrastructure

## RE Difficulty Assessment

| Aspect | Assessment |
|--------|-----------|
| Code format | Minified JavaScript (plaintext) |
| Readability | High -- beautify and read directly |
| String extraction | Trivial -- standard text search |
| Control flow recovery | Full -- standard JavaScript |
| Patching | Edit JS files, repackage APK |
| Obfuscation ceiling | Standard JS obfuscators (rare in practice) |
| Overall difficulty | **Easy** (rank 15/28) |

The JavaScript is not bytecode-compiled, making uni-app one of the easier frameworks to reverse engineer. The main challenge is volume -- `app-service.js` can be large (1-5 MB minified) -- and navigating the DCloud-specific API surface. Most malicious uni-app samples use minimal or no obfuscation, relying instead on rapid deployment and replacement to evade takedowns.

## References

- [DCloud uni-app Documentation](https://uniapp.dcloud.net.cn/)
- [dcloudio/uni-app -- GitHub](https://github.com/dcloudio/uni-app)
- [Frida](https://frida.re/)
- [jadx](https://github.com/skylot/jadx)
