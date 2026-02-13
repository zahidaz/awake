# Development Frameworks

Cross-platform frameworks change the Android threat model. Each framework introduces its own runtime, packaging format, and inter-layer bridge that creates attack surfaces absent in native Android apps. Identifying which framework built an app determines the entire reverse engineering approach, the toolchain, and the attack surface. An app built with Flutter has zero useful DEX code. A Cordova app has all logic in plaintext JavaScript. A React Native app with a JavaScript bridge creates an interception point between the UI layer and native APIs.

## Framework Categories

| Category | Frameworks | Code Location | Primary Attack Surface |
|----------|-----------|---------------|----------------------|
| Web-based hybrid | [Cordova](cordova.md), [Capacitor](cordova.md), [PWA/TWA](pwa-twa.md), [RPG Maker](rpgmaker.md), [GDevelop](gdevelop.md) | JavaScript in `assets/www/` | Plaintext source, WebView bridge, XSS-to-native escalation |
| JS bridge | [React Native](react-native.md), [NativeScript](nativescript.md), [Titanium](titanium.md), [uni-app](uni-app.md) | JavaScript bundle in assets, native bridge layer | Bridge interception, bundle tampering, Hermes bytecode |
| Compiled native | [Flutter](flutter.md), [Qt](qt.md), [Delphi](delphi.md), [Unreal Engine](unreal-engine.md) | Compiled binary in `.so` libraries | Stripped symbols, proprietary runtimes, no DEX-level visibility |
| .NET/Mono | [Xamarin](xamarin.md), [Compose Multiplatform](compose-multiplatform.md), [Unity (Mono)](unity.md) | IL assemblies (`.dll`) or DEX | .NET decompilation, assembly tampering, Mono runtime hooks |
| IL2CPP | [Unity (IL2CPP)](unity.md) | Compiled native + metadata | `global-metadata.dat` extraction, Il2CppDumper symbol recovery |
| Lua/Python VM | [Corona](corona.md), [Cocos2d-x](cocos2d-x.md), [Kivy](kivy.md), [Defold](defold.md), [Ren'Py](renpy.md) | Bytecode in assets, interpreted at runtime | Bytecode decompilation, asset extraction, runtime hooking |
| No-code | [AppInventor](appinventor.md), [B4A](b4a.md) | Standard DEX (generated Java) | Fully decompilable, predictable code patterns |
| Game engines | [Godot](godot.md), [GameMaker](gamemaker.md), [libGDX](libgdx.md) | Engine-specific archive formats | `.pck` extraction, proprietary bytecode, engine-level hooks |

## Framework Identification

The fastest way to identify a framework is to unzip the APK and check for indicator files and native libraries.

| Framework | File Indicators | Native Libraries | Package/Class Markers |
|-----------|----------------|-------------------|----------------------|
| [React Native](react-native.md) | `assets/index.android.bundle` | `libjsc.so` or `libhermes.so` | `com.facebook.react.*` |
| [Flutter](flutter.md) | `assets/flutter_assets/kernel_blob.bin` (debug) | `libflutter.so`, `libapp.so` | `io.flutter.*` (thin bootstrap) |
| [Xamarin / .NET MAUI](xamarin.md) | `assemblies/*.dll` in APK root or `assets/` | `libmonosgen-2.0.so`, `libxamarin-app.so` | `mono.MonoRuntimeProvider` |
| [Cordova / Ionic](cordova.md) | `assets/www/index.html`, `assets/www/cordova.js` | None framework-specific | `org.apache.cordova.*` |
| [Capacitor](cordova.md) | `assets/public/index.html` | None framework-specific | `com.getcapacitor.*` |
| [Unity](unity.md) (Mono) | `assets/bin/Data/Managed/*.dll` | `libmono.so`, `libunity.so` | `com.unity3d.player.UnityPlayer` |
| [Unity](unity.md) (IL2CPP) | `global-metadata.dat` in Metadata/ | `libil2cpp.so`, `libunity.so` | `com.unity3d.player.UnityPlayer` |
| [Godot](godot.md) | `assets/*.pck` | `libgodot_android.so` | `org.godotengine.*` |
| [Unreal Engine](unreal-engine.md) | `assets/*.pak`, `assets/*.utoc` | `libUE4.so` or `libUnreal.so` | `com.epicgames.unreal.GameActivity` |
| [NativeScript](nativescript.md) | `assets/app/bundle.js` | `libNativeScript.so` | `org.nativescript.*` |
| [Kotlin Multiplatform](kotlin-multiplatform.md) | No unique file indicators | None framework-specific | Standard Kotlin classes in DEX |
| [Qt for Android](qt.md) | `assets/*.rcc` | `libQt5Core_*.so`, `libQt6Core_*.so` | `org.qtproject.qt5.*` |
| [Kivy (Python)](kivy.md) | `assets/private.tar`, `assets/public.tar` | `libpython*.so`, `libSDL2.so` | `org.kivy.*` |
| [Delphi / RAD Studio](delphi.md) | None distinctive | `libFMXNativeActivity.so` | `com.embarcadero.*` |
| [B4A (Basic4Android)](b4a.md) | `assets/*.bal` | None framework-specific | `anywheresoftware.b4a.*` |
| [GameMaker](gamemaker.md) | `assets/game.droid` | `libyoyo.so` | `com.yoyogames.*` |
| [Corona / Solar2D](corona.md) | `assets/resource.car` | `libcorona.so`, `liblua.so` | `com.ansca.corona.*` |
| [Cocos2d-x](cocos2d-x.md) | `assets/src/*.lua` or `assets/script/` | `libcocos2dlua.so` or `libcocos2djs.so` | `org.cocos2dx.*` |
| [Titanium](titanium.md) | `assets/Resources/` | `libkroll-v8.so`, `libtitanium.so` | `org.appcelerator.titanium.*` |
| [Compose Multiplatform](compose-multiplatform.md) | No unique file indicators | None framework-specific | `androidx.compose.*` in DEX |
| [AppInventor / Kodular](appinventor.md) | `assets/youngandroidproject/` | None framework-specific | `com.google.appinventor.*`, `appinventor.ai_*` |
| [libGDX](libgdx.md) | `assets/*.atlas`, `assets/*.tmx` | `libgdx.so` | `com.badlogic.gdx.*` |
| [Defold](defold.md) | `assets/game.dmanifest`, `assets/game.arcd` | `libdmengine.so` | `com.defold.*` |
| [Ren'Py](renpy.md) | `assets/renpy/`, `assets/game/*.rpyc` | `libpython*.so`, `librenpy.so` | `org.renpy.*` |
| [RPG Maker](rpgmaker.md) | `assets/www/js/rpg_*.js` | None framework-specific | RPG Maker MV/MZ uses Cordova-like webview |
| [uni-app](uni-app.md) | `assets/apps/`, `assets/data/dcloud_*.json` | None framework-specific | `io.dcloud.*` |
| [GDevelop](gdevelop.md) | `assets/www/gd.js`, `assets/www/pixi*.js` | None framework-specific | Cordova-wrapped HTML5 game |
| [Felgo](felgo.md) | `assets/*.rcc` | `libQt5Core*.so`, `libFelgo*.so` | `net.vplay.*` or `com.felgo.*` |
| [PWA / TWA](pwa-twa.md) | Minimal APK, `assetlinks.json` reference | None | `LauncherActivity` + Chrome Custom Tabs |

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
elif grep -q "libgodot_android.so" /tmp/apk_contents.txt; then
    echo "Godot"
elif grep -q "libUE4.so" /tmp/apk_contents.txt || grep -q "libUnreal.so" /tmp/apk_contents.txt; then
    echo "Unreal Engine"
elif grep -q "libNativeScript.so" /tmp/apk_contents.txt; then
    echo "NativeScript"
elif grep -q "libQt5Core" /tmp/apk_contents.txt || grep -q "libQt6Core" /tmp/apk_contents.txt; then
    echo "Qt for Android"
elif grep -q "libpython" /tmp/apk_contents.txt && grep -q "libSDL2.so" /tmp/apk_contents.txt; then
    echo "Kivy (Python)"
elif grep -q "libFMXNativeActivity.so" /tmp/apk_contents.txt; then
    echo "Delphi / RAD Studio"
elif grep -q "libyoyo.so" /tmp/apk_contents.txt; then
    echo "GameMaker"
elif grep -q "libcorona.so" /tmp/apk_contents.txt; then
    echo "Corona / Solar2D"
elif grep -q "libcocos2d" /tmp/apk_contents.txt; then
    echo "Cocos2d-x"
elif grep -q "libtitanium.so" /tmp/apk_contents.txt || grep -q "libkroll-v8.so" /tmp/apk_contents.txt; then
    echo "Titanium (Appcelerator)"
elif grep -q "libgdx.so" /tmp/apk_contents.txt; then
    echo "libGDX"
elif grep -q "libdmengine.so" /tmp/apk_contents.txt; then
    echo "Defold"
elif grep -q "assets/renpy/" /tmp/apk_contents.txt; then
    echo "Ren'Py"
elif grep -q "assets/www/js/rpg_core.js" /tmp/apk_contents.txt; then
    echo "RPG Maker MV/MZ"
elif grep -q "io.dcloud" /tmp/apk_contents.txt || grep -q "assets/data/dcloud_" /tmp/apk_contents.txt; then
    echo "uni-app"
elif grep -q "assets/www/gd.js" /tmp/apk_contents.txt; then
    echo "GDevelop"
elif grep -q "youngandroidproject" /tmp/apk_contents.txt; then
    echo "AppInventor / Kodular"
elif grep -q "anywheresoftware.b4a" /tmp/apk_contents.txt; then
    echo "B4A (Basic4Android)"
else
    echo "Native Android (Java/Kotlin)"
fi
```

Frida-based runtime detection:

```javascript
Java.perform(function() {
    var detected = false;

    var checks = [
        ["com.facebook.react.ReactActivity", "React Native"],
        ["io.flutter.embedding.engine.FlutterEngine", "Flutter"],
        ["mono.MonoRuntimeProvider", "Xamarin"],
        ["org.apache.cordova.CordovaActivity", "Cordova"],
        ["com.getcapacitor.BridgeActivity", "Capacitor"],
        ["com.unity3d.player.UnityPlayer", "Unity"],
        ["org.godotengine.godot.Godot", "Godot"],
        ["com.epicgames.unreal.GameActivity", "Unreal Engine"],
        ["org.nativescript.NativeScriptActivity", "NativeScript"],
        ["org.qtproject.qt5.android.QtActivity", "Qt"],
        ["org.kivy.android.PythonActivity", "Kivy"],
        ["com.embarcadero.firemonkey.FMXNativeActivity", "Delphi"],
        ["anywheresoftware.b4a.BA", "B4A"],
        ["org.appcelerator.titanium.TiApplication", "Titanium"],
        ["com.badlogic.gdx.backends.android.AndroidApplication", "libGDX"],
        ["org.renpy.android.PythonSDLActivity", "Ren'Py"],
        ["io.dcloud.PandoraEntry", "uni-app"],
        ["com.google.appinventor.components.runtime.Form", "AppInventor"],
    ];

    checks.forEach(function(pair) {
        try {
            Java.use(pair[0]);
            send("Framework: " + pair[1]);
            detected = true;
        } catch(e) {}
    });

    if (!detected) {
        send("Framework: Native Android");
    }
});
```

## Attack Surfaces by Framework Type

### Web-Based Hybrid (Cordova, Capacitor, PWA)

Hybrid apps wrap a WebView around web content. The entire application logic is JavaScript in `assets/www/`, readable without decompilation.

| Attack Surface | Risk | Exploitation |
|---------------|------|-------------|
| Plaintext source code | All business logic, API keys, auth tokens visible in cleartext | Direct file extraction from APK |
| JavaScript bridge | Native plugin calls (`cordova.exec()`) expose device APIs to JS context | Hook or patch bridge calls to intercept parameters |
| WebView vulnerabilities | `setJavaScriptEnabled(true)`, `setAllowFileAccess(true)` | XSS-to-file-read, JavaScript interface injection |
| Insecure `@JavascriptInterface` | Exported methods callable from any JavaScript context within the WebView | Inject JS to call exposed native methods |
| No code signing for JS | JavaScript can be modified without breaking APK signature | Repackage with modified `assets/www/` content |
| Client-side validation | Auth checks, premium feature gates implemented in JS | Patch JavaScript to bypass client-side logic |

[SpyLoan](../../malware/families/spyloan.md) and predatory lending apps frequently use Cordova because web developers can build functional Android apps without mobile-specific skills. The readable JavaScript makes these apps trivial to analyze.

### JavaScript Bridge (React Native, NativeScript)

Bridge-based frameworks run JavaScript in a dedicated engine (JavaScriptCore, Hermes, V8) and communicate with native Android APIs through a serialized bridge.

| Attack Surface | Risk | Exploitation |
|---------------|------|-------------|
| Bridge interception | All native API calls pass through a serializable bridge | Frida hooks on `nativeCallSyncHook` or `com.facebook.react.bridge.*` |
| Bundle tampering | JS bundle in `assets/` can be extracted, modified, repackaged | Modify `index.android.bundle`, disable auth checks or inject logging |
| Hermes bytecode | Hermes pre-compiles JS to custom bytecode, harder to read | [hermes-dec](https://github.com/P1sec/hermes-dec) decompiles to readable JS |
| JS-level secrets | API keys, endpoint URLs, feature flags stored in JS bundle | String extraction from bundle, even Hermes bytecode |
| CodePush / OTA updates | React Native apps can download JS updates at runtime | MITM the update channel to inject malicious code |
| Deep linking through JS router | Navigation handled in JS, deep links parsed client-side | Craft deep links that navigate to unintended screens or pass malicious parameters |

### Compiled Native (Flutter, Qt, Delphi, Unreal)

These frameworks compile application code to native ARM instructions. The DEX layer is a thin bootstrap with no business logic.

| Attack Surface | Risk | Exploitation |
|---------------|------|-------------|
| No DEX-level visibility | jadx shows only framework bootstrap code | Must use framework-specific tools (blutter for Flutter, Ghidra for Qt/Delphi) |
| Stripped symbols | Release builds strip function names from `.so` | blutter recovers Dart symbols from AOT snapshots; Qt/Delphi require manual RE |
| BoringSSL pinning (Flutter) | SSL pinning implemented in native `libflutter.so` | Patch `ssl_crypto_x509_session_verify_cert_chain`, use reFlutter |
| Dart snapshot format | Flutter's AOT snapshot is a proprietary format | blutter + Ghidra for code analysis, Frida for runtime hooks at recovered offsets |
| Platform channel bridge | Flutter communicates with native code via MethodChannel | Hook `io.flutter.plugin.common.MethodChannel` to intercept platform calls |

[FluHorse](../../malware/families/fluhorse.md) uses Flutter because Dart AOT compilation into `libapp.so` defeats the standard jadx analysis pipeline. Analysts must use blutter to recover Dart symbols before meaningful analysis is possible.

### .NET / Mono (Xamarin, Unity Mono)

.NET-based frameworks package IL assemblies (`.dll` files) that decompile to near-source-quality C# with tools like dnSpy or ILSpy.

| Attack Surface | Risk | Exploitation |
|---------------|------|-------------|
| High-fidelity decompilation | IL assemblies decompile to readable C# with types, names, and control flow intact | dnSpy/ILSpy produce near-original source code |
| Assembly tampering | `.dll` files can be modified and repackaged | Patch C# IL directly with dnSpy, repackage APK |
| Mono runtime hooks | Mono exposes `mono_jit_runtime_invoke` for hooking any managed method | Frida hooks on Mono runtime internals |
| .NET MAUI blob evasion | .NET MAUI stores assemblies in blob files that evade DEX-based scanners | McAfee [documented](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/) malware using C# in blob files to bypass DEX scanning |

### IL2CPP (Unity)

Unity's IL2CPP backend compiles C# to native C++ then to ARM. The `.dll` assemblies are gone, but `global-metadata.dat` preserves type information.

| Attack Surface | Risk | Exploitation |
|---------------|------|-------------|
| Metadata extraction | `global-metadata.dat` contains all class names, method names, and string literals | Il2CppDumper extracts full type hierarchy and generates C# stubs |
| Symbol-guided RE | Il2CppDumper output maps native addresses to C# method names | Load Il2CppDumper output into Ghidra/IDA for named native analysis |
| SDK embedding | Unity games embed third-party SDKs that may be malicious | [Goldoson](../../malware/families/goldoson.md) was a malicious SDK in 60+ legitimate Unity games (100M+ installs) |
| Asset bundle tampering | Unity asset bundles can be extracted, modified, and repacked | AssetStudio for extraction, custom tools for repacking |

## Supply Chain Risks

Cross-platform frameworks increase supply chain attack surface through their dependency chains.

| Risk | Framework | Example |
|------|-----------|---------|
| Malicious SDK in legitimate apps | Unity | [Goldoson](../../malware/families/goldoson.md) SDK embedded in 60+ apps, collected device data and performed ad fraud |
| Compromised npm packages | React Native, Cordova, NativeScript | Typosquatting and dependency confusion attacks against JavaScript package registries |
| Malicious plugins | Cordova, Capacitor | Plugins bridge JS to native APIs; a malicious plugin gets full native access |
| Pre-built binary dependencies | Flutter, Unity, React Native | Native `.so` libraries from third-party packages may contain backdoors |
| OTA code injection | React Native (CodePush), Cordova (Hot Code Push) | Runtime code updates bypass Play Store review and app signing |

OTA update mechanisms are particularly concerning. React Native's CodePush and similar systems allow downloading and executing new JavaScript at runtime, completely bypassing Google Play review. A compromised update server or MITM attack on the update channel can inject arbitrary code into deployed apps.

## SSL Pinning Bypass by Framework

| Framework | Pinning Location | Bypass Method | Tool |
|-----------|-----------------|---------------|------|
| React Native | JS layer or native TrustManager | Patch bundle or Java-layer Frida hook | Frida, bundle patching |
| Flutter | BoringSSL in `libflutter.so` | Patch `ssl_crypto_x509_session_verify_cert_chain` | reFlutter, Ghidra binary patch |
| Xamarin | Mono `ServicePointManager` or `MobileTlsProvider` | Patch the .dll or Frida mono runtime hook | dnSpy, Frida |
| Cordova / Ionic | Java plugin (OkHttp) or `WebViewClient` | Standard Java-layer Frida hooks | Frida, Objection |
| Unity (Mono) | C# `UnityWebRequest` or embedded OkHttp | Patch `Assembly-CSharp.dll` or Java-layer hook | dnSpy, Frida |
| Unity (IL2CPP) | Native compiled cert check | Il2CppDumper to locate function, Frida native hook | Il2CppDumper, Frida |
| Godot | mbedTLS compiled into engine | Native hook on `mbedtls_ssl_handshake` | Frida, Ghidra |
| Unreal Engine | OpenSSL or platform TrustManager | Native hook or Java-layer bypass | Frida |
| NativeScript | V8 bridge to Java TrustManager | Java-layer Frida hooks | Frida |
| Qt | `QSslSocket` in `libQt5Network.so` | Native Frida hook on SSL verification | Frida, Ghidra |
| Kivy | Python `ssl` module via `libpython` | Patch Python ssl module or hook native OpenSSL | Frida |
| Delphi | Indy TIdSSLIOHandlerSocketOpenSSL | Native hook on OpenSSL verify callback | Frida, Ghidra |
| B4A | Java OkHttp or HttpURLConnection | Standard Java-layer hooks | Frida, Objection |
| Titanium | V8-based JS with Java HTTP wrappers | Java-layer Frida hooks | Frida |
| libGDX | Java HttpURLConnection or OkHttp | Standard Java-layer hooks | Frida, Objection |
| Ren'Py | Python `urllib`/`requests` via `libpython` | Patch Python ssl or hook native OpenSSL | Frida |
| uni-app | WebView or Java HTTP client | Java-layer hooks or WebView interception | Frida |
| AppInventor / Kodular | Java HttpURLConnection | Standard Java-layer hooks | Frida, Objection |
| Compose Multiplatform | OkHttp or Ktor client | Standard Java-layer hooks | Frida, Objection |
| Native Android | OkHttp `CertificatePinner`, TrustManager, NSC | Standard Java-layer Frida hooks | Frida, Objection |

## Hooking Strategy by Framework

| Framework | Frida Approach | Hook Target | Effectiveness |
|-----------|---------------|-------------|---------------|
| React Native (JSC) | Java bridge hooks + JS bundle patching | `com.facebook.react.bridge.*`, native module calls | Moderate |
| React Native (Hermes) | Native hooks on `libhermes.so` | Hermes runtime functions, `nativeCallSyncHook` | Limited |
| Flutter | Native hooks on `libapp.so` at blutter offsets | Dart function addresses from blutter output | Moderate |
| Xamarin | Mono runtime hooks or DLL patching | `mono_jit_runtime_invoke`, .NET methods via Mono API | High |
| Cordova / Ionic | WebView hooks + direct JS modification | `WebView.loadUrl`, `evaluateJavascript`, JS bridge | High |
| Unity (Mono) | Mono runtime hooks | `Assembly-CSharp.dll` methods via Mono API | High |
| Unity (IL2CPP) | Native hooks at Il2CppDumper offsets | C++ compiled method addresses from metadata dump | Moderate |
| Godot | Native hooks on `libgodot_android.so` | GDScript VM functions, exported engine methods | Limited |
| Unreal Engine | Native hooks on `libUE4.so` | Blueprint bytecode interpreter, UObject methods | Low |
| NativeScript | V8 bridge hooks + JS patching | Java bridge layer, native API bindings | Moderate |
| Kotlin Multiplatform | Standard Java hooks | Regular Java/Kotlin methods in DEX | High |
| Qt | Native hooks on Qt libraries | `QNetworkAccessManager`, `QSslSocket` | Low |
| Kivy | Python runtime hooks via `libpython` | Python function objects, C extension calls | Limited |
| Delphi | Native hooks on `libFMXNativeActivity.so` | Object Pascal compiled methods | Low |
| B4A | Standard Java hooks | Generated Java classes in DEX | High |
| Titanium | V8 bridge hooks + JS patching | `org.appcelerator.titanium.*`, Kroll bridge | Moderate |
| libGDX | Standard Java hooks | `com.badlogic.gdx.*` game loop and scene classes | High |
| Compose Multiplatform | Standard Java hooks | Regular Kotlin/Compose methods in DEX | High |
| AppInventor / Kodular | Standard Java hooks | `com.google.appinventor.*` components | High |
| Ren'Py | Python runtime hooks via `libpython` | Python game script functions, Ren'Py engine | Limited |
| RPG Maker | WebView hooks + JS modification | JavaScript game engine in `assets/www/` | High |
| uni-app | WebView hooks + bridge interception | `io.dcloud.*` bridge, JavaScript engine | Moderate |
| Defold | Native hooks on `libdmengine.so` | Lua VM functions, engine exports | Limited |
| GDevelop | WebView hooks + JS modification | Pixi.js game engine in `assets/www/` | High |
| Felgo | Native hooks on Qt + Felgo libraries | QML engine, Felgo game/app components | Low |

## Reverse Engineering Difficulty Ranking

From easiest to hardest:

| Rank | Framework | Why |
|------|-----------|-----|
| 1 | Cordova / Ionic / Capacitor | All code is readable JavaScript in `assets/www/` |
| 2 | RPG Maker MV/MZ | JavaScript game engine in `assets/www/js/`, Cordova-wrapped |
| 3 | GDevelop | HTML5 game code in `assets/www/`, Pixi.js readable |
| 4 | PWA / TWA | Web code visible via browser DevTools, thin native wrapper |
| 5 | B4A | Generates standard Java classes, fully decompilable with jadx |
| 6 | AppInventor / Kodular | Generated Java code, decompiles cleanly with jadx |
| 7 | Xamarin (Mono) | .NET DLLs decompile to near-source C# |
| 8 | Unity (Mono) | Same as Xamarin -- .NET DLLs in `assets/bin/Data/Managed/` |
| 9 | Kotlin Multiplatform | Standard DEX, analyzed with jadx like any native app |
| 10 | Compose Multiplatform | Standard DEX with Compose UI classes, jadx works |
| 11 | libGDX | Java game framework, standard DEX decompilation |
| 12 | NativeScript | JavaScript bundles, similar to React Native |
| 13 | React Native (JSC) | Minified but readable JavaScript bundle |
| 14 | Titanium | JavaScript in `assets/Resources/`, V8 execution |
| 15 | uni-app | Vue-based JS in `assets/apps/`, WebView or V8 |
| 16 | React Native (Hermes) | Requires Hermes bytecode decompilation |
| 17 | Kivy | Python bytecode (.pyc) decompilable but sometimes encrypted |
| 18 | Ren'Py | Python + compiled .rpyc scripts, decompilable with unrpyc |
| 19 | Corona / Solar2D | Lua bytecode decompilation, sometimes encrypted |
| 20 | Defold | Lua scripts in .arcd archive, extractable but custom format |
| 21 | GameMaker | Proprietary data.droid format, limited tooling |
| 22 | Godot | GDScript in .pck extractable, but GDNative/C++ modules are native |
| 23 | Unity (IL2CPP) | Il2CppDumper + Ghidra, but metadata preserves symbols |
| 24 | Flutter | AOT-compiled Dart with stripped symbols, requires blutter |
| 25 | Felgo | Qt-based native with QML scripting layer |
| 26 | Delphi | Object Pascal compiled to native ARM, minimal metadata |
| 27 | Qt for Android | Pure native C++ with Qt abstractions, minimal metadata |
| 28 | Unreal Engine | Heavy native C++ with UE abstractions, massive binary |

## Malware Use of Frameworks

| Framework | Known Malware | Motivation |
|-----------|--------------|------------|
| Native (Java/Kotlin) | [Cerberus](../../malware/families/cerberus.md), [GodFather](../../malware/families/godfather.md), [Anatsa](../../malware/families/anatsa.md), [Octo](../../malware/families/octo.md), [Hook](../../malware/families/hook.md), [Vultur](../../malware/families/vultur.md) | Full API access, mature packing ecosystem |
| Flutter | [FluHorse](../../malware/families/fluhorse.md) | AOT compilation defeats jadx, cross-platform |
| React Native | Phishing campaigns, fake banking apps | Rapid cross-platform development |
| Cordova / Ionic | [SpyLoan](../../malware/families/spyloan.md), predatory lending apps | Fastest development cycle, web skills sufficient |
| Unity | [Goldoson](../../malware/families/goldoson.md) SDK in legitimate games | SDK embedding for massive install base |
| .NET MAUI | Data theft campaigns | C# in blob files evades DEX-based scanning |
| B4A | Commodity RATs, SMS stealers | Low barrier to entry, drag-and-drop IDE |
| AppInventor / Kodular | Low-sophistication spyware, stalkerware | No-code development, used by non-programmers |
| Titanium | Phishing apps (historical) | Rapid JS-based development, declining usage |
| uni-app | Chinese market phishing, gambling apps | Dominant in Chinese app ecosystem |

Framework choice correlates with threat actor sophistication. Banking trojan operators prefer native Android for maximum control and access to commercial packers. Less sophisticated actors building phishing or data harvesting campaigns choose web-based frameworks for speed. Flutter adoption by malware authors is increasing as its AOT compilation provides a free obfuscation layer that defeats the standard jadx pipeline.

## Detection Challenges

| Framework | Scanner Challenge | Why |
|-----------|-----------------|-----|
| Flutter | No DEX code to scan | All logic in native `libapp.so`, invisible to DEX-based pattern matching |
| .NET MAUI | Logic in blob files | C# assemblies stored outside DEX, most scanners skip them |
| React Native (Hermes) | Bytecode format | Hermes bytecode requires specialized decompilation tooling |
| Cordova / hybrid | JavaScript not scanned | Most Android AV engines focus on DEX; JS in `assets/www/` is ignored |
| Unity (IL2CPP) | Native compilation | Game logic compiled to `libil2cpp.so`, no DEX representation |

Android security scanners (Play Protect, VirusTotal engines) were designed to analyze DEX bytecode. Cross-platform frameworks that store logic in JavaScript bundles, .NET assemblies, Dart AOT snapshots, or native compiled libraries bypass the primary scanning pipeline. This creates a structural detection gap that malware authors exploit.

## Tools Summary

| Tool | Framework Target | Purpose |
|------|-----------------|---------|
| [jadx](https://github.com/skylot/jadx) | Native Android, KMP, B4A | DEX to Java decompilation |
| [dnSpy](https://github.com/dnSpyEx/dnSpy) / [ILSpy](https://github.com/icsharpcode/ILSpy) | Xamarin, Unity (Mono) | .NET IL decompilation to C# |
| [blutter](https://github.com/worawit/blutter) | Flutter | Dart AOT snapshot analysis, symbol recovery |
| [reFlutter](https://github.com/Impact-I/reFlutter) | Flutter | SSL bypass and snapshot extraction |
| [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) | Unity (IL2CPP) | Metadata extraction, C# stub generation |
| [Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) | Unity (IL2CPP) | Alternative IL2CPP analyzer |
| [hbctool](https://github.com/bongtrop/hbctool) | React Native (Hermes) | Hermes bytecode disassembly |
| [hermes-dec](https://github.com/P1sec/hermes-dec) | React Native (Hermes) | Hermes bytecode decompilation |
| [gdsdecomp](https://github.com/bruvzg/gdsdecomp) | Godot | .pck resource extraction and GDScript recovery |
| [unluac](https://github.com/HansWessworht/unluac) | Corona/Solar2D, Cocos2d-x | Lua bytecode decompilation |
| [Frida](https://frida.re/) | All frameworks | Runtime instrumentation and hooking |
| [Ghidra](https://ghidra-sre.org/) | Flutter, Unity (IL2CPP), Qt, UE, native | Native ARM code analysis |
