# Qt for Android

Qt for Android apps are built in C++ (with optional QML for UI), compiled to native ARM shared libraries via Qt's toolchain. The Android wrapper is a thin Java shell that bootstraps the Qt runtime, loads native libraries, and delegates all rendering and logic to the C++ layer. Qt is maintained by The Qt Company and is used in both commercial and open-source applications, ranging from industrial control panels to media players ported from desktop.

## Architecture

### Runtime Model

Qt apps on Android follow a host-guest pattern:

| Layer | Components |
|-------|------------|
| **Java shell** | `QtActivity` (extends `Activity`), `QtServiceDelegate`, loader classes in `org.qtproject.qt5.*` or `org.qtproject.qt.*` |
| **Qt runtime** | `libQt5Core.so` / `libQt6Core.so`, `libQt5Gui.so` / `libQt6Gui.so`, `libQt5Widgets.so` or `libQt5Quick.so` / `libQt6Quick.so` |
| **Application** | Developer's native `.so` (e.g., `libMyApp.so`) compiled from C++ sources |
| **QML engine** | `libQt5Qml.so` / `libQt6Qml.so` -- interprets `.qml` files for declarative UI |

The Java shell performs minimal work: it initializes the Android `Activity`, sets up the `SurfaceView` for rendering, and calls `System.loadLibrary()` to load the Qt libraries. From that point, all logic runs in native code.

### Qt Widgets vs QML

Qt apps use one of two UI paradigms:

| Paradigm | Description |
|----------|-------------|
| **Qt Widgets** | Traditional C++ UI, fully compiled into the native `.so`, no extractable UI definitions |
| **QML / Qt Quick** | Declarative UI language (JavaScript-like syntax), stored as `.qml` files either embedded in Qt Resource files (`.rcc` / `.qrc`) or shipped as assets |

QML apps are significantly easier to reverse because the UI logic is in readable text files rather than compiled C++.

### Rendering Pipeline

Qt renders its own UI surface rather than using Android's native view system. It draws directly to a `SurfaceView` or `TextureView` via OpenGL ES or Vulkan. This means standard Android UI inspection tools (Layout Inspector, `uiautomator`) show a single opaque surface with no widget hierarchy.

## Identification

| Indicator | Location |
|-----------|----------|
| `libQt5Core.so` or `libQt6Core.so` | `lib/<arch>/` in APK |
| `libQt5Gui.so` or `libQt6Gui.so` | `lib/<arch>/` |
| `libQt5Quick.so` or `libQt6Quick.so` | Present if app uses QML |
| `libQt5Qml.so` or `libQt6Qml.so` | QML engine library |
| `org.qtproject.qt5.android.*` | DEX classes (Qt5) |
| `org.qtproject.qt.android.*` | DEX classes (Qt6) |
| `assets/--QtLoader--` | Qt deployment metadata |
| `assets/*.rcc` | Compiled Qt Resource files |
| `.qml` files in assets | QML source files (if not packed into `.rcc`) |

Quick check:

```bash
unzip -l target.apk | grep -iE "(libQt|\.rcc|\.qml|qtproject)"
```

## Code Location

### Native Libraries

All application logic resides in native `.so` files in `lib/<arch>/`:

```bash
unzip target.apk "lib/arm64-v8a/*" -d extracted/
ls extracted/lib/arm64-v8a/
```

The developer's code is typically in a single `.so` file (e.g., `libMyApp.so`), while Qt framework libraries are separate (`libQt5Core.so`, `libQt5Network.so`, etc.). The app `.so` links against the Qt libraries.

### QML Resources

QML files may be:

1. **Loose in assets** -- directly readable after APK extraction
2. **Packed in `.rcc` files** -- compiled Qt Resource Container format
3. **Compiled into the binary** -- embedded via Qt's resource system at build time

### Extracting QML from .rcc Files

Qt Resource files (`.rcc`) use a documented binary format. The `rcc` tool from a Qt SDK installation can list and extract contents:

```bash
rcc --list assets/qml_resources.rcc
rcc --output extracted_resources/ assets/qml_resources.rcc
```

Alternatively, use [qrc_extractor](https://github.com/aspect-apps/qrc-extractor) or parse the format manually. The `.rcc` header starts with `qres` (magic bytes `0x71 0x72 0x65 0x73`).

For resources compiled into the binary, search for the `qInitResources` function in the native `.so` -- the resource data is embedded as a byte array and registered at startup:

```bash
strings libMyApp.so | grep -E "(\.qml|\.js|qrc:/)"
```

## Analysis Tools & Workflow

| Tool | Purpose |
|------|---------|
| [Ghidra](https://ghidra-sre.org/) | Primary disassembler for native ARM analysis of application `.so` |
| [IDA Pro](https://hex-rays.com/ida-pro/) | Commercial disassembler with superior ARM decompilation |
| [rizin/Cutter](https://github.com/rizinorg/cutter) | Open-source alternative for native binary analysis |
| [jadx](https://github.com/skylot/jadx) | Decompile the Java shell (minimal logic but reveals library loading order) |
| [rcc](https://doc.qt.io/qt-6/rcc.html) | Qt Resource Compiler -- extract `.rcc` file contents |
| [Frida](https://frida.re/) | Runtime hooking of native functions |
| [GammaRay](https://github.com/KDAB/GammaRay) | Qt introspection tool (requires debug build or injection) |

### Recommended Workflow

1. **Unzip APK** and confirm Qt presence via `libQt5Core.so` / `libQt6Core.so`
2. **Identify UI paradigm** -- presence of `libQt5Quick.so` or `.qml` files indicates QML
3. **Extract QML** from assets or `.rcc` files -- this is the easiest win for understanding UI logic and data flow
4. **Load application `.so`** into Ghidra or IDA for native analysis
5. **Recover Qt metadata** -- Qt's meta-object system (MOC) embeds signal/slot names, property definitions, and class hierarchies as structured data in the binary
6. **Search for string literals** in the native binary for API endpoints, encryption keys, protocol details
7. **Hook at runtime** with Frida to intercept network calls, crypto operations, and business logic

### Qt Meta-Object Recovery

Qt's Meta-Object Compiler (MOC) generates metadata structures for every `QObject` subclass. These structures survive compilation and contain:

- Class names as plaintext strings
- Signal and slot method names
- Property names and types
- Enumeration values

In Ghidra, search for cross-references to `QMetaObject::staticMetaObject` or look for the `qt_meta_data_` and `qt_meta_stringdata_` symbols. These provide a roadmap of the application's class hierarchy, method names, and inter-object communication patterns.

```bash
strings libMyApp.so | grep -E "^(qt_meta_|staticMetaObject)"
```

## Hooking Strategy

### Network Interception

Qt apps use `QNetworkAccessManager` for HTTP/HTTPS requests. Hook the native implementation to intercept all network traffic:

```javascript
var libNetwork = Process.findModuleByName("libQt5Network.so") || Process.findModuleByName("libQt6Network.so");
if (libNetwork) {
    libNetwork.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("QNetworkAccessManager") !== -1 && exp.name.indexOf("createRequest") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[Qt Network] createRequest called");
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

### Signal/Slot Interception

Qt's signal/slot mechanism routes through `QMetaObject::activate`. Hooking this function intercepts all inter-object communication:

```javascript
var libCore = Process.findModuleByName("libQt5Core.so") || Process.findModuleByName("libQt6Core.so");
if (libCore) {
    libCore.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("QMetaObject") !== -1 && exp.name.indexOf("activate") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[Qt Signal] activate called from: " + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

### Crypto and Data Hooks

For intercepting cryptographic operations, target `QCryptographicHash`, `QSslSocket`, and any custom crypto wrappers:

```javascript
var libCore = Process.findModuleByName("libQt5Core.so") || Process.findModuleByName("libQt6Core.so");
if (libCore) {
    libCore.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("QCryptographicHash") !== -1 && exp.name.indexOf("addData") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    var data = args[1];
                    var len = args[2].toInt32();
                    console.log("[Qt Crypto] addData len=" + len + " data=" + hexdump(data, {length: Math.min(len, 64)}));
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

## SSL Pinning Bypass

Qt implements SSL/TLS through `QSslSocket`, which wraps OpenSSL (bundled with Qt for Android). SSL pinning is enforced via `QSslSocket::setPeerVerifyMode()` and custom `QSslError` handling in the `sslErrors` signal.

### QSslSocket Verification Hook

```javascript
var libNetwork = Process.findModuleByName("libQt5Network.so") || Process.findModuleByName("libQt6Network.so");
if (libNetwork) {
    libNetwork.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("QSslSocket") !== -1 && exp.name.indexOf("setPeerVerifyMode") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    args[1] = ptr(0);
                    console.log("[SSL] setPeerVerifyMode forced to VerifyNone");
                }
            });
        }
    });
}
```

### Ignoring SSL Errors

Qt apps that pin certificates typically connect the `sslErrors` signal to a slot that calls `QSslSocket::ignoreSslErrors()`. To force bypass, hook `ignoreSslErrors` to always execute, or hook the error handler to suppress certificate validation failures:

```javascript
var libNetwork = Process.findModuleByName("libQt5Network.so") || Process.findModuleByName("libQt6Network.so");
if (libNetwork) {
    libNetwork.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("QNetworkReply") !== -1 && exp.name.indexOf("sslErrors") !== -1 && exp.type === "function") {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[SSL] sslErrors signal intercepted -- suppressing");
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

### OpenSSL Direct Bypass

Since Qt bundles its own OpenSSL, the standard `SSL_CTX_set_verify` bypass also works:

```javascript
var libssl = Process.findModuleByName("libssl.so");
if (libssl) {
    var sslVerify = libssl.findExportByName("SSL_CTX_set_verify");
    if (sslVerify) {
        Interceptor.attach(sslVerify, {
            onEnter: function(args) {
                args[1] = ptr(0);
                args[2] = ptr(0);
                console.log("[SSL] SSL_CTX_set_verify forced to SSL_VERIFY_NONE");
            }
        });
    }
}
```

## RE Difficulty Assessment

| Aspect | Qt Widgets | QML / Qt Quick |
|--------|-----------|---------------|
| Code format | Compiled C++ (native ARM) | C++ logic compiled + QML text files for UI |
| Readability | Low -- requires native disassembly | Moderate -- QML files are readable, C++ still requires disassembly |
| String extraction | Good -- Qt MOC metadata preserves class/method names | Good -- QML files contain property names, signal connections |
| Control flow recovery | Standard native RE techniques | UI flow visible in QML, business logic requires native RE |
| Patching | Binary patching of `.so` | Edit QML files directly for UI changes, binary patch for logic |
| Overall difficulty | **Hard** (rank 8/28) | **Moderate-Hard** (rank 11/28) |

The Qt meta-object system is a significant advantage for reverse engineers -- it preserves class names, method signatures, and signal/slot connections that would be stripped in a typical native binary. QML apps provide even more surface area because the UI layer is declarative text. The primary challenge is the compiled C++ business logic, which requires standard native ARM reverse engineering skills.

## References

- [Qt for Android Documentation](https://doc.qt.io/qt-6/android.html)
- [Qt Resource System](https://doc.qt.io/qt-6/resources.html)
- [Qt Meta-Object System](https://doc.qt.io/qt-6/metaobjects.html)
- [GammaRay -- KDAB Qt Introspection](https://github.com/KDAB/GammaRay)
- [qrc-extractor](https://github.com/aspect-apps/qrc-extractor)
- [Frida -- Dynamic Instrumentation](https://frida.re/)
- [Ghidra](https://ghidra-sre.org/)
- [rizin/Cutter](https://github.com/rizinorg/cutter)
