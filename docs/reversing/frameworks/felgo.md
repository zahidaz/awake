# Felgo

Felgo is a cross-platform SDK built on top of Qt, using QML (Qt Modeling Language) as its primary scripting layer and C++ for performance-critical native code. Originally launched as "V-Play" for game development, it rebranded to Felgo and expanded into general app development. Felgo apps ship Qt's core native libraries alongside Felgo-specific libraries and bundle QML scripts inside Qt Resource Container (`.rcc`) files. The reverse engineering approach splits between extracting and reading QML scripts from resource files and analyzing compiled C++/Qt native libraries with disassemblers.

## Architecture

### Component Stack

| Layer | Component |
|-------|-----------|
| **QML Scripts** | Application logic, UI definitions, game mechanics written in QML/JavaScript |
| **Felgo SDK** | Game engine components (scenes, entities, physics), app components (navigation, theming) |
| **Qt Framework** | Core platform abstraction -- networking, file I/O, rendering, event loop |
| **Native C++** | Custom C++ modules, Qt plugin implementations, performance-critical code |
| **Android Shell** | Thin Java wrapper using `org.qtproject.qt5.android.QtActivity` or Felgo's custom activity |

### QML Engine

QML is a declarative language with inline JavaScript support. Felgo apps define their UI and logic in `.qml` files that are interpreted by Qt's QML engine at runtime. The QML engine (`libQt5Qml*.so`) parses and executes these scripts, resolving property bindings and signal-slot connections dynamically.

QML files can contain embedded JavaScript blocks for imperative logic:

```qml
import Felgo 4.0
import QtQuick 2.0

App {
    onInitTheme: {
        var endpoint = "https://api.example.com/v1/auth"
        HttpRequest.get(endpoint).then(function(res) {
            storage.setValue("token", res.body.token)
        })
    }
}
```

This means API endpoints, authentication logic, and business rules are often visible in extracted QML files.

### Rendering Pipeline

Felgo uses Qt's scene graph for rendering, which runs on a dedicated render thread using OpenGL ES or Vulkan. Game apps use Felgo's entity-component system built on top of the scene graph. This architecture means UI and game logic live in QML, while the rendering pipeline is handled entirely in native code.

## Identification

| Indicator | Location |
|-----------|----------|
| `libQt5Core*.so` | Qt core library in `lib/` |
| `libQt5Qml*.so` | QML engine library |
| `libQt5Quick*.so` | Qt Quick rendering library |
| `libFelgo*.so` | Felgo SDK library |
| `assets/*.rcc` | Qt Resource Container files holding QML scripts and assets |
| `net.vplay.*` | Legacy V-Play package prefix in DEX/manifest |
| `com.felgo.*` | Current Felgo package prefix |
| `org.qtproject.qt5.*` | Qt Android integration classes |

Quick check:

```bash
unzip -l target.apk | grep -iE "(libQt5|libFelgo|\.rcc|felgo|vplay)"
```

### Distinguishing Felgo from Plain Qt

Both Felgo and plain Qt apps contain `libQt5Core*.so` and `.rcc` files. The presence of `libFelgo*.so` or Felgo-specific package names (`com.felgo.*`, `net.vplay.*`) distinguishes Felgo apps from generic Qt applications.

```bash
unzip -l target.apk | grep -i felgo
```

If no Felgo-specific libraries are found but Qt libraries are present, the app is a plain Qt application (covered in the [Qt for Android](qt.md) page).

## Code Location & Extraction

### Qt Resource Container (.rcc) Files

QML scripts, JavaScript files, images, and other assets are bundled into `.rcc` files -- Qt's binary resource archive format. These files are the primary reverse engineering target.

Extract `.rcc` files from the APK, then decompile them with Qt's `rcc` tool:

```bash
unzip target.apk "assets/*.rcc" -d extracted/
rcc --reverse --output extracted/rcc_out/ extracted/assets/qml_resources.rcc
```

The `.rcc` format starts with a `qres` magic header (bytes `71 72 65 73`), followed by a tree of resource entries. If `rcc` is unavailable, the Python package `qtrcc` provides equivalent extraction.

### Extracted QML Analysis

After extraction, the QML files are plaintext and fully readable:

```bash
find extracted/rcc_out/ -name "*.qml" -o -name "*.js"
```

Search for high-value targets in extracted QML/JS:

```bash
grep -rniE "(http|api|token|password|secret|encrypt|key)" extracted/rcc_out/
```

### Compiled QML Cache

Some Qt apps pre-compile QML to bytecode (`.qmlc` / `.jsc` files) for faster startup. These are cached compilations of QML files and contain Qt's internal bytecode format.

The bytecode is version-specific to the Qt release. Tools for decompiling `.qmlc` are limited, but the string table within the bytecode still contains readable identifiers and literals:

```bash
strings extracted/rcc_out/*.qmlc | grep -iE "(http|api|token|key)"
```

### Native Libraries

C++ logic compiles into shared libraries. The primary targets:

| Library | Contents |
|---------|----------|
| `libFelgo*.so` | Felgo SDK -- game engine, app components, networking |
| `libQt5Core*.so` | Qt core runtime |
| `libQt5Network*.so` | Qt networking stack (HTTP, SSL, sockets) |
| App-specific `.so` | Custom C++ modules registered as QML types |

Analyze with Ghidra or IDA. Qt's signal-slot mechanism uses string-based method lookups via `qt_metacall`, which preserves method name strings in the binary.

## Analysis Workflow

1. **Unzip APK** and confirm Felgo indicators (`libFelgo*.so`, `.rcc` files)
2. **Extract `.rcc`** files using `rcc --reverse` or Python tooling
3. **Read QML** files -- these contain UI definitions, business logic, API calls
4. **Search** QML/JS for endpoints, credentials, encryption keys, storage operations
5. **Map** Felgo/Qt API usage (`HttpRequest`, `Storage`, `WebSocket`, `FileUtils`)
6. **Analyze** native `.so` files in Ghidra for C++ logic not exposed in QML
7. **Hook** at runtime with Frida targeting Qt and Felgo native functions

### Key Felgo APIs to Search For

| API | Purpose |
|-----|---------|
| `HttpRequest` | HTTP client -- reveals endpoints |
| `WebSocket` | Persistent connections -- potential C2 channel |
| `Storage` | Key-value persistence -- stored credentials |
| `FileUtils` | File system operations -- data exfiltration paths |
| `NativeUtils` | Platform-specific native calls |
| `GameNetwork` | Felgo multiplayer backend communication |
| `Firebase` | Push notifications, analytics |

## Hooking Strategy

### Native Library Hooks

Frida hooks on Qt and Felgo native libraries:

```javascript
var qtNetwork = Process.findModuleByName("libQt5Network.so");
if (qtNetwork) {
    qtNetwork.enumerateExports().forEach(function(exp) {
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

### QML Engine Interception

Hook the QML engine to intercept script evaluation:

```javascript
var qtQml = Process.findModuleByName("libQt5Qml.so");
if (qtQml) {
    qtQml.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("evaluate") !== -1 && exp.type === "function") {
            console.log("[QML] " + exp.name + " @ " + exp.address);
        }
    });
}
```

### SSL Pinning Bypass

Felgo/Qt apps use `QSslSocket` for TLS, which links against OpenSSL or BoringSSL compiled into `libQt5Network*.so`. Standard Java-layer bypasses do not work because Qt manages its own TLS stack.

Hook the native SSL verification:

```javascript
var sslLib = Process.findModuleByName("libssl.so");
if (sslLib) {
    var SSL_CTX_set_verify = sslLib.findExportByName("SSL_CTX_set_verify");
    if (SSL_CTX_set_verify) {
        Interceptor.attach(SSL_CTX_set_verify, {
            onEnter: function(args) {
                args[1] = ptr(0);
                args[2] = ptr(0);
            }
        });
    }
}
```

## Obfuscation

Pre-compiled QML (`.qmlc`) converts readable QML into Qt bytecode, providing a baseline level of obfuscation -- though string literals remain visible. C++ modules in `.so` files are stripped of debug symbols in release builds but retain signal/slot method names via Qt's `qt_metacall` mechanism. Felgo apps in the wild rarely apply additional obfuscation beyond release-mode compilation.

## RE Difficulty Assessment

| Aspect | QML Layer | C++ Native Layer |
|--------|-----------|-----------------|
| Code format | Plaintext QML/JavaScript | Compiled ARM native |
| Readability | High after .rcc extraction | Low -- standard native RE |
| String extraction | Trivial | Moderate (Qt preserves some metadata) |
| Control flow recovery | Full | Partial (Ghidra) |
| Patching | Edit QML, rebuild .rcc, repackage | Binary patching in Ghidra |
| Overall difficulty | **Easy** (QML scripts) | **Hard** (native C++) |
| Combined ranking | **Moderate-Hard** (rank 25/28) |

The split between readable QML scripts and compiled C++ native code creates a two-tier analysis challenge. If the app's logic is primarily in QML (common for Felgo apps), reverse engineering is straightforward. If significant logic is pushed into C++ modules, difficulty increases substantially. The limited tooling ecosystem for Qt/QML mobile reverse engineering compared to other frameworks adds friction.

## References

- [Felgo Documentation](https://felgo.com/doc/)
- [Qt Resource System Documentation](https://doc.qt.io/qt-5/resources.html)
- [Qt QML Engine Internals](https://doc.qt.io/qt-5/qtqml-index.html)
- [Ghidra](https://ghidra-sre.org/)
- [Frida](https://frida.re/)
- [rcc Tool Documentation](https://doc.qt.io/qt-5/rcc.html)
