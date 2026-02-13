# Delphi / RAD Studio

Delphi for Android (Embarcadero RAD Studio) compiles Object Pascal to native ARM code via an LLVM-based backend. The UI framework is FireMonkey (FMX), which renders its own cross-platform widgets rather than using Android's native view system. The resulting APK contains a thin Java shell that bootstraps a single large native `.so` library holding the entire application -- UI, business logic, and runtime support. Delphi Android apps are relatively uncommon on Google Play but appear in enterprise tooling, legacy business apps, and occasionally in malware samples targeting specific regions.

## Architecture

### Compilation Pipeline

| Stage | Description |
|-------|-------------|
| **Source** | Object Pascal (`.pas`, `.dpr`) with optional inline assembly |
| **Compiler** | `dccaarm64` (ARM64) or `dccaarm` (ARM32) -- Delphi's LLVM-based compiler |
| **Output** | Native ARM shared library (`libFMXNativeActivity.so` or custom name) |
| **Runtime** | Delphi RTL (runtime library) statically linked into the `.so` |
| **UI** | FireMonkey (FMX) renders via OpenGL ES / Skia -- no Android native widgets |

### Runtime Model

| Layer | Components |
|-------|------------|
| **Java shell** | `FMXNativeActivity` (extends `NativeActivity`), `com.embarcadero.firemonkey.*` classes |
| **Native library** | Single `.so` containing application code, Delphi RTL, FireMonkey framework |
| **Rendering** | FireMonkey draws to a `SurfaceView` via OpenGL ES or Skia backend |
| **Networking** | Indy (`TIdHTTP`, `TIdTCPClient`) or `TNetHTTPClient` compiled into the native binary |

The Java layer is minimal. `FMXNativeActivity` uses Android's `NativeActivity` mechanism to immediately hand control to the native `.so`, which initializes the Delphi RTL and FireMonkey renderer. Almost all logic -- including UI event handling, networking, and data storage -- runs in native code.

### FireMonkey UI

FireMonkey does not use Android's `View` hierarchy. It paints everything to a GPU surface, meaning:

- Android Layout Inspector and `uiautomator` show a single opaque surface
- Accessibility services see minimal widget tree
- UI automation tools cannot interact with individual FMX controls

## Identification

| Indicator | Location |
|-----------|----------|
| `libFMXNativeActivity.so` | `lib/<arch>/` -- default name for Delphi Android apps |
| `com.embarcadero.firemonkey.*` | DEX classes in the Java shell |
| `com.embarcadero.rtl.*` | DEX helper classes for RTL integration |
| `FMXNativeActivity` | Main activity in `AndroidManifest.xml` |
| Large single `.so` (10-50+ MB) | `lib/<arch>/` -- contains entire app + RTL + FMX |
| `System.`, `Vcl.`, `Fmx.`, `IdHTTP` | String literals in the native binary (Delphi unit names) |

Quick check:

```bash
unzip -l target.apk | grep -iE "(libFMX|embarcadero)"
```

Secondary check via strings in the native library:

```bash
strings lib/arm64-v8a/libFMXNativeActivity.so | grep -iE "(System\.|Fmx\.|embarcadero|TId)"
```

## Code Location

### Single Native Binary

The entire application is in one `.so` file. Unlike frameworks that split logic across multiple libraries or script files, Delphi compiles everything -- application code, RTL, FireMonkey, and third-party libraries -- into a single monolithic binary.

```bash
unzip target.apk "lib/arm64-v8a/*" -d extracted/
ls -lh extracted/lib/arm64-v8a/
```

Expect a large file (typically 10-50 MB or more) because the Delphi RTL and FireMonkey framework are statically linked.

### RTTI in the Binary

Delphi embeds extensive Runtime Type Information (RTTI) in compiled binaries. This is one of the most valuable features for reverse engineering -- RTTI structures contain:

- Class names (fully qualified with unit prefix, e.g., `Unit1.TForm1`)
- Method names (published methods)
- Property names, types, and accessor methods
- Virtual method tables with readable names
- Form resource data (DFM serialized as binary)

This metadata survives compilation and is present in release builds unless explicitly stripped (which is rare in practice).

## Analysis Tools & Workflow

| Tool | Purpose |
|------|---------|
| [Ghidra](https://ghidra-sre.org/) | Primary disassembler -- load the `.so` and recover RTTI structures |
| [IDA Pro](https://hex-rays.com/ida-pro/) | Commercial disassembler with ARM decompiler |
| [IDR (Interactive Delphi Reconstructor)](https://github.com/AHotGarbage/IDR_x86) | Parses Delphi RTTI from executables -- primarily x86/Windows but RTTI format knowledge transfers |
| [Delphi RTTI Ghidra Scripts](https://github.com/AerospaceDoe/Delphi-RTTI-Parser-Ghidra) | Ghidra scripts to parse Delphi RTTI structures from ARM binaries |
| [jadx](https://github.com/skylot/jadx) | Decompile Java shell (minimal but shows manifest and entry points) |
| [Frida](https://frida.re/) | Runtime hooking of native functions |

### Recommended Workflow

1. **Unzip APK** and confirm Delphi via `libFMXNativeActivity.so` or `com.embarcadero.*` classes
2. **Extract the native `.so`** from `lib/<arch>/`
3. **Run strings extraction** to identify Delphi unit names, class names, and API endpoints
4. **Load into Ghidra** and apply Delphi RTTI parsing scripts to recover class hierarchies
5. **Locate key classes** by searching RTTI strings for network-related (`TIdHTTP`, `TNetHTTPClient`), crypto (`TCipher`, `THash`), or form names (`TLoginForm`, `TMainForm`)
6. **Map virtual method tables** -- Delphi VMTs have a predictable layout with class name pointer, instance size, and method pointers
7. **Hook at runtime** with Frida to intercept function calls, network traffic, and data processing

### RTTI Recovery in Ghidra

Delphi VMT structures follow a documented layout. The class name is stored as a ShortString (length-prefixed Pascal string) at a known offset from the VMT pointer:

```bash
strings libFMXNativeActivity.so | grep -E "^(T[A-Z][a-zA-Z]+|Unit[0-9]|Fmx\.|System\.)"
```

Look for patterns like `TForm1`, `TMainForm`, `TDataModule1` -- these indicate developer-created classes. Cross-reference these names in Ghidra with the surrounding code to find business logic entry points.

### DFM Form Resources

Delphi forms are serialized as DFM (Delphi Form Module) resources, often embedded in the binary. DFM data contains the complete UI layout: component names, properties, event handler assignments, and nested component hierarchies. Search for DFM signatures (`TPF0` for binary DFM format) in the `.so`:

```bash
strings -e l libFMXNativeActivity.so | grep "TPF0"
```

## Hooking Strategy

### Network Interception

Delphi apps commonly use Indy (`TIdHTTP`) or `TNetHTTPClient` for networking. These are compiled into the native binary, so hooks target the native `.so`:

```javascript
var libApp = Process.findModuleByName("libFMXNativeActivity.so");
if (libApp) {
    libApp.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("TIdHTTP") !== -1 && exp.name.indexOf("DoRequest") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[Delphi HTTP] DoRequest called");
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

### Symbol Enumeration

Delphi binaries often export or contain symbols with mangled Object Pascal names. Enumerate them to find targets:

```javascript
var libApp = Process.findModuleByName("libFMXNativeActivity.so");
if (libApp) {
    libApp.enumerateExports().forEach(function(exp) {
        if (exp.type === "function") {
            console.log("[Export] " + exp.name + " @ " + exp.address);
        }
    });
}
```

### Function Tracing

For tracing specific Delphi class methods, use pattern-based hooking on mangled names:

```javascript
var libApp = Process.findModuleByName("libFMXNativeActivity.so");
if (libApp) {
    libApp.enumerateSymbols().forEach(function(sym) {
        if (sym.name.indexOf("TMainForm") !== -1 || sym.name.indexOf("TLoginForm") !== -1) {
            Interceptor.attach(sym.address, {
                onEnter: function(args) {
                    console.log("[Delphi] " + sym.name + " called");
                },
                onLeave: function(retval) {}
            });
        }
    });
}
```

## SSL Pinning Bypass

Delphi apps implement SSL/TLS through Indy's `TIdSSLIOHandlerSocketOpenSSL` or the newer `TNetHTTPClient` with `THTTPSecureProtocol`. Both ultimately use OpenSSL (bundled or system).

### Indy SSL Handler Hook

```javascript
var libApp = Process.findModuleByName("libFMXNativeActivity.so");
if (libApp) {
    libApp.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("TIdSSLIOHandler") !== -1 && exp.name.indexOf("Verify") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[SSL] TIdSSLIOHandler verify intercepted");
                },
                onLeave: function(retval) {
                    retval.replace(ptr(1));
                    console.log("[SSL] Forced verify to return true");
                }
            });
        }
    });
}
```

### OpenSSL Direct Bypass

Since Delphi bundles OpenSSL, target the verification callback directly:

```javascript
var libssl = Process.findModuleByName("libssl.so");
if (libssl) {
    var setVerify = libssl.findExportByName("SSL_CTX_set_verify");
    if (setVerify) {
        Interceptor.attach(setVerify, {
            onEnter: function(args) {
                args[1] = ptr(0);
                args[2] = ptr(0);
                console.log("[SSL] SSL_CTX_set_verify forced to SSL_VERIFY_NONE");
            }
        });
    }
}
```

### TNetHTTPClient Certificate Validation

For apps using the newer `TNetHTTPClient`, the `OnValidateServerCertificate` event controls pinning. Hook the validation callback:

```javascript
var libApp = Process.findModuleByName("libFMXNativeActivity.so");
if (libApp) {
    libApp.enumerateSymbols().forEach(function(sym) {
        if (sym.name.indexOf("ValidateServerCertificate") !== -1 || sym.name.indexOf("OnValidateCert") !== -1) {
            Interceptor.attach(sym.address, {
                onEnter: function(args) {
                    console.log("[SSL] Certificate validation callback intercepted");
                },
                onLeave: function(retval) {
                    retval.replace(ptr(1));
                }
            });
        }
    });
}
```

## Obfuscation & Anti-Analysis

Delphi Android apps rarely employ advanced obfuscation. The ecosystem lacks mature obfuscation tooling comparable to Java/Kotlin or JavaScript frameworks. RTTI preservation means class/method/property names are readable in release builds, developers rarely strip symbols, DFM form resources expose UI structure, and few commercial protectors target Delphi ARM binaries. Some developers apply generic ARM binary protectors or use app-level protectors from the [Packers](../../packers/index.md) ecosystem, but these are uncommon.

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Compiled native ARM (Object Pascal via LLVM) |
| Readability | Low for code, high for metadata (RTTI, DFM) |
| String extraction | Excellent -- RTTI preserves class/method/property names |
| Control flow recovery | Standard native RE, aided by RTTI-based function identification |
| Patching | Binary patching of the `.so` |
| Obfuscation ceiling | Low -- limited tooling for Delphi ARM obfuscation |
| Overall difficulty | **Moderate-Hard** (rank 10/28) |

The rich RTTI metadata in Delphi binaries is a double-edged sword for developers -- it significantly aids reverse engineering by providing a readable map of the application's class structure, method names, and properties. The main challenge is the size of the monolithic binary and the need for ARM native analysis skills. Once RTTI is parsed, locating and understanding specific functionality becomes substantially easier than with a typical stripped C/C++ binary.

## References

- [Embarcadero RAD Studio Documentation](https://docwiki.embarcadero.com/RADStudio/en/Main_Page)
- [FireMonkey Overview](https://docwiki.embarcadero.com/RADStudio/en/FireMonkey)
- [Delphi RTTI Documentation](https://docwiki.embarcadero.com/RADStudio/en/Run-Time_Type_Information)
- [IDR -- Interactive Delphi Reconstructor](https://github.com/AHotGarbage/IDR_x86)
- [Delphi RTTI Parser for Ghidra](https://github.com/AerospaceDoe/Delphi-RTTI-Parser-Ghidra)
- [Ghidra](https://ghidra-sre.org/)
- [Frida -- Dynamic Instrumentation](https://frida.re/)
- [Indy Project (Internet Direct)](https://github.com/IndySockets/Indy)
