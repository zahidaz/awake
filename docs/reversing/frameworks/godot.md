# Godot

Godot is an open-source game engine that uses GDScript (a Python-like language) or C# for game logic, with resources packed into `.pck` archive files. On Android, the engine compiles into `libgodot_android.so`, and all game assets -- scripts, scenes, textures, audio -- are bundled into a single `.pck` file stored in `assets/`. The engine's open-source nature means its internals are fully documented, and its custom scripting VM and resource formats are well understood, making decompilation highly effective when GDScript is used. GDExtension (Godot 4.x) and GDNative (Godot 3.x) allow developers to ship compiled native modules alongside GDScript, which require traditional native reverse engineering.

## Architecture

A Godot Android APK contains three layers:

| Layer | Component | Contents |
|-------|-----------|----------|
| Java shell | `org.godotengine.godot.Godot` | Minimal Android activity -- initializes the engine, handles lifecycle |
| Engine binary | `libgodot_android.so` | GDScript VM, scene tree, physics, rendering, mbedTLS, audio (~15-30 MB) |
| Game payload | `assets/*.pck` | All game resources -- GDScript bytecode, scenes, textures, audio, shaders |

The Java layer is a thin wrapper. Decompiling it with jadx reveals only engine initialization and permission handling. All meaningful game logic resides in the `.pck` file as GDScript bytecode or, in C# variants, as .NET assemblies.

### Scripting Modes

| Mode | Format | RE Difficulty |
|------|--------|---------------|
| GDScript (VM) | `.gd` source or `.gdc` bytecode in `.pck` | Low -- fully decompilable with gdsdecomp |
| C# (Mono) | .NET DLLs in `.pck` or `assemblies/` | Low -- decompile with dnSpy/ILSpy like Xamarin |
| GDExtension (Godot 4.x) | `.so` native shared libraries | High -- requires Ghidra/IDA |
| GDNative (Godot 3.x) | `.so` native shared libraries | High -- requires Ghidra/IDA |

### GDScript Bytecode

GDScript source files (`.gd`) are compiled to bytecode (`.gdc`) during export. The bytecode file begins with a 4-byte magic (`GDSC` for Godot 4.x compiled scripts) followed by a bytecode version number tied to the engine version. The bytecode version changes between Godot releases, so decompilation tools must match the target engine version.

In Godot 4.3+, an intermediate representation format (`.gdir` with magic `GDIR`) was introduced for GDScript, storing a more structured bytecode that includes type information and optimization hints.

### .pck File Format

The PCK archive is Godot's custom resource package format:

| Field | Description |
|-------|-------------|
| Magic | `GDPC` (4 bytes) |
| Format version | Pack format version number |
| Engine version | Major.minor.patch of the Godot version used |
| File table | Path strings + offsets + sizes + MD5 hashes |
| File data | Concatenated resource blobs |

PCK files can optionally be embedded inside the executable binary (common on desktop, rare on Android). On Android, they are typically standalone files in `assets/`.

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/*.pck` | PCK game archive (primary analysis target) |
| `libgodot_android.so` | Engine binary in `lib/<arch>/` |
| `org.godotengine.*` | Package prefix in DEX and AndroidManifest.xml |
| `org.godotengine.godot.Godot` | Main activity class |
| `project.binary` | Compiled project settings inside `.pck` |
| `.gdextension` / `.gdnlib` | GDExtension/GDNative config files inside `.pck` |

```bash
unzip -l target.apk | grep -E "(\.pck|libgodot|godotengine)"
```

### Engine Version Detection

The Godot engine version is embedded in the PCK header and can also be extracted from `libgodot_android.so`:

```bash
strings lib/arm64-v8a/libgodot_android.so | grep -E "^[0-9]+\.[0-9]+\.[0-9]+"
```

The version determines which bytecode format is used and which decompilation tools are compatible.

## Analysis Workflow

### Step 1: Extract the PCK

Extract the `.pck` file from the APK:

```bash
unzip target.apk assets/*.pck -d extracted/
```

### Step 2: Decompile with gdsdecomp (GDRE Tools)

[gdsdecomp](https://github.com/GDRETools/gdsdecomp) (also called GDRE Tools) is the primary tool for Godot reverse engineering. It supports Godot 2.x, 3.x, and 4.x projects and can perform full project recovery from PCK, APK, or EXE files.

```bash
gdre_tools --headless --recover="extracted/assets/game.pck" --output-dir="recovered_project/"
```

Full project recovery extracts all resources and decompiles GDScript bytecode back to `.gd` source files. The recovered project can be opened directly in the Godot editor for analysis.

For targeted decompilation of specific scripts:

```bash
gdre_tools --headless --decompile="res://scripts/main.gdc" --bytecode=4.3.0
```

### Step 3: Analyze Recovered GDScript

The decompiled `.gd` files are near-source quality. GDScript decompilation preserves:

- Function names and signatures
- Variable names (not stripped in standard exports)
- String literals
- Class inheritance hierarchy
- Signal connections and node paths
- Export variables and their types

Search for network endpoints, encryption keys, and authentication logic:

```bash
grep -rn "http\|https\|api\|key\|secret\|token\|password" recovered_project/
```

### Step 4: C# Variant Analysis

If the game uses C# instead of GDScript, the `.pck` or a separate `assemblies/` directory contains .NET DLLs. Extract and decompile with dnSpy or ILSpy:

```bash
gdre_tools --headless --extract="extracted/assets/game.pck" --output-dir="pck_contents/"
```

Look for `*.dll` files in the extracted output, particularly `Assembly-CSharp.dll` or project-named assemblies.

### Step 5: GDExtension / GDNative Modules

GDExtension (Godot 4.x) and GDNative (Godot 3.x) modules are compiled shared libraries (`.so` on Android) that extend the engine with native code. These cannot be decompiled by gdsdecomp.

Identify native modules by looking for `.gdextension` or `.gdnlib` configuration files in the extracted PCK:

```bash
grep -rn "gdextension\|gdnlib" pck_contents/
```

The `.gdextension` file specifies library paths per platform. Extract the corresponding `.so` file and analyze with Ghidra or IDA.

### Analysis Tools Summary

| Tool | Purpose | URL |
|------|---------|-----|
| [gdsdecomp / GDRE Tools](https://github.com/GDRETools/gdsdecomp) | PCK extraction, GDScript decompilation, full project recovery | Godot 2.x-4.x |
| [GdTool](https://github.com/lucasbaizer/GdTool) | Lightweight GDScript compiler/decompiler (.NET-based) | All GDScript versions |
| [Ghidra](https://ghidra-sre.org/) | Native analysis of GDExtension/GDNative `.so` modules | N/A |
| [dnSpy](https://github.com/dnSpyEx/dnSpy) / [ILSpy](https://github.com/icsharpcode/ILSpy) | C# variant DLL decompilation | .NET assemblies |
| [Frida](https://frida.re/) | Runtime hooking of engine and script functions | All versions |

## Hooking

### GDScript VM Hooking

Frida hooks target `libgodot_android.so` to intercept GDScript VM execution. Key hook points include script function dispatch, signal emission, and resource loading:

```javascript
var godot = Process.findModuleByName("libgodot_android.so");

godot.enumerateExports().forEach(function(exp) {
    if (exp.name.indexOf("GDScript") !== -1 || exp.name.indexOf("gdscript") !== -1) {
        console.log("[Godot] " + exp.name + " @ " + exp.address);
    }
});
```

### HTTP Request Interception

Godot's `HTTPRequest` and `HTTPClient` nodes use mbedTLS internally. Hook the HTTP layer to capture network traffic:

```javascript
var godot = Process.findModuleByName("libgodot_android.so");

godot.enumerateExports().forEach(function(exp) {
    if (exp.name.indexOf("HTTPClient") !== -1 && exp.name.indexOf("request") !== -1) {
        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                console.log("[Godot HTTP] request called");
            }
        });
    }
});
```

### GDExtension Function Hooking

For games using GDExtension modules, hook the native library directly:

```javascript
var extension = Process.findModuleByName("libcustom_extension.so");
if (extension) {
    extension.enumerateExports().forEach(function(exp) {
        console.log("[GDExt] " + exp.name + " @ " + exp.address);
    });
}
```

## SSL Pinning

Godot compiles [mbedTLS](https://github.com/Mbed-TLS/mbedtls) directly into `libgodot_android.so` for all TLS operations. Standard Java-layer SSL bypass scripts (OkHttp, TrustManager) do not work because the engine never touches the Android Java TLS stack.

### mbedTLS Hook Bypass

Hook `mbedtls_ssl_handshake` or the certificate verification callback in `libgodot_android.so`:

```javascript
var godot = Process.findModuleByName("libgodot_android.so");

var handshake = godot.enumerateExports().filter(function(e) {
    return e.name.indexOf("mbedtls_ssl_handshake") !== -1;
});

if (handshake.length > 0) {
    Interceptor.attach(handshake[0].address, {
        onLeave: function(retval) {
            retval.replace(0x0);
            console.log("[mbedTLS] Handshake bypassed");
        }
    });
}
```

### Certificate Verification Bypass

Target the X.509 certificate verification function:

```javascript
var godot = Process.findModuleByName("libgodot_android.so");

var verify = godot.enumerateExports().filter(function(e) {
    return e.name.indexOf("mbedtls_x509_crt_verify") !== -1;
});

if (verify.length > 0) {
    Interceptor.attach(verify[0].address, {
        onLeave: function(retval) {
            retval.replace(0x0);
            console.log("[mbedTLS] Certificate verification bypassed");
        }
    });
}
```

If mbedTLS symbols are not exported (stripped builds), use byte pattern scanning against known mbedTLS function prologues in `libgodot_android.so`.

## Malware Context

### GodLoader

Godot has been directly exploited as a malware delivery mechanism. In November 2024, Check Point Research disclosed [GodLoader](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/), a campaign that abused the Godot engine to distribute cross-platform malware loaders.

| Aspect | Details |
|--------|---------|
| Discovery | November 2024, Check Point Research |
| Infections | 17,000+ systems since June 2024 |
| Mechanism | Malicious GDScript packed into `.pck` files, executed by legitimate Godot engine binaries |
| Payloads | RedLine Stealer, XMRig cryptocurrency miner |
| Distribution | Stargazer Goblin network -- 200+ fake GitHub repositories masquerading as game tools and cracked software |
| Detection | Near-zero VirusTotal detection at time of discovery |
| Evasion | Adds `C:\` drive to Windows Defender exclusion list, sandbox/VM detection |
| Platforms | Windows, Linux, macOS (Android explored) |

The attack works because the Godot engine binary itself is legitimate and signed. The malicious logic resides entirely in the `.pck` file as GDScript, which executes within the Godot VM. Antivirus engines do not parse `.pck` files or analyze GDScript bytecode, resulting in effectively zero detection.

### Why Godot Appeals to Threat Actors

- **Signed engine binary** -- the Godot executable is legitimate, trusted by AV heuristics
- **GDScript execution** -- Turing-complete scripting with filesystem access, process execution, and network capabilities
- **Cross-platform** -- single `.pck` payload works on Windows, Linux, macOS
- **No compilation required** -- GDScript runs interpreted or from bytecode, no native compilation step
- **Open-source engine** -- threat actors can study the engine source to optimize evasion

### Analysis Approach for GodLoader Samples

1. Extract the `.pck` from the distribution package
2. Use gdsdecomp to recover the GDScript source
3. Look for `OS.execute()`, `OS.shell_open()`, `HTTPRequest` nodes, and filesystem operations
4. Trace C2 URLs in string literals and HTTP request targets
5. Check for sandbox detection logic (VM detection, debugger checks)

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | GDScript bytecode in `.pck` (fully decompilable) |
| Tool maturity | High -- gdsdecomp handles all Godot versions reliably |
| Symbol recovery | Excellent -- function names, variable names, class hierarchy preserved |
| Control flow | Full recovery -- decompiled GDScript is near-source quality |
| String extraction | Trivial -- strings preserved in bytecode and PCK resources |
| SSL bypass | Moderate -- requires mbedTLS native hooks (Java-layer useless) |
| GDExtension/GDNative modules | Hard -- compiled native code, Ghidra/IDA required |
| Overall difficulty | **Moderate** (rank 22/28) -- easy for pure GDScript, hard when native modules are involved |

The primary bottleneck is GDExtension/GDNative modules. Pure GDScript games are straightforward -- gdsdecomp produces near-source quality output. When native modules are present, the analyst must combine GDScript decompilation (for high-level logic) with native RE (for the compiled extension code).

## References

- [gdsdecomp / GDRE Tools](https://github.com/GDRETools/gdsdecomp)
- [GdTool -- Lightweight GDScript Decompiler](https://github.com/lucasbaizer/GdTool)
- [Godot Engine Source Code](https://github.com/godotengine/godot)
- [GDExtension Documentation](https://docs.godotengine.org/en/stable/tutorials/scripting/gdextension/what_is_gdextension.html)
- [Check Point Research: GodLoader -- Gaming Engines as Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/)
- [Godot Engine Statement on GodLoader](https://godotengine.org/article/statement-on-godloader-malware-loader/)
- [BleepingComputer: GodLoader Infects Thousands](https://www.bleepingcomputer.com/news/security/new-godloader-malware-infects-thousands-of-gamers-using-godot-scripts/)
- [Godot Mod Loader Wiki: Decompiling with GDRE Tools](https://wiki.godotmodding.com/guides/modding/tools/decompile_games/)
