# Unity

Unity apps on Android ship as native APKs containing one of two compilation backends: **Mono** (C# assemblies as .NET DLLs) or **IL2CPP** (C# compiled to native ARM code via an intermediate C++ transpilation step). The backend choice determines the entire reverse engineering approach. Mono apps are trivially decompilable back to near-source C#; IL2CPP apps require metadata recovery from `global-metadata.dat` combined with native binary analysis of `libil2cpp.so`. Unity holds a dominant share of the mobile game market and is also used in non-game apps, making it a frequent target for both malware analysis and game security research.

## Architecture

### Build Pipeline

Unity compiles C# game logic through one of two backends before packaging as an APK:

| Stage | Mono Backend | IL2CPP Backend |
|-------|-------------|----------------|
| Source | C# scripts (.cs) | C# scripts (.cs) |
| Compilation | Mono compiler produces .NET DLLs (CIL bytecode) | Mono compiler produces CIL, then il2cpp transpiles to C++ source |
| Final form | `Assembly-CSharp.dll` + framework DLLs in APK | `libil2cpp.so` (native ARM) + `global-metadata.dat` |
| Runtime | Mono VM interprets/JITs the CIL bytecode | Native code runs directly, il2cpp runtime handles GC and type system |

### APK Structure

```
base.apk/
├── assets/
│   └── bin/
│       └── Data/
│           ├── Managed/                  (Mono only)
│           │   ├── Assembly-CSharp.dll
│           │   ├── Assembly-CSharp-firstpass.dll
│           │   ├── UnityEngine.dll
│           │   └── ...
│           ├── globalgamemanagers
│           ├── data.unity3d
│           ├── level0
│           ├── resources.assets
│           └── sharedassets0.assets
├── lib/
│   ├── arm64-v8a/
│   │   ├── libunity.so
│   │   ├── libil2cpp.so              (IL2CPP only)
│   │   └── libmono.so                (Mono only)
│   └── armeabi-v7a/
│       └── ...
├── classes.dex
└── AndroidManifest.xml
```

The `global-metadata.dat` file (IL2CPP) is located either at `assets/bin/Data/Managed/Metadata/global-metadata.dat` or embedded within `assets/bin/Data/` depending on Unity version.

### Mono Runtime

The Mono backend bundles a full .NET runtime (`libmono.so`) that loads CIL assemblies at startup. Game logic lives in `Assembly-CSharp.dll`, which contains standard .NET metadata -- class definitions, method signatures, string literals, and IL opcodes. Third-party plugins ship as separate DLLs in the same `Managed/` directory.

### IL2CPP Runtime

IL2CPP converts all CIL bytecode to C++ source, then compiles that C++ with the platform's native toolchain (NDK clang for Android). The output is a single `libil2cpp.so` containing all game logic as native ARM instructions. Class names, method signatures, field types, and string literals are preserved in `global-metadata.dat`, a structured binary file that the IL2CPP runtime reads at initialization to populate reflection data.

## Identification

| Indicator | What It Confirms |
|-----------|-----------------|
| `lib/*/libunity.so` | Unity engine (present in both backends) |
| `lib/*/libil2cpp.so` | IL2CPP backend |
| `lib/*/libmono.so` | Mono backend |
| `assets/bin/Data/Managed/*.dll` | Mono backend (assemblies present) |
| `global-metadata.dat` | IL2CPP backend |
| `com.unity3d.player.UnityPlayer` in DEX | Unity bootstrap activity |
| `unity.build-id` in `AndroidManifest.xml` meta-data | Unity build system |
| `globalgamemanagers` in `assets/bin/Data/` | Unity asset system |

Quick identification:

```bash
unzip -l target.apk | grep -E "(libunity|libil2cpp|libmono|global-metadata|Assembly-CSharp)"
```

Determine the backend:

```bash
unzip -l target.apk | grep -q "libil2cpp" && echo "IL2CPP" || echo "Mono"
```

## Code Location & Extraction

### Mono Backend

All game code exists as standard .NET assemblies:

```bash
mkdir -p extracted
unzip target.apk "assets/bin/Data/Managed/*.dll" -d extracted/
```

Primary targets:

| DLL | Contents |
|-----|----------|
| `Assembly-CSharp.dll` | All game/app C# scripts |
| `Assembly-CSharp-firstpass.dll` | Scripts in `Standard Assets` or `Plugins` folders |
| `Assembly-UnityScript.dll` | Legacy UnityScript code (rare, deprecated) |
| Third-party DLLs | Photon, PlayFab, Firebase, ad SDKs |

These are standard CIL assemblies -- open them directly in [dnSpy](https://github.com/dnSpyEx/dnSpy) or [ILSpy](https://github.com/icsharpcode/ILSpy) for full decompilation back to readable C#.

### IL2CPP Backend

Game code is compiled into native ARM instructions inside `libil2cpp.so`. Metadata preserving class/method names is in `global-metadata.dat`:

```bash
mkdir -p extracted
unzip target.apk "lib/arm64-v8a/libil2cpp.so" -d extracted/
unzip target.apk "assets/bin/Data/Managed/Metadata/global-metadata.dat" -d extracted/
```

If `global-metadata.dat` is not at that path, search for it:

```bash
unzip -l target.apk | grep "global-metadata"
```

## Analysis Tools

| Tool | Purpose | URL |
|------|---------|-----|
| [dnSpy](https://github.com/dnSpyEx/dnSpy) | .NET decompiler/debugger for Mono DLLs | `github.com/dnSpyEx/dnSpy` |
| [ILSpy](https://github.com/icsharpcode/ILSpy) | .NET decompiler (cross-platform) | `github.com/icsharpcode/ILSpy` |
| [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) | Extract types, methods, strings from IL2CPP | `github.com/Perfare/Il2CppDumper` |
| [Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) | IL2CPP analysis, generates pseudo-C# and Ghidra scripts | `github.com/SamboyCoding/Cpp2IL` |
| [Il2CppInspector](https://github.com/djkaty/Il2CppInspector) | IL2CPP structure recovery, IDA/Ghidra script generation | `github.com/djkaty/Il2CppInspector` |
| [AssetStudio](https://github.com/Perfare/AssetStudio) | Extract and preview Unity assets (textures, meshes, audio) | `github.com/Perfare/AssetStudio` |
| [AssetRipper](https://github.com/AssetRipper/AssetRipper) | Full Unity project recovery from assets | `github.com/AssetRipper/AssetRipper` |
| [Ghidra](https://ghidra-sre.org/) | Native binary analysis for `libil2cpp.so` | `ghidra-sre.org` |
| IDA Pro | Native binary analysis (commercial) | `hex-rays.com` |
| [Frida](https://frida.re/) | Runtime instrumentation and hooking | `frida.re` |

## Analysis Workflow

### Mono Backend Workflow

Mono apps yield near-source-quality decompilation with minimal effort.

**Step 1: Extract assemblies**

```bash
unzip target.apk "assets/bin/Data/Managed/*.dll" -d work/
```

**Step 2: Decompile with dnSpy or ILSpy**

Open `Assembly-CSharp.dll` in dnSpy. The output is readable C# with original class names, method names, and string literals intact. Navigate the type tree to find:

- Network request handlers (API endpoints, auth tokens)
- In-app purchase validation logic
- Anti-cheat implementations
- Encryption/decryption routines
- Server communication protocols

**Step 3: Modify and repackage (if needed)**

dnSpy supports direct editing of CIL. Modify a method, save the assembly, replace it in the APK, re-sign, and install:

```bash
cp modified/Assembly-CSharp.dll work/assets/bin/Data/Managed/
cd work && zip -r ../modified.apk . && cd ..
apksigner sign --ks keystore.jks modified.apk
```

### IL2CPP Backend Workflow

IL2CPP requires a two-phase approach: metadata recovery followed by native analysis.

**Step 1: Extract binary and metadata**

```bash
unzip target.apk "lib/arm64-v8a/libil2cpp.so" -d work/
unzip target.apk "assets/bin/Data/Managed/Metadata/global-metadata.dat" -d work/
```

**Step 2: Run Il2CppDumper**

```bash
Il2CppDumper libil2cpp.so global-metadata.dat output/
```

Il2CppDumper produces:

| Output File | Contents |
|-------------|----------|
| `dump.cs` | C# class/method declarations with RVA addresses (no method bodies) |
| `il2cpp.h` | C header with struct definitions for all types |
| `script.json` | Method name-to-address mappings |
| `stringliteral.json` | All string literals with their addresses |
| `ghidra_with_struct.py` | Ghidra script to apply type info and rename functions |
| `ida_with_struct_py3.py` | IDA script for the same purpose |

**Step 3: Apply metadata to disassembler**

Load `libil2cpp.so` in Ghidra, then run the generated script:

```
ghidra_with_struct.py
```

This renames thousands of `FUN_XXXXX` functions to their original C# method names and applies struct definitions, transforming an opaque ARM binary into a navigable codebase.

**Step 4: Alternative -- Cpp2IL**

[Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) goes further than Il2CppDumper by attempting to reconstruct method bodies:

```bash
Cpp2IL --game-path . --exe-name libil2cpp.so --output-as isil
```

The ISIL (Intermediate Static IL) output provides pseudo-instructions for each method, approximating the original logic without full decompilation.

**Step 5: Search recovered data**

```bash
grep -i "api\|token\|secret\|password\|encrypt\|decrypt\|http" output/dump.cs
```

```bash
python3 -c "
import json
with open('output/stringliteral.json') as f:
    for s in json.load(f):
        v = s.get('value', '')
        if any(k in v.lower() for k in ['http', 'api', 'key', 'token', 'secret']):
            print(v)
"
```

## Hooking Strategy

### Mono Runtime Hooks

When targeting Mono-backend Unity apps, hook through the Mono runtime API exported by `libmono.so`. The key function is `mono_runtime_invoke`, which the VM calls for every managed method invocation:

```javascript
var mono = Process.findModuleByName("libmono.so");

var mono_runtime_invoke = Module.findExportByName("libmono.so", "mono_runtime_invoke");
Interceptor.attach(mono_runtime_invoke, {
    onEnter: function(args) {
        var method = args[0];
        var mono_method_get_name = new NativeFunction(
            Module.findExportByName("libmono.so", "mono_method_get_name"),
            "pointer", ["pointer"]
        );
        var name = mono_method_get_name(method).readUtf8String();
        if (name.indexOf("Login") !== -1 || name.indexOf("Purchase") !== -1) {
            console.log("[Mono] " + name + " called");
        }
    }
});
```

Enumerate all loaded assemblies and their classes:

```javascript
var mono_assembly_foreach = new NativeFunction(
    Module.findExportByName("libmono.so", "mono_assembly_foreach"),
    "void", ["pointer", "pointer"]
);

var callback = new NativeCallback(function(assembly, userData) {
    var mono_assembly_get_image = new NativeFunction(
        Module.findExportByName("libmono.so", "mono_assembly_get_image"),
        "pointer", ["pointer"]
    );
    var mono_image_get_name = new NativeFunction(
        Module.findExportByName("libmono.so", "mono_image_get_name"),
        "pointer", ["pointer"]
    );
    var image = mono_assembly_get_image(assembly);
    console.log("[Mono Assembly] " + mono_image_get_name(image).readUtf8String());
}, "void", ["pointer", "pointer"]);

mono_assembly_foreach(callback, ptr(0));
```

### IL2CPP Hooks

For IL2CPP apps, use the RVA offsets from Il2CppDumper's `script.json` to hook specific methods as native functions:

```javascript
var il2cpp = Process.findModuleByName("libil2cpp.so");
var baseAddr = il2cpp.base;

var scriptData = {
    "GameManager$$SendScore": "0x1A3F40",
    "NetworkManager$$PostRequest": "0x1B2C80",
    "CryptoHelper$$Decrypt": "0x1C8D10"
};

Object.keys(scriptData).forEach(function(methodName) {
    var offset = parseInt(scriptData[methodName], 16);
    var addr = baseAddr.add(offset);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log("[IL2CPP] " + methodName + " called");
            console.log("  arg0: " + args[0]);
            console.log("  arg1: " + args[1]);
        },
        onLeave: function(retval) {
            console.log("  retval: " + retval);
        }
    });
});
```

Read IL2CPP string objects (Il2CppString has a length field at offset +0x10 and UTF-16 chars at +0x14):

```javascript
function readIl2CppString(ptr) {
    if (ptr.isNull()) return "null";
    var length = ptr.add(0x10).readInt();
    if (length <= 0 || length > 4096) return "<invalid>";
    return ptr.add(0x14).readUtf16String(length);
}
```

### il2cpp_resolve_icall Hook

Internal calls (`[MethodImpl(MethodImplOptions.InternalCall)]`) route through `il2cpp_resolve_icall`. Hook this to monitor all icall resolutions:

```javascript
var resolve_icall = Module.findExportByName("libil2cpp.so", "il2cpp_resolve_icall");
Interceptor.attach(resolve_icall, {
    onEnter: function(args) {
        this.name = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        console.log("[icall] " + this.name + " -> " + retval);
    }
});
```

## SSL Pinning Bypass

Unity's networking stack has multiple pinning surfaces depending on how the developer implemented HTTP requests.

### UnityWebRequest

Unity's built-in HTTP client (`UnityEngine.Networking.UnityWebRequest`) uses the engine's internal TLS implementation. On Android, this typically delegates to the platform's SSL stack or BoringSSL bundled in `libunity.so`. Hook the certificate validation callback:

```javascript
var il2cpp = Process.findModuleByName("libil2cpp.so");

var symbols = il2cpp.enumerateExports();
symbols.forEach(function(sym) {
    if (sym.name.indexOf("CertificateHandler") !== -1 && sym.name.indexOf("ValidateCertificate") !== -1) {
        Interceptor.attach(sym.address, {
            onLeave: function(retval) {
                retval.replace(1);
                console.log("[SSL] Forced CertificateHandler.ValidateCertificate to return true");
            }
        });
    }
});
```

### OkHttp (Java Layer)

Many Unity apps use Android-native HTTP libraries through Java plugins. OkHttp pinning bypass applies identically to standard Android apps:

```javascript
Java.perform(function() {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, certs) {
        console.log("[SSL] Bypassed OkHttp pin for: " + host);
    };
});
```

### Custom Certificate Validation

Some Unity apps implement certificate validation in C# by subclassing `CertificateHandler`:

```csharp
public class AcceptAllCerts : CertificateHandler
{
    protected override bool ValidateCertificate(byte[] certificateData)
    {
        return true;
    }
}
```

For IL2CPP apps, locate the `ValidateCertificate` RVA in `dump.cs` and force it to return `true`:

```javascript
var validateCertAddr = il2cpp.base.add(0xRVA_FROM_DUMP);
Interceptor.attach(validateCertAddr, {
    onLeave: function(retval) {
        retval.replace(1);
    }
});
```

### BoringSSL (Native)

Unity bundles BoringSSL in some configurations. Bypass at the native layer:

```javascript
var ssl_verify = Module.findExportByName("libssl.so", "SSL_CTX_set_custom_verify");
if (ssl_verify) {
    Interceptor.attach(ssl_verify, {
        onEnter: function(args) {
            args[2] = new NativeCallback(function(ssl, out) {
                return 0;
            }, "int", ["pointer", "pointer"]);
        }
    });
}
```

## Obfuscation

### Mono Backend Obfuscation

Mono assemblies are standard .NET DLLs, so any .NET obfuscator works. Common ones found in Unity apps:

| Obfuscator | Techniques | Impact on RE |
|------------|-----------|--------------|
| [Beebyte Obfuscator](https://assetstore.unity.com/packages/tools/utilities/obfuscator-48919) | Identifier renaming, string encryption, control flow obfuscation, fake code injection | Class/method names replaced with random strings; strings decrypted at runtime |
| Odin Obfuscator | Identifier renaming, anti-decompiler traps | dnSpy may crash on protected methods; ILSpy usually handles them |
| ConfuserEx | Control flow flattening, anti-tamper, constant encryption | Switch-based dispatch replaces structured code |
| Dotfuscator | Identifier renaming, string encryption, pruning | Microsoft's obfuscator, lightweight protection |

Beebyte is the most common Unity-specific obfuscator. When present, `Assembly-CSharp.dll` will contain classes named like `\u0001`, `\u0002` or randomized alphanumeric strings instead of meaningful names. String literals are replaced with calls to a decryption method.

### IL2CPP Backend Obfuscation

IL2CPP provides a baseline level of protection by compiling to native code, but `global-metadata.dat` preserves all type/method names by default.

Obfuscation applied at the C# level before IL2CPP compilation:

- **Identifier renaming** -- affects names in `global-metadata.dat` and `dump.cs` output from Il2CppDumper
- **String encryption** -- strings in `stringliteral.json` appear as encrypted blobs; runtime decryption function must be located and hooked
- **Metadata encryption** -- some protections encrypt `global-metadata.dat` and decrypt it at runtime before IL2CPP initialization; Il2CppDumper fails on encrypted metadata

### Encrypted global-metadata.dat

Certain protections (including some Chinese game publishers) encrypt `global-metadata.dat`. Indicators:

- Il2CppDumper fails with a metadata signature error
- The file does not start with bytes `AF 1B B1 FA` (the standard metadata magic)
- `libil2cpp.so` contains a custom loader that decrypts the metadata before passing it to `il2cpp_init`

To recover encrypted metadata, dump it from memory after the app initializes:

```javascript
var il2cpp_init = Module.findExportByName("libil2cpp.so", "il2cpp_init");
Interceptor.attach(il2cpp_init, {
    onLeave: function(retval) {
        var metadataReg = Module.findExportByName("libil2cpp.so", "il2cpp_get_global_metadata");
        if (metadataReg) {
            var getMetadata = new NativeFunction(metadataReg, "pointer", []);
            var metadata = getMetadata();
            var magic = metadata.readU32();
            if (magic === 0xFAB11BAF) {
                var size = metadata.add(4).readU32();
                var dump = metadata.readByteArray(size);
                var f = new File("/data/local/tmp/global-metadata-decrypted.dat", "wb");
                f.write(dump);
                f.close();
                console.log("[+] Dumped decrypted metadata: " + size + " bytes");
            }
        }
    }
});
```

## Malware Context

Unity's popularity in mobile gaming makes it a vector for malicious SDKs and trojanized game mods.

| Threat | Details |
|--------|---------|
| [Goldoson](../../malware/families/goldoson.md) SDK | Malicious advertising SDK found in 60+ legitimate Unity games on Google Play (100M+ downloads). Collected installed app lists, Wi-Fi/Bluetooth device data, GPS location. Operated as a supply chain compromise where developers unknowingly included the SDK. |
| Crypto miners in game mods | Trojanized Unity game APKs distributed through third-party stores and Telegram channels. Embed Coinhive-derived or XMRig-based miners that run during gameplay, exploiting the expectation of high CPU/GPU usage in games. |
| Ad fraud frameworks | Malicious Unity plugins that load hidden WebViews for click fraud, similar to Goldoson's ad-clicking behavior. Games provide cover for battery and data consumption. |
| Data harvesting SDKs | Third-party analytics SDKs embedded in Unity games that exceed declared data collection, exfiltrating contacts, SMS, or location under the cover of game analytics. |
| Fake game clones | Repackaged popular Unity games with injected malware payloads. The attacker decompiles a Mono-backend game, injects malicious code into `Assembly-CSharp.dll`, re-signs, and distributes through third-party stores. |

!!! info "Supply Chain Risk"
    Unity's plugin ecosystem (Asset Store, third-party SDKs) creates a wide attack surface for supply chain compromise. The Goldoson case demonstrated that legitimate developers with millions of downloads can unknowingly distribute malware through a single malicious SDK dependency. When analyzing Unity malware, check all DLLs in the `Managed/` directory -- not just `Assembly-CSharp.dll` -- for third-party SDK code.

## RE Difficulty Assessment

| Aspect | Mono Backend | IL2CPP Backend |
|--------|-------------|----------------|
| Code format | .NET CIL assemblies | Native ARM + metadata file |
| Decompilation quality | Near-source C# | Method signatures only (bodies require native RE) |
| String extraction | Trivial (in DLL) | Trivial (`stringliteral.json` from Il2CppDumper) |
| Control flow recovery | Full | Requires Ghidra/IDA with metadata scripts |
| Patching | Edit CIL in dnSpy, replace DLL | Patch ARM instructions in `libil2cpp.so` |
| Obfuscation ceiling | .NET obfuscators (Beebyte, ConfuserEx) | Metadata encryption + native obfuscation |
| Hooking | Mono runtime API | Native function hooks via RVA offsets |
| Overall difficulty | **Easy** | **Moderate to Hard** |

Mono-backend Unity apps are among the easiest Android targets to reverse engineer -- standard .NET tooling produces clean, readable output. IL2CPP raises the bar significantly, but the metadata file is a critical weakness: as long as `global-metadata.dat` is recoverable (from disk or memory), method names and type structures can be mapped onto the native binary, reducing the problem to conventional native RE with good symbol information.

## References

- [dnSpy -- .NET Debugger and Assembly Editor (dnSpyEx fork)](https://github.com/dnSpyEx/dnSpy)
- [ILSpy -- .NET Decompiler](https://github.com/icsharpcode/ILSpy)
- [Il2CppDumper -- Unity IL2CPP Metadata Extractor](https://github.com/Perfare/Il2CppDumper)
- [Cpp2IL -- IL2CPP Analysis Framework](https://github.com/SamboyCoding/Cpp2IL)
- [Il2CppInspector -- IL2CPP Reverse Engineering Toolkit](https://github.com/djkaty/Il2CppInspector)
- [AssetStudio -- Unity Asset Explorer](https://github.com/Perfare/AssetStudio)
- [AssetRipper -- Unity Project Recovery](https://github.com/AssetRipper/AssetRipper)
- [Unity IL2CPP Internals -- Unity Blog](https://blog.unity.com/engine-platform/an-introduction-to-ilcpp-internals)
- [Reverse Engineering Unity Games -- Katyscode (Il2CppInspector author)](https://katyscode.wordpress.com/2021/01/15/reverse-engineering-il2cpp-games/)
- [Goldoson Malicious SDK in Unity Games -- McAfee](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [Ghidra -- NSA Reverse Engineering Framework](https://ghidra-sre.org/)
