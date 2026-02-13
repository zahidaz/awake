# Xamarin / .NET MAUI

Xamarin and its successor .NET MAUI allow developers to write Android apps in C#, compiling to .NET assemblies (DLLs) that run on the Mono runtime. From a reverse engineering perspective, this is excellent: .NET intermediate language (IL) decompiles cleanly back to near-source C# using tools like dnSpy and ILSpy. The challenge is locating and extracting the assemblies, which are stored in increasingly obscured formats across Xamarin, .NET MAUI, and .NET MAUI 9 releases.

Microsoft ended Xamarin support in May 2024, designating .NET MAUI as the official successor. Both frameworks use the Mono runtime on Android, but .NET MAUI introduces new packaging formats that complicate extraction. McAfee documented malware campaigns exploiting .NET MAUI's blob-based storage to evade DEX-focused scanners -- the malicious logic sits in C# DLLs that standard Android security tools never inspect.

## Architecture

### Mono Runtime

Both Xamarin and .NET MAUI embed the Mono runtime (`libmonosgen-2.0.so`) into the APK. Mono provides JIT compilation (default) or AOT compilation for .NET assemblies on Android.

| Mode | Runtime Library | Assembly Format | RE Approach |
|------|----------------|----------------|-------------|
| **JIT (default)** | `libmonosgen-2.0.so` | IL bytecode in DLLs, compiled to native at runtime | Decompile DLLs with dnSpy/ILSpy |
| **AOT** | `libmonosgen-2.0.so` + `*.dll.so` | Pre-compiled native code per assembly | Native analysis with Ghidra, limited IL recovery |
| **Hybrid (AOT + Interpreter)** | `libmonosgen-2.0.so` | Mix of pre-compiled and interpreted code | DLLs present but some methods pre-compiled |

JIT mode is by far the most common in production apps. The assemblies are shipped as standard .NET DLLs containing IL bytecode, which Mono JIT-compiles to native ARM instructions at first execution. These DLLs decompile almost perfectly back to C#.

### Execution Flow

```
Android Activity launch
  → MonoRuntimeProvider.attachInfo()
    → Mono VM initialization (libmonosgen-2.0.so)
      → Load assemblies (from DLLs, blob, or ELF payload)
        → JIT compile and execute C# entry point
```

The Java/Kotlin layer contains only a thin bootstrap: `mono.MonoRuntimeProvider` initializes the Mono VM, then hands off execution to the C# code.

### .NET MAUI Differences

.NET MAUI is architecturally similar to Xamarin but uses the .NET 6+ runtime instead of legacy Mono. Key differences:

| Aspect | Xamarin | .NET MAUI |
|--------|---------|-----------|
| Runtime | Mono | .NET 6/7/8/9 (still Mono-based on Android) |
| Assembly storage | `assemblies/` directory or `assemblies.blob` | `assemblies.blob` (MAUI 8), `libassemblies.<arch>.blob.so` (MAUI 9) |
| Bootstrap | `MonoRuntimeProvider` | `MauiApplication` |
| Support status | EOL (May 2024) | Active |

## Identification

| Indicator | Location |
|-----------|----------|
| `assemblies/*.dll` | Loose DLL files in `assemblies/` directory (oldest format) |
| `assemblies.blob` + `assemblies.manifest` | Packed assembly store (Xamarin 13+, MAUI 8) |
| `libassemblies.<arch>.blob.so` | ELF-embedded assemblies (.NET MAUI 9) |
| `libmonosgen-2.0.so` | Mono runtime library |
| `libxamarin-app.so` | Xamarin application bridge |
| `mono.MonoRuntimeProvider` | Bootstrap class in DEX |
| `libmonodroid.so` | Mono-Android interop bridge |
| `Mono.Android.dll` | Android bindings assembly |

```bash
unzip -l target.apk | grep -iE "(assemblies|monosgen|xamarin|monodroid)"
```

## Code Location & Extraction

The extraction method depends on how the assemblies are packaged. Three formats exist, corresponding to different Xamarin/.NET MAUI generations.

### Format 1: Loose DLLs (Legacy Xamarin)

Oldest format -- assemblies stored as individual `.dll` files in the `assemblies/` directory within the APK:

```bash
unzip target.apk "assemblies/*.dll" -d extracted/
ls extracted/assemblies/
```

The DLLs may be compressed with LZ4 (indicated by an `XALZ` header). Decompress before analysis:

```python
import lz4.block
with open("assemblies/MyApp.dll", "rb") as f:
    data = f.read()
    if data[:4] == b"XALZ":
        header_size = 12
        uncompressed_size = int.from_bytes(data[8:12], "little")
        decompressed = lz4.block.decompress(data[header_size:], uncompressed_size=uncompressed_size)
        with open("MyApp.dll", "wb") as out:
            out.write(decompressed)
```

### Format 2: Assembly Store Blob (Xamarin 13+ / .NET MAUI 8)

Modern Xamarin and .NET MAUI 8 apps pack all assemblies into `assemblies.blob` and `assemblies.manifest` files:

```bash
unzip target.apk "assemblies/*" -d extracted/
```

Use [pyxamstore](https://github.com/jakev/pyxamstore) to unpack:

```bash
pip install pyxamstore
pyxamstore unpack -d extracted/assemblies/
```

pyxamstore reads the manifest, locates each assembly in the blob, decompresses LZ4 if applied, and writes individual DLL files. The output directory contains standard .NET assemblies ready for decompilation.

### Format 3: ELF-Embedded Assemblies (.NET MAUI 9)

.NET MAUI 9 introduced a significant change: assemblies are embedded in ELF shared object files named `libassemblies.<arch>.blob.so`. The assemblies live in a custom ELF section called `payload`.

```bash
unzip target.apk "lib/arm64-v8a/libassemblies.arm64-v8a.blob.so" -d extracted/
```

Extract the payload section using `llvm-objcopy`:

```bash
llvm-objcopy --dump-section payload=assemblies_payload.bin \
    extracted/lib/arm64-v8a/libassemblies.arm64-v8a.blob.so
```

The extracted `assemblies_payload.bin` contains the assembly store in the same format as Format 2. Parse it with pyxamstore or a custom script. Individual DLLs within the payload may still carry the `XALZ` LZ4 compression header and require decompression.

!!! warning "MAUI 9 Tooling Gaps"
    As of early 2025, pyxamstore does not natively handle the ELF extraction step. The `llvm-objcopy` extraction must be done manually before feeding the payload to pyxamstore. Automated tooling for the full MAUI 9 pipeline is still maturing.

### Bundle Format (libmonodroid_bundle_app.so)

Some Xamarin apps use the "bundle" format, embedding all assemblies into `libmonodroid_bundle_app.so`. Use [mono_unbundle](https://github.com/talshimoni/mono_unbundle) to extract:

```bash
python3 mono_unbundle.py lib/arm64-v8a/libmonodroid_bundle_app.so output_dir/
```

## Analysis Tools & Workflow

| Tool | Purpose | Platform |
|------|---------|----------|
| [dnSpy](https://github.com/dnSpyEx/dnSpy) | .NET decompiler + debugger, edit and recompile IL | Windows |
| [ILSpy](https://github.com/icsharpcode/ILSpy) | .NET decompiler (read-only, cross-platform via CLI) | Windows, macOS, Linux |
| [dotPeek](https://www.jetbrains.com/decompiler/) | JetBrains .NET decompiler | Windows |
| [pyxamstore](https://github.com/jakev/pyxamstore) | Unpack `assemblies.blob` stores | Python |
| [XamAsmUnZ](https://github.com/cihansol/XamAsmUnZ) | Decompress XALZ-compressed assemblies | Python |
| [mono_unbundle](https://github.com/talshimoni/mono_unbundle) | Extract DLLs from `libmonodroid_bundle_app.so` | Python |
| [Fridax](https://github.com/NorthwaveSecurity/fridax) | Frida wrapper for Mono JIT/AOT method hooking | Node.js |
| [frida-xamarin-unpin](https://github.com/GoSecure/frida-xamarin-unpin) | Xamarin SSL pinning bypass | Frida |
| [Frida](https://frida.re/) | Runtime instrumentation | Cross-platform |
| [jadx](https://github.com/skylot/jadx) | DEX decompilation (Java bootstrap only) | Cross-platform |

### Recommended Workflow

1. **Identify format** -- check for loose DLLs, `assemblies.blob`, or `libassemblies.*.blob.so`
2. **Extract assemblies** -- use the appropriate extraction method for the format
3. **Decompress** -- handle XALZ/LZ4 compression if present
4. **Decompile** -- open DLLs in dnSpy or ILSpy
5. **Analyze C# source** -- search for API endpoints, encryption, credential handling
6. **Patch if needed** -- dnSpy allows editing and recompiling IL directly
7. **Repackage** -- compress, repack into blob/APK, re-sign

### Decompilation Quality

.NET IL decompiles to near-perfect C# source code. Variable names, string literals, class hierarchies, and control flow are all preserved. This makes Xamarin/.NET MAUI apps among the easiest to reverse engineer -- the C# output is often more readable than the original source due to compiler normalizations.

```csharp
public async Task<LoginResponse> Authenticate(string username, string password)
{
    var client = new HttpClient();
    var payload = new { user = username, pass = password };
    var json = JsonConvert.SerializeObject(payload);
    var content = new StringContent(json, Encoding.UTF8, "application/json");
    var response = await client.PostAsync("https://api.example.com/auth", content);
    return JsonConvert.DeserializeObject<LoginResponse>(await response.Content.ReadAsStringAsync());
}
```

The above is representative of what dnSpy produces from a Xamarin DLL -- structurally identical to the original source.

## SSL Pinning Bypass

### Frida Mono Runtime Hook

The most common pinning mechanism in Xamarin is `ServicePointManager.ServerCertificateValidationCallback`. On Mono, this is a static delegate that can be overridden at runtime.

[frida-xamarin-unpin](https://github.com/GoSecure/frida-xamarin-unpin) handles this automatically:

```bash
frida -U -f com.target.app -l frida-xamarin-unpin.js --no-pause
```

The script hooks the Mono runtime to intercept the certificate validation callback and force it to return `true`.

### Manual Mono Hook

For custom pinning implementations, hook the Mono runtime's JIT compilation to intercept specific C# methods:

```javascript
var mono = Module.findExportByName("libmonosgen-2.0.so", "mono_jit_runtime_invoke");
Interceptor.attach(mono, {
    onEnter: function(args) {
        var methodName = Memory.readUtf8String(
            Module.findExportByName("libmonosgen-2.0.so", "mono_method_get_name")(args[0])
        );
        if (methodName && methodName.indexOf("ValidateCertificate") !== -1) {
            this.shouldPatch = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldPatch) {
            console.log("[Xamarin] Certificate validation bypassed");
        }
    }
});
```

### DLL Patching (Permanent Bypass)

The most reliable approach: patch the certificate validation directly in the DLL.

1. Extract the target DLL (e.g., `MyApp.dll`)
2. Open in dnSpy
3. Locate the certificate validation method (search for `ServerCertificateValidationCallback`, `ServicePointManager`, or `X509Certificate`)
4. Replace the validation body to return `true`:

```csharp
public bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
{
    return true;
}
```

5. Save the modified DLL in dnSpy (File > Save Module)
6. Repackage the DLL into the APK (compress with LZ4 if the original was compressed)
7. Re-sign and install

This approach is permanent and avoids runtime hooking entirely.

### Java-Layer Fallback

Some Xamarin apps use the `AndroidClientHandler` instead of the Mono HTTP stack, which delegates to Android's native `HttpURLConnection`. In this case, standard Java-layer hooks work:

```javascript
Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        return untrustedChain;
    };
});
```

## Hooking Strategy

### Fridax (Mono Method Interception)

[Fridax](https://github.com/NorthwaveSecurity/fridax) provides a high-level interface for hooking .NET methods at the Mono runtime level:

```bash
npm install
npm run fridax
```

Fridax supports both JIT and AOT compiled methods. For JIT targets, it forces JIT compilation of the target method using `mono_compile_method()`, then hooks the resulting native code.

### Direct Mono API Hooking

Hook arbitrary C# methods by resolving them through the Mono embedding API:

```javascript
var monoModule = Process.findModuleByName("libmonosgen-2.0.so");

var mono_get_root_domain = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_get_root_domain"),
    "pointer", []
);

var mono_assembly_foreach = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_assembly_foreach"),
    "void", ["pointer", "pointer"]
);

var mono_class_get_method_from_name = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_class_get_method_from_name"),
    "pointer", ["pointer", "pointer", "int"]
);

var mono_compile_method = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_compile_method"),
    "pointer", ["pointer"]
);
```

After resolving the target method, force JIT compilation to get a native address, then use `Interceptor.attach`:

```javascript
var methodPtr = mono_class_get_method_from_name(targetClass, Memory.allocUtf8String("Authenticate"), 2);
var nativeCode = mono_compile_method(methodPtr);

Interceptor.attach(nativeCode, {
    onEnter: function(args) {
        console.log("[Mono] Authenticate called");
    },
    onLeave: function(retval) {
        console.log("[Mono] Authenticate returned");
    }
});
```

### Java Bridge Interception

The Mono-Android bridge passes through JNI. Hook the Java side to intercept Mono-to-Android calls:

```javascript
Java.perform(function() {
    var MonoRuntimeProvider = Java.use("mono.MonoRuntimeProvider");
    console.log("[Xamarin] MonoRuntimeProvider loaded");

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("mono.") === 0) {
                console.log("[Mono Bridge] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

### Enumerating Loaded Assemblies

List all .NET assemblies loaded in the Mono runtime:

```javascript
var mono_assembly_foreach = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_assembly_foreach"),
    "void", ["pointer", "pointer"]
);

var mono_assembly_get_name = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_assembly_get_name"),
    "pointer", ["pointer"]
);

var mono_assembly_name_get_name = new NativeFunction(
    Module.findExportByName("libmonosgen-2.0.so", "mono_assembly_name_get_name"),
    "pointer", ["pointer"]
);

var callback = new NativeCallback(function(assembly, userData) {
    var aname = mono_assembly_get_name(assembly);
    var name = Memory.readUtf8String(mono_assembly_name_get_name(aname));
    console.log("[Assembly] " + name);
}, "void", ["pointer", "pointer"]);

mono_assembly_foreach(callback, ptr(0));
```

## Obfuscation & Anti-Analysis

### Default State

Out of the box, Xamarin/.NET MAUI assemblies contain full type names, method names, string literals, and IL bytecode. Without additional protection, decompilation produces near-source C#.

### .NET Obfuscators

| Tool | Techniques |
|------|-----------|
| [Dotfuscator](https://www.preemptive.com/products/dotfuscator/) | Renaming, string encryption, control flow obfuscation, tamper detection |
| [Babel Obfuscator](https://www.babelfor.net/) | IL-level flow obfuscation, string encryption, metadata stripping |
| [ConfuserEx](https://github.com/yck1509/ConfuserEx) | Open-source: anti-debug, anti-dump, control flow, constant encryption |
| [ArmDot](https://www.armdot.com/) | .NET MAUI support, method-level virtualization, code encryption |
| [R8/ProGuard](../../packers/r8-proguard.md) | Java/Kotlin layer only -- does not affect .NET assemblies |

Even with obfuscation, .NET IL retains enough structure for tools like [de4dot](https://github.com/de4dot/de4dot) to automatically deobfuscate many transformations.

### AOT Compilation as Protection

When AOT mode is used, assemblies are pre-compiled to native code (`*.dll.so` files). The original IL may be stripped, making decompilation impossible. However, AOT is uncommon in practice due to increased APK size and build complexity.

### .NET MAUI Blob Evasion

The shift from loose DLLs to blob storage and ELF-embedded payloads is not obfuscation per se, but it evades security tools that only scan DEX files. Since the C# code lives in binary blob files that standard Android scanners do not inspect, malware using .NET MAUI can pass automated scanning that would flag equivalent Java/Kotlin code.

## Malware Context

### McAfee Xamalicious Backdoor

In late 2023, [McAfee discovered Xamalicious](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/stealth-backdoor-android-xamalicious-actively-infecting-devices/), a backdoor built with Xamarin that had been active since mid-2020. Found in 25 Google Play apps with 327,000+ downloads, Xamalicious exploited the Xamarin build process itself as a packing mechanism. The malicious code was hidden in C# assemblies that standard Android scanners never inspect. After gaining accessibility service access, Xamalicious dynamically injected a second-stage assembly DLL from its C2 server for ad fraud. McAfee linked the operation to the Cash Magnet ad-fraud app, revealing the commercial motivation behind the technical investment in framework abuse.

### McAfee .NET MAUI Malware Report

In March 2025, [McAfee documented Android malware campaigns using .NET MAUI to evade detection](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/). The campaigns exploited the fundamental gap in Android security tooling: most scanners analyze DEX files for suspicious code patterns, but .NET MAUI stores all application logic in C# binary blobs that these scanners ignore.

Key findings from the McAfee report:

| Technique | Details |
|-----------|---------|
| **Blob-based evasion** | All malicious logic in C# DLLs inside binary blob files, invisible to DEX scanners |
| **Multi-stage decryption** | Stage 1: XOR-decrypt a loader. Stage 2: AES-decrypt the .NET MAUI payload. Stage 3: execute C# malware |
| **Manifest bloating** | `AndroidManifest.xml` padded with randomly generated strings to confuse static analysis |
| **TCP C2 communication** | Raw TCP sockets instead of HTTP, avoiding standard network traffic signatures |
| **Target apps** | Fake banking, social media (X/Twitter clone), dating, and communication apps |
| **Target regions** | India and China |

!!! warning "Detection Gap"
    The McAfee report highlights that contemporary Android security tools are designed to scan DEX files for suspicious logic. .NET MAUI's architecture stores code in binary blobs that are not inspected. This is a systemic blind spot, not a bug in specific tools. Any malware using .NET MAUI benefits from this evasion automatically.

### Broader .NET MAUI Malware Patterns

| Campaign Type | Technique |
|---------------|-----------|
| Fake banking apps | Clone banking UI in C#/XAML, harvest credentials, forward to C2 |
| Data theft | Collect contacts, SMS, photos from Mono APIs, exfiltrate via TCP |
| Credential harvesting | Display [phishing](../../attacks/phishing-techniques.md) forms, POST data to attacker server |

### Why .NET MAUI Appeals to Malware Authors

- **DEX-blind scanners** -- all logic in .NET blobs, not in Dalvik bytecode
- **Multi-layer encryption** -- XOR + AES staging adds layers before the C# payload executes
- **Cross-platform** -- C# codebase targets Android and iOS
- **Rapid development** -- C#/XAML is a productive development environment with strong tooling
- **Ironically easy to RE** -- once assemblies are extracted, decompilation is trivial, but automated scanners never get that far

## RE Difficulty Assessment

| Aspect | Mono (JIT) | AOT | .NET MAUI 9 |
|--------|-----------|-----|-------------|
| Assembly extraction | Easy (loose DLLs or pyxamstore) | DLLs present but code pre-compiled | Moderate (ELF section extraction) |
| Decompilation quality | Near-perfect C# | Limited (native code) | Near-perfect C# (after extraction) |
| String recovery | Full | Partial | Full |
| Hooking | High (Mono API, Fridax) | Moderate (native hooks) | High (same Mono API) |
| Patching | Easy (dnSpy edit + recompile) | Difficult | Easy (after extraction) |
| Overall difficulty | **Easy** (rank 7/28) | **Moderate** | **Easy-Moderate** (rank 7/28 once extracted) |

The core RE challenge with Xamarin/.NET MAUI is extraction, not analysis. Once DLLs are in hand, decompilation produces high-fidelity C# source. The difficulty comes from identifying the correct packaging format and applying the right extraction tool. For .NET MAUI 9's ELF-embedded format, the additional `llvm-objcopy` step and potential XALZ decompression add friction but do not fundamentally change the analysis outcome.

## References

- [McAfee: New Android Malware Campaigns Using .NET MAUI](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/)
- [pyxamstore -- Xamarin AssemblyStore Parser](https://github.com/jakev/pyxamstore)
- [Unpacking Xamarin AssemblyStore Blobs -- The Cobra Den](https://www.thecobraden.com/posts/unpacking_xamarin_assembly_stores/)
- [Fridax -- Frida for Xamarin](https://github.com/NorthwaveSecurity/fridax)
- [frida-xamarin-unpin -- GoSecure](https://github.com/GoSecure/frida-xamarin-unpin)
- [Bypassing Xamarin Certificate Pinning -- GoSecure](https://gosecure.ai/blog/2020/04/06/bypassing-xamarin-certificate-pinning-on-android/)
- [mono_unbundle -- Extract DLLs from Bundle](https://github.com/talshimoni/mono_unbundle)
- [Decompiling .NET MAUI 9 Android Applications -- Walkowski](https://mwalkowski.com/post/decompiling-an-android-application-written-in-net-maui-9-xamarin/)
- [Appknox: Xamarin Reverse Engineering Guide](https://www.appknox.com/blog/xamarin-reverse-engineering-a-guide-for-penetration-testers)
- [dnSpy -- .NET Debugger and Decompiler](https://github.com/dnSpyEx/dnSpy)
- [ILSpy -- .NET Decompiler](https://github.com/icsharpcode/ILSpy)
- [HackTricks: Xamarin Apps](https://book.hacktricks.xyz/mobile-pentesting/xamarin-apps)
