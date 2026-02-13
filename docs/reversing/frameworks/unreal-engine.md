# Unreal Engine

Unreal Engine compiles game logic as native C++ into a massive shared library (`libUE4.so` for UE4, `libUnreal.so` for UE5), with Blueprint visual scripting compiled to bytecode embedded in asset files. On Android, all game content is packaged into `.pak` files (UE4 legacy format) or `.utoc`/`.ucas` containers (UE5 IoStore format). The engine binary regularly exceeds 200 MB, making it one of the largest and most complex targets in Android reverse engineering. Unreal Engine games frequently ship with anti-cheat solutions, encrypted PAK files, and obfuscated asset structures.

## Architecture

An Unreal Engine Android APK contains three layers:

| Layer | Component | Contents |
|-------|-----------|----------|
| Java shell | `com.epicgames.unreal.GameActivity` | Minimal Android activity -- engine initialization, lifecycle, permissions |
| Engine binary | `libUE4.so` / `libUnreal.so` | Complete engine -- C++ game logic, Blueprint VM, rendering, physics, networking (~200-400 MB) |
| Game content | `assets/*.pak` / `.utoc` / `.ucas` | All game assets -- meshes, textures, audio, Blueprint bytecode, data tables |

The Java layer is a thin wrapper. All game logic -- whether written in C++ or Blueprint -- compiles into the engine binary or is serialized into PAK assets.

### C++ Compilation

Game C++ code compiles directly into `libUE4.so` alongside the engine. There is no separation between engine code and game code in the final binary. The resulting `.so` is a monolithic native library containing:

- All engine subsystems (rendering, physics, audio, networking, input)
- All game-specific C++ classes
- The UObject reflection system and metadata
- Blueprint bytecode interpreter
- Serialization/deserialization for all UAsset types

### Blueprint Visual Scripting

Blueprints are Unreal's visual scripting system. They compile to Kismet bytecode stored in `.uasset` files within PAK archives. The bytecode is interpreted by the Blueprint VM at runtime.

| Blueprint Aspect | Details |
|-----------------|---------|
| Storage | Serialized in `.uasset` files inside PAK archives |
| Format | Kismet bytecode -- register-based VM with typed instructions |
| Bytecodes | Defined in `Script.h` -- assignment, conditional jumps, switch, function calls |
| Execution | Interpreted by `UObject::ProcessEvent` at runtime |
| Metadata | Class names, function names, variable names preserved in UAsset serialization |

### PAK File System

UE4 uses the PAK format for packaging game content. UE5 introduced the IoStore container format (`.utoc`/`.ucas`) alongside legacy PAK.

| Format | Engine Version | Files | Description |
|--------|---------------|-------|-------------|
| PAK (legacy) | UE4 all, UE5 | `.pak` | Single archive with file table and compressed/encrypted entries |
| IoStore | UE4.26+, UE5 | `.utoc` + `.ucas` + `.pak` | Optimized container -- `.utoc` is the table of contents, `.ucas` is the content archive |

PAK files can be encrypted with AES-256. The encryption key is compiled into the engine binary.

## Identification

| Indicator | Location |
|-----------|----------|
| `libUE4.so` | `lib/<arch>/libUE4.so` -- UE4 engine binary |
| `libUnreal.so` | `lib/<arch>/libUnreal.so` -- UE5 engine binary |
| `assets/*.pak` | PAK game archives |
| `assets/*.utoc` / `*.ucas` | IoStore containers (UE5) |
| `com.epicgames.unreal.GameActivity` | Main activity class in AndroidManifest.xml |
| `com.epicgames.unreal.*` | Package prefix in DEX |
| `UE4CommandLine.txt` | Command line arguments file in assets |

```bash
unzip -l target.apk | grep -E "(libUE4|libUnreal|\.pak|\.utoc|\.ucas|epicgames)"
```

### Engine Version Detection

```bash
strings lib/arm64-v8a/libUE4.so | grep -E "^4\.[0-9]+\.[0-9]+"
strings lib/arm64-v8a/libUnreal.so | grep -E "^5\.[0-9]+\.[0-9]+"
```

## Analysis Workflow

### Step 1: PAK Extraction

Extract PAK files from the APK:

```bash
unzip target.apk "assets/*.pak" "assets/*.utoc" "assets/*.ucas" -d extracted/
```

### Step 2: Decrypt PAK (If Encrypted)

Many UE games encrypt PAK files with AES-256. The key is embedded in the engine binary.

Extract the AES key from the engine binary using [UnrealKey](https://github.com/devinacker/UnrealKey):

```bash
python3 unrealkey.py lib/arm64-v8a/libUE4.so
```

Alternatively, search for the key registration function and extract the Base64-encoded key:

```bash
strings lib/arm64-v8a/libUE4.so | grep -E "^[A-Za-z0-9+/]{43}=$"
```

The [FModel/Unreal-Game-Keys](https://github.com/FModel/Unreal-Game-Keys) repository maintains a collection of known AES keys for popular games.

### Step 3: Unpack PAK Contents

Use [FModel](https://fmodel.app/) (GUI) or command-line tools to extract PAK contents:

**Legacy PAK:**

```bash
UnrealPak -Extract extracted/assets/game.pak output_dir/ -aes=0x<hex_key>
```

**IoStore containers (UE5):**

[ZenTools](https://github.com/WorkingRobot/ZenTools) extracts cooked packages (`.uasset`/`.uexp`) from IoStore containers:

```bash
zentools extract extracted/assets/ output_dir/
```

### Step 4: Asset Analysis with FModel

[FModel](https://fmodel.app/) is the primary tool for Unreal Engine asset analysis. It can:

- Browse PAK/IoStore archives with or without encryption keys
- Export textures, meshes, and audio to standard formats
- View UAsset properties and Blueprint data
- Convert Zen assets between formats

[UAssetAPI](https://github.com/atenfyr/UAssetAPI) provides programmatic access to UAsset files for automated analysis:

```bash
UAssetGUI path/to/asset.uasset
```

### Step 5: Blueprint Decompilation

Blueprint bytecode (Kismet) stored in UAsset files can be decompiled with [KismetKompiler](https://github.com/tge-was-taken/KismetKompiler):

```bash
kismetkompiler decompile path/to/blueprint.uasset -o decompiled_output/
```

KismetKompiler recovers Blueprint node graphs from the serialized Kismet bytecode, producing readable pseudo-code showing function calls, variable assignments, and control flow.

### Step 6: Native C++ Analysis

The C++ game logic compiled into `libUE4.so` requires traditional native RE. The UObject reflection system preserves significant metadata:

**UE4Dumper** dumps UObject metadata from a running game process on Android:

```bash
./ue4dumper -p <pid> -o dump_output/
```

[frida-ue4dump](https://github.com/hackcatml/frida-ue4dump) achieves the same via Frida for UE >= 4.23 (64-bit):

```javascript
var processEventOffset = 0x1234567;
```

The dump produces SDK headers with class hierarchies, property offsets, and function signatures, dramatically improving Ghidra/IDA analysis.

### Analysis Tools Summary

| Tool | Purpose | URL |
|------|---------|-----|
| [FModel](https://fmodel.app/) | PAK/IoStore browser, asset viewer, texture/mesh export | Primary asset analysis |
| [UAssetAPI](https://github.com/atenfyr/UAssetAPI) / UAssetGUI | Programmatic UAsset parsing and editing | Asset modification |
| [KismetKompiler](https://github.com/tge-was-taken/KismetKompiler) | Blueprint (Kismet) bytecode decompilation | Blueprint RE |
| [UE4Dumper](https://github.com/kp7742/UE4Dumper) | Runtime UObject metadata dump from Android processes | SDK generation |
| [frida-ue4dump](https://github.com/hackcatml/frida-ue4dump) | Frida-based UObject dump for UE >= 4.23 64-bit | SDK generation |
| [UnrealKey](https://github.com/devinacker/UnrealKey) | AES-256 decryption key extraction from engine binary | PAK decryption |
| [ZenTools](https://github.com/WorkingRobot/ZenTools) | IoStore (.utoc/.ucas) extraction | UE5 container extraction |
| [Ghidra](https://ghidra-sre.org/) | Native analysis of libUE4.so with UObject type info | C++ RE |
| [Frida](https://frida.re/) | Runtime hooking of UObject methods and engine functions | Dynamic analysis |

## Hooking

Hooking Unreal Engine games on Android is challenging due to the massive binary size, C++ vtable-based dispatch, and the UObject system's complexity.

### UObject ProcessEvent Hooking

`UObject::ProcessEvent` is the central dispatch function for Blueprint and replicated function calls. Hooking it captures all Blueprint-level function invocations:

```javascript
var ue4 = Process.findModuleByName("libUE4.so");

var processEvent = ue4.enumerateExports().filter(function(e) {
    return e.name.indexOf("ProcessEvent") !== -1;
});

if (processEvent.length > 0) {
    Interceptor.attach(processEvent[0].address, {
        onEnter: function(args) {
            var uobject = args[0];
            var ufunction = args[1];
            console.log("[UE4] ProcessEvent: " + uobject + " func=" + ufunction);
        }
    });
}
```

### Virtual Function Table Hooking

UObject-derived classes use C++ vtables for polymorphic dispatch. Replace vtable entries to intercept specific method calls:

```javascript
var ue4 = Process.findModuleByName("libUE4.so");
var vtableAddr = ue4.base.add(0xVTABLE_OFFSET);

var originalFunc = vtableAddr.readPointer();
var replacement = new NativeCallback(function(thisPtr) {
    console.log("[UE4] Hooked vtable call on " + thisPtr);
    return originalFunc(thisPtr);
}, "pointer", ["pointer"]);

Memory.protect(vtableAddr, Process.pointerSize, "rwx");
vtableAddr.writePointer(replacement);
```

### GWorld and GObjects Enumeration

Enumerate loaded UObjects at runtime to discover game state:

```javascript
var ue4 = Process.findModuleByName("libUE4.so");

var gobjects = ue4.enumerateExports().filter(function(e) {
    return e.name.indexOf("GUObjectArray") !== -1;
});

if (gobjects.length > 0) {
    console.log("[UE4] GUObjectArray @ " + gobjects[0].address);
}
```

## Anti-Cheat

Unreal Engine games frequently ship with anti-cheat middleware that actively detects and prevents reverse engineering:

| Solution | Description |
|----------|-------------|
| Easy Anti-Cheat (EAC) | Epic's own anti-cheat -- kernel-level on PC, user-space on Android. Detects Frida, debuggers, memory tampering |
| BattlEye | Third-party anti-cheat with Android support. Integrity checks on engine binary |
| Custom solutions | Game-specific integrity checks, server-side validation, encrypted network protocols |

### Anti-Cheat Bypass Considerations

- EAC on Android runs in user-space, making it more bypassable than the kernel-level PC variant
- Frida detection is common -- use [frida-gadget](https://frida.re/docs/gadget/) injection or renamed Frida builds
- Memory integrity checks scan `libUE4.so` -- avoid inline hooks, prefer vtable replacement
- Network traffic validation may detect modified game state server-side

## SSL Pinning

Unreal Engine's TLS implementation varies by version and platform configuration:

| Method | Description | Bypass |
|--------|-------------|--------|
| OpenSSL (bundled) | Compiled into engine binary | Hook `SSL_CTX_set_verify` in libUE4.so |
| Platform TrustManager | Uses Android Java TLS stack | Standard Java-layer Frida bypass |
| libcurl | Engine's HTTP client uses libcurl with OpenSSL | Hook `CURLOPT_SSL_VERIFYPEER` |

### OpenSSL Native Bypass

```javascript
var ue4 = Process.findModuleByName("libUE4.so");

var sslVerify = ue4.enumerateExports().filter(function(e) {
    return e.name.indexOf("SSL_CTX_set_verify") !== -1;
});

if (sslVerify.length > 0) {
    Interceptor.attach(sslVerify[0].address, {
        onEnter: function(args) {
            args[1] = ptr(0x0);
            console.log("[UE4 SSL] Verification disabled");
        }
    });
}
```

### Java TrustManager Bypass

When the engine delegates to Android's Java TLS stack, standard Java-layer hooks work:

```javascript
Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[UE4 SSL] TrustManager bypassed for: " + host);
        return untrustedChain;
    };
});
```

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Native ARM64 C++ (200-400 MB monolithic binary) |
| Tool maturity | Low-Moderate -- UE4Dumper/frida-ue4dump help, but C++ RE remains manual |
| Symbol recovery | Partial -- UObject reflection preserves class/property names, but function implementations are stripped |
| Blueprint recovery | Moderate -- KismetKompiler decompiles Blueprint bytecode from UAssets |
| Control flow | Extremely difficult -- massive binary, C++ vtable dispatch, template-heavy code |
| String extraction | Moderate -- strings spread across engine binary and PAK assets |
| SSL bypass | Variable -- depends on TLS implementation (OpenSSL native vs Java TrustManager) |
| Anti-cheat | Common -- EAC, BattlEye, custom solutions add significant complexity |
| Overall difficulty | **Very Hard** (rank 28/28) -- hardest framework to reverse engineer on Android |

Unreal Engine is the most difficult Android framework to reverse engineer. The monolithic native binary with no managed code layer, combined with anti-cheat protection and encrypted assets, makes thorough analysis extremely time-consuming. Blueprint decompilation via KismetKompiler and UObject metadata dumps via UE4Dumper/frida-ue4dump are essential to make any meaningful progress.

## References

- [FModel -- Unreal Engine Asset Viewer](https://fmodel.app/)
- [UAssetAPI -- Unreal Engine Asset Parser](https://github.com/atenfyr/UAssetAPI)
- [KismetKompiler -- Blueprint Decompiler](https://github.com/tge-was-taken/KismetKompiler)
- [UE4Dumper -- Android UObject Dumper](https://github.com/kp7742/UE4Dumper)
- [frida-ue4dump -- Frida UE4 Dump Script](https://github.com/hackcatml/frida-ue4dump)
- [UnrealKey -- AES Key Extractor](https://github.com/devinacker/UnrealKey)
- [FModel/Unreal-Game-Keys -- Known AES Keys](https://github.com/FModel/Unreal-Game-Keys)
- [UE Modding Tools Collection](https://github.com/Buckminsterfullerene02/UE-Modding-Tools)
- [Blueprint VM Overview -- Gamedev Guide](https://ikrima.dev/ue4guide/engine-programming/blueprints/bp-virtualmachine-overview/)
- [Unofficial UE Modding Guide](https://unofficial-modding-guide.com/posts/thebasics/)
