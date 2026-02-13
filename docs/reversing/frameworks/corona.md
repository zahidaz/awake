# Corona SDK / Solar2D

Corona SDK (rebranded as Solar2D in 2020) builds Android apps using Lua as the scripting language, with a C/C++ runtime handling rendering, physics, and platform APIs. Application Lua code is compiled to Lua bytecode and packed into a `resource.car` archive inside the APK's `assets/` directory. The runtime executes this bytecode through an embedded Lua VM (`liblua.so`) managed by the Corona native engine (`libcorona.so`). Solar2D is open-source and primarily used for 2D games, though some utility apps and malware samples have used the framework for rapid cross-platform deployment.

## Architecture

| Component | Role |
|-----------|------|
| **Lua VM** | Executes Lua bytecode via embedded `liblua.so` (Lua 5.1 based) |
| **Corona Runtime** | C++ engine managing app lifecycle, rendering, and native API bridging |
| **resource.car** | Corona Archive containing compiled Lua bytecode files |
| **Corona Plugins** | Native libraries providing extended functionality (ads, analytics, IAP) |

Execution flow: Android activity launches via `com.ansca.corona.CoronaActivity`, `libcorona.so` initializes the runtime and Lua VM, the runtime loads Lua bytecode from `resource.car`, and `main.lua` (compiled) executes as the entry point. All application logic runs through Lua calling Corona APIs for rendering, networking, and platform access.

| Library | Purpose |
|---------|---------|
| `libcorona.so` | Corona runtime engine |
| `liblua.so` | Lua 5.1 virtual machine |
| `libalmixer.so` | Audio mixing library |
| `libmpg123.so` | MP3 decoding |
| `libopenal.so` | OpenAL audio backend |

## Identification

| Indicator | Location |
|-----------|----------|
| `libcorona.so` | `lib/<arch>/` directory |
| `liblua.so` | `lib/<arch>/` directory |
| `assets/resource.car` | Corona archive with compiled Lua files |
| `com.ansca.corona.*` | Package prefix in DEX classes |
| `com.ansca.corona.CoronaActivity` | Main activity class |

Quick check:

```bash
unzip -l target.apk | grep -E "(libcorona|liblua|resource\.car|corona)"
```

## Code Location & Extraction

### resource.car Format

The `resource.car` file is a Corona-specific archive containing compiled Lua bytecode files. It uses a custom header and file table, not a standard archive format.

```bash
unzip target.apk assets/resource.car -d extracted/
```

### Unpacking resource.car

Use the [Car Unpacker](https://github.com/niclaslindstedt/corona-car-unpacker) tool:

```bash
python3 car_unpacker.py extracted/assets/resource.car -o lua_output/
```

If no unpacker is available, examine the binary structure:

```bash
xxd -l 64 extracted/assets/resource.car
strings extracted/assets/resource.car | grep "\.lu"
```

The archive contains files with `.lu` extensions -- compiled Lua bytecode, not Lua source.

### Identifying Lua Bytecode

Lua 5.1 bytecode files start with a distinctive header:

| Offset | Value | Meaning |
|--------|-------|---------|
| 0x00 | `\x1bLua` | Lua bytecode signature |
| 0x04 | `0x51` | Lua version 5.1 |
| 0x05 | `0x00` | Format version (official) |

```bash
xxd -l 8 lua_output/main.lu
```

## Lua Decompilation

[unluac](https://github.com/HansWessworht/unluac) is the primary decompiler for Lua 5.1 bytecode:

```bash
java -jar unluac.jar lua_output/main.lu > main.lua
```

Batch decompilation:

```bash
for f in lua_output/*.lu; do
    java -jar unluac.jar "$f" > "${f%.lu}.lua" 2>/dev/null
done
```

[luadec](https://github.com/viruscamp/luadec) is an alternative that handles some constructs unluac struggles with:

```bash
./luadec lua_output/main.lu > main.lua
```

| Tool | Strengths | Weaknesses |
|------|-----------|------------|
| [unluac](https://github.com/HansWessworht/unluac) | Best overall Lua 5.1 support | Struggles with heavily obfuscated bytecode |
| [luadec](https://github.com/viruscamp/luadec) | Handles some edge cases better | Less maintained, harder to build |

### Analysis of Decompiled Code

```bash
grep -rn "network\.request\|socket\|http" decompiled/
grep -rn "crypto\|encrypt\|decrypt\|key\|password" decompiled/
```

Key Corona API patterns:

| Pattern | Significance |
|---------|-------------|
| `network.request()` | HTTP requests -- extract endpoints and parameters |
| `network.download()` | File downloads from remote servers |
| `system.getInfo()` | Device fingerprinting |
| `native.showAlert()` | UI dialogs -- phishing lure text |
| `store.purchase()` | In-app purchase manipulation |
| `crypto.digest()` | Cryptographic operations |
| `io.open()` | Local file access |

## Encryption

Some Corona/Solar2D apps encrypt their Lua bytecode before packing into `resource.car`. Indicators:

- Extracted `.lu` files do not start with `\x1bLua` header
- Files appear as random bytes with high entropy
- Decompilers fail with format errors

The decryption routine resides in `libcorona.so` since the runtime must decrypt bytecode before passing it to the Lua VM. The most reliable extraction method is intercepting `luaL_loadbuffer` to capture bytecode after decryption:

```javascript
var luaModule = Process.findModuleByName("liblua.so");
if (luaModule) {
    var luaL_loadbuffer = luaModule.findExportByName("luaL_loadbuffer");
    if (luaL_loadbuffer) {
        Interceptor.attach(luaL_loadbuffer, {
            onEnter: function(args) {
                var buf = args[1];
                var size = args[2].toInt32();
                var name = args[3].readCString();
                console.log("[Lua] Loading: " + name + " (" + size + " bytes)");
                var outPath = "/data/local/tmp/lua_dump/" + name.replace(/\//g, "_");
                var f = new File(outPath, "wb");
                f.write(buf.readByteArray(size));
                f.close();
            }
        });
    }
}
```

This captures every Lua chunk after decryption, producing clean bytecode files that can be decompiled with unluac.

To locate decryption symbols statically:

```javascript
var coronaModule = Process.findModuleByName("libcorona.so");
if (coronaModule) {
    coronaModule.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("decrypt") !== -1 || exp.name.indexOf("Decrypt") !== -1) {
            console.log("[Corona] " + exp.name + " @ " + exp.address);
        }
    });
}
```

## Hooking Strategy

### Lua VM Interception

The primary hooking point is `luaL_loadbuffer` in `liblua.so`, which receives all Lua code before execution:

```javascript
var luaModule = Process.findModuleByName("liblua.so");
var luaL_loadbuffer = luaModule.findExportByName("luaL_loadbuffer");

Interceptor.attach(luaL_loadbuffer, {
    onEnter: function(args) {
        this.name = args[3].readCString();
        this.size = args[2].toInt32();
        console.log("[Lua] Load: " + this.name + " size=" + this.size);
    }
});
```

### Lua Function Call Monitoring

Hook `lua_pcall` to trace function execution:

```javascript
var lua_pcall = luaModule.findExportByName("lua_pcall");

Interceptor.attach(lua_pcall, {
    onEnter: function(args) {
        var nargs = args[1].toInt32();
        var nresults = args[2].toInt32();
        console.log("[Lua] pcall nargs=" + nargs + " nresults=" + nresults);
    },
    onLeave: function(retval) {
        if (retval.toInt32() !== 0) {
            console.log("[Lua] pcall error code: " + retval.toInt32());
        }
    }
});
```

### Java-Layer Corona Hooks

```javascript
Java.perform(function() {
    var CoronaActivity = Java.use("com.ansca.corona.CoronaActivity");
    CoronaActivity.onCreate.implementation = function(bundle) {
        console.log("[Corona] Activity created");
        this.onCreate(bundle);
    };

    var CoronaRuntimeTaskDispatcher = Java.use("com.ansca.corona.CoronaRuntimeTaskDispatcher");
    CoronaRuntimeTaskDispatcher.send.implementation = function(task) {
        console.log("[Corona] Runtime task: " + task.getClass().getName());
        this.send(task);
    };
});
```

## SSL Pinning Bypass

Corona's networking uses Java's HTTP stack under the hood. Standard Android SSL bypass techniques apply:

```javascript
Java.perform(function() {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

    var TrustAll = Java.registerClass({
        name: "com.bypass.TrustAll",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var managers = Java.array("javax.net.ssl.TrustManager", [TrustAll.$new()]);
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, managers, null);
    SSLContext.setDefault(ctx);
});
```

If pinning is implemented in Lua code via `network.request` parameters, patch the decompiled Lua source, recompile with `luac`, repack into `resource.car`, and rebuild the APK.

## RE Difficulty Assessment

| Aspect | Standard Build | Encrypted Lua |
|--------|---------------|---------------|
| Code format | Lua 5.1 bytecode in resource.car | Encrypted bytecode in resource.car |
| Readability | High after decompilation with unluac | Requires runtime dump first |
| String extraction | Trivial from bytecode | Requires decryption |
| Decompiler quality | Good -- unluac handles most constructs | Same after decryption |
| Patching | Decompile, edit, recompile with luac | Must also handle re-encryption or bypass |
| Overall difficulty | **Easy** | **Moderate** |

Corona/Solar2D apps with standard (unencrypted) Lua bytecode are straightforward targets. The `resource.car` unpacking adds one extra step compared to frameworks that store scripts as loose files, but mature tooling handles this well. Encrypted builds require runtime interception via `luaL_loadbuffer` hooking to dump decrypted bytecode before decompilation can proceed.

## References

- [Solar2D Open Source Engine](https://github.com/coronalabs/corona)
- [unluac -- Lua Decompiler](https://github.com/HansWessworht/unluac)
- [luadec -- Lua Decompiler](https://github.com/viruscamp/luadec)
- [Corona CAR Unpacker](https://github.com/niclaslindstedt/corona-car-unpacker)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [Lua 5.1 Bytecode Reference](https://www.lua.org/source/5.1/lopcodes.h.html)
