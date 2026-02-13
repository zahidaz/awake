# Cocos2d-x

Cocos2d-x is a C++ game engine that supports three scripting modes on Android: Lua bindings, JavaScript bindings, and pure C++. The engine compiles to a native shared library (`libcocos2dlua.so`, `libcocos2djs.so`, or `libgame.so`) with optional scripting layers that store game logic as Lua or JavaScript files in the APK's `assets/` directory. Cocos2d-x is one of the most widely used mobile game engines globally, particularly in Asian markets, and its scripting variants appear in both legitimate apps and malware that disguises itself as gaming applications.

## Architecture

### Engine Variants

| Variant | Primary Library | Script Location | Scripting Language |
|---------|----------------|-----------------|-------------------|
| **Cocos2d-x Lua** | `libcocos2dlua.so` | `assets/src/` or `assets/res/` | Lua 5.1 / LuaJIT |
| **Cocos2d-x JS** | `libcocos2djs.so` | `assets/script/` or `assets/src/` | JavaScript (SpiderMonkey) |
| **Cocos2d-x C++** | `libgame.so` or `libcocos2dcpp.so` | N/A (compiled into native lib) | None |

| Component | Role |
|-----------|------|
| **Cocos2d-x Core** | C++ engine handling rendering, physics, audio, input |
| **Lua Binding (tolua++)** | Bridges Lua scripts to C++ engine classes via auto-generated bindings |
| **JS Binding (SpiderMonkey)** | Mozilla's JS engine with C++ bindings for Cocos2d-x APIs |
| **FileUtils** | Unified file resolution system -- checks writable paths first, then assets |

For the Lua variant, `libcocos2dlua.so` initializes the engine and Lua VM, then `FileUtils` loads `main.lua` from `assets/src/`. For the JS variant, `libcocos2djs.so` initializes SpiderMonkey and loads `main.js` from `assets/script/`. Both scripting variants drive game logic through `cc.*` API bindings.

## Identification

| Indicator | Location |
|-----------|----------|
| `libcocos2dlua.so` | Lua-scripted Cocos2d-x app |
| `libcocos2djs.so` | JS-scripted Cocos2d-x app |
| `libcocos2dcpp.so` or `libgame.so` | Pure C++ Cocos2d-x app |
| `org.cocos2dx.*` | Package prefix in DEX classes |
| `org.cocos2dx.lib.Cocos2dxActivity` | Base activity class |
| `assets/src/*.lua` or `assets/src/*.luac` | Lua script files |
| `assets/script/*.js` or `assets/script/*.jsc` | JavaScript files |

```bash
unzip -l target.apk | grep -E "(libcocos2d|cocos2dx|\.lua$|\.luac$|\.jsc$)"
```

## Lua Variant -- Extraction & Analysis

Lua scripts reside in `assets/src/` with the entry point at `main.lua`:

```bash
unzip target.apk "assets/src/*" -d extracted/
find extracted/assets/src/ -name "*.lua" -o -name "*.luac" | head -30
```

If `.lua` files are plaintext, analysis is direct:

```bash
grep -rn "cc\.FileUtils\|cc\.Application\|http\|socket\|network" extracted/assets/src/
grep -rn "crypto\|encrypt\|decode\|key\|password" extracted/assets/src/
```

Files with `.luac` extension or `.lua` files starting with `\x1bLua` are compiled Lua bytecode. Decompile with [unluac](https://github.com/HansWessworht/unluac):

```bash
java -jar unluac.jar extracted/assets/src/main.luac > main.lua
```

### XXTEA Encryption

XXTEA is the most common encryption scheme for Lua scripts in Cocos2d-x. The engine's `FileUtils` class decrypts scripts at load time using a key compiled into the native library.

Indicators of XXTEA encryption:

- `.lua` or `.luac` files that do not start with `\x1bLua`
- Files may start with a custom signature followed by encrypted data
- All script files have similar high-entropy byte distributions

The key is stored in the native library, passed to `FileUtils::setXXTEAKeyAndSign()`. Extract it statically:

```bash
strings libcocos2dlua.so | grep -A2 -B2 "XXTEA"
```

Or extract at runtime with Frida:

```javascript
var cocos = Process.findModuleByName("libcocos2dlua.so");
if (cocos) {
    cocos.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("XXTEAKey") !== -1 || exp.name.indexOf("setXXTEA") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[XXTEA] Key: " + args[1].readPointer().readCString());
                    console.log("[XXTEA] Sign: " + args[2].readPointer().readCString());
                }
            });
        }
    });
}
```

Once the key and sign are known, decrypt offline:

```python
import xxtea
import sys

KEY = b"your_xxtea_key_here"
SIGN = b"your_sign_here"

def decrypt_file(path, output):
    with open(path, "rb") as f:
        data = f.read()
    if data[:len(SIGN)] == SIGN:
        data = data[len(SIGN):]
    decrypted = xxtea.decrypt(data, KEY)
    with open(output, "wb") as f:
        f.write(decrypted)

for f in sys.argv[1:]:
    out = f.replace(".luac", "_dec.lua").replace(".lua", "_dec.lua")
    decrypt_file(f, out)
    print(f + " -> " + out)
```

After XXTEA decryption, the output is standard Lua bytecode that can be decompiled with unluac.

### LuaJIT Bytecode

Some Cocos2d-x builds use LuaJIT instead of standard Lua 5.1. LuaJIT bytecode starts with `\x1bLJ` instead of `\x1bLua`:

```bash
xxd -l 4 extracted/assets/src/main.lua
```

[ljd](https://github.com/NightNord/ljd) is the primary LuaJIT decompiler but produces lower quality output than unluac does for standard Lua 5.1:

```bash
./ljd extracted/assets/src/main.lua > main_decompiled.lua
```

## JavaScript Variant -- Extraction & Analysis

JS scripts reside in `assets/script/` or `assets/src/`:

```bash
unzip target.apk "assets/script/*" -d extracted/
grep -rn "cc\.log\|cc\.director\|XMLHttpRequest\|http" extracted/assets/script/
```

SpiderMonkey bytecode files (`.jsc`) lack mature open-source decompilers. For `.jsc` files, focus on string extraction (`strings main.jsc`), runtime hooking of SpiderMonkey evaluation functions, and intercepting `ScriptingCore::evalString` in `libcocos2djs.so`.

## Pure C++ Variant -- Native Analysis

When no scripting layer is present, all game logic is compiled into the native library. Load `libcocos2dcpp.so` or `libgame.so` into [Ghidra](https://ghidra-sre.org/) and focus on classes inheriting from `cocos2d::Scene`, `cocos2d::Layer`, and `cocos2d::Node`.

| Symbol Pattern | Purpose |
|---------------|---------|
| `*::init()` | Scene/layer initialization |
| `*::update(float)` | Per-frame game logic |
| `*::onTouchBegan` | Touch input handling |
| `*HttpRequest*` | Network communication |
| `*UserDefault*` | Local persistent storage |

## Hooking Strategy

### Lua Variant -- luaL_loadbuffer

Intercept Lua script loading to dump decrypted bytecode:

```javascript
var luaModule = Process.findModuleByName("libcocos2dlua.so");
var luaL_loadbuffer = luaModule.findExportByName("luaL_loadbuffer");

Interceptor.attach(luaL_loadbuffer, {
    onEnter: function(args) {
        var buf = args[1];
        var size = args[2].toInt32();
        var name = args[3].readCString();
        console.log("[Lua] Loading: " + name + " (" + size + " bytes)");
        if (size > 0) {
            var outPath = "/data/local/tmp/cocos_lua/" + name.replace(/\//g, "_");
            var f = new File(outPath, "wb");
            f.write(buf.readByteArray(size));
            f.close();
        }
    }
});
```

### JS Variant -- SpiderMonkey

```javascript
var jsModule = Process.findModuleByName("libcocos2djs.so");
jsModule.enumerateExports().forEach(function(exp) {
    if (exp.name.indexOf("evalString") !== -1 || exp.name.indexOf("executeScript") !== -1) {
        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                try {
                    var script = args[1].readCString();
                    if (script && script.length < 1000) {
                        console.log("[JS] Eval: " + script.substring(0, 200));
                    }
                } catch(e) {}
            }
        });
    }
});
```

### Native HTTP Interception

```javascript
var cocos = Process.findModuleByName("libcocos2dlua.so") || Process.findModuleByName("libcocos2djs.so");
if (cocos) {
    cocos.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("HttpClient") !== -1 && exp.name.indexOf("send") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[HTTP] HttpClient::send called");
                }
            });
        }
    });
}
```

### Java-Layer Hooks

```javascript
Java.perform(function() {
    var Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
    Cocos2dxActivity.onCreate.implementation = function(bundle) {
        console.log("[Cocos] Activity created");
        this.onCreate(bundle);
    };
});
```

## SSL Pinning Bypass

Cocos2d-x uses `HttpClient` based on libcurl or Java's `HttpURLConnection` depending on the build. For Java-layer pinning:

```javascript
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

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

For native libcurl-based pinning, hook `curl_easy_setopt` and disable `CURLOPT_SSL_VERIFYPEER` (option 64):

```javascript
var libcurl = Process.findModuleByName("libcurl.so");
if (libcurl) {
    var curl_easy_setopt = libcurl.findExportByName("curl_easy_setopt");
    Interceptor.attach(curl_easy_setopt, {
        onEnter: function(args) {
            if (args[1].toInt32() === 64) {
                args[2] = ptr(0);
            }
        }
    });
}
```

## RE Difficulty Assessment

| Aspect | Lua (Plaintext) | Lua (XXTEA) | Lua (LuaJIT) | JS | Pure C++ |
|--------|----------------|-------------|--------------|-----|----------|
| Code access | Direct | Key extraction needed | Direct bytecode | Direct or .jsc | Native binary |
| Decompilation | Trivial | After decryption | Moderate (ljd) | Trivial or N/A | Ghidra/IDA |
| String extraction | Trivial | After decryption | Trivial | Trivial | Trivial |
| Patching | Edit Lua, repack | Decrypt, edit, re-encrypt | Difficult | Edit JS, repack | Binary patching |
| Overall difficulty | **Very Easy** | **Moderate** | **Moderate-Hard** | **Easy** | **Hard** |

The Lua variant with XXTEA encryption is the most commonly encountered configuration in production Cocos2d-x apps. The key is always recoverable from the native library (statically via Ghidra or dynamically via Frida), making XXTEA a speed bump rather than a true barrier. LuaJIT bytecode presents a genuine challenge due to limited decompiler support. Pure C++ builds require full native reverse engineering and represent the hardest Cocos2d-x targets.

## References

- [Cocos2d-x Source](https://github.com/cocos2d/cocos2d-x)
- [unluac -- Lua Decompiler](https://github.com/HansWessworht/unluac)
- [luadec -- Lua Decompiler](https://github.com/viruscamp/luadec)
- [ljd -- LuaJIT Decompiler](https://github.com/NightNord/ljd)
- [XXTEA Python Library](https://github.com/xxtea/xxtea-python)
- [Ghidra -- NSA Reverse Engineering Framework](https://ghidra-sre.org/)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
