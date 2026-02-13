# Defold

Defold is an open-source game engine developed by the Defold Foundation (originally King, now independent). It uses Lua as its scripting language with a native C++ engine core compiled into `libdmengine.so`. Game assets and Lua scripts are bundled into a proprietary archive format (`.arcd` / `.arci`) rather than shipped as loose files, making extraction a required first step. Defold targets 2D games primarily and has a smaller market share than Unity or Godot, but its archive-based asset packaging creates a distinct reverse engineering workflow.

## Architecture

### Engine Structure

| Layer | Implementation |
|-------|---------------|
| **Engine core** | C++ compiled to `libdmengine.so` (per-ABI native library) |
| **Scripting** | Lua 5.1 (LuaJIT on some platforms, standard Lua VM on Android) |
| **Rendering** | OpenGL ES / Vulkan via engine abstractions |
| **Physics** | Box2D (2D) / Bullet (3D) integrated in engine |
| **Asset system** | Proprietary archive format (`.arcd` data + `.arci` index) |

All game logic is written in Lua scripts that the engine executes via its embedded Lua VM. The C++ engine handles rendering, physics, input, sound, and platform integration. Lua scripts define game object behaviors, UI logic, and scene transitions through Defold's component model.

### Game Object Model

Defold organizes games around collections (scenes), game objects (entities), and scripts (`.script` for game logic, `.gui_script` for UI logic). At build time, all files are compiled into binary representations and packed into the archive. Lua scripts are compiled to Lua bytecode (not shipped as plaintext).

## Identification

| Indicator | Location |
|-----------|----------|
| `libdmengine.so` | Defold engine native library (definitive) |
| `assets/game.arcd` | Game data archive (compiled assets + scripts) |
| `assets/game.arci` | Archive index file |
| `assets/game.dmanifest` | Defold manifest -- project settings, dependencies |
| `assets/game.projectc` | Compiled project settings |
| `assets/game.public.der` | Archive signature public key |
| `com.defold.*` | Engine Java classes in DEX |
| `com.dynamo.bob.*` | Build tool remnants occasionally present |

Quick check:

```bash
unzip -l target.apk | grep -E "(libdmengine|game\.arcd|game\.dmanifest)"
```

The presence of both `libdmengine.so` and `game.arcd` confirms a Defold application. The `.dmanifest` file contains project metadata in a Protocol Buffers format.

## Code Location

Game logic resides in Lua scripts compiled to Lua 5.1 bytecode and packed inside `assets/game.arcd`. The archive also contains all other game assets (textures, sounds, tilemaps, collections, GUI definitions). The native engine library `libdmengine.so` contains no game-specific logic -- it is the same engine binary across all Defold games, only differing by engine version.

The DEX layer contains only thin Android lifecycle glue code (`com.defold.engine.GameActivity`, etc.) with no game logic.

## Archive Extraction

### Defold Archive Format

The Defold archive consists of two files:

| File | Purpose |
|------|---------|
| `game.arci` | Index -- maps file paths (hashed) to offsets and sizes within the data file |
| `game.arcd` | Data -- concatenated binary blobs of all compiled assets |

The index stores entries as path hashes (DJB2 or similar) with offset, size, and compression metadata. Assets may be LZ4-compressed within the archive.

### Extraction Tools

[defold-unpacker](https://github.com/nickthecoder/defold-unpacker) parses the `.arci` index and extracts files from `.arcd`:

```bash
python defold-unpacker.py --index assets/game.arci --data assets/game.arcd --output extracted/
```

For custom extraction, the Defold engine source is open ([GitHub](https://github.com/defold/defold)). The archive format is defined in `engine/resource/src/resource_archive.h`.

### Extracted File Types

Extraction produces compiled binary versions of all game files. The primary RE targets are `.scriptc` (game object scripts) and `.gui_scriptc` (GUI scripts), both containing Lua 5.1 bytecode. Other files include `.collectionc` (scene data, Protocol Buffers), `.goc` (game objects), `.atlasc`/`.texturec` (texture data), and `.soundc` (audio metadata).

## Lua Decompilation

### Lua Bytecode Format

Defold compiles Lua scripts to standard Lua 5.1 bytecode. Each `.scriptc` file starts with the Lua bytecode header:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 bytes | Signature: `\x1bLua` |
| 0x04 | 1 byte | Version: `0x51` (Lua 5.1) |
| 0x05 | 1 byte | Format version |
| 0x06 | 1 byte | Endianness |

Verify with:

```bash
xxd -l 8 extracted/logic/main.scriptc
```

### Decompilation Tools

| Tool | Purpose |
|------|---------|
| [unluac](https://github.com/HansWessworworking/unluac) | Java-based Lua decompiler, best results for Lua 5.1 |
| [luadec](https://github.com/viruscamp/luadec) | C-based Lua 5.1 decompiler |
| [luajit-decompiler](https://github.com/nickthecoder/luajit-decompiler) | For LuaJIT bytecode (if applicable) |

=== "unluac"

    ```bash
    java -jar unluac.jar extracted/logic/main.scriptc > main.lua
    ```

=== "luadec"

    ```bash
    luadec extracted/logic/main.scriptc > main.lua
    ```

### Decompiled Output

Lua 5.1 bytecode retains local variable names, string literals, function structure, and upvalue names unless explicitly stripped. Defold's build pipeline does not strip debug info by default, producing near-source-level decompilation output. Decompiled scripts follow the engine's lifecycle API:

```lua
function init(self)
    self.speed = 200
    self.health = 100
    msg.post(".", "acquire_input_focus")
end

function update(self, dt)
    local pos = go.get_position()
    pos.x = pos.x + self.speed * dt
    go.set_position(pos)
end

function on_message(self, message_id, message, sender)
    if message_id == hash("damage") then
        self.health = self.health - message.amount
    end
end

function on_input(self, action_id, action)
    if action_id == hash("touch") and action.pressed then
        msg.post("/game/spawner", "spawn_enemy")
    end
end
```

Key Defold API functions to trace:

| Function | Purpose |
|----------|---------|
| `msg.post()` | Inter-object messaging (primary communication mechanism) |
| `go.get_position()` / `go.set_position()` | Game object transforms |
| `http.request()` | Network requests (C2 communication vector) |
| `sys.save()` / `sys.load()` | Persistent storage |
| `sys.open_url()` | Open external URLs |
| `iap.buy()` | In-app purchase triggers |

## Hooking

### Dump Lua Scripts at Runtime

Hook `luaL_loadbuffer` in `libdmengine.so` to capture every Lua script as the engine loads it, bypassing archive extraction entirely:

```javascript
var dmengine = Process.findModuleByName("libdmengine.so");
if (dmengine) {
    var loadbuffer = dmengine.enumerateExports().filter(function(e) {
        return e.name.indexOf("luaL_loadbuffer") !== -1;
    });
    if (loadbuffer.length > 0) {
        Interceptor.attach(loadbuffer[0].address, {
            onEnter: function(args) {
                var buf = args[1];
                var size = args[2].toInt32();
                var name = args[3].readCString();
                console.log("[Lua] Loading: " + name + " (" + size + " bytes)");
                var outPath = "/data/local/tmp/defold_scripts/" + name.replace(/\//g, "_");
                var f = new File(outPath, "wb");
                f.write(buf.readByteArray(size));
                f.close();
                console.log("[Lua] Dumped to: " + outPath);
            }
        });
    }
}
```

### Intercept HTTP Requests

```javascript
var dmengine = Process.findModuleByName("libdmengine.so");
if (dmengine) {
    dmengine.enumerateExports().forEach(function(exp) {
        if (exp.name.indexOf("HttpRequest") !== -1 || exp.name.indexOf("http_request") !== -1) {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("[HTTP] Request intercepted");
                }
            });
        }
    });
}
```

### Lua VM State Intercepts

Hook `lua_pcall` to trace all Lua function execution at the VM level. Similarly, hook `lua_tostring`, `lua_tonumber`, and `lua_pushstring` to observe data flowing through the Lua stack. All these symbols are exported from `libdmengine.so` and can be resolved with `Module.findExportByName()`.

## Analysis Workflow

1. **Unzip APK** and confirm Defold (`libdmengine.so` + `game.arcd`)
2. **Extract archive** using defold-unpacker or manual tools
3. **Identify script files** (`.scriptc`, `.gui_scriptc`)
4. **Decompile Lua bytecode** with unluac or luadec
5. **Trace `http.request()`** calls for network communication
6. **Trace `msg.post()`** calls to understand inter-object messaging flow
7. **Review collection files** to understand scene structure
8. **Hook at runtime** with Frida on `libdmengine.so` for dynamic analysis

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Lua 5.1 bytecode in proprietary archive |
| Readability | High after extraction and decompilation (variable names often preserved) |
| String extraction | Requires archive extraction first, then trivial |
| Control flow recovery | Full -- Lua 5.1 decompilation is mature |
| Patching | Replace `.scriptc` in archive or hook at runtime |
| Obfuscation ceiling | Low -- no built-in obfuscation tooling |
| Overall difficulty | **Moderate** |

The primary barrier is the archive extraction step. Once scripts are extracted and decompiled, analysis is straightforward -- Lua 5.1 decompilation is a solved problem with mature tooling. The Defold engine being open-source further assists reverse engineering, as all engine APIs and internal data formats are documented in the source code.

## References

- [Defold -- Official Site](https://defold.com/)
- [Defold Engine -- GitHub](https://github.com/defold/defold)
- [unluac -- Lua Decompiler](https://github.com/HansWessworworking/unluac)
- [luadec -- Lua 5.1 Decompiler](https://github.com/viruscamp/luadec)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [Ghidra -- NSA Reverse Engineering Framework](https://ghidra-sre.org/)
