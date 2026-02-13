# GameMaker

GameMaker compiles game logic written in GML (GameMaker Language) into proprietary bytecode stored in a monolithic data file -- `game.droid` on Android (equivalent to `data.win` on Windows). The engine runtime (`libyoyo.so`) interprets this bytecode at runtime. All game assets -- sprites, audio, room layouts, GML bytecode, and string tables -- are serialized into the single data file. GameMaker offers two compilation modes: VM (bytecode interpreted by the runner) and YYC (YoYo Compiler, which transpiles GML to C++ and compiles to native code). The compilation mode fundamentally changes the reverse engineering approach.

## Architecture

A GameMaker Android APK contains two or three layers depending on compilation mode:

### VM Mode (Bytecode)

| Layer | Component | Contents |
|-------|-----------|----------|
| Java shell | `com.yoyogames.runner.RunnerActivity` | Minimal Android activity -- initializes the engine |
| Engine runner | `libyoyo.so` | GML bytecode interpreter, rendering, audio, physics, networking (~5-15 MB) |
| Game data | `assets/game.droid` | All game content -- GML bytecode, sprites, audio, rooms, strings |

### YYC Mode (Native Compiled)

| Layer | Component | Contents |
|-------|-----------|----------|
| Java shell | `com.yoyogames.runner.RunnerActivity` | Same minimal wrapper |
| Compiled game | `libyoyo.so` | GML transpiled to C++ and compiled alongside the engine into a single native binary (~20-80 MB) |
| Game data | `assets/game.droid` | Asset data only -- sprites, audio, rooms (no bytecode -- code is in libyoyo.so) |

### VM vs YYC Identification

| Indicator | VM Mode | YYC Mode |
|-----------|---------|----------|
| `libyoyo.so` size | ~5-15 MB (runner only) | ~20-80 MB (runner + compiled game code) |
| `game.droid` contents | Contains GML bytecode in CODE chunk | No CODE chunk -- code compiled natively |
| Performance | Interpreted, slower | Native, 2-3x faster |
| RE difficulty | Moderate -- bytecode decompilable | Hard -- native C++ from GML transpilation |

### game.droid / data.win Format

The data file uses GameMaker's proprietary IFF-like chunk format. Each chunk has an 8-byte header (4-byte tag + 4-byte size):

| Chunk Tag | Contents |
|-----------|----------|
| `FORM` | Root container chunk |
| `GEN8` | General info -- game name, build version, flags |
| `OPTN` | Game options and settings |
| `LANG` | Language/localization strings |
| `EXTN` | Extensions metadata |
| `SOND` | Sound definitions |
| `AGRP` | Audio group definitions |
| `SPRT` | Sprite definitions -- dimensions, origins, collision masks |
| `BGND` | Background definitions |
| `PATH` | Path definitions |
| `SCPT` | Script name-to-index mappings |
| `GLOB` | Global script indices |
| `SHDR` | Shader source code |
| `FONT` | Font definitions |
| `TMLN` | Timeline definitions |
| `OBJT` | Object definitions -- events, parent objects, physics properties |
| `ROOM` | Room layouts -- instances, tiles, views |
| `DAFL` | Data files |
| `TPAG` | Texture page items -- UV coordinates for sprites on atlases |
| `CODE` | GML bytecode (VM mode only) |
| `VARI` | Variable definitions |
| `FUNC` | Function definitions and references |
| `STRG` | String table -- all string literals |
| `TXTR` | Texture atlas PNG data |
| `AUDO` | Raw audio data |

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/game.droid` | Game data file (primary analysis target) |
| `libyoyo.so` | Engine runner / compiled game in `lib/<arch>/` |
| `com.yoyogames.runner.*` | Package prefix in DEX and AndroidManifest.xml |
| `com.yoyogames.*` | Alternative package prefix for older versions |
| `RunnerActivity` | Main activity class |

```bash
unzip -l target.apk | grep -E "(game\.droid|libyoyo|yoyogames)"
```

### GameMaker Version Detection

The `GEN8` chunk in `game.droid` contains the GameMaker build version. Extract it with UndertaleModTool or parse the first bytes after the `GEN8` chunk header.

## Analysis Workflow

### Step 1: Extract game.droid

```bash
unzip target.apk assets/game.droid -d extracted/
```

### Step 2: Analyze with UndertaleModTool

[UndertaleModTool](https://github.com/UnderminersTeam/UndertaleModTool) (UTMT) is the most complete tool for analyzing GameMaker data files. Despite its name, it works with any GameMaker: Studio game, not just Undertale.

UTMT can:

- Parse every chunk in the data file
- Decompile GML bytecode to readable GML source (VM mode)
- Disassemble GML bytecode to assembly (VM mode)
- Browse and export all assets (sprites, audio, rooms, strings)
- Modify and recompile code and assets
- Search across all scripts and objects

```bash
UTMT_CLI extracted/assets/game.droid
```

UTMT supports:

| GameMaker Version | Support Level |
|-------------------|---------------|
| GM:S 1.4 (bytecode 15/16) | Full decompilation and recompilation |
| GM:S 2.x | Full decompilation, partial recompilation |
| GameMaker 2022+ | Partial support, improving |

### Step 3: GML Code Decompilation

In VM mode, the `CODE` chunk contains GML bytecode for every script, object event, and timeline moment. UTMT decompiles this to readable GML:

The decompiled output preserves:

- Function and script names
- Variable names (both local and global)
- String literals
- Control flow (if/else, switch, for, while, repeat)
- Object event types (Create, Step, Draw, etc.)
- Built-in function calls (http_request, file_text_open, etc.)

Search decompiled code for security-relevant patterns:

```bash
grep -rn "http_\|url\|api\|key\|secret\|token\|password\|encrypt\|decrypt" decompiled_scripts/
```

### Step 4: String Table Analysis

The `STRG` chunk contains every string literal in the game. Extract and search it for endpoints, keys, and configuration data:

```bash
strings extracted/assets/game.droid | grep -iE "(http|api|key|secret|token)"
```

### Step 5: Asset Extraction

UTMT exports sprites, audio, fonts, and room layouts. Sprites are stored as regions on texture atlases (`TXTR` chunk) -- UTMT handles the UV remapping to export individual sprite frames.

### Step 6: YYC Mode Analysis

If the game was compiled with YYC, the `CODE` chunk is absent and all GML logic is compiled into `libyoyo.so` as native C++. Analysis requires Ghidra or IDA:

1. Load `libyoyo.so` in Ghidra
2. Search for GML built-in function name strings (they are preserved as lookup keys)
3. Cross-reference string usage to locate game logic functions
4. The transpiled C++ follows predictable patterns from GML source structure

YYC-compiled binaries retain function name strings for GML built-ins (e.g., `http_post_string`, `ds_map_find_value`, `show_debug_message`) because the runner needs them for extension callbacks. These strings serve as anchors for locating game logic in the native binary.

### Analysis Tools Summary

| Tool | Purpose | URL |
|------|---------|-----|
| [UndertaleModTool](https://github.com/UnderminersTeam/UndertaleModTool) | Full data file analysis, GML decompilation, asset extraction, modification | Primary tool |
| [gamebreaker](https://github.com/steviegt6/gamebreaker) | GameMaker reverse engineering and modding framework | Alternative tooling |
| [ida_gamemaker](https://github.com/return-of-modding/ida_gamemaker) | IDA Python scripts for GameMaker native binary RE | YYC mode analysis |
| [Ghidra](https://ghidra-sre.org/) | Native analysis of YYC-compiled libyoyo.so | YYC mode analysis |
| [Frida](https://frida.re/) | Runtime hooking of libyoyo.so functions | Dynamic analysis |

## Hooking

### libyoyo.so Function Hooking

Hook exported functions in `libyoyo.so` to intercept GML runtime operations:

```javascript
var yoyo = Process.findModuleByName("libyoyo.so");

yoyo.enumerateExports().forEach(function(exp) {
    if (exp.name.indexOf("HTTP") !== -1 || exp.name.indexOf("http") !== -1) {
        console.log("[GM] " + exp.name + " @ " + exp.address);
    }
});
```

### GML Built-in Function Interception

GML built-in functions like `http_post_string`, `http_request`, `file_text_write_string` are resolved by name at runtime. Hook the function lookup mechanism or the built-in functions directly:

```javascript
var yoyo = Process.findModuleByName("libyoyo.so");

var httpPost = yoyo.enumerateExports().filter(function(e) {
    return e.name.indexOf("http_post_string") !== -1;
});

if (httpPost.length > 0) {
    Interceptor.attach(httpPost[0].address, {
        onEnter: function(args) {
            console.log("[GM HTTP] http_post_string called");
        }
    });
}
```

### Variable Access Monitoring

Hook variable read/write functions to monitor game state changes:

```javascript
var yoyo = Process.findModuleByName("libyoyo.so");

var varFuncs = yoyo.enumerateExports().filter(function(e) {
    return e.name.indexOf("Variable") !== -1 && e.type === "function";
});

varFuncs.forEach(function(f) {
    console.log("[GM Var] " + f.name + " @ " + f.address);
});
```

## Security Posture

GameMaker's proprietary data format provides moderate protection through obscurity:

| Factor | Effect |
|--------|--------|
| Proprietary chunk format | Not parseable by standard tools -- requires specialized GameMaker-aware tools |
| Binary bytecode | GML bytecode is not human-readable without decompilation |
| YYC compilation | Transpilation to C++ eliminates bytecode entirely |
| Limited tooling | Fewer RE tools compared to Unity or Flutter ecosystems |
| String preservation | String literals remain extractable from the STRG chunk regardless of compilation mode |
| Asset bundling | All assets in a single file rather than loose files |

### Weaknesses

- VM mode bytecode is fully decompilable by UTMT with near-source quality
- String table contains all literals in plaintext
- No built-in encryption for game.droid
- Extension source code (GML) preserved in EXTN chunk metadata
- No code signing or integrity verification on game.droid by default

## RE Difficulty Assessment

| Aspect | VM Mode | YYC Mode |
|--------|---------|----------|
| Code format | GML bytecode in game.droid | Native C++ in libyoyo.so |
| Tool maturity | Good -- UTMT handles decompilation well | Low -- requires manual native RE |
| Symbol recovery | Excellent -- function/variable names preserved | Partial -- built-in function name strings preserved |
| Control flow | Full recovery via UTMT decompiler | Standard native RE difficulty |
| String extraction | Trivial -- STRG chunk | Trivial -- strings still in binary |
| Hooking | Limited -- must hook native runner functions | Limited -- same native hooking |
| Overall difficulty | **Moderate** (rank 21/28) | **Hard** (rank 26/28) |

The primary factor is the compilation mode. VM-mode GameMaker games are straightforward to reverse engineer -- UTMT produces near-source GML output with full variable and function names. YYC-compiled games are significantly harder, requiring native RE skills comparable to any other compiled C++ application, though the predictable transpilation patterns and preserved string table provide useful anchors.

## References

- [UndertaleModTool (UTMT)](https://github.com/UnderminersTeam/UndertaleModTool)
- [gamebreaker -- GameMaker RE Tools](https://github.com/steviegt6/gamebreaker)
- [ida_gamemaker -- IDA Scripts for GameMaker](https://github.com/return-of-modding/ida_gamemaker)
- [On GameMaker Game Decompilation -- yal.cc](https://yal.cc/on-gamemaker-studio-game-decompilation/)
- [GameMaker Data File Format -- Retro Reversing](https://www.retroreversing.com/game-maker)
- [GameMaker YoYo Compiler Documentation](https://manual.gamemaker.io/monthly/en/Settings/YoYo_Compiler.htm)
- [PortMaster: Understanding GameMaker Engine](https://gist.github.com/JeodC/ec64b05191d73c91e7a6a12f55b31af3)
