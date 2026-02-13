# Ren'Py

Ren'Py is an open-source visual novel engine built on Python and Pygame/SDL2. On Android, Ren'Py apps ship a full CPython interpreter (`libpython*.so`) alongside compiled Ren'Py scripts (`.rpyc` files) and Python bytecode (`.pyc` files) inside the APK's `assets/` directory. The engine's scripting language compiles to Python bytecode at build time, but the compilation is reversible -- making Ren'Py one of the most straightforward frameworks to reverse engineer on Android.

## Architecture

### Engine Stack

| Layer | Component | Role |
|-------|-----------|------|
| **Scripting** | Ren'Py Script Language (`.rpy`) | High-level DSL for dialogue, choices, transitions, game flow |
| **Compilation** | `.rpy` to `.rpyc` | Ren'Py compiles scripts to pickled Python AST representations |
| **Runtime** | CPython (`libpython*.so`) | Full Python interpreter embedded in the APK |
| **Rendering** | Pygame/SDL2 (`libSDL2.so`) | 2D rendering, audio playback, input handling |
| **Platform** | `librenpy.so` | Ren'Py native acceleration module |
| **Android Shell** | `org.renpy.android` | Java bootstrap that initializes Python and launches the engine |

### Build Process

Ren'Py uses [RAPT](https://github.com/renpy/rapt) (Ren'Py Android Packaging Tool) to package games for Android. The tool bundles the Python runtime, engine libraries, and compiled game scripts into an APK. The process compiles `.rpy` source scripts into `.rpyc` files -- serialized Python objects containing the game's abstract syntax tree (AST) -- and packages them under `assets/game/`.

### Script Compilation Format

`.rpyc` files are not Python bytecode. They are **pickled Python objects** representing the Ren'Py AST. Each `.rpyc` file contains:

- A two-byte header slot (format identifier)
- Zlib-compressed pickled data
- Ren'Py AST nodes representing dialogue, menus, jumps, conditionals, and Python blocks

This distinction matters: standard Python decompilers (`uncompyle6`, `decompyle3`) do not work on `.rpyc` files. A dedicated tool (`unrpyc`) is required.

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/renpy/` | Core Ren'Py engine scripts |
| `assets/game/*.rpyc` | Compiled game scripts |
| `assets/game/*.rpa` | Ren'Py archive files (images, audio, fonts) |
| `libpython*.so` | Embedded CPython interpreter (e.g., `libpython2.7.so`, `libpython3.9.so`) |
| `librenpy.so` | Ren'Py native acceleration module |
| `libSDL2.so` | SDL2 rendering backend |
| `org.renpy.android` | Java package prefix in DEX classes |
| `org.renpy.android.PythonSDLActivity` | Main activity class |

Quick check:

```bash
unzip -l target.apk | grep -E "(renpy/|\.rpyc|libpython|librenpy)"
```

## Code Location

### Primary Targets

| Path | Content | Format |
|------|---------|--------|
| `assets/game/*.rpyc` | Compiled game scripts | Pickled Ren'Py AST (zlib-compressed) |
| `assets/game/*.rpa` | Asset archives | Ren'Py archive format (images, audio, video) |
| `assets/renpy/**/*.pyo` | Engine bytecode | Python compiled bytecode |
| `assets/game/bytecode.rpyb` | Additional compiled bytecode | Ren'Py bytecode bundle |
| `assets/game/script_version.txt` | Engine version identifier | Plaintext |

### Python Bytecode

Ren'Py bundles Python `.pyo`/`.pyc` files for both the engine internals (`assets/renpy/`) and any custom Python modules the developer includes. These are standard CPython bytecode and can be decompiled with Python bytecode decompilers.

## Extraction & Decompilation

### .rpyc Decompilation with unrpyc

[unrpyc](https://github.com/CensoredUsername/unrpyc) is the standard tool for decompiling `.rpyc` files back to readable `.rpy` source:

```bash
unzip target.apk "assets/game/*.rpyc" -d extracted/
git clone https://github.com/CensoredUsername/unrpyc.git
python unrpyc/unrpyc.py extracted/assets/game/*.rpyc
```

unrpyc unpickles the AST and reconstructs the original Ren'Py script syntax. The output is near-identical to the original `.rpy` source, including dialogue text, menu choices, character definitions, conditional branches, and embedded Python blocks.

For batch processing:

```bash
find extracted/assets/game/ -name "*.rpyc" -exec python unrpyc/unrpyc.py {} \;
```

### .rpa Archive Extraction

Ren'Py archive files (`.rpa`) bundle game assets. [rpatool](https://github.com/Shizmob/rpatool) extracts them:

```bash
pip install rpatool
rpatool -x extracted/assets/game/archive.rpa -o output_dir/
```

Alternatively, [unrpa](https://github.com/Lattyware/unrpa):

```bash
pip install unrpa
unrpa -mp output_dir/ extracted/assets/game/archive.rpa
```

### Python Bytecode Decompilation

For `.pyo`/`.pyc` files in `assets/renpy/` and custom modules:

=== "uncompyle6 (Python 2.x)"

    ```bash
    pip install uncompyle6
    uncompyle6 extracted/assets/renpy/ast.pyo > ast.py
    ```

=== "decompyle3 (Python 3.x)"

    ```bash
    pip install decompyle3
    decompyle3 extracted/assets/renpy/ast.pyc > ast.py
    ```

=== "pycdc (Cross-version)"

    ```bash
    git clone https://github.com/zrax/pycdc.git
    cd pycdc && cmake . && make
    ./pycdc extracted/assets/renpy/ast.pyc > ast.py
    ```

    [pycdc](https://github.com/zrax/pycdc) handles a wider range of Python bytecode versions than uncompyle6 or decompyle3.

## Analysis Workflow

### Recommended Workflow

1. **Unzip APK** and confirm Ren'Py indicators (`assets/renpy/`, `.rpyc` files, `libpython*.so`)
2. **Extract .rpyc files** from `assets/game/`
3. **Decompile with unrpyc** to recover full Ren'Py scripts
4. **Extract .rpa archives** for asset analysis
5. **Search decompiled scripts** for network calls, `renpy.python` blocks, file operations
6. **Decompile Python bytecode** in `assets/renpy/` for engine-level analysis
7. **Hook at runtime** with Frida for dynamic inspection

### Key Analysis Targets in Decompiled Scripts

| Pattern | Significance |
|---------|-------------|
| `python:` blocks | Embedded Python code -- may contain network calls, crypto, file I/O |
| `$ persistent.*` | Persistent game state -- save data, unlock flags, purchase records |
| `renpy.call_in_new_context()` | Dynamic code execution |
| `im.matrix` / `transform` | Asset manipulation (may hide content) |
| `config.keymap` | Custom input handling |
| URLs and endpoints | Network communication, analytics, license checks |

## Hooking Strategy

### Python Runtime Hooking

Since Ren'Py ships a full CPython interpreter, hook the Python C API through `libpython*.so`:

```javascript
var pythonModule = Process.findModuleByName("libpython3.9.so");
if (pythonModule) {
    var PyRun = Module.findExportByName(pythonModule.name, "PyRun_SimpleString");
    if (PyRun) {
        Interceptor.attach(PyRun, {
            onEnter: function(args) {
                console.log("[Python] PyRun_SimpleString: " + args[0].readUtf8String());
            }
        });
    }
}
```

### Injecting Python Code

Execute arbitrary Python inside the Ren'Py runtime:

```javascript
var pythonModule = Process.findModuleByName("libpython3.9.so");
if (pythonModule) {
    var PyRun = new NativeFunction(
        Module.findExportByName(pythonModule.name, "PyRun_SimpleString"),
        "int",
        ["pointer"]
    );
    var payload = Memory.allocUtf8String("import renpy; print(renpy.config.__dict__)");
    PyRun(payload);
}
```

### SDL2 Event Interception

Hook SDL2 for input monitoring:

```javascript
var sdlModule = Process.findModuleByName("libSDL2.so");
if (sdlModule) {
    var SDL_PollEvent = Module.findExportByName(sdlModule.name, "SDL_PollEvent");
    Interceptor.attach(SDL_PollEvent, {
        onLeave: function(retval) {
            if (retval.toInt32() === 1) {
                console.log("[SDL2] Event polled");
            }
        }
    });
}
```

## Script Modification & Patching

### Direct Script Replacement

Ren'Py's compilation is fully reversible. The patching workflow:

1. Extract and decompile `.rpyc` to `.rpy` with unrpyc
2. Modify the `.rpy` source
3. Recompile to `.rpyc` using Ren'Py SDK (or simply include the `.rpy` -- Ren'Py loads `.rpy` over `.rpyc` if both exist)
4. Repackage APK, re-sign, install

### Force-Loading Modified Scripts

Ren'Py prioritizes `.rpy` files over `.rpyc` when both exist in the same directory. Placing a modified `.rpy` alongside its `.rpyc` counterpart forces the engine to use the plaintext version without recompilation.

## Obfuscation & Protection

### Common Protections

| Technique | Description | Bypass |
|-----------|-------------|--------|
| `.rpa` archives with custom keys | Modified archive format with non-standard index offsets | Analyze `renpy/loader.py` for key extraction |
| Bytecode-only distribution | Shipping `.rpyc` without `.rpy` source | unrpyc decompiles fully |
| Python version mismatch | Using unusual Python versions to break decompilers | Use pycdc or match the specific Python version |
| Custom pickle classes | Modified AST classes that break unrpyc | Patch unrpyc to handle custom classes |

Some Ren'Py games implement license checks in Python blocks within game scripts. These are trivially located and bypassed after decompilation with unrpyc.

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Pickled AST (fully decompilable) |
| Readability after decompilation | High -- near-original source recovery |
| String extraction | Trivial (dialogue text in AST) |
| Control flow recovery | Full |
| Patching | Trivial -- replace scripts or add `.rpy` overrides |
| Obfuscation ceiling | Low -- Python-based, limited protection options |
| Overall difficulty | **Easy** |

Ren'Py games are among the easiest Android applications to reverse engineer. The combination of a fully decompilable script format, a standard Python interpreter, and a well-maintained decompilation toolchain (unrpyc) means that near-complete source recovery is the norm. Analysis effort focuses on reading the decompiled game logic rather than fighting obfuscation.

## References

- [unrpyc -- CensoredUsername](https://github.com/CensoredUsername/unrpyc)
- [rpatool -- Shizmob](https://github.com/Shizmob/rpatool)
- [unrpa -- Lattyware](https://github.com/Lattyware/unrpa)
- [pycdc -- Decompyle++](https://github.com/zrax/pycdc)
- [RAPT -- Ren'Py Android Packaging Tool](https://github.com/renpy/rapt)
- [Ren'Py Engine Source](https://github.com/renpy/renpy)
- [Ren'Py Documentation](https://www.renpy.org/doc/html/)
