# Kivy (Python for Android)

Kivy apps embed a full CPython (or occasionally PyPy) runtime inside the APK, bundled via [python-for-android](https://github.com/kivy/python-for-android) (p4a). The UI is rendered through SDL2 onto a `SurfaceView`, bypassing Android's native widget system entirely. Application logic is written in Python, compiled to `.pyc` bytecode, and packed into an archive (typically `assets/private.tar` or `assets/private.mp3`) that gets extracted at first launch. Kivy is an open-source framework primarily used for prototyping, educational apps, and niche tools -- but its Python foundation makes it trivial to recover source code from production builds.

## Architecture

### Runtime Model

| Layer | Components |
|-------|------------|
| **Java shell** | `PythonActivity` or `PythonService` (extends `Activity`/`Service`), `org.kivy.android.*` classes |
| **Native runtime** | `libpython3.x.so` -- embedded CPython interpreter |
| **SDL2 layer** | `libSDL2.so`, `libSDL2_image.so`, `libSDL2_mixer.so`, `libSDL2_ttf.so` -- rendering and input |
| **Python modules** | `.pyc` files (compiled bytecode) packed in `assets/private.tar` or `assets/private.mp3` |
| **Kivy framework** | Pure Python Kivy modules alongside application code in the same archive |

### Bootstrap Flow

1. `PythonActivity` starts and calls native initialization via JNI
2. `libSDL2.so` initializes the rendering surface
3. `libpython3.x.so` starts the CPython interpreter
4. Python bootstrap extracts `private.tar` to the app's internal storage (first run)
5. The interpreter executes `main.py` (or `main.pyc`) as the entry point
6. Kivy initializes its event loop, window, and widget tree on the SDL2 surface

### Rendering

Kivy renders through SDL2 and OpenGL ES, drawing its own widget system. Android UI tools (Layout Inspector, `uiautomator`) see a single opaque `SurfaceView`. Kivy widgets (`Button`, `Label`, `TextInput`) are Python objects with no Android `View` counterpart.

## Identification

| Indicator | Location |
|-----------|----------|
| `libpython3.x.so` | `lib/<arch>/` -- embedded CPython runtime |
| `libSDL2.so` | `lib/<arch>/` -- SDL2 rendering library |
| `libSDL2_image.so`, `libSDL2_mixer.so` | `lib/<arch>/` -- SDL2 companion libraries |
| `assets/private.tar` or `assets/private.mp3` | Packed Python bytecode archive |
| `org.kivy.android.*` | DEX classes |
| `org.kivy.android.PythonActivity` | Main activity in manifest |
| `libmain.so` | p4a bootstrap native entry point |
| `_python_bundle` | Directory name inside the extracted archive |

Quick check:

```bash
unzip -l target.apk | grep -iE "(libpython|libSDL2|private\.(tar|mp3)|org\.kivy)"
```

!!! note "private.mp3 Disguise"
    Some p4a builds rename `private.tar` to `private.mp3` to bypass asset compression in older Android build tools. The file is still a tar archive regardless of extension.

## Code Extraction

### Extracting the Python Archive

The primary target is the `private.tar` (or `private.mp3`) archive containing all Python bytecode:

```bash
unzip target.apk assets/private.tar -d extracted/
cd extracted/assets/
tar xf private.tar
```

If the archive is named `private.mp3`:

```bash
unzip target.apk assets/private.mp3 -d extracted/
cd extracted/assets/
tar xf private.mp3
```

### Archive Contents

The extracted archive typically contains:

| Path | Contents |
|------|----------|
| `main.pyc` | Application entry point |
| `*.pyc` | Application Python modules (compiled bytecode) |
| `kivy/` | Kivy framework modules (`.pyc`) |
| `*.kv` | Kivy language files (declarative UI definitions, plaintext) |
| `certifi/` | CA certificate bundle (if requests library is included) |
| `*.so` | Native extension modules (e.g., compiled Cython modules) |

### Kivy Language Files (.kv)

Kivy uses a declarative UI language stored in `.kv` files. These are plaintext and directly readable:

```bash
find extracted/ -name "*.kv" -exec ls -la {} \;
```

`.kv` files define the widget tree, property bindings, and event handlers. They are analogous to QML in Qt or XAML in .NET -- reading them reveals the app's UI structure and data flow without any decompilation.

### On-Device Extraction

If the archive is difficult to extract statically, pull the unpacked Python files from the app's internal storage after first launch:

```bash
adb shell run-as com.target.package tar cf /data/local/tmp/pyfiles.tar /data/data/com.target.package/files/app/
adb pull /data/local/tmp/pyfiles.tar
```

## Python Bytecode Decompilation

### .pyc File Format

Python `.pyc` files start with a 4-byte magic number identifying the Python version, followed by 4 bytes of flags, 8 bytes of timestamp/hash, and the marshalled code object. The magic number is critical -- it determines which Python version the bytecode targets, and decompilers must match this version.

### Decompilation Tools

| Tool | Python Versions | Notes |
|------|----------------|-------|
| [uncompyle6](https://github.com/rocky/python-uncompyle6) | 2.x -- 3.8 | Most mature decompiler, excellent output quality for supported versions |
| [decompyle3](https://github.com/rocky/python-decompile3) | 3.7 -- 3.8 | Fork of uncompyle6 focused on Python 3 |
| [pycdc](https://github.com/zrax/pycdc) | 1.0 -- 3.12+ | C++ decompiler, broadest version support, less polished output |
| [pylingual](https://pylingual.io/) | 3.x (wide range) | Web-based and CLI decompiler using neural network-assisted reconstruction |
| [dis](https://docs.python.org/3/library/dis.html) | All | Built-in Python disassembler -- outputs raw bytecode, not source |

=== "uncompyle6"

    ```bash
    pip install uncompyle6
    uncompyle6 -o decompiled/ extracted/main.pyc
    uncompyle6 -o decompiled/ extracted/*.pyc
    ```

=== "pycdc"

    ```bash
    git clone https://github.com/zrax/pycdc.git
    cd pycdc && cmake . && make
    ./pycdc extracted/main.pyc > decompiled/main.py
    ```

=== "pylingual"

    ```bash
    pip install pylingual
    pylingual extracted/main.pyc -o decompiled/main.py
    ```

!!! warning "Version Mismatch"
    p4a bundles a specific CPython version (commonly 3.8--3.11). Check the `.pyc` magic number to determine the exact version before choosing a decompiler. Using the wrong decompiler version produces garbage output or fails entirely.

### Identifying Python Version from .pyc

```bash
xxd -l 4 extracted/main.pyc
```

Common magic numbers:

| Magic (hex) | Python Version |
|-------------|---------------|
| `420D0D0A` | 3.7 |
| `550D0D0A` | 3.8 |
| `610D0D0A` | 3.9 |
| `6F0D0D0A` | 3.10 |
| `A70D0D0A` | 3.11 |
| `CB0D0D0A` | 3.12 |

### Batch Decompilation

```bash
find extracted/ -name "*.pyc" -exec uncompyle6 -o decompiled/ {} +
```

For Python versions beyond 3.8, use pycdc instead:

```bash
find extracted/ -name "*.pyc" -exec sh -c './pycdc "$1" > "decompiled/$(basename "$1" .pyc).py"' _ {} \;
```

## Analysis Workflow

1. **Unzip APK** and confirm Kivy via `libpython*.so`, `libSDL2.so`, and `private.tar`
2. **Extract `private.tar`** to obtain `.pyc` and `.kv` files
3. **Read `.kv` files** for UI structure and event handler names
4. **Check Python version** from `.pyc` magic bytes
5. **Decompile `.pyc` files** with the appropriate tool (uncompyle6 for 3.7-3.8, pycdc for broader support)
6. **Review `main.py`** as the entry point -- trace imports and function calls
7. **Search decompiled source** for API endpoints, credentials, crypto keys, C2 URLs
8. **Hook at runtime** with Frida for dynamic analysis of encrypted/obfuscated values

## Hooking Strategy

### Python Object Hooks via libpython

Hook CPython internal functions to intercept Python-level operations:

```javascript
var libpython = Process.findModuleByName("libpython3.8.so") || Process.findModuleByName("libpython3.9.so") || Process.findModuleByName("libpython3.10.so") || Process.findModuleByName("libpython3.11.so");
if (libpython) {
    var pyEval = libpython.findExportByName("PyEval_EvalFrameDefault");
    if (pyEval) {
        console.log("[Python] PyEval_EvalFrameDefault @ " + pyEval);
    }

    var pyImport = libpython.findExportByName("PyImport_ImportModule");
    if (pyImport) {
        Interceptor.attach(pyImport, {
            onEnter: function(args) {
                console.log("[Python] import: " + Memory.readUtf8String(args[0]));
            },
            onLeave: function(retval) {}
        });
    }
}
```

### Network and Function Call Interception

Python networking (`urllib3`, `requests`, `http.client`) flows through `libpython`'s socket layer and ultimately `libssl`. Hook `SSL_write` and `SSL_read` in `libssl.so` to capture all encrypted traffic (see SSL Pinning Bypass section for `libssl` hook patterns).

For intercepting specific Python function calls, hook `PyObject_Call` and use `PyObject_Repr` to resolve the callable's name at runtime. Filter for targets like `request`, `encrypt`, or `send` to reduce noise.

## SSL Pinning Bypass

Kivy/Python apps handle SSL through Python's `ssl` module or the `certifi` CA bundle. Bypass approaches:

### OpenSSL Verification Bypass

```javascript
var libssl = Process.findModuleByName("libssl.so") || Process.findModuleByName("libssl1.1.so") || Process.findModuleByName("libssl3.so");
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

    var verifyResult = libssl.findExportByName("SSL_get_verify_result");
    if (verifyResult) {
        Interceptor.attach(verifyResult, {
            onLeave: function(retval) {
                retval.replace(ptr(0));
                console.log("[SSL] SSL_get_verify_result forced to X509_V_OK");
            }
        });
    }
}
```

### Patching the certifi Bundle

Python's `requests` library validates certificates against the `certifi` CA bundle. Append a custom CA certificate to the extracted `certifi/cacert.pem`, repackage `private.tar`, and rebuild the APK.

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Python bytecode (`.pyc`) + plaintext `.kv` UI files |
| Readability | High -- decompiled Python is near-original source quality |
| String extraction | Trivial -- strings preserved in bytecode constant pools |
| Control flow recovery | Full -- Python decompilers recover structured code |
| Patching | Edit decompiled `.py`, recompile to `.pyc`, repackage |
| Obfuscation ceiling | Low -- Python bytecode is fundamentally transparent |
| Overall difficulty | **Easy** (rank 14/28) |

Kivy apps are among the easiest Android targets to reverse engineer. The Python bytecode decompiles to near-original source code, `.kv` files provide the UI structure in plaintext, and the framework offers no meaningful obfuscation layer. The only complications are Python version mismatches with decompiler tools and the occasional use of Cython-compiled extension modules (`.so` files within the bundle), which require native analysis.

## References

- [Kivy Framework](https://kivy.org/)
- [python-for-android (p4a)](https://github.com/kivy/python-for-android)
- [uncompyle6](https://github.com/rocky/python-uncompyle6)
- [decompyle3](https://github.com/rocky/python-decompile3)
- [pycdc -- C++ Python Decompiler](https://github.com/zrax/pycdc)
- [pylingual](https://pylingual.io/)
- [Frida -- Dynamic Instrumentation](https://frida.re/)
- [Kivy Language (.kv) Documentation](https://kivy.org/doc/stable/guide/lang.html)
- [CPython .pyc Format](https://docs.python.org/3/library/py_compile.html)
