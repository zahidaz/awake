# Virbox Protector


Virbox Protector is a commercial application shielding solution developed by **SenseShield Technology**, a Chinese software protection company. While designed for legitimate developers to protect their applications from reverse engineering, Virbox has been observed in sophisticated Android malware campaigns.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | SenseShield Technology |
| Origin | China |
| Type | Commercial Packer/Protector |
| Platforms | Android, Windows, Linux, macOS, ARM-Linux |
| Min Android | Android 4.0+ (API 14) |
| Architectures | ARM V7/V8, x86, x64 |
| Website | [appsec.virbox.com](https://appsec.virbox.com/) |


## Identification

### File Artifacts

| Artifact | Description |
|----------|-------------|
| Stub Package | Hex-based package name |
| Stub Class | Stub app class Extending Application |
| Native Library | `libvirbox_*.so` in assets or lib folder |
| Tag String | `"virbox"` string reference |

### Native Library Naming Convention

```
libvirbox_a32.so   // ARM 32-bit
libvirbox_a64.so   // ARM 64-bit
libvirbox_x86.so   // x86
libvirbox_x64.so   // x86_64
libvirbox_mips.so  // MIPS
libvirbox_m64.so   // MIPS64
```

### Native Method Signatures

Obfuscated JNI methods follow this pattern:

```java
native void I6f7de22b_00(Context context);
native void I6f7de22b_01(Context context, Application app, String className);
native void I6f7de22b_02(Activity activity, Bundle bundle);
native void I6f7de22b_03(Activity activity);
native void I6f7de22b_04(Activity activity);
native void I6f7de22b_05(Network network, NetworkCapabilities caps);
native boolean I6f7de22b_06();
```

## Protection Mechanisms

### DEX Protection

#### DEX Encryption

Encrypts the entire classes.dex file. Decryption occurs at runtime via native code. Not recommended for Google Play apps as it may fail store checks.

#### DEX Virtualization

Converts Dalvik bytecode into proprietary VM instructions:

1. Original method bytecode is extracted
2. Bytecode is transformed into custom instruction set
3. Custom VM interpreter executes in native layer
4. Original method becomes a stub calling native VM

This defeats static analysis as the bytecode no longer exists in standard Dalvik format.

#### String Encryption

Sensitive strings are encrypted and decrypted at runtime via SDK labels.

### Native Library Protection

- **Code Section Encryption**: Encrypts .text section of .so files
- **Symbol Table Stripping**: Removes function names and exports
- **Import/Export Hiding**: Obscures dynamic linking information
- **Function Virtualization**: Critical functions converted to VM code

### Runtime Protection (RASP)

#### Anti-Debugging

Detects debuggers using multiple techniques:

- Checks for TracerPid in `/proc/self/status`
- Detects ptrace attachment
- Monitors for IDA Pro, gdb, jeb, lldb
- App exits immediately upon detection

#### Anti-Injection

- Dual-session ptrace to block external attachment
- Detects .so injection attempts
- Monitors for Frida, Xposed hooks

#### Emulator Detection

Identifies emulator environments via:

- Build properties (ro.product.model, ro.hardware)
- File system artifacts
- Hardware characteristics
- App terminates if emulator detected

#### Root Detection

Checks for:

- su binary presence
- Root management apps
- Modified system partitions

#### Multi-Parallel Detection

Prevents app cloning and multi-account environments.

#### Signature Verification

Validates APK signature against expected developer certificate to prevent repackaging.

#### File Integrity Check

Hash verification of APK contents to detect tampering.

## VM Architecture

Virbox's DEX virtualization replaces Dalvik bytecode with a proprietary instruction set executed by an embedded native interpreter. This is not obfuscation or encryption -- the original bytecode is destroyed and replaced with an entirely different representation that only the Virbox VM can execute.

### Custom Instruction Set

The Virbox VM uses a proprietary opcode table that has no relationship to the Dalvik instruction set. Each Virbox opcode maps to one or more Dalvik operations, but the encoding, operand layout, and instruction widths are all different. The opcode table is randomized per build, so two APKs protected by Virbox will have different opcode assignments even if they contain identical source code. This per-build randomization defeats pattern-based analysis -- you cannot build a universal Virbox disassembler from a single sample.

Key properties of the instruction set:

- Variable-width instructions (not aligned to Dalvik's 16-bit unit boundaries)
- Opcodes are assigned from a shuffled table generated at protection time
- Operand encoding differs from Dalvik's register/immediate format
- String, type, and method references use an indirection table rather than direct DEX pool indices

### Dispatch Loop Structure

The VM interpreter in `libvirbox_*.so` uses a **threaded dispatch** model rather than a simple switch-case loop. In a switch dispatch interpreter, a central loop reads an opcode, branches through a switch statement, executes the handler, and loops back. Threaded dispatch eliminates the central loop: each opcode handler ends with a direct jump to the next handler, computed from the next opcode in the bytecode stream.

```c
void vm_entry(VMContext *ctx) {
    ctx->pc = ctx->bytecode_start;
    ctx->handler_table[*ctx->pc](ctx);
}

void op_handler_0x3A(VMContext *ctx) {
    uint16_t reg_dst = ctx->pc[1];
    uint16_t reg_src = ctx->pc[2];
    ctx->registers[reg_dst] = ctx->registers[reg_src] + 1;
    ctx->pc += 3;
    ctx->handler_table[*ctx->pc](ctx);
}
```

This structure makes static analysis harder because IDA and Ghidra cannot resolve the indirect jump targets without knowing the handler table layout. The control flow graph of the interpreter appears as a set of disconnected basic blocks rather than a recognizable loop.

### VM Boundary Crossings

Not every method in a protected APK is virtualized. Virbox allows developers to select which classes and methods to virtualize. This creates a boundary between virtualized code (executing inside the Virbox VM) and non-virtualized code (running as normal Dalvik bytecode in ART).

**Virtualized calling non-virtualized**: When VM code needs to invoke a standard Java method, the VM interpreter uses JNI to call back into the Dalvik/ART runtime. The VM marshals arguments from its internal register file into JNI call parameters, invokes `CallObjectMethod`/`CallVoidMethod`/etc., and stores the return value back into VM registers.

**Non-virtualized calling virtualized**: The original Java method is replaced with a native stub. When ART dispatches the method call, it hits the JNI stub, which enters the VM interpreter with the method's virtualized bytecode. Arguments are transferred from ART's register frame into the VM's register file.

These boundary crossings are observable through JNI hooking and represent one of the few points where you can intercept data flowing through virtualized code.

### Register Mapping

The Virbox VM maintains its own register file, separate from ART's virtual registers. The VM register count is not constrained by Dalvik's 16-register addressing limit for most instructions. During boundary crossings, a marshaling layer maps between ART registers (v0, v1, ...) and VM registers (r0, r1, ...). The mapping is not one-to-one -- the VM may use more registers than the original Dalvik method due to instruction set differences.

### Why Static Analysis Tools Fail

IDA Pro and Ghidra can disassemble the `libvirbox_*.so` binary and identify the VM interpreter functions. However, they cannot make sense of the virtualized bytecode because:

1. The bytecode is data, not native code -- disassemblers will not attempt to decode it
2. The opcode-to-handler mapping is only resolvable at runtime (stored in a table initialized during VM startup)
3. The per-build opcode randomization means no fixed processor module can decode all samples
4. Building a custom IDA processor module requires extracting the opcode table from each individual sample

A custom Ghidra or IDA processor module is theoretically possible per-sample, but extracting the opcode table requires either dynamic analysis of the interpreter initialization or significant manual reverse engineering of the table construction code in `libvirbox_*.so`.

## Technical Analysis

### Stub Application Structure

```java
package v6f7de22b;

class app extends Application {

    static String TAG = "virbox";
    static Context appContext;

    String nativeLibPath;
    String realAppClassName;
    String newResDir;
    boolean initialized = false;
    Application realApplication;
    Object savedProviders;

    native void I6f7de22b_00(Context context);
    native void I6f7de22b_01(Context context, Application app, String className);
    native void I6f7de22b_02(Activity activity, Bundle bundle);
    native void I6f7de22b_03(Activity activity);
    native void I6f7de22b_04(Activity activity);
    native void I6f7de22b_05(Network network, NetworkCapabilities caps);
    native boolean I6f7de22b_06();
}
```

### Architecture Detection

```java
String getLibrarySuffix(String abi, boolean is64bit) {
    if (!is64bit) {
        if (abi.contains("armeabi")) return "_a32.so";
        if (abi.contains("arm64"))   return "_a64.so";
        if (abi.contains("x86_64"))  return "_x64.so";
        if (abi.contains("x86"))     return "_x86.so";
        if (abi.contains("mips64"))  return "_m64.so";
        if (abi.contains("mips"))    return "_mips.so";
    } else {
        if (abi.contains("armeabi")) return "_x86.so";
        if (abi.contains("arm64") || abi.contains("x86_64")) return "_x64.so";
        if (abi.contains("x86"))     return "_x86.so";
        if (abi.contains("mips64"))  return "_m64.so";
        if (abi.contains("mips"))    return "_mips.so";
    }
    return "";
}
```

### Native Library Extraction

```java
boolean extractAsset(Context ctx, String assetName, String destDir, String destName) {
    String destPath = destDir + "/" + destName;
    File dir = new File(destDir);
    if (!dir.exists()) dir.mkdirs();

    File destFile = new File(destPath);
    InputStream assetStream = ctx.getAssets().open(assetName);

    if (destFile.exists() && filesAreEqual(assetStream, new FileInputStream(destFile))) {
        assetStream.close();
        return true;
    }

    destFile.delete();
    assetStream.close();

    assetStream = ctx.getAssets().open(assetName);
    FileOutputStream fos = new FileOutputStream(destPath);

    byte[] buffer = new byte[1024];
    int bytesRead;
    while ((bytesRead = assetStream.read(buffer)) != -1) {
        fos.write(buffer, 0, bytesRead);
    }

    assetStream.close();
    fos.close();

    destFile.setReadable(true, false);
    destFile.setExecutable(true, false);
    destFile.setWritable(false, false);

    return true;
}
```

### Initialization (attachBaseContext)

```java
void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    appContext = base;

    String abi = Build.CPU_ABI;
    String libSuffix = getLibrarySuffix(abi, false);
    String libName = "libvirbox" + libSuffix;

    String nativeDir = getApplicationInfo().nativeLibraryDir;
    String dataDir = getFilesDir().getAbsolutePath();

    if (assetExists(base, libName)) {
        extractAsset(base, libName, dataDir, libName);
        this.nativeLibPath = dataDir + "/" + libName;
    } else {
        this.nativeLibPath = nativeDir + "/" + libName;
    }

    System.load(this.nativeLibPath);

    I6f7de22b_00(base);

    saveProviders();

    this.realAppClassName = getRealApplicationClassName();

    if (this.realAppClassName != null) {
        Class realAppClass = Class.forName(this.realAppClassName);
        this.realApplication = (Application) realAppClass.newInstance();

        Method attachMethod = Application.class.getDeclaredMethod("attach", Context.class);
        attachMethod.setAccessible(true);
        attachMethod.invoke(this.realApplication, base);
    }

    I6f7de22b_01(base, this.realApplication, this.realAppClassName);

    registerActivityLifecycleCallbacks(new ActivityLifecycleHandler());

    ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
    cm.registerDefaultNetworkCallback(new NetworkHandler());
}
```

### ContentProvider Manipulation

Virbox delays ContentProvider initialization to ensure proper unpacking order:

```java
void saveProviders() {
    Class activityThreadClass = Class.forName("android.app.ActivityThread");
    Method currentMethod = activityThreadClass.getMethod("currentActivityThread");
    Object activityThread = currentMethod.invoke(null);

    Object boundApp = getField(activityThread, "mBoundApplication").get(activityThread);
    Field providersField = getField(boundApp, "providers");

    this.savedProviders = providersField.get(boundApp);
    providersField.set(boundApp, null);
}

void restoreProviders() {
    Class activityThreadClass = Class.forName("android.app.ActivityThread");
    Method currentMethod = activityThreadClass.getMethod("currentActivityThread");
    Object activityThread = currentMethod.invoke(null);

    Object boundApp = getField(activityThread, "mBoundApplication").get(activityThread);
    getField(boundApp, "providers").set(boundApp, this.savedProviders);

    if (this.savedProviders != null) {
        Method installProviders = activityThreadClass.getDeclaredMethod(
            "installContentProviders", Context.class, List.class);
        installProviders.setAccessible(true);
        installProviders.invoke(activityThread, this.realApplication, this.savedProviders);
        this.savedProviders = null;
    }
}
```

### Application Replacement

Replaces stub Application with real Application in Android internals:

```java
void replaceApplication() {
    Class activityThreadClass = Class.forName("android.app.ActivityThread");
    Method currentMethod = activityThreadClass.getMethod("currentActivityThread");
    Object activityThread = currentMethod.invoke(null);

    Field initialAppField = activityThreadClass.getDeclaredField("mInitialApplication");
    initialAppField.setAccessible(true);
    if (initialAppField.get(activityThread) == this) {
        initialAppField.set(activityThread, this.realApplication);
    }

    Field allAppsField = activityThreadClass.getDeclaredField("mAllApplications");
    allAppsField.setAccessible(true);
    List allApps = (List) allAppsField.get(activityThread);
    for (int i = 0; i < allApps.size(); i++) {
        if (allApps.get(i) == this) {
            allApps.set(i, this.realApplication);
        }
    }

    Class loadedApkClass;
    try {
        loadedApkClass = Class.forName("android.app.LoadedApk");
    } catch (ClassNotFoundException e) {
        loadedApkClass = Class.forName("android.app.ActivityThread$PackageInfo");
    }

    Field appField = loadedApkClass.getDeclaredField("mApplication");
    appField.setAccessible(true);

    Field resDirField = loadedApkClass.getDeclaredField("mResDir");
    resDirField.setAccessible(true);

    Field loadedApkField = null;
    try {
        loadedApkField = Application.class.getDeclaredField("mLoadedApk");
    } catch (NoSuchFieldException e) {}

    String[] packageFields = {"mPackages", "mResourcePackages"};

    for (String fieldName : packageFields) {
        Field packagesField = activityThreadClass.getDeclaredField(fieldName);
        packagesField.setAccessible(true);
        Map packages = (Map) packagesField.get(activityThread);

        for (Object entry : packages.entrySet()) {
            Object weakRef = ((Map.Entry) entry).getValue();
            Object loadedApk = ((WeakReference) weakRef).get();

            if (loadedApk != null && appField.get(loadedApk) == this) {
                appField.set(loadedApk, this.realApplication);

                if (this.newResDir != null) {
                    resDirField.set(loadedApk, this.newResDir);
                }

                if (loadedApkField != null) {
                    loadedApkField.set(this.realApplication, loadedApk);
                }
            }
        }
    }
}
```

### Resource Replacement

```java
void replaceResources() {
    if (this.newResDir == null) return;

    AssetManager newAssets = AssetManager.class.getConstructor().newInstance();
    Method addPath = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
    addPath.setAccessible(true);

    int result = (Integer) addPath.invoke(newAssets, this.newResDir);
    if (result == 0) {
        throw new IllegalStateException("Could not create new AssetManager");
    }

    if (Build.VERSION.SDK_INT <= 19) {
        Method ensureBlocks = AssetManager.class.getDeclaredMethod("ensureStringBlocks");
        ensureBlocks.setAccessible(true);
        ensureBlocks.invoke(newAssets);
    }

    Class resourcesManagerClass = Class.forName("android.app.ResourcesManager");
    Method getInstance = resourcesManagerClass.getDeclaredMethod("getInstance");
    Object resourcesManager = getInstance.invoke(null);

    Collection resourcesList;
    try {
        Field activeField = resourcesManagerClass.getDeclaredField("mActiveResources");
        activeField.setAccessible(true);
        resourcesList = ((ArrayMap) activeField.get(resourcesManager)).values();
    } catch (NoSuchFieldException e) {
        Field refsField = resourcesManagerClass.getDeclaredField("mResourceReferences");
        refsField.setAccessible(true);
        resourcesList = (Collection) refsField.get(resourcesManager);
    }

    for (Object ref : resourcesList) {
        Resources res = (Resources) ((WeakReference) ref).get();

        try {
            Field assetsField = Resources.class.getDeclaredField("mAssets");
            assetsField.setAccessible(true);
            assetsField.set(res, newAssets);
        } catch (NoSuchFieldException e) {
            Field implField = Resources.class.getDeclaredField("mResourcesImpl");
            implField.setAccessible(true);
            Object impl = implField.get(res);

            Field implAssetsField = impl.getClass().getDeclaredField("mAssets");
            implAssetsField.setAccessible(true);
            implAssetsField.set(impl, newAssets);
        }

        res.updateConfiguration(res.getConfiguration(), res.getDisplayMetrics());
    }
}
```

### onCreate Execution

```java
void onCreate() {
    if (this.realApplication != null) {
        replaceApplication();
        replaceResources();
        restoreProviders();
    }

    super.onCreate();

    if (this.realApplication != null) {
        this.realApplication.onCreate();
    }
}
```

### Activity Lifecycle Monitoring

```java
class ActivityLifecycleHandler implements ActivityLifecycleCallbacks {
    Handler handler = new Handler();
    Runnable hijackDetector;

    void cancelHijackCheck() {
        if (hijackDetector != null) {
            handler.removeCallbacks(hijackDetector);
            hijackDetector = null;
        }
    }

    void scheduleHijackCheck(Activity activity) {
        if (activity == null || activity.isFinishing() || activity.isDestroyed()) {
            return;
        }

        hijackDetector = new Runnable() {
            WeakReference<Activity> activityRef = new WeakReference<>(activity);

            void run() {
                Activity act = activityRef.get();
                if (act != null && !act.isFinishing() && !act.isDestroyed()) {
                    String msg = isChineseLocale()
                        ? "应用已被切换至后台"
                        : "App has been switched to background";
                    Toast.makeText(act, msg, Toast.LENGTH_SHORT).show();
                }
            }
        };

        handler.postDelayed(hijackDetector, 1000);
    }

    void onActivityCreated(Activity activity, Bundle state) {
        I6f7de22b_02(activity, state);
    }

    void onActivityStarted(Activity activity) {
        I6f7de22b_03(activity);
    }

    void onActivityResumed(Activity activity) {
        cancelHijackCheck();
    }

    void onActivityPaused(Activity activity) {
        if (I6f7de22b_06()) {
            scheduleHijackCheck(activity);
        }
        I6f7de22b_04(activity);
    }
}
```

### Network Monitoring

```java
class NetworkHandler extends ConnectivityManager.NetworkCallback {
    void onCapabilitiesChanged(Network network, NetworkCapabilities caps) {
        I6f7de22b_05(network, caps);
    }
}
```

### Reflection Helper

```java
Field getField(Object obj, String fieldName) {
    Class cls = obj.getClass();
    while (cls != null) {
        try {
            Field field = cls.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            cls = cls.getSuperclass();
        }
    }
    throw new IllegalStateException(fieldName);
}
```

## Reflection Targets Summary

### ActivityThread

| Field | Purpose |
|-------|---------|
| `mInitialApplication` | Primary Application reference |
| `mAllApplications` | List of all Application instances |
| `mBoundApplication` | AppBindData containing providers |
| `mPackages` | Package name to LoadedApk map |
| `mResourcePackages` | Resource package map |

### LoadedApk

| Field | Purpose |
|-------|---------|
| `mApplication` | Application instance reference |
| `mResDir` | Resource directory path |

### ResourcesManager

| Field | Purpose |
|-------|---------|
| `mActiveResources` | Active Resources map (older Android) |
| `mResourceReferences` | Resource references (newer Android) |

### AppBindData

| Field | Purpose |
|-------|---------|
| `providers` | List of ContentProvider info |


## Unpacking Methodology

Virbox is the hardest commercial Android packer to unpack. Standard DEX dumping techniques that work against Tencent Legu, Bangcle, or even DexProtector are ineffective here because the core protection is not encryption -- it is virtualization. The original Dalvik bytecode for protected methods does not exist in memory at any point during execution. There is no "dump window" for virtualized methods because those methods never return to Dalvik bytecode form. They execute as native VM code inside the interpreter.

This fundamentally changes the analyst's approach. Instead of trying to recover the original code, the goal shifts to extracting behavioral information through dynamic observation.

### frida-dexdump Limitations

Tools like [frida-dexdump](https://github.com/hluwa/frida-dexdump) scan process memory for DEX magic bytes (`dex\n035\0` or `dex\n039\0`) and dump any DEX structures they find. Against Virbox, this will recover:

- The stub DEX containing the Virbox loader classes
- Any non-virtualized DEX code (if the developer only virtualized selected methods)
- The encrypted original DEX in some configurations (which cannot be used without the decryption key)

It will **not** recover the virtualized methods. Those methods exist only as proprietary bytecode interpreted by the native VM. frida-dexdump has no way to recognize or extract this data because it is not in DEX format.

### VM Interpreter Analysis

The most technically demanding approach targets the VM interpreter itself. The goal is to hook the dispatch loop and log opcode execution to reconstruct what the virtualized code does.

```javascript
var libvirbox = Process.findModuleByName("libvirbox_a64.so");

var exports = libvirbox.enumerateExports();
var symbols = libvirbox.enumerateSymbols();

var vmDispatch = null;
exports.forEach(function(exp) {
    if (exp.name.indexOf("vm_dispatch") !== -1 ||
        exp.name.indexOf("interpreter") !== -1) {
        vmDispatch = exp.address;
    }
});

if (vmDispatch) {
    Interceptor.attach(vmDispatch, {
        onEnter: function(args) {
            console.log("[VM] dispatch called from " +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n"));
        }
    });
}
```

Since exports are typically stripped, a more practical approach is scanning for the dispatch loop pattern in the `.text` section:

```javascript
var libvirbox = Process.findModuleByName("libvirbox_a64.so");
var baseAddr = libvirbox.base;
var size = libvirbox.size;

Memory.scan(baseAddr, size, "?? ?? ?? ?? 1F 20 03 D5 ?? ?? ?? 94", {
    onMatch: function(address, size) {
        console.log("[SCAN] potential dispatch at: " + address);
    },
    onComplete: function() {
        console.log("[SCAN] complete");
    }
});
```

This approach requires significant per-sample effort and is rarely worth pursuing unless the objective is understanding the VM itself rather than the protected application.

### Bypassing RASP

Before any dynamic analysis can begin, the RASP checks must be neutralized. Virbox's RASP will terminate the process via `System.exit()` or `Runtime.exit()` when it detects debugging, rooting, emulation, or injection. The most reliable approach is to block all exit paths early in spawn mode.

#### Blocking Process Termination

```javascript
Java.perform(function() {
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(code) {
        console.log("[RASP] System.exit(" + code + ") blocked");
        console.log(Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exit.implementation = function(code) {
        console.log("[RASP] Runtime.exit(" + code + ") blocked");
        console.log(Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
    };

    var Process = Java.use("android.os.Process");
    Process.killProcess.implementation = function(pid) {
        console.log("[RASP] killProcess(" + pid + ") blocked");
    };
});
```

#### Defeating Anti-Frida Detection

Virbox scans `/proc/self/maps` for Frida artifacts and checks for the Frida server port. Use [reFrida](https://github.com/zahidaz/refrida) to avoid common detection signatures, or manually patch the detection:

```javascript
var openPtr = Module.findExportByName(null, "open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc/") !== -1 &&
            this.path.indexOf("/maps") !== -1) {
            this.isMaps = true;
            this.fd = retval.toInt32();
        }
    }
});

var readPtr = Module.findExportByName(null, "read");
Interceptor.attach(readPtr, {
    onLeave: function(retval) {
        if (this.isMaps) {
            var buf = this.context.x1;
            var content = buf.readUtf8String(retval.toInt32());
            if (content.indexOf("frida") !== -1 || content.indexOf("gadget") !== -1) {
                var cleaned = content.replace(/.*frida.*/gi, "")
                                     .replace(/.*gadget.*/gi, "");
                buf.writeUtf8String(cleaned);
            }
        }
    }
});
```

#### TracerPid Bypass

```javascript
var fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc/") !== -1 &&
            this.path.indexOf("/status") !== -1) {
            this.statusFile = retval;
        }
    }
});

var fgets = Module.findExportByName(null, "fgets");
Interceptor.attach(fgets, {
    onLeave: function(retval) {
        if (retval && !retval.isNull()) {
            var line = retval.readUtf8String();
            if (line && line.indexOf("TracerPid") !== -1) {
                retval.writeUtf8String("TracerPid:\t0\n");
            }
        }
    }
});
```

### Hooking Native Library Loading

Intercepting `System.loadLibrary` and `System.load` reveals the order in which Virbox loads its components and helps identify the right moment to attach further hooks:

```javascript
Java.perform(function() {
    var System = Java.use("java.lang.System");

    System.loadLibrary.implementation = function(name) {
        console.log("[LIB] System.loadLibrary: " + name);
        this.loadLibrary(name);
        if (name.indexOf("virbox") !== -1) {
            console.log("[LIB] Virbox native library loaded, attaching hooks...");
            hookVirboxInternals();
        }
    };

    System.load.implementation = function(path) {
        console.log("[LIB] System.load: " + path);
        this.load(path);
        if (path.indexOf("virbox") !== -1) {
            console.log("[LIB] Virbox native library loaded from: " + path);
            hookVirboxInternals();
        }
    };
});

function hookVirboxInternals() {
    var mod = Process.findModuleByName("libvirbox_a64.so");
    if (!mod) mod = Process.findModuleByName("libvirbox_a32.so");
    if (!mod) return;

    console.log("[LIB] Module base: " + mod.base + " size: " + mod.size);

    mod.enumerateExports().forEach(function(exp) {
        console.log("[EXPORT] " + exp.name + " @ " + exp.address);
    });
}
```

### Memory Analysis

For the DEX encryption mode (as opposed to virtualization), there is a window during which decrypted DEX data exists in memory. Scanning `/proc/self/maps` for anonymous memory regions with the right characteristics can locate decrypted content:

```javascript
function scanForDex() {
    var maps = File.readAllText("/proc/self/maps");
    var lines = maps.split("\n");

    lines.forEach(function(line) {
        if (line.indexOf("rw") !== -1 && line.indexOf("/") === -1) {
            var parts = line.split("-");
            var start = ptr("0x" + parts[0]);
            try {
                var magic = start.readByteArray(4);
                var header = new Uint8Array(magic);
                if (header[0] === 0x64 && header[1] === 0x65 &&
                    header[2] === 0x78 && header[3] === 0x0a) {
                    var fileSize = start.add(32).readU32();
                    console.log("[DEX] Found at " + start + " size: " + fileSize);
                    var dexData = start.readByteArray(fileSize);
                    var f = new File("/data/local/tmp/dumped_" +
                        start.toString().slice(2) + ".dex", "wb");
                    f.write(dexData);
                    f.close();
                    console.log("[DEX] Dumped to /data/local/tmp/");
                }
            } catch(e) {}
        }
    });
}

Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.onResume.implementation = function() {
        this.onResume();
        scanForDex();
    };
});
```

This works for DEX encryption but not for DEX virtualization. For virtualized methods, the bytecode never appears in DEX form in memory.

### Intercepting Network Calls from Virtualized Code

Even when code is virtualized, its network communications pass through standard Android APIs. Hooking at the network layer captures C2 URLs, exfiltrated data, and command protocols regardless of code protection:

```javascript
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function(url) {
        console.log("[NET] URL: " + url);
        this.$init(url);
    };

    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.setRequestProperty.implementation = function(key, value) {
        console.log("[NET] Header: " + key + ": " + value);
        this.setRequestProperty(key, value);
    };

    var OkHttpClient;
    try {
        OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function() {
            var request = this.request();
            console.log("[OKHTTP] " + request.method() + " " + request.url());
            return this.execute();
        };
    } catch(e) {}

    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
            console.log("[WEBVIEW] loadUrl: " + url);
            this.loadUrl(url);
        };
    } catch(e) {}
});
```

### Partial Analysis Strategy

When full unpacking is infeasible (which is the common case for Virbox-virtualized samples), shift to behavioral analysis:

- **Network traffic**: Use mitmproxy or Burp Suite with SSL pinning bypass to capture all HTTP/HTTPS traffic. C2 URLs, exfiltration endpoints, and command structures are all visible regardless of code protection.
- **File system activity**: Monitor file creation, reads, and writes using `inotifywait` or Frida hooks on `open()`, `write()`, `unlink()`. Credential storage, configuration files, and staging directories become visible.
- **IPC observation**: Hook `startActivity`, `startService`, `sendBroadcast`, and `ContentResolver` operations to map the application's interaction with other components and apps.
- **Accessibility service abuse**: If the malware registers an AccessibilityService, hook `onAccessibilityEvent` to log every UI interaction the malware performs.
- **SharedPreferences**: Hook `SharedPreferences.Editor` methods to capture configuration values the malware stores locally.

This behavioral approach often yields sufficient intelligence for threat reporting without ever recovering the original bytecode.

## Malware Usage

### Klopatra Banking Trojan (2025)

Virbox was discovered protecting the [Klopatra](../malware/families/klopatra.md) Android banking trojan targeting Turkish financial institutions.

- Described as "rarely seen in the Android threat landscape"
- Combined with native libraries for maximum evasion
- Analysis only succeeded via unprotected development build
- Protection "drastically increases time and expertise required"

### Gigabud + SpyNote Infrastructure (2024)

[Zimperium zLabs revealed](https://zimperium.com/blog/a-network-of-harm-gigabud-threat-and-its-associates) that both Gigabud (a banking credential stealer) and [SpyNote](../malware/families/spynote.md) were protected by Virbox across shared distribution infrastructure. The investigation identified 79 phishing sites and 11 C2 servers distributing both families, targeting 50+ financial apps. This represents the first documented case of Virbox protecting multiple distinct malware families operating through coordinated infrastructure.

### GoldFactory Group

GoldFactory is the Chinese-speaking threat group that standardized on Virbox across its entire malware portfolio. The group operates [GoldDigger](../malware/families/goldpickaxe.md), [GoldPickaxe](../malware/families/goldpickaxe.md), GoldDiggerPlus, and [Gigabud](../malware/families/gigabud.md) -- all Android banking trojans that use Virbox as their primary protection layer.

#### Why Virbox

GoldFactory's selection of Virbox is not arbitrary. Several factors make it the natural choice for a Chinese-speaking cybercrime operation focused on financial fraud:

- **Chinese origin**: SenseShield Technology operates primarily in Chinese, with documentation, support, and licensing infrastructure accessible to Chinese-speaking buyers. Procurement is straightforward compared to Western protectors like DexGuard or Arxan.
- **VM-level protection**: Financial fraud malware has a short operational window. Virbox's DEX virtualization buys time against incident responders and malware analysts -- even partial analysis requires days of effort per sample.
- **RASP suite**: The built-in anti-debugging, anti-rooting, and anti-emulation checks provide defense-in-depth without requiring the malware authors to implement their own.
- **Legitimate cover**: Because Virbox is a legitimate commercial product used by many non-malicious apps, its presence alone does not flag the APK as malicious in automated scanning pipelines.

#### GoldPickaxe and Biometric Theft

[GoldPickaxe](../malware/families/goldpickaxe.md) is the most technically notable member of the GoldFactory family. It steals facial biometric data from victims by tricking them into recording face videos, then uses AI-generated deepfakes to bypass bank face-verification systems. The Android variant wraps this entire workflow in Virbox virtualization, meaning the facial capture logic, deepfake preparation, and exfiltration code are all protected by the VM. This makes it exceptionally difficult to analyze the biometric theft mechanism through static analysis.

The iOS variant of GoldPickaxe cannot use Virbox (which does not support iOS app protection in the same way), so cross-platform comparison between the Android and iOS variants has been one route for analysts to infer what the Android variant's virtualized code does.

#### Gigabud and Infrastructure Overlap

[Zimperium's September 2024 investigation](https://zimperium.com/blog/a-network-of-harm-gigabud-threat-and-its-associates) revealed that [Gigabud](../malware/families/gigabud.md) and [SpyNote](../malware/families/spynote.md) shared distribution infrastructure (79 phishing sites, 11 C2 servers), with both families protected by Virbox. [Cyble's August 2024 analysis](https://cyble.com/blog/unmasking-the-overlap-between-golddigger-and-gigabud-android-malware/) confirmed code-level overlap between Gigabud and GoldDigger, with both using `libstrategy.so` for UI interaction alongside Virbox packing. This makes GoldFactory the first documented threat group to deploy Virbox consistently across multiple distinct malware families operating through coordinated infrastructure.

#### Attribution Indicators

| Indicator | Details |
|-----------|---------|
| Language | Chinese-language strings in development artifacts, Chinese-language C2 panels |
| Targeting | Southeast Asia (Thailand, Vietnam, Philippines), expanding to Latin America and South Africa |
| Operational model | Highly localized lures impersonating government services and banking apps |
| Technical signature | Consistent use of Virbox across all family members, shared `libstrategy.so` library |
| Timeline | GoldDigger (2023), GoldDiggerPlus (2023-2024), GoldPickaxe (2024), Gigabud (active since 2022, linked 2024) |

## Analyst Workflow

### Step-by-Step Procedure

**Step 1: Triage and Identification**

Confirm Virbox protection by checking for the artifacts listed in the Identification section. Run APKiD if available. Look for `libvirbox_*.so` in the lib or assets directory, hex-based package names, and the `"virbox"` string tag.

**Step 2: Determine Virtualization Scope**

Not all methods in a Virbox-protected APK are virtualized. Developers choose which classes and methods to protect. Decompile the APK with jadx and examine the output:

- Methods that decompile normally contain standard Dalvik bytecode and are not virtualized
- Methods that show only a `native` declaration with a hex-prefixed name (e.g., `I6f7de22b_02`) are virtualized
- If jadx recovers substantial application logic, the sample is only partially virtualized, and static analysis remains viable for the non-virtualized portions

**Step 3: Static Analysis of Non-Virtualized Code**

Extract everything possible from the readable portions:

- AndroidManifest.xml: permissions, components, intent filters
- Non-virtualized Activities and Services: application flow, UI logic
- Resource files: strings.xml (may contain URLs, configuration), layouts
- Receiver registrations: broadcast-based triggers

**Step 4: Set Up Dynamic Analysis Environment**

Prepare a rooted device or emulator with RASP bypass scripts loaded. Use spawn mode with Frida to inject the RASP bypass before Virbox's checks execute:

```bash
frida -U -f com.target.package -l rasp_bypass.js --no-pause
```

Use [reFrida](https://github.com/zahidaz/refrida) to reduce Frida's detection footprint. Load the `System.exit` and `Runtime.exit` blockers first, then layer additional hooks.

**Step 5: Network Traffic Capture**

Set up mitmproxy or Burp Suite as the device proxy. Use [objection](https://github.com/sensepost/objection) or a Frida script for SSL pinning bypass:

```bash
objection -g com.target.package explore -s "android sslpinning disable"
```

Run the application through its full workflow. Capture all HTTP/HTTPS requests. C2 endpoints, exfiltration URLs, and command protocols are visible in cleartext after SSL bypass regardless of Virbox protection.

**Step 6: Behavioral Hooking**

Deploy Frida hooks for the behavioral observation points described in the Partial Analysis Strategy section. Focus on:

- Network calls (URL construction, HTTP requests)
- File system operations (credential storage, configuration drops)
- IPC (inter-component communication, broadcasts)
- Accessibility events (if the malware uses AccessibilityService)
- SMS operations (interception, exfiltration)

**Step 7: Report and Indicator Extraction**

Compile findings into actionable intelligence:

- Network IOCs: C2 domains, IP addresses, URL patterns
- File system IOCs: dropped file names, paths, hashes
- Behavioral IOCs: permission abuse patterns, accessibility actions
- Infrastructure mapping: shared hosting, certificate reuse, domain registration patterns

### Decision Tree

```
Is libvirbox_*.so present?
├── No → Not Virbox-protected, use standard analysis
└── Yes → Virbox confirmed
    │
    Does jadx decompile application methods?
    ├── Most methods readable → Partially virtualized
    │   ├── Analyze non-virtualized code statically
    │   ├── Focus dynamic analysis on virtualized methods
    │   └── Cross-reference static and dynamic findings
    └── Most methods are native stubs → Fully virtualized
        ├── Skip static code analysis
        ├── Go fully dynamic
        ├── Focus on network traffic capture
        ├── Deploy behavioral hooks
        └── Extract IOCs from observable behavior
```

### Tool Selection

| Tool | Purpose |
|------|---------|
| [reFrida](https://github.com/zahidaz/refrida) | Frida with reduced detection footprint for hooking Virbox-protected apps |
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Dump non-virtualized DEX from memory (limited against virtualized methods) |
| [mitmproxy](https://mitmproxy.org/) | Transparent HTTP/HTTPS proxy for C2 extraction |
| [objection](https://github.com/sensepost/objection) | SSL pinning bypass, runtime exploration |
| [jadx](https://github.com/skylot/jadx) | Decompile non-virtualized portions, manifest analysis |
| [APKiD](https://github.com/rednaga/APKiD) | Identify Virbox and determine protection type |
| [Ghidra](https://ghidra-sre.org/) | Analyze `libvirbox_*.so` native library (VM interpreter RE) |

## Comparison with Other Protectors

| Dimension | Virbox | DexGuard | DexProtector | Arxan (Digital.ai) | Chinese Packers |
|-----------|--------|----------|--------------|---------------------|-----------------|
| **Origin** | China (SenseShield) | Belgium (Guardsquare) | USA (Licel) | USA (Digital.ai) | China (various) |
| **DEX Protection** | Virtualization + Encryption | Encryption + Obfuscation | Encryption + Native bridge | Obfuscation + Guard network | Encryption (mostly) |
| **VM-based Protection** | Yes (core feature) | No | No | No | Rare (some Tencent Legu variants) |
| **Native Protection** | Code encryption + Virtualization | Limited | vtable hooking | Guard mesh + Obfuscation | Basic encryption |
| **RASP** | Anti-debug, root, emulator, injection | Anti-tamper, root, debug | Full RASP suite (EMVCo certified) | Environmental checks, tamper detection | Basic anti-debug |
| **Unpacking Difficulty** | Very high (virtualization) | Medium (encryption recoverable) | Medium-high (native bridge) | High (guard network) | Low-medium (well-documented) |
| **frida-dexdump Effective?** | No (virtualized methods) | Partially | Partially | N/A (obfuscation, not encryption) | Yes (most families) |
| **Static Analysis** | Infeasible for VM code | Possible after deobfuscation | Possible after decryption | Difficult but possible | Possible after unpacking |
| **Malware Adoption** | GoldFactory, Klopatra, Gigabud | Widespread across families | Occasional | Rare in malware | Dominant in Chinese malware |
| **Build Integration** | Post-build (APK input) | Gradle plugin (source required) | Post-build (APK/AAB input) | Build-time + Post-build | Post-build (APK upload) |
| **Cost to Attacker** | Commercial license required | Commercial license required | Commercial license required | Commercial license required | Free or cheap |
| **Google Play Compatibility** | Limited (DEX encryption may fail checks) | Full | Full | Full | Limited |

## References

- [Virbox Protector Documentation](https://documentation.virbox.com/use-cases/protect-mobile-applications/protect-android-apk-projects)
- [Virbox Android Protection](https://appsec.virbox.com/androidprotection.html)
- [Virbox Best Practices](https://documentation.virbox.com/use-cases/protect-mobile-applications/best-practice-to-protect-android-apps)
- [SenseShield GitHub](https://github.com/SenseShield/Virbox-Protector)
- [Klopatra Analysis - Cleafy Labs](https://www.cleafy.com/cleafy-labs/klopatra-exposing-a-new-android-banking-trojan-operation-with-roots-in-turkey)
- [Gigabud Threat Network - Zimperium zLabs](https://zimperium.com/blog/a-network-of-harm-gigabud-threat-and-its-associates)
- [GoldDigger and Gigabud Overlap - Cyble](https://cyble.com/blog/unmasking-the-overlap-between-golddigger-and-gigabud-android-malware/)
- [Gigabud Banking Malware - Group-IB](https://www.group-ib.com/blog/gigabud-banking-malware/)
- [GoldFactory Threat Group - Group-IB](https://www.group-ib.com/blog/goldfactory-fraud-apps/)
- [GoldPickaxe iOS Trojan - Group-IB](https://www.group-ib.com/blog/goldpickaxe-ios-trojan/)
- [ESET H1 2024 Threat Report - GoldDigger/GoldFactory](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h1-2024/)
- [ThreatFabric 2024 Mobile Threat Landscape](https://www.threatfabric.com/blogs/the-mobile-threat-landscape-in-2024)
- [Gigabud RAT - Cyble (Initial Discovery)](https://cyble.com/blog/gigabud-rat-new-android-rat-masquerading-as-government-agencies/)
