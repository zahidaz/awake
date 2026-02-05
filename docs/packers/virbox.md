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


## Malware Abuse

### Klopatra Banking Trojan (2025)

Virbox was discovered protecting the **Klopatra** Android banking trojan targeting Turkish financial institutions.

**Observations:**

- Described as "rarely seen in the Android threat landscape"
- Combined with native libraries for maximum evasion
- Analysis only succeeded via unprotected development build
- Protection "drastically increases time and expertise required"

## References

- [Virbox Protector Documentation](https://documentation.virbox.com/use-cases/protect-mobile-applications/protect-android-apk-projects)
- [Virbox Android Protection](https://appsec.virbox.com/androidprotection.html)
- [Virbox Best Practices](https://documentation.virbox.com/use-cases/protect-mobile-applications/best-practice-to-protect-android-apps)
- [SenseShield GitHub](https://github.com/SenseShield/Virbox-Protector)
- [Klopatra Analysis - Cleafy Labs](https://www.cleafy.com/cleafy-labs/klopatra-exposing-a-new-android-banking-trojan-operation-with-roots-in-turkey)
