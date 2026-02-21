# R8 / ProGuard

R8 and ProGuard are code transformation tools that ship with the Android build toolchain. They are technically obfuscators, not packers -- they do not encrypt DEX files, wrap native loaders, or perform any runtime self-protection. However, they are the most commonly encountered code transformation in Android reverse engineering, and understanding their output is a prerequisite for analyzing virtually any production Android application.

## Overview

| Attribute | ProGuard | R8 |
|-----------|----------|-----|
| Developer | Guardsquare (Eric Lafortune) | Google |
| Type | Open-source obfuscator/optimizer | Built into Android Gradle Plugin |
| Status | Legacy (still functional) | Default since AGP 3.4.0 (2019) |
| Rule format | `-keep` rules in `proguard-rules.pro` | Same rule format as ProGuard |
| Implementation | Separate JAR, processes .class files | Integrated into D8 dexer, processes directly to DEX |

R8 replaced ProGuard as the default code shrinker and obfuscator in the Android Gradle Plugin. Both use the same configuration file format (`proguard-rules.pro`), so from a rule-writing perspective they are interchangeable. The key difference is implementation: R8 operates directly on DEX bytecode as part of the D8 compilation pipeline, while ProGuard operated on Java bytecode before dexing.

For reverse engineers, this distinction rarely matters. The output of both tools produces the same general patterns in decompiled code. R8 tends to be more aggressive with certain optimizations (inlining, class merging), which can make decompiled output slightly different.

## What They Do

### Name Obfuscation

The most visible transformation. Classes, methods, and fields are renamed to short, meaningless identifiers:

```
com.example.myapp.network.ApiClient  ->  a.b.c
com.example.myapp.network.ApiClient.fetchUserProfile()  ->  a.b.c.a()
com.example.myapp.model.UserProfile  ->  a.b.d
com.example.myapp.model.UserProfile.displayName  ->  a.b.d.a
com.example.myapp.model.UserProfile.emailAddress  ->  a.b.d.b
```

Names are assigned alphabetically within each scope. The first class in a package becomes `a`, the second `b`, and so on. After `z`, naming continues with `aa`, `ab`, etc. This scheme is deterministic per build but changes between releases as code is added or removed.

### Code Shrinking (Tree Shaking)

Removes unreachable code. Starting from entry points (activities, services, content providers, broadcast receivers declared in the manifest), R8/ProGuard traces all reachable code paths and discards everything else. This eliminates:

- Unused classes and interfaces
- Unused methods and fields
- Unused code branches within methods
- Unused library code pulled in as dependencies

For analysts, this means the APK only contains code that is actually reachable. Dead library code and unused features are stripped, reducing noise in the decompiled output.

### Optimization

R8 performs several bytecode-level optimizations:

| Optimization | Effect on Decompiled Code |
|-------------|--------------------------|
| Method inlining | Small methods disappear; their code appears at call sites |
| Devirtualization | Virtual calls replaced with direct calls when only one implementation exists |
| Constant propagation | Computed constants replaced with literal values |
| Dead branch removal | Unreachable if/else branches eliminated |
| Enum unboxing | Enum classes replaced with int constants (R8 only, with full mode) |
| Class merging | Separate classes merged into one when possible (R8 only) |
| Outlining | Repeated code sequences extracted into shared methods (R8 only) |

### What They Do NOT Do

R8 and ProGuard provide zero runtime protection:

- **No string encryption** -- all string literals remain as plaintext in the DEX
- **No class/DEX encryption** -- the DEX file is fully readable
- **No anti-debugging** -- no detection of debuggers, Frida, or Xposed
- **No anti-tampering** -- no signature verification or integrity checks
- **No root/emulator detection** -- no environmental checks
- **No native code protection** -- JNI libraries are untouched
- **No control flow obfuscation** -- code logic remains structurally intact

This is the fundamental distinction between R8/ProGuard and tools like [DexGuard](dexguard.md), [Virbox](virbox.md), or [Chinese packers](tencent-legu.md). If an APK only uses R8/ProGuard, all strings, API calls, URLs, and logic are visible in static analysis. The only challenge is navigating renamed identifiers.

## Reverse Engineering R8/ProGuard Output

### Reading Obfuscated Code

Typical R8/ProGuard output in jadx:

```java
package a.b;

public class c {
    private final d a;
    private String b;

    public c(d dVar) {
        this.a = dVar;
    }

    public void a(String str) {
        this.b = str;
        this.a.a("https://api.example.com/user", str, new a.b.e() {
            @Override
            public void a(String str2) {
                f.a(str2);
            }

            @Override
            public void b(Exception exc) {
                Log.e("NetClient", exc.getMessage());
            }
        });
    }
}
```

The class and method names are meaningless, but the string literals (`"https://api.example.com/user"`, `"NetClient"`) and Android framework calls (`Log.e`) are fully visible. This is the key advantage for analysts: R8/ProGuard cannot hide what the code actually does.

### Using mapping.txt

When a build produces an R8/ProGuard-obfuscated APK, it also generates a `mapping.txt` file that maps obfuscated names back to original names. This file is used for crash report deobfuscation (uploaded to Google Play Console or Crashlytics).

Format:

```
com.example.myapp.network.ApiClient -> a.b.c:
    okhttp3.OkHttpClient httpClient -> a
    java.lang.String baseUrl -> b
    void fetchUserProfile(java.lang.String) -> a
    void handleResponse(okhttp3.Response) -> b
com.example.myapp.model.UserProfile -> a.b.d:
    java.lang.String displayName -> a
    java.lang.String emailAddress -> b
```

Analysts occasionally obtain `mapping.txt` through:

- Leaked build artifacts (CI/CD misconfigurations, exposed storage buckets)
- Google Play Console access (internal assessments)
- Bundled accidentally in the APK itself (rare but happens)
- Firebase Crashlytics storage (if accessible)

jadx can apply mapping files directly via `File > Load mappings`.

### jadx Deobfuscation Features

jadx provides built-in deobfuscation that renames classes and methods based on usage patterns, even without `mapping.txt`:

- **Auto-rename** (`--deobf` flag or `Preferences > Deobfuscation`): assigns readable names based on heuristics
- **Type-based renaming**: when a field is assigned from `getSharedPreferences()`, jadx can infer the field likely holds preferences
- **Interface method propagation**: if an obfuscated class implements `View.OnClickListener`, jadx knows the `a()` method is actually `onClick()`

### Recovering Original Names

Even without mapping files, many original names survive obfuscation or can be inferred:

**String References**

Log tags, exception messages, and debug strings often reveal the original purpose:

```java
public class a {
    public void b() {
        Log.d("PaymentProcessor", "Processing transaction");
        ...
    }
}
```

The log tag `"PaymentProcessor"` reveals the class purpose despite its `a` name.

**Android Framework and Library Calls**

Method signatures of Android APIs and common libraries are never obfuscated:

```java
public class a extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if ("android.provider.Telephony.SMS_RECEIVED".equals(action)) {
            ...
        }
    }
}
```

The superclass, overridden method name, and intent action string immediately identify this as an SMS interceptor.

**Reflection Usage**

Code that uses reflection must reference original class and method names as strings:

```java
Class cls = Class.forName("android.telephony.TelephonyManager");
Method m = cls.getMethod("getDeviceId");
```

These strings survive obfuscation because they are runtime values, not compile-time identifiers.

**Serialized Field Names**

JSON serialization libraries preserve field names as strings:

```java
public class d {
    @SerializedName("account_number")
    public String a;

    @SerializedName("routing_number")
    public String b;

    @SerializedName("balance")
    public double c;
}
```

The `@SerializedName` annotations (or equivalent JSON keys) reveal the real purpose of each field.

**AIDL Interfaces**

AIDL-generated code retains transaction names and descriptor strings:

```java
public static final String DESCRIPTOR = "com.example.myapp.IRemoteService";
```

**Manifest-Declared Components**

Activities, services, receivers, and providers declared in `AndroidManifest.xml` keep their full class names because the Android runtime needs to find and instantiate them.

## Keep Rules as Intelligence

The `proguard-rules.pro` file (or `consumer-rules.pro` for libraries) defines which classes, methods, and fields must not be renamed or removed. These rules are a goldmine for analysts because they reveal architectural decisions and dependencies.

### Reading Keep Rules

```
-keep class com.example.myapp.api.** { *; }
-keep class com.example.myapp.model.** { *; }
-keepclassmembers class * implements android.os.Parcelable {
    static ** CREATOR;
}
-keepnames class * extends com.example.myapp.plugin.PluginBase
```

These rules tell an analyst:

- The `api` and `model` packages contain classes used via reflection or serialization (likely API request/response models)
- The app uses `Parcelable` for IPC
- There is a plugin system with a `PluginBase` class and dynamically loaded implementations

### What Keep Rules Reveal

| Rule Pattern | Implies |
|-------------|---------|
| `-keep class **.model.** { *; }` | JSON/XML serialization models -- field names map to API schema |
| `-keep class ** extends android.app.Service` | Services loaded by name (possibly from config) |
| `-keepclassmembers class * { @com.google.gson.annotations.* <fields>; }` | Uses Gson for JSON parsing |
| `-keep class **.BuildConfig { *; }` | Build configuration exposed at runtime |
| `-keep class * implements java.io.Serializable` | IPC or persistence via Java serialization |
| `-keep class **.js.** { *; }` | JavaScript bridge interfaces for WebView |
| `-keepclassmembers class * { @android.webkit.JavascriptInterface <methods>; }` | WebView JS bridge -- potential attack surface |

### Finding Keep Rules in APKs

R8 embeds a processed version of the keep rules into the build. Some APKs include the original `proguard-rules.pro` in the root of the APK or inside `META-INF/`. Additionally, library AARs bundle their own `proguard.txt` consumer rules that get merged into the final configuration.

## Common Patterns

### Enum Names Survive

Enum constants are almost always preserved because `Enum.valueOf(String)` requires the original name at runtime:

```java
public enum a {
    TRANSACTION_SUCCESS,
    TRANSACTION_FAILED,
    TRANSACTION_PENDING,
    INSUFFICIENT_FUNDS;
}
```

The class name `a` is obfuscated, but the constant names reveal intent. This is one of the most reliable sources of plaintext names in obfuscated APKs.

### Parcelable Classes

Classes implementing `Parcelable` require a public `CREATOR` field and are often referenced by name in intents. The default ProGuard rules keep the `CREATOR` field, and the class itself is typically kept because it crosses process boundaries.

### Manifest-Declared Components

All components declared in `AndroidManifest.xml` retain their original fully qualified class names:

```xml
<activity android:name="com.example.myapp.ui.LoginActivity" />
<service android:name="com.example.myapp.service.DataExfiltrationService" />
<receiver android:name="com.example.myapp.receiver.BootReceiver" />
```

These names survive R8/ProGuard because the Android framework instantiates them by name. The manifest is the first place to look for meaningful class names in an obfuscated APK.

### Serialization Models

GSON, Moshi, Jackson, and similar libraries require field names to match JSON keys. These classes are either kept entirely or annotated with `@SerializedName` / `@Json`:

```java
public class c {
    @SerializedName("device_id")
    String a;

    @SerializedName("installed_apps")
    List<String> b;

    @SerializedName("sms_messages")
    List<d> c;
}
```

The annotations expose the data model regardless of field renaming.

### Native Method Declarations

JNI method names must match between Java and native code. If using static registration (not `RegisterNatives`), the native method names survive obfuscation:

```java
public class a {
    public static native String decryptPayload(byte[] data, int key);
}
```

However, if the class containing the native method is renamed, the corresponding JNI function name in the .so must also match the obfuscated name (e.g., `Java_a_b_c_decryptPayload`). Developers often keep native classes unobfuscated to avoid this complexity.

## R8 vs ProGuard Differences

### Class Merging (R8 Only)

R8 can merge classes that have a single implementation or are only used in one place. A class and its only subclass may be collapsed into one:

```
Before R8:
  abstract class BaseRepository { void save(Data d); }
  class UserRepository extends BaseRepository { void save(Data d) { ... } }

After R8:
  class a { void a(b bVar) { ... } }
```

The inheritance relationship disappears entirely. This makes reconstructing the original architecture harder.

### More Aggressive Inlining

R8 inlines more aggressively than ProGuard. Short methods (getters, setters, simple wrappers) are absorbed into their callers. The decompiled output may show inline code where the original had clean method boundaries:

```java
this.a.b = this.c.a().getSharedPreferences("prefs", 0).getString("token", "");
```

This single line might represent three separate method calls in the original source.

### Enum Unboxing (R8 Full Mode)

With R8 full mode (`android.enableR8.fullMode=true`), enums can be replaced with integer constants. The enum class disappears and all `switch` statements use raw ints. This removes the enum name survival pattern described above.

### Kotlin Metadata Stripping

R8 strips Kotlin metadata annotations by default. ProGuard preserved them unless explicitly told to remove them. The presence or absence of `kotlin.Metadata` annotations on classes can hint at which tool was used.

### Identifying Which Tool Was Used

| Indicator | ProGuard | R8 |
|-----------|----------|-----|
| Class merging observed | No | Possible |
| Kotlin metadata present | Often preserved | Stripped |
| `$$Lambda$` synthetic classes | Present | Desugared differently |
| Enum constants as ints | No | Possible (full mode) |
| Build metadata comment in mapping.txt | `# ProGuard, version X.Y.Z` | `# compiler: R8` |

In practice, distinguishing the tool rarely matters for analysis. The deobfuscation approach is the same regardless.

## Malware Usage

### ProGuard/R8-Only Malware

Many Android malware families ship with only R8 or ProGuard obfuscation and no additional packing. This is the lowest tier of protection:

- All strings (C2 URLs, API keys, target app lists) are plaintext in the DEX
- All API calls are visible to static analysis tools
- Behavioral analysis is possible without any unpacking or decryption
- Automated scanners (VirusTotal, Google Play Protect) can pattern-match directly

Families that historically relied on R8/ProGuard alone include early variants of [SpyNote](../malware/families/spynote.md), [Cerberus](../malware/families/cerberus.md)-lineage builders, and many low-sophistication SMS stealers and banking trojans.

### Distinguishing from DexGuard

[DexGuard](dexguard.md) is built by Guardsquare, the same company that maintains ProGuard. DexGuard extends R8/ProGuard with encryption and runtime protection. Key differences in decompiled output:

| Feature | R8/ProGuard | DexGuard |
|---------|-------------|----------|
| String literals | Plaintext | Encrypted (method calls returning strings) |
| String access | `"https://c2.example.com"` | `o.oo("\\x4a\\x2f...")` |
| Class loading | Standard | Custom class loader for encrypted classes |
| Native libraries | None added | `libdexguard.so` or obfuscated stubs |
| Asset files | Normal | Encrypted DEX payloads in `assets/` |
| APKiD detection | No special flags | `packer: DexGuard`, `anti_disassembly: DexGuard` |
| Environmental checks | None | Root, emulator, debugger, Frida, Xposed detection |

The fastest way to distinguish: open the APK in jadx and search for string literals. If C2 URLs, package names, and configuration data appear as readable strings, it is R8/ProGuard. If strings are replaced by method calls to single-letter classes that take byte arrays, it is likely DexGuard or another string-encrypting protector.

### Layered Protection

More sophisticated malware operations use R8/ProGuard as a base layer and add protection on top:

```
R8/ProGuard (name obfuscation, shrinking)
  + Custom string encryption (XOR/AES of sensitive strings)
  + Dynamic class loading (second-stage DEX from assets or network)
  + Native code for critical logic (C2 communication, credential theft)
```

This layered approach is cheaper than licensing DexGuard and gives operators more control. Analysts should not assume that R8/ProGuard-level obfuscation is the only protection present -- always check for custom encryption methods and dynamic loading patterns.

## Analyst Workflow

```
1. Open APK in jadx
2. Check AndroidManifest.xml for component names (Activities, Services, Receivers)
3. Search strings for URLs, IPs, package names, API endpoints
4. If all strings are plaintext -> R8/ProGuard only, proceed with static analysis
5. If strings are encrypted -> additional protection present (DexGuard, custom)
6. Use jadx deobfuscation (--deobf) to auto-rename classes
7. Start from manifest-declared components and trace call graphs
8. Use enum names, log tags, and serialization annotations to reconstruct meaning
9. Cross-reference with mapping.txt if available
```

## References

- [R8 Documentation](https://developer.android.com/build/shrink-code)
- [ProGuard Manual](https://www.guardsquare.com/manual/home)
- [R8 Compatibility FAQ](https://r8.googlesource.com/r8/+/refs/heads/main/compatibility-faq.md)
- [APKiD](https://github.com/rednaga/APKiD)
