# Kotlin Multiplatform

Kotlin Multiplatform (KMP) allows developers to write shared business logic in Kotlin that compiles to platform-native output -- standard JVM/DEX bytecode on Android, native binaries on iOS, and JavaScript for web. On Android, KMP code compiles to the same DEX bytecode as any regular Kotlin Android app, making it indistinguishable at the binary level from a standard native app. This is the core reverse engineering challenge: there are no unique runtime markers, custom VMs, or bundled interpreters to identify. The framework is developed by JetBrains and reached stable status in November 2023.

## Architecture

### Shared Code Model

KMP projects use a hierarchical source set structure where common business logic lives in `commonMain` and platform-specific implementations live in platform source sets:

| Source Set | Purpose |
|------------|---------|
| **commonMain** | Shared business logic, data models, networking, serialization |
| **androidMain** | Android-specific implementations (platform APIs, UI bindings) |
| **iosMain** | iOS-specific implementations (not relevant to Android RE) |
| **commonTest** | Shared test code |

At compile time, the Kotlin compiler merges `commonMain` and `androidMain` into standard Kotlin/JVM bytecode, which then goes through D8/R8 to produce DEX. The resulting APK contains no trace of the multiplatform source structure.

### Expect/Actual Pattern

KMP's primary mechanism for platform abstraction is the `expect`/`actual` pattern. Common code declares an `expect` function or class, and each platform provides an `actual` implementation:

In source, this looks like a common interface with platform-specific backends. After compilation to DEX, the `expect` declarations disappear entirely -- they exist only at compile time. The decompiled output shows only the concrete `actual` implementations as regular Kotlin classes and functions.

### Compilation Pipeline

```
commonMain (Kotlin) ──┐
                      ├──> Kotlin/JVM Compiler ──> .class files ──> D8/R8 ──> DEX
androidMain (Kotlin) ─┘
```

The output is identical to a standard Kotlin Android project. No intermediate bytecode formats, no embedded interpreters, no bundled scripts.

## Identification

KMP apps produce standard DEX bytecode with no definitive fingerprint. Identification relies on indirect signals rather than definitive markers.

| Indicator | Confidence | Details |
|-----------|------------|---------|
| Ktor classes in DEX | High | `io.ktor.client.*` is the standard KMP HTTP client |
| kotlinx.serialization | Medium | `kotlinx.serialization.*` classes are common in KMP projects |
| kotlinx.coroutines | Low | Used widely in all Kotlin projects, not KMP-specific |
| Multi-target library packages | Medium | Presence of `org.jetbrains.kotlinx.*` utility libraries |
| Lack of framework markers | N/A | No React Native, Flutter, or Xamarin markers in an app that has iOS counterpart |

Quick check for Ktor (strongest KMP signal):

```bash
jadx -d output/ target.apk
grep -r "io.ktor" output/ --include="*.java" -l
```

### What You Will NOT Find

Unlike Flutter (`libflutter.so`), React Native (`libhermes.so`), or Xamarin (`libmonosgen.so`), KMP leaves no native libraries, bundled runtimes, or asset files that betray its origin. The DEX bytecode is structurally identical to a hand-written Kotlin Android app.

!!! warning "Identification is Probabilistic"
    There is no single artifact that definitively identifies a KMP app. The best approach is to look for a combination of common KMP libraries (Ktor, kotlinx.serialization, kotlinx.datetime) alongside the absence of other cross-platform framework markers.

## Analysis

### Standard Jadx Workflow

Since KMP compiles to normal DEX bytecode, the standard Android reverse engineering workflow applies without modification:

```bash
jadx -d output/ target.apk
```

The decompiled output is standard Kotlin (displayed as Java by jadx, or as Kotlin with `--decompile-kotlin` flag). All KMP shared code appears as regular classes and functions.

### Identifying Former commonMain Code

Code that originated in `commonMain` often exhibits these patterns in decompiled output:

| Pattern | Indicator |
|---------|-----------|
| Platform abstraction wrappers | Classes that wrap simple platform calls (e.g., `PlatformProvider.getDeviceId()`) |
| Interface + single implementation | An interface with exactly one Android implementation, suggesting expect/actual origin |
| Ktor networking throughout | All HTTP calls using Ktor rather than OkHttp/Retrofit directly |
| kotlinx.serialization annotations | `@Serializable` data classes with generated `Companion` serializers |
| kotlinx.datetime usage | `kotlinx.datetime.Instant` instead of `java.time.*` |

### Data Class Serialization

KMP apps heavily use `kotlinx.serialization` for JSON handling. The compiler plugin generates serializer companion objects for each `@Serializable` data class:

```bash
grep -r "serializer" output/ --include="*.java" | grep "Companion"
```

These generated serializers contain the complete field mapping, making it straightforward to reconstruct API request/response models even in R8-obfuscated builds.

## Ktor Client Networking

[Ktor](https://ktor.io/) is the standard HTTP client in KMP projects because it supports all KMP targets. On Android, Ktor uses OkHttp as its underlying engine by default.

### Ktor Architecture on Android

```
Application Code ──> Ktor Client API ──> CIO / OkHttp Engine ──> Network
```

The key classes in decompiled output:

| Class | Purpose |
|-------|---------|
| `io.ktor.client.HttpClient` | Main client entry point |
| `io.ktor.client.engine.okhttp.OkHttpEngine` | Android HTTP engine (wraps OkHttp) |
| `io.ktor.client.request.HttpRequestBuilder` | Request construction |
| `io.ktor.client.plugins.contentnegotiation.*` | JSON serialization plugin |
| `io.ktor.client.plugins.auth.*` | Authentication plugin (Bearer, Basic) |

### Intercepting Ktor Traffic

Since Ktor uses OkHttp on Android, standard OkHttp interceptor hooks work:

```javascript
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");

    Builder.build.implementation = function() {
        var client = this.build();
        console.log("[Ktor/OkHttp] Client built with interceptors: " + client.interceptors());
        return client;
    };
});
```

### Ktor SSL Pinning

Ktor on Android delegates TLS to OkHttp, so standard OkHttp certificate pinner bypasses apply:

```javascript
Java.perform(function() {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
        console.log("[Ktor] Bypassed certificate pin for: " + hostname);
    };
});
```

Some KMP apps configure Ktor-level pinning through `io.ktor.client.engine.okhttp.OkHttpConfig`. This still resolves to OkHttp's `CertificatePinner` at runtime.

## Hooking Strategy

### Standard Kotlin/Java Hooks

KMP compiles to standard DEX, so all Frida Java hooks work without special handling:

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.example.shared.NetworkRepository");
    TargetClass.fetchUserData.implementation = function(userId) {
        console.log("[KMP] fetchUserData called with: " + userId);
        var result = this.fetchUserData(userId);
        console.log("[KMP] fetchUserData returned: " + result);
        return result;
    };
});
```

### Coroutine-Aware Hooking

KMP shared code uses Kotlin coroutines extensively. Suspend functions compile to methods with an extra `Continuation` parameter:

```javascript
Java.perform(function() {
    var ApiService = Java.use("com.example.shared.ApiService");
    ApiService.getProfile.overload("java.lang.String", "kotlin.coroutines.Continuation").implementation = function(token, continuation) {
        console.log("[KMP] getProfile called with token: " + token);
        return this.getProfile(token, continuation);
    };
});
```

### Enumerating Shared Module Classes

To find classes originating from the shared KMP module, enumerate classes matching the shared module package:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("shared") !== -1 || className.indexOf("common") !== -1) {
                console.log("[KMP Shared] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

KMP shared modules typically compile to a package like `com.example.shared.*` or `com.example.common.*`, though this is entirely developer-configurable.

### Hooking kotlinx.serialization

Intercept JSON deserialization to capture API responses:

```javascript
Java.perform(function() {
    var Json = Java.use("kotlinx.serialization.json.Json");
    var JsonKt = Java.use("kotlinx.serialization.json.internal.StreamingJsonDecoder");

    JsonKt.decodeSerializableValue.implementation = function(deserializer) {
        var result = this.decodeSerializableValue(deserializer);
        console.log("[KMP Serialization] Decoded: " + result.toString());
        return result;
    };
});
```

## Shared Code Patterns

### Repository Pattern

KMP projects frequently use a repository pattern where shared code defines repositories that abstract data sources:

In decompiled output, look for classes ending in `Repository` or `DataSource` in the shared package. These contain the core business logic and API call definitions.

### Multiplatform Settings / Key-Value Storage

KMP apps often use [multiplatform-settings](https://github.com/russhwolf/multiplatform-settings) for key-value storage. On Android, this wraps `SharedPreferences`:

```javascript
Java.perform(function() {
    var SharedPrefs = Java.use("android.app.SharedPreferencesImpl");
    SharedPrefs.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[KMP Settings] getString(" + key + ") = " + value);
        return value;
    };
});
```

### Koin Dependency Injection

[Koin](https://insert-koin.io/) is the dominant DI framework in KMP projects (Dagger/Hilt are Android-only). In decompiled output, look for `org.koin.core.*` classes and module definitions that reveal the app's dependency graph and service architecture.

## RE Difficulty Assessment

| Aspect | Assessment |
|--------|------------|
| Code format | Standard DEX bytecode |
| Identification | Difficult -- no unique markers |
| Decompilation | Full -- standard jadx output |
| String extraction | Standard -- all strings in DEX string pool |
| Control flow recovery | Full -- standard Kotlin compiled code |
| Hooking | Standard Frida Java hooks |
| Patching | Standard smali patching workflow |
| Obfuscation ceiling | R8/ProGuard, DexGuard, same as any native Android app |
| Overall difficulty | **Easy** (once identified) |

The irony of KMP from a reverse engineering perspective is that the identification step is the hardest part. Once you determine an app uses KMP, every standard Android analysis technique works without modification. There is no custom VM to understand, no bytecode format to decompile, and no bridge to intercept.

## References

- [Kotlin Multiplatform Documentation](https://kotlinlang.org/docs/multiplatform.html)
- [Ktor Client Documentation](https://ktor.io/docs/client-create-new-application.html)
- [kotlinx.serialization Guide](https://github.com/Kotlin/kotlinx.serialization/blob/master/docs/serialization-guide.md)
- [Koin -- Kotlin Multiplatform DI](https://insert-koin.io/docs/reference/koin-mp/kmp/)
- [multiplatform-settings -- russhwolf](https://github.com/russhwolf/multiplatform-settings)
- [jadx -- Android DEX Decompiler](https://github.com/skylot/jadx)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [KMP Expect/Actual Mechanism](https://kotlinlang.org/docs/multiplatform-expect-actual.html)
