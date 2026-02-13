# Compose Multiplatform

Compose Multiplatform extends Jetpack Compose -- Google's declarative UI toolkit for Android -- to run on iOS, desktop (JVM), and web (Wasm/JS). On Android, Compose Multiplatform produces identical output to standard Jetpack Compose: the Compose compiler plugin transforms `@Composable` functions into optimized DEX bytecode with a reactive state management system. From a reverse engineering perspective, Compose Multiplatform apps on Android are indistinguishable from apps using regular Jetpack Compose. The framework is developed by JetBrains and builds directly on top of Google's `androidx.compose.*` libraries.

## Architecture

### Compose Runtime Model

Compose uses a compiler plugin that transforms declarative `@Composable` functions into an efficient slot table-based UI tree. The runtime manages state, recomposition (re-rendering when state changes), and the UI node tree.

| Component | Purpose |
|-----------|---------|
| **Compose Compiler Plugin** | Kotlin compiler plugin that transforms `@Composable` functions at build time |
| **Compose Runtime** | Manages the slot table, state tracking, and recomposition scheduling |
| **Compose UI** | Layout system, drawing, input handling, modifiers |
| **Compose Foundation** | Basic UI components (Row, Column, Box, LazyColumn, Text) |
| **Compose Material 3** | Material Design component library |

### Compilation Pipeline

```
@Composable functions (Kotlin) ──> Compose Compiler Plugin ──> Kotlin/JVM bytecode ──> D8/R8 ──> DEX
```

The Compose compiler plugin runs during Kotlin compilation and transforms `@Composable` functions into state-aware code that integrates with the Compose runtime's slot table. The output is standard JVM bytecode that flows through the normal Android build pipeline.

### Slot Table & Recomposition

The Compose runtime maintains a **slot table** -- a linear array that stores the UI tree structure, state values, and group markers. Each `@Composable` function call is assigned a **group key** (an integer derived from its source location) that the runtime uses to track identity across recompositions.

When state changes, the runtime uses the slot table to determine which `@Composable` functions need to re-execute (recompose). Only affected subtrees are re-rendered, not the entire UI.

In decompiled output, this manifests as generated code that calls `Composer.startRestartGroup()`, `Composer.endRestartGroup()`, `Composer.changed()`, and other runtime methods wrapping every composable function body.

## Identification

Compose Multiplatform apps are identified the same way as standard Jetpack Compose apps, since they use the same `androidx.compose.*` libraries on Android.

| Indicator | Location |
|-----------|----------|
| `androidx.compose.runtime.*` | Compose runtime classes in DEX |
| `androidx.compose.ui.*` | Compose UI framework classes |
| `androidx.compose.material3.*` | Material Design 3 components |
| `androidx.compose.foundation.*` | Foundation layout components |
| `ComposableSingletons$*` | Generated singleton classes for lambda composables |
| `*Kt$*$*` | Generated classes from Compose lambda transformations |

Quick check:

```bash
jadx -d output/ target.apk
grep -r "androidx.compose" output/ --include="*.java" -l | head -20
```

### Distinguishing Compose Multiplatform from Jetpack Compose

On Android, there is no reliable way to distinguish Compose Multiplatform from standard Jetpack Compose. Both produce the same `androidx.compose.*` classes in DEX. Indirect signals include:

| Signal | Confidence |
|--------|------------|
| Ktor client present alongside Compose | High (KMP networking + Compose UI) |
| `org.jetbrains.compose.*` resource classes | Medium (Compose Multiplatform resource system) |
| Shared module package with Compose code | Medium (multiplatform project structure) |
| App available on both Android and iOS with identical UI | Contextual (suggests shared UI toolkit) |

!!! info "Does It Matter?"
    For reverse engineering purposes, distinguishing Compose Multiplatform from Jetpack Compose is irrelevant. The analysis approach is identical. The distinction only matters for understanding the developer's project structure and whether shared business logic might follow KMP patterns.

## Analysis

### Decompilation with Jadx

Standard jadx decompilation works. Compose apps produce verbose generated code due to the Compose compiler plugin:

```bash
jadx -d output/ target.apk
```

### Understanding Compose-Generated Code

The Compose compiler transforms every `@Composable` function. A simple composable in source becomes significantly more complex in decompiled output. Key patterns to recognize:

| Generated Pattern | Meaning |
|-------------------|---------|
| `Composer.startRestartGroup(int key)` | Beginning of a composable scope, `key` identifies the source location |
| `Composer.endRestartGroup()` | End of composable scope, returns `ScopeUpdateScope` for recomposition |
| `Composer.changed(value)` | Checks if a parameter changed since last composition |
| `Composer.skipToGroupEnd()` | Skips recomposition of this subtree (parameters unchanged) |
| `Composer.startReplaceableGroup(int)` | Non-restartable group (conditional or loop body) |
| `$changed` parameter | Bitmask tracking which parameters changed, used for skip optimization |
| `ComposableSingletons$FileName` | Singleton holder for lambda composables |

### Reading Decompiled Composables

When analyzing decompiled Compose code, strip away the Composer boilerplate mentally. The actual logic sits between the `startRestartGroup` and `endRestartGroup` calls. The `$changed` bitmask parameters and `Composer.changed()` checks are optimization scaffolding, not business logic.

A decompiled composable that looks like 80 lines typically contains 10-15 lines of actual logic buried in Composer state-tracking calls.

### State Management Patterns

Compose state is the primary data flow mechanism. In decompiled output, state holders appear as:

| Class | Purpose |
|-------|---------|
| `MutableStateImpl` | Wraps a value with change notification (`mutableStateOf()`) |
| `SnapshotStateList` | Observable list implementation |
| `SnapshotStateMap` | Observable map implementation |
| `DerivedSnapshotState` | Computed state derived from other state values |
| `StateFlowKt` | Kotlin Flow collected as Compose state |

### ViewModel Integration

Compose apps typically use Android `ViewModel` for state management. The ViewModel holds business logic and exposes state as `StateFlow` or `MutableState`:

```bash
grep -r "ViewModel" output/ --include="*.java" -l
grep -r "StateFlow" output/ --include="*.java" -l
```

ViewModels contain the bulk of the business logic and are the primary analysis targets -- not the composable UI functions.

## Navigation Analysis

Compose Navigation defines the app's screen graph. Analyzing navigation reveals the app's complete screen structure and data flow between screens.

```bash
grep -r "NavHost\|composable(\|navigation(" output/ --include="*.java"
```

Navigation routes are string-based and often contain hardcoded route patterns that reveal the app's structure:

```bash
grep -r "\".*/{.*}\"" output/ --include="*.java"
```

This finds parameterized routes like `"profile/{userId}"` or `"transaction/{txId}"`.

## Hooking Strategy

### Standard Kotlin Hooks

Compose compiles to standard Kotlin/JVM bytecode. All Frida Java hooks work:

```javascript
Java.perform(function() {
    var LoginVM = Java.use("com.example.app.ui.login.LoginViewModel");
    LoginVM.login.overload("java.lang.String", "java.lang.String", "kotlin.coroutines.Continuation").implementation = function(email, password, cont) {
        console.log("[Compose] login: " + email + " / " + password);
        return this.login(email, password, cont);
    };
});
```

### Hooking Compose State Changes

Intercept state mutations to observe data flow through the UI:

```javascript
Java.perform(function() {
    var SnapshotMutableState = Java.use("androidx.compose.runtime.SnapshotMutableStateImpl");
    SnapshotMutableState.setValue.implementation = function(value) {
        console.log("[Compose State] setValue: " + value);
        this.setValue(value);
    };
});
```

This fires on every `mutableStateOf()` value change across the entire app, which can be noisy. Filter by inspecting the call stack:

```javascript
Java.perform(function() {
    var SnapshotMutableState = Java.use("androidx.compose.runtime.SnapshotMutableStateImpl");
    SnapshotMutableState.setValue.implementation = function(value) {
        var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        if (trace.indexOf("com.example.app") !== -1) {
            console.log("[Compose State] " + value + "\n" + trace);
        }
        this.setValue(value);
    };
});
```

### Hooking Recomposition

Monitor which composables recompose to understand UI update patterns:

```javascript
Java.perform(function() {
    var Composer = Java.use("androidx.compose.runtime.ComposerImpl");
    Composer.startRestartGroup.implementation = function(key) {
        console.log("[Recompose] group key: " + key);
        return this.startRestartGroup(key);
    };
});
```

### Intercepting Network Calls from ViewModels

Since ViewModels contain the business logic, hooking the repository or API service layer is more effective than hooking UI code:

```javascript
Java.perform(function() {
    var Retrofit = Java.use("retrofit2.Retrofit");
    Retrofit.create.implementation = function(service) {
        console.log("[API] Creating service: " + service.getName());
        return this.create(service);
    };
});
```

For Compose Multiplatform apps using Ktor instead of Retrofit:

```javascript
Java.perform(function() {
    var HttpClient = Java.use("io.ktor.client.HttpClient");
    HttpClient.execute$ktor_client_core.implementation = function(builder, cont) {
        console.log("[Ktor] Request: " + builder.getUrl().toString());
        return this["execute$ktor_client_core"](builder, cont);
    };
});
```

## SSL Pinning Bypass

Compose apps use standard Android networking libraries. The SSL pinning bypass depends on which HTTP client the app uses:

=== "OkHttp / Retrofit"

    ```javascript
    Java.perform(function() {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, certs) {
            console.log("[SSL] Bypassed pin for: " + host);
        };
    });
    ```

=== "Ktor (Compose Multiplatform)"

    Ktor on Android uses OkHttp as its engine, so the same OkHttp bypass applies. See the [Kotlin Multiplatform](kotlin-multiplatform.md#ktor-ssl-pinning) page for details.

## RE Difficulty Assessment

| Aspect | Assessment |
|--------|------------|
| Code format | Standard DEX bytecode |
| Identification | Easy -- `androidx.compose.*` classes present |
| Decompilation | Full -- but Compose compiler output is verbose |
| String extraction | Standard -- all strings in DEX string pool |
| Control flow recovery | Full -- standard Kotlin, but buried in Composer boilerplate |
| Business logic location | ViewModels and repositories, not composable functions |
| Hooking | Standard Frida Java hooks |
| Patching | Standard smali patching workflow |
| Obfuscation ceiling | R8/ProGuard, DexGuard, same as native Android |
| Overall difficulty | **Easy** (rank equivalent to native Kotlin apps) |

The primary challenge with Compose apps is not the framework itself but the volume of generated boilerplate from the Compose compiler plugin. Each `@Composable` function expands into significantly more bytecode than its source equivalent. The analysis strategy is to focus on ViewModels and repository classes for business logic, treating the composable UI layer as secondary unless UI manipulation or screen-scraping is specifically relevant.

## References

- [Compose Multiplatform -- JetBrains](https://www.jetbrains.com/compose-multiplatform/)
- [Jetpack Compose Architecture -- Android Developers](https://developer.android.com/develop/ui/compose/mental-model)
- [Compose Compiler Plugin Documentation](https://developer.android.com/develop/ui/compose/compiler)
- [Understanding Compose Runtime -- Leland Richardson](https://medium.com/androiddevelopers/under-the-hood-of-jetpack-compose-part-2-of-2-37b2c20c852)
- [Compose Navigation Documentation](https://developer.android.com/develop/ui/compose/navigation)
- [jadx -- Android DEX Decompiler](https://github.com/skylot/jadx)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [Ktor Client Documentation](https://ktor.io/docs/client-create-new-application.html)
