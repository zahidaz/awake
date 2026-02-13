# libGDX

libGDX is an open-source Java game development framework that produces standard Android APKs with conventional DEX bytecode. Unlike engines with custom VMs or bytecode formats, libGDX game logic is written in Java (or Kotlin), compiled to standard DEX, and decompiles directly with [jadx](https://github.com/skylot/jadx). The framework provides cross-platform abstractions for rendering (OpenGL ES), input, audio, and file I/O, but the compiled output is indistinguishable from a standard Android app at the bytecode level. A native library (`libgdx.so`) handles low-level OpenGL and audio operations.

## Architecture

### Framework Structure

| Layer | Implementation |
|-------|---------------|
| **Game logic** | Java/Kotlin -- compiled to standard DEX |
| **Framework core** | `com.badlogic.gdx.*` classes in DEX |
| **Native backend** | `libgdx.so` -- JNI bridge for OpenGL ES, audio, native buffers |
| **Platform backend** | `com.badlogic.gdx.backends.android.*` -- Android lifecycle integration |
| **Extensions** | Optional: Box2D (`libgdx-box2d.so`), FreeType (`libgdx-freetype.so`), Bullet physics |

libGDX follows a single-entry-point pattern. The developer implements `com.badlogic.gdx.ApplicationListener` (or extends `com.badlogic.gdx.Game`) and registers it with the Android launcher activity. All game logic flows through lifecycle callbacks:

| Callback | Purpose |
|----------|---------|
| `create()` | Initialization -- load assets, set up first screen |
| `render()` | Called every frame -- game loop (update + draw) |
| `resize()` | Window/surface size changed |
| `pause()` | App backgrounded |
| `resume()` | App foregrounded |
| `dispose()` | Cleanup -- release resources |

### Screen Management

Most libGDX apps use the `Screen` interface (via the `Game` base class) to organize gameplay into discrete screens. The `Game` class delegates to `Screen` instances, each with `show()`, `render()`, `hide()`, and `dispose()` callbacks. Typical screen classes (`MainMenuScreen`, `GameScreen`, `SettingsScreen`) are the primary targets for understanding app flow.

## Identification

| Indicator | Location |
|-----------|----------|
| `libgdx.so` | Core native library (definitive) |
| `libgdx-box2d.so` | Box2D physics extension |
| `libgdx-freetype.so` | FreeType font rendering extension |
| `libgdx-bullet.so` | Bullet 3D physics extension |
| `com.badlogic.gdx.*` | Framework classes in DEX |
| `com.badlogic.gdx.backends.android.*` | Android backend classes |
| `com.badlogic.gdx.backends.android.AndroidApplication` | Typical launcher activity superclass |
| `assets/*.atlas` | Texture atlas files |
| `assets/*.tmx` / `assets/*.tmj` | Tiled map files |
| `assets/*.fnt` | BitmapFont files |

Quick check:

```bash
unzip -l target.apk | grep -E "(libgdx|com\.badlogic|\.atlas)"
```

The launcher activity typically extends `AndroidApplication` and contains a call to `initialize()` with the main `ApplicationListener` instance -- this reveals the game's entry point class.

## Code Location & Extraction

All game logic lives in standard DEX bytecode. There is no embedded interpreter, no custom bytecode, no script files to extract. The analysis workflow is identical to any standard Android app:

```bash
jadx -d output/ target.apk
```

### Finding the Entry Point

The Android launcher activity reveals the game's main class:

```java
public class AndroidLauncher extends AndroidApplication {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        AndroidApplicationConfiguration config = new AndroidApplicationConfiguration();
        initialize(new MyGame(), config);
    }
}
```

The class passed to `initialize()` (here `MyGame`) is the `ApplicationListener` implementation containing the game's entry point. Trace from there.

### Class Organization Patterns

libGDX projects typically organize into `*.screens` (screen implementations), `*.entities` (game entities), `*.systems` (ECS systems if using Ashley or Artemis), `*.assets` (resource loading), and `*.network` (networking/C2 communication). Look for these package patterns in jadx to orient analysis.

## Analysis Workflow

1. **Decompile** with `jadx -d output/ target.apk`
2. **Find the launcher activity** in `AndroidManifest.xml` (the activity with `MAIN`/`LAUNCHER` intent filter)
3. **Find the `ApplicationListener`** -- the class passed to `initialize()` in the launcher
4. **Trace `create()`** -- this initializes screens, loads assets, and sets the first screen
5. **Trace screen classes** -- look for `setScreen()` calls to map the screen flow
6. **Examine `render()` methods** -- contains game loop logic, update/draw cycles

### Identifying Network Communication

libGDX provides `com.badlogic.gdx.Net` for HTTP requests and TCP/UDP sockets. Search decompiled output for `sendHttpRequest`, `HttpRequest`, `Net.HttpResponseListener`, `Socket`, and `ServerSocket` to locate all network communication. Many libGDX apps also use OkHttp or Retrofit directly rather than the framework's built-in networking.

### Asset Analysis

libGDX games store assets in the APK's `assets/` directory in standard formats: texture atlases (`.atlas` + `.png`), Tiled maps (`.tmx` XML / `.tmj` JSON), BitmapFonts (`.fnt` + `.png`), skin files (`.json`), particle effects (`.p`), and standard audio formats. All are plaintext or standard binary -- no proprietary encryption.

Texture atlas `.atlas` files are plaintext indexes mapping sprite names to coordinates within the companion `.png` sheet. Sprite names (e.g., `player_idle`, `enemy_walk`) reveal game entity types. TMX maps contain level layout, spawn points, and gameplay configuration in readable XML.

## Hooking

libGDX apps use standard Java -- all Frida hooks target DEX-level Java methods:

### Intercept Screen Transitions

```javascript
Java.perform(function() {
    var Game = Java.use("com.badlogic.gdx.Game");

    Game.setScreen.implementation = function(screen) {
        console.log("[Screen] Switching to: " + screen.getClass().getName());
        this.setScreen(screen);
    };
});
```

### Intercept Network Requests

```javascript
Java.perform(function() {
    var Net = Java.use("com.badlogic.gdx.Net");
    var HttpRequest = Java.use("com.badlogic.gdx.Net$HttpRequest");

    HttpRequest.setUrl.implementation = function(url) {
        console.log("[HTTP] URL: " + url);
        this.setUrl(url);
    };

    HttpRequest.setContent.implementation = function(content) {
        console.log("[HTTP] Body: " + content);
        this.setContent(content);
    };
});
```

### Intercept Preferences (Local Storage)

libGDX uses `Preferences` for persistent key-value storage (wraps Android `SharedPreferences`):

```javascript
Java.perform(function() {
    var AndroidPreferences = Java.use("com.badlogic.gdx.backends.android.AndroidPreferences");

    AndroidPreferences.putString.implementation = function(key, val) {
        console.log("[Prefs] putString: " + key + " = " + val);
        return this.putString(key, val);
    };
});
```

### Intercept File I/O

```javascript
Java.perform(function() {
    var AndroidFileHandle = Java.use("com.badlogic.gdx.backends.android.AndroidFileHandle");

    AndroidFileHandle.readString.overload().implementation = function() {
        var content = this.readString();
        console.log("[File] Read: " + this.path() + " (" + content.length + " chars)");
        return content;
    };
});
```

### Enumerate Game Classes

Discover all loaded classes in the game's namespace to identify hook targets:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("com.targetgame") !== -1) {
                console.log("[Class] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

## Obfuscation

### R8 / ProGuard

libGDX release builds typically run through [R8/ProGuard](../../packers/r8-proguard.md), which minifies class and method names. The framework classes (`com.badlogic.gdx.*`) are usually kept unobfuscated via ProGuard rules, but game-specific classes get mangled names. Trace from known entry points (`ApplicationListener.create()`, `setScreen()`) to reconstruct class purposes.

### Native Library

The `libgdx.so` native library handles OpenGL ES calls, audio mixing, and buffer management. It rarely contains game-specific logic -- game code stays in Java/DEX. Analyze with [Ghidra](https://ghidra-sre.org/) only if investigating framework-level vulnerabilities.

## Malware Context

libGDX is primarily used for legitimate game development. Its appearance in malware is uncommon but follows specific patterns:

| Use Case | Details |
|----------|---------|
| Trojanized games | Legitimate libGDX games repackaged with malicious payloads injected into the DEX |
| Ad fraud | Games with excessive or hidden ad loading, click injection via WebView overlays |
| Data harvesting | Games collecting device identifiers, contacts, or location beyond gameplay needs |

libGDX malware is typically a legitimate game with malicious code added, rather than a purpose-built malicious application. The game serves as a vehicle for user engagement (retention) while background components perform the actual malicious activity. Analyze the non-game packages in the DEX (outside `com.badlogic.gdx.*` and the game's own namespace) for injected malicious classes.

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Standard DEX (Java/Kotlin) |
| Readability | High -- standard Java decompilation, framework APIs are well-documented |
| String extraction | Trivial -- standard DEX strings |
| Control flow recovery | Full -- standard Java decompilation |
| Patching | Standard APK patching (smali editing or jadx export) |
| Obfuscation ceiling | R8/ProGuard on game classes; framework classes stay readable |
| Overall difficulty | **Easy** |

libGDX apps are among the most straightforward to reverse engineer. The framework adds no abstraction barriers beyond standard Java -- no custom VM, no bytecode format, no asset encryption. The open-source framework code ([GitHub](https://github.com/libgdx/libgdx)) serves as a complete API reference. Analysis effort is equivalent to any standard Android Java application.

## References

- [libGDX -- Official Site](https://libgdx.com/)
- [libGDX -- GitHub](https://github.com/libgdx/libgdx)
- [libGDX Wiki](https://github.com/libgdx/libgdx/wiki)
- [jadx -- Dex to Java Decompiler](https://github.com/skylot/jadx)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
- [Ghidra -- NSA Reverse Engineering Framework](https://ghidra-sre.org/)
