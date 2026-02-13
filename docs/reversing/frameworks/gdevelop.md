# GDevelop

GDevelop is an open-source, no-code/low-code 2D game engine that exports HTML5 games using Pixi.js for rendering. On Android, GDevelop games are wrapped in Apache Cordova (or Capacitor in newer exports), placing the entire game runtime and logic inside `assets/www/` as plaintext JavaScript. The engine compiles its visual event system into a single monolithic `gd.js` file -- the primary reverse engineering target.

## Architecture

### Engine Stack

| Layer | Component | Role |
|-------|-----------|------|
| **Game Logic** | `gd.js` | Compiled event sheets -- all game behavior in one file |
| **Runtime** | `gdjs-evtsext-*.js` | Extension behaviors (physics, pathfinding, etc.) |
| **Rendering** | `pixi.js` / `pixi-renderers/*.js` | Pixi.js 2D rendering (WebGL/Canvas) |
| **Audio** | `howler.min.js` | Audio playback via Howler.js |
| **Platform** | Cordova / Capacitor WebView | `android.webkit.WebView` hosting the HTML5 game |
| **Android Shell** | Cordova activity | Java bootstrap loading `index.html` |

### Compilation Model

GDevelop's visual event sheets (drag-and-drop logic blocks) compile into JavaScript functions at export time. Each scene's events become a set of functions in `gd.js`, with a consistent naming pattern:

- `gdjs.<SceneName>Code.func` -- main scene event functions
- `gdjs.<SceneName>Code.eventsList*` -- event handler arrays
- `gdjs.RuntimeScene` -- base scene management class
- `gdjs.RuntimeObject` -- base object class

The compiled output is verbose but structured. Variable names and scene/object names from the GDevelop editor are preserved as string identifiers in the generated code, making the logic straightforward to follow.

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/www/gd.js` | Compiled game logic (primary target) |
| `assets/www/pixi-renderers/*.js` | GDevelop's Pixi.js renderer modules |
| `assets/www/libs/pixi.js` or `assets/www/pixi.min.js` | Pixi.js rendering library |
| `assets/www/howler.min.js` | Howler.js audio library |
| `assets/www/index.html` | Entry point referencing `gd.js` |
| `assets/www/data.json` | Game project data (scenes, objects, resources) |
| `gdjs.RuntimeScene` in JS | GDevelop runtime namespace |
| `gdjs.evtTools.*` in JS | GDevelop event tools namespace |

Quick check:

```bash
unzip -l target.apk | grep -E "(gd\.js|gdjs|pixi-renderers)"
```

### Version Detection

```bash
unzip -p target.apk assets/www/gd.js | head -5
```

GDevelop exports include a version comment or `gdjs.projectData` object containing the engine version at the top of `gd.js`.

## Code Location

### Primary Files

| Path | Content | Size (typical) |
|------|---------|----------------|
| `assets/www/gd.js` | All compiled game logic, runtime classes, event handlers | 500KB -- 5MB+ |
| `assets/www/data.json` | Project metadata, scene definitions, object properties, resource lists | 50KB -- 1MB |
| `assets/www/gdjs-evtsext-*.js` | Extension code (physics, tween, pathfinding, etc.) | 10KB -- 100KB each |
| `assets/www/pixi-renderers/pixi.js` | Pixi.js rendering (standard, unmodified) | ~500KB |
| `assets/www/resources/` | Game assets (images, audio, fonts, JSON data) | Varies |

### Code Structure in gd.js

The `gd.js` file contains both the GDevelop runtime engine and the compiled game logic:

| Section | Content |
|---------|---------|
| `gdjs.RuntimeGame` | Game initialization, scene management, global variables |
| `gdjs.RuntimeScene` | Scene lifecycle, object management, layer system |
| `gdjs.RuntimeObject` | Base object class with position, angle, visibility |
| `gdjs.SpriteRuntimeObject` | Sprite-specific behavior (animations, collision) |
| `gdjs.Variable` | Variable system (game, scene, object scope) |
| `gdjs.evtTools` | Built-in event tools (camera, sound, storage, network) |
| `gdjs.<SceneName>Code` | Per-scene compiled event handlers |

## Extraction & Analysis

### Basic Extraction

```bash
unzip target.apk "assets/www/*" -d extracted/
```

### Code Beautification

`gd.js` is typically minified in production exports:

```bash
npx prettier --write extracted/assets/www/gd.js
```

### Identifying Game Logic

After beautification, search for scene-specific code:

```bash
grep -n "gdjs\..*Code\." extracted/assets/www/gd.js | head -50
```

GDevelop preserves original scene and object names as string literals. Search for game-specific identifiers:

```bash
grep -n "getObjects\|getVariables\|getLayer\|createObject" extracted/assets/www/gd.js | head -30
```

### Project Data Analysis

The `data.json` file contains the full project structure:

```bash
python3 -c "import json; d=json.load(open('extracted/assets/www/data.json')); print(json.dumps(d.get('properties',{}), indent=2))"
```

This reveals scene names, global variables, resource file paths, and extension dependencies.

### Network Communication

GDevelop's built-in network actions use `gdjs.evtTools.network`:

```bash
grep -n "evtTools\.network\|XMLHttpRequest\|fetch(\|\.send(" extracted/assets/www/gd.js
```

### Storage Analysis

GDevelop uses `gdjs.evtTools.storage` for local persistence (backed by `localStorage`):

```bash
grep -n "evtTools\.storage\|localStorage\|writeNumberInJSONFile\|writeStringInJSONFile" extracted/assets/www/gd.js
```

## Hooking Strategy

### WebView JavaScript Injection

Inject JavaScript through the Cordova WebView:

```javascript
Java.perform(function() {
    Java.choose("android.webkit.WebView", {
        onMatch: function(webview) {
            webview.evaluateJavascript(
                "var _origCreate = gdjs.RuntimeScene.prototype.createObject;" +
                "gdjs.RuntimeScene.prototype.createObject = function(name) {" +
                "  console.log('[GDevelop] Creating object: ' + name);" +
                "  return _origCreate.apply(this, arguments);" +
                "};",
                null
            );
        },
        onComplete: function() {}
    });
});
```

### Variable Monitoring

```javascript
Java.perform(function() {
    Java.choose("android.webkit.WebView", {
        onMatch: function(webview) {
            webview.evaluateJavascript(
                "var _origSetValue = gdjs.Variable.prototype.setNumber;" +
                "gdjs.Variable.prototype.setNumber = function(val) {" +
                "  console.log('[GDevelop] Variable set: ' + val);" +
                "  return _origSetValue.call(this, val);" +
                "};",
                null
            );
        },
        onComplete: function() {}
    });
});
```

### Scene Lifecycle Hooks

```javascript
Java.perform(function() {
    Java.choose("android.webkit.WebView", {
        onMatch: function(webview) {
            webview.evaluateJavascript(
                "var _origLoadScene = gdjs.RuntimeGame.prototype._doLoadScene;" +
                "gdjs.RuntimeGame.prototype._doLoadScene = function(name, data) {" +
                "  console.log('[GDevelop] Loading scene: ' + name);" +
                "  return _origLoadScene.apply(this, arguments);" +
                "};",
                null
            );
        },
        onComplete: function() {}
    });
});
```

### Direct JS Modification

As with all Cordova-wrapped games, direct modification is the simplest approach:

1. Extract `assets/www/` from APK
2. Edit `gd.js` or any other file
3. Repackage, re-sign, install

## Obfuscation & Protection

### Default State

GDevelop exports produce **unobfuscated** JavaScript by default. The compiled event code preserves:

- Scene names as string literals
- Object names as string identifiers
- Variable names in accessor calls
- Extension and behavior names

### Possible Protections

| Technique | Description | Bypass |
|-----------|-------------|--------|
| JavaScript minification | Name mangling via Terser/UglifyJS | Beautify -- structure still readable |
| javascript-obfuscator | Control flow flattening, string encoding | Standard JS deobfuscation tools |
| Cordova plugin protection | Native license checks via Cordova plugins | Hook Java layer |
| Custom encryption | Encrypted `data.json` or resources | Key must be in JS -- trace loading code |

In practice, GDevelop games rarely employ additional obfuscation beyond the default minification. The target audience (no-code developers) seldom adds custom protection layers.

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Plaintext JavaScript |
| Readability | High -- scene/object names preserved |
| String extraction | Trivial |
| Control flow recovery | Full (standard JS) |
| Patching | Trivial -- edit JS directly |
| Data modification | Trivial -- JSON project data |
| Obfuscation ceiling | Low -- rarely applied |
| Overall difficulty | **Easy** |

GDevelop games on Android are fully transparent. The compiled event system produces verbose, structured JavaScript that preserves the original scene and object names from the visual editor. Combined with the Cordova wrapper providing no additional protection, analysis requires only a text editor and a JavaScript beautifier.

## References

- [GDevelop Engine Source](https://github.com/4ian/GDevelop)
- [GDevelop Runtime (GDJS)](https://github.com/4ian/GDevelop/tree/master/GDJS/Runtime)
- [Pixi.js -- 2D Rendering Engine](https://github.com/pixijs/pixijs)
- [Howler.js -- Audio Library](https://github.com/goldfire/howler.js)
- [Apache Cordova](https://cordova.apache.org/)
- [GDevelop Documentation](https://wiki.gdevelop.io/)
