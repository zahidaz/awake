# RPG Maker MV/MZ

RPG Maker MV and MZ produce HTML5 games using Pixi.js for rendering and a JavaScript-based engine for game logic. On Android, these games are wrapped in Apache Cordova (or a similar WebView shell), placing all game code and assets under `assets/www/` as plaintext JavaScript. The entire engine, plugin system, and game data ship uncompiled -- making RPG Maker one of the most transparent frameworks to reverse engineer on Android.

## Architecture

### Engine Variants

| Version | Rendering | Runtime | Android Wrapper | Release |
|---------|-----------|---------|-----------------|---------|
| **RPG Maker MV** | Pixi.js v4 | Custom JS engine | Cordova (Crosswalk WebView on older builds) | 2015 |
| **RPG Maker MZ** | Pixi.js v5 (PIXI.js updated) | Refactored JS engine with effekseer support | Cordova | 2020 |

Both versions share the same fundamental architecture on Android:

| Layer | Component | Role |
|-------|-----------|------|
| **Game Logic** | `rpg_managers.js`, `rpg_objects.js`, `rpg_scenes.js` | Core game systems (save/load, battle, map, events) |
| **Engine Core** | `rpg_core.js` | Base classes, bitmap handling, input, rendering setup |
| **Rendering** | `pixi.js` / `pixi.min.js` | 2D WebGL/Canvas rendering via Pixi.js |
| **Plugins** | `js/plugins/*.js` | Developer and third-party extensions |
| **Data** | `data/*.json` | Maps, events, actors, items, skills, enemies, tilesets |
| **Android Shell** | Cordova WebView | `android.webkit.WebView` hosting the HTML5 game |

### Execution Flow

The Android app loads `assets/www/index.html` in a Cordova WebView. This HTML file loads `pixi.js`, the RPG Maker core scripts, plugins, and then boots the game. All execution happens within the WebView's JavaScript engine -- there are no native components beyond the Cordova shell.

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/www/js/rpg_core.js` | RPG Maker engine core |
| `assets/www/js/rpg_managers.js` | Game manager classes (SaveManager, BattleManager, etc.) |
| `assets/www/js/rpg_objects.js` | Game object definitions (Game_Actor, Game_Map, etc.) |
| `assets/www/js/rpg_scenes.js` | Scene management (Scene_Title, Scene_Battle, etc.) |
| `assets/www/js/rpg_sprites.js` | Sprite rendering classes |
| `assets/www/js/rpg_windows.js` | UI window classes |
| `assets/www/js/plugins.js` | Plugin loader configuration |
| `assets/www/js/plugins/` | Plugin directory |
| `assets/www/data/*.json` | Game data files (JSON) |
| `assets/www/index.html` | Entry point HTML |
| `assets/www/js/pixi.js` or `assets/www/js/libs/pixi.js` | Pixi.js rendering library |

Quick check:

```bash
unzip -l target.apk | grep -E "(rpg_core|rpg_managers|rpg_objects|rpg_scenes)"
```

### MV vs MZ Differentiation

| Feature | MV | MZ |
|---------|-----|-----|
| `rpg_core.js` header | `Utils.RPGMAKER_NAME = "MV"` | `Utils.RPGMAKER_NAME = "MZ"` |
| Pixi version | v4.x | v5.x |
| `js/libs/effekseer.min.js` | Absent | Present (particle effects) |
| `rmmz_*.js` naming | Not used | Some builds use `rmmz_core.js`, `rmmz_managers.js`, etc. |

## Code Location

All game logic is plaintext JavaScript in `assets/www/js/`:

| File | Content |
|------|---------|
| `rpg_core.js` | Base engine classes: `Bitmap`, `Graphics`, `Input`, `TouchInput`, `Tilemap` |
| `rpg_managers.js` | `DataManager`, `BattleManager`, `AudioManager`, `SceneManager`, `PluginManager` |
| `rpg_objects.js` | `Game_System`, `Game_Map`, `Game_Player`, `Game_Actor`, `Game_Enemy`, `Game_Party` |
| `rpg_scenes.js` | `Scene_Boot`, `Scene_Title`, `Scene_Map`, `Scene_Battle`, `Scene_Menu`, `Scene_Shop` |
| `rpg_sprites.js` | `Sprite_Character`, `Sprite_Battler`, `Sprite_Animation` |
| `rpg_windows.js` | `Window_Base`, `Window_Message`, `Window_MenuCommand`, `Window_ShopBuy` |
| `plugins.js` | Plugin configuration array (load order, parameters) |
| `plugins/*.js` | Individual plugin files |

Game data is stored as JSON in `assets/www/data/` -- `Map*.json` (map layouts, events), `Actors.json`, `Enemies.json`, `Items.json`, `Skills.json`, `Weapons.json`, `Armors.json`, `CommonEvents.json`, and `System.json` (game configuration, encryption key, starting party).

## Extraction & Analysis

### Basic Extraction

```bash
unzip target.apk "assets/www/*" -d extracted/
```

The extracted `assets/www/` directory is a complete, functional web application. It can be opened directly in a desktop browser for analysis and debugging:

```bash
cd extracted/assets/www/
python3 -m http.server 8080
```

### Code Analysis

The JavaScript is typically unminified or lightly minified. RPG Maker ships its engine files in readable form:

```bash
npx prettier --write extracted/assets/www/js/*.js
grep -rn "http\|api\|token\|key\|secret\|password\|eval\|Function(" extracted/assets/www/js/
```

Plugins in `assets/www/js/plugins/` are standalone JavaScript files and the primary location for custom developer logic. The `plugins.js` file lists all loaded plugins with their parameters and load order.

## Asset Encryption

### RPG Maker MV/MZ Encryption System

RPG Maker MV and MZ include a built-in asset encryption feature that XOR-encrypts image (`.rpgmvp` / `.png_`) and audio (`.rpgmvo` / `.ogg_`) files. The encryption is weak by design:

- Uses a 16-byte encryption key stored in `System.json` as the `encryptionKey` field
- Only the first 16 bytes of each file are XORed with the key
- The rest of the file is unmodified

Extraction of the key:

```bash
grep -o '"encryptionKey":"[^"]*"' extracted/assets/www/data/System.json
```

### Decryption

The decryption logic is in `rpg_core.js` under `Decrypter`:

```bash
grep -A 20 "Decrypter" extracted/assets/www/js/rpg_core.js
```

Dedicated decryption tools:

- [Petschko's RPG Maker MV Decrypter](https://github.com/AtelierMizworworker/rpg-maker-mv-decrypter) and similar forks
- Manual decryption: read the 16-byte key from `System.json`, XOR the first 16 bytes of each encrypted file, restore original file headers

The encryption provides no meaningful security. The key is plaintext in the APK, the algorithm is XOR on a 16-byte prefix, and the decryption routine ships in the game's own JavaScript.

## Hooking Strategy

### WebView JavaScript Injection

Since RPG Maker runs inside a Cordova WebView, inject JavaScript through the WebView interface:

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        this.loadUrl(url);
        this.evaluateJavascript(
            "console.log(JSON.stringify($dataSystem));",
            null
        );
    };
});
```

### Hooking Game State

RPG Maker stores all game state in global objects (`$gameVariables`, `$gameParty`, `$dataSystem`). Inject into the WebView to monitor or modify:

```javascript
Java.perform(function() {
    Java.choose("android.webkit.WebView", {
        onMatch: function(webview) {
            webview.evaluateJavascript(
                "var _origSetValue = Game_Variables.prototype.setValue;" +
                "Game_Variables.prototype.setValue = function(id, val) {" +
                "  console.log('[RPG] Variable ' + id + ' = ' + val);" +
                "  _origSetValue.call(this, id, val);" +
                "};" +
                "var _origSave = DataManager.saveGame;" +
                "DataManager.saveGame = function(savefileId) {" +
                "  console.log('[RPG] Save slot=' + savefileId + ' gold=' + $gameParty.gold());" +
                "  return _origSave.call(this, savefileId);" +
                "};",
                null
            );
        },
        onComplete: function() {}
    });
});
```

### Direct JS Modification

The simplest approach is modifying the JavaScript files directly:

1. Extract `assets/www/js/` from APK
2. Edit any `.js` file (engine, plugins, or add new files)
3. Repackage APK with modified files
4. Re-sign and install

No compilation step is needed. The WebView executes whatever JavaScript is present.

## Plugin System & Obfuscation

Plugins extend the engine by overriding prototype methods on core classes, and are the primary location for DRM, encryption, anti-cheat, in-app purchase, and analytics logic. Each plugin is a standalone JS file -- analyze `plugins.js` for the load manifest, then read each plugin directly.

| Technique | Description | Bypass |
|-----------|-------------|--------|
| JavaScript minification | Variable/function name mangling | Beautify + analyze |
| Plugin obfuscation | javascript-obfuscator / Jscrambler on plugin JS | Standard deobfuscation tools |
| Custom encryption | Additional encryption layer on data JSONs | Key is in the JS -- trace `DataManager` |
| Cordova plugin protection | Native Cordova plugins for license checks | Hook Java layer |

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Plaintext JavaScript |
| Readability | High -- typically unminified engine code |
| String extraction | Trivial |
| Control flow recovery | Full (standard JS) |
| Patching | Trivial -- edit JS directly, no compilation |
| Data modification | Trivial -- JSON game data |
| Asset encryption | Weak -- XOR with plaintext key |
| Overall difficulty | **Easy** |

RPG Maker MV/MZ games on Android are effectively open-source applications. The engine ships readable JavaScript, game data is JSON, asset encryption is a 16-byte XOR with the key in plaintext, and the entire application runs inside a WebView that accepts arbitrary JavaScript injection. Analysis effort is minimal -- the primary challenge is navigating the volume of game data and plugin code rather than defeating any protection mechanism.

## References

- [RPG Maker MV CoreScripts](https://github.com/rpgtkool/RPGMakerMV)
- [RPG Maker MZ CoreScripts](https://github.com/rpgtkool/RPGMakerMZ)
- [Petschko's RPG Maker MV/MZ File Decrypter](https://github.com/AtelierMizworworker/rpg-maker-mv-decrypter)
- [RPG Maker MV Plugin Documentation](https://rpgmaker.fandom.com/wiki/RPG_Maker_MV)
- [Pixi.js -- 2D Rendering Engine](https://github.com/pixijs/pixijs)
- [Apache Cordova](https://cordova.apache.org/)
