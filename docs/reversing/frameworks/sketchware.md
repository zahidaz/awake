# Sketchware / Sketchware Pro

Sketchware is a visual block-based Android IDE that runs on Android itself -- users build apps by dragging and connecting Scratch-like blocks directly on their phone. The block logic is compiled to standard Java bytecode and packaged as a conventional APK. There is no custom VM, no embedded interpreter, no proprietary bytecode format. The resulting APK decompiles cleanly with jadx like any other Android app.

Sketchware Pro is the community-maintained open-source fork ([GitHub](https://github.com/Sketchware-Pro/Sketchware-Pro)) that replaced the original after the original developers abandoned it. Pro adds custom block support, local library imports, Kotlin code blocks, AAB output, and a wider built-in library set. From a reversing perspective, apps built with either variant are functionally identical -- standard DEX with predictable class structures.

The low barrier to entry makes Sketchware attractive to unsophisticated threat actors. ASEC documented malicious apps built with Sketchware Pro performing file deletion, remote access, and APK dropper functions. The Arsink RAT campaign -- 1,200+ samples targeting 45,000 devices across 143 countries -- involved a developer who posted YouTube tutorials on how to build malware in Sketchware Pro before weaponizing the same skills.

## Architecture

### Compilation Pipeline

The block-to-APK pipeline runs entirely on-device:

| Stage | Output |
|-------|--------|
| **Block editor** | Project data stored as five flat files (`file`, `library`, `logic`, `resource`, `view`) in `/.sketchware/data/<project_id>/` |
| **Code generation** | `a.a.a.Jx` generates Java source for activities; `a.a.a.Lx` generates component and listener source; `a.a.a.Ix` generates `AndroidManifest.xml`; `a.a.a.Ox` generates XML layouts |
| **Java compilation** | Standard `javac` or `ecj` invocation inside the Sketchware Pro app |
| **DEX compilation** | `d8` / `dx` produces standard DEX |
| **APK packaging** | `aapt` + `apksigner`, zipaligned output |

The build system is exposed in the Sketchware Pro source via `a.a.a.ProjectBuilder`. The class `a.a.a.qq` is the registry for built-in library dependencies. The class `a.a.a.yq` manages all project file paths.

### Generated Code Structure

| Generated Element | Pattern |
|-------------------|---------|
| Main activity class | `MainActivity` (always the default first screen name) |
| Additional activities | User-named: `SettingsActivity`, `LoginActivity`, etc. |
| Layout XML for main | `activity_main.xml` (or `main.xml` in older builds) |
| Additional layout XML | `activity_<name>.xml` per screen |
| Package name | User-defined at project creation time -- no fixed prefix |

Activities extend `AppCompatActivity`. Sketchware does not bundle a proprietary base class -- all app logic lives in standard Android SDK classes. This makes it indistinguishable at the class-hierarchy level from a hand-written app.

### Built-in Library Registry

Sketchware Pro ships approximately 80 libraries inside its own APK that it can inject into user projects. The full registry is in [`mod/jbk/build/BuiltInLibraries.java`](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/main/app/src/main/java/mod/jbk/build/BuiltInLibraries.java). Key libraries that appear in built APKs when enabled:

| Library | Artifact |
|---------|----------|
| AppCompat | `androidx.appcompat:appcompat` |
| Material Components | `com.google.android.material:material:1.6.1` |
| RecyclerView | `androidx.recyclerview:recyclerview` |
| Glide | `com.github.bumptech.glide:glide:4.11.0` |
| OkHttp | `com.squareup.okhttp3:okhttp:3.9.1` |
| Gson | `com.google.code.gson:gson:2.8.7` |
| Lottie | `com.airbnb.android:lottie:3.4.0` |
| Firebase Auth | `com.google.firebase:firebase-auth` |
| Firebase Realtime DB | `com.google.firebase:firebase-database:19.3.1` |
| Firebase Storage | `com.google.firebase:firebase-storage` |
| Firebase Cloud Messaging | `com.google.firebase:firebase-messaging` |
| AdMob | `com.google.android.gms:play-services-ads` |
| Google Maps | `com.google.android.gms:play-services-maps` |
| Facebook Audience Network | `com.facebook.android:audience-network-sdk:5.9.0` |
| OneSignal | `com.onesignal:OneSignal:3.14.0` |
| CircleImageView | `de.hdodenhof:circleimageview` |
| Kotlin stdlib | `org.jetbrains.kotlin:kotlin-stdlib` |

Libraries are only bundled if the project explicitly enables them. A Sketchware app that uses no libraries contains only the standard Android SDK calls.

## Identification

There is no fixed package prefix, no embedded runtime class, and no mandatory string that marks every Sketchware APK. Identification relies on a combination of structural and behavioral indicators.

### Structural Indicators

| Indicator | Where to Look | Notes |
|-----------|---------------|-------|
| `MainActivity` as primary entry point | `AndroidManifest.xml` | Default and almost never renamed |
| `activity_main.xml` layout | `res/layout/` | Default layout name |
| No ProGuard / R8 processing | Class names, field names | Sketchware does not apply obfuscation by default |
| `testkey` signing certificate | APK signature block | Development builds signed with AOSP testkey before user configures a real keystore |
| Firebase dependencies | DEX package hierarchy | `com.google.firebase.*` present when Firebase blocks used |
| OkHttp 3.9.1 specifically | DEX | Version pinned in the built-in registry; distinctive version fingerprint |
| Glide 4.11.0 specifically | DEX | Same -- pinned version |
| Simple, flat activity structure | Decompiled Java | No dependency injection, no MVVM, no complex abstractions |
| User-facing strings hardcoded | `strings.xml` or inline Java | No localization, strings defined directly in blocks |

### Signing Certificate

Development builds (compiled via the Run button within Sketchware Pro) are signed with the AOSP `testkey`. This causes generic AV heuristics to flag them:

- Avast: `Android:Evo-gen [Trj]`
- BitDefender: `Android.Riskware.TestKey.rA`
- Ikarus: `Trojan.AndroidOS.Agent`

User-exported release builds use a custom keystore configured in the Sign/Export menu. A release-signed Sketchware APK has no distinguishing certificate -- it looks identical to any other self-signed Android app.

### Quick Shell Check

```bash
apksigner verify --print-certs target.apk | grep -i "subject\|issuer"
```

For `testkey`-signed builds, the subject and issuer will contain `Android Debug` or the AOSP testkey DN.

```bash
unzip -l target.apk | grep -E "^.*\.xml$" | head -20
```

Presence of `res/layout/activity_main.xml` with no other layout files strongly suggests a minimal Sketchware app.

```bash
jadx --no-res -d out/ target.apk 2>/dev/null
ls out/sources/
```

A Sketchware app with no obfuscation and simple block logic will have a flat package hierarchy with a small number of classes.

## Project File Format

On the device running Sketchware Pro, project data is stored in plain files (not an archive):

```
/.sketchware/data/<project_id>/
    file      -- file component configs
    library   -- enabled library declarations
    logic     -- block logic for all activities (serialized JSON-like format)
    resource  -- resource declarations (images, sounds, fonts)
    view      -- UI layout definitions
```

Exported backups use the `.swb` extension (Sketchware Backup) -- a ZIP archive containing those same files. The Sketchware Pro app can import `.swb` files to restore a project.

Block logic in the `logic` file describes the visual blocks as a structured tree. The generator classes (`Jx`, `Lx`, `Ox`) parse this format and emit Java and XML source. The format is not encrypted or obfuscated.

## Analysis Workflow

### Decompilation

Standard jadx produces clean output -- no special tooling needed:

```bash
jadx -d decompiled/ target.apk
```

Because Sketchware applies no obfuscation, the decompiled output is verbose and readable. All variable names, method names, and string literals are intact.

### Navigating Generated Code

1. **Start at `MainActivity`** -- this is always the entry point. Find it in `AndroidManifest.xml` under the `MAIN` / `LAUNCHER` intent filter.
2. **Read `onCreate()`** -- Sketchware initializes all views, sets up listeners, and configures components here. Everything the block editor built is visible as sequential method calls.
3. **Check for Firebase initialization** -- if Firebase blocks were used, `FirebaseApp.initializeApp(this)` appears in `onCreate()` and Firebase DB / Auth / FCM references follow.
4. **Look for network calls** -- OkHttp usage appears as `new OkHttpClient()` with explicit `Request` and `Call` objects. All URLs are hardcoded string literals.
5. **Trace event handlers** -- button click handlers, timer callbacks, and lifecycle methods are named after the variable names the user assigned in the block editor (e.g., `btn_login.setOnClickListener(...)`, `textview_result.setText(...)`).
6. **Check permissions in manifest** -- the manifest lists exactly the permissions the user added via blocks. No permission is added automatically beyond what the blocks require.

### Decompiled Code Pattern

A typical Sketchware-generated `onCreate()` for a login screen:

```java
@Override
public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    edittext_username = (EditText) findViewById(R.id.edittext_username);
    edittext_password = (EditText) findViewById(R.id.edittext_password);
    btn_login = (Button) findViewById(R.id.btn_login);
    textview_status = (TextView) findViewById(R.id.textview_status);

    btn_login.setOnClickListener(new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            String user = edittext_username.getText().toString();
            String pass = edittext_password.getText().toString();
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("http://192.168.1.1/login.php?u=" + user + "&p=" + pass)
                .build();
            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    final String body = response.body().string();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            textview_status.setText(body);
                        }
                    });
                }
                @Override
                public void onFailure(Call call, IOException e) {}
            });
        }
    });
}
```

The variable names (`edittext_username`, `btn_login`) are the exact names the user typed in the Sketchware block editor. C2 URLs and API endpoints are always inline string literals -- never encrypted, never fetched dynamically unless the user explicitly added those blocks.

### Obfuscation

Sketchware applies no obfuscation. There is no R8, no ProGuard, no string encryption. All code ships with the variable names assigned in the block editor. The only "obfuscation" is the default `testkey` signing causing AV heuristics to fire -- which is not intentional protection.

Sketchware Pro users can import external libraries that are pre-obfuscated (e.g., commercial SDKs), and can add raw Java code blocks that hand-write obfuscated logic, but the Sketchware framework itself contributes no obfuscation.

## Hooking

All standard Android Java hooks work without modification:

### Intercept OkHttp Requests

```javascript
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");

    var RealCall = Java.use("okhttp3.RealCall");
    RealCall.execute.implementation = function() {
        console.log("[OkHttp] URL: " + this.request().url().toString());
        return this.execute();
    };
});
```

### Intercept Firebase Database Writes

```javascript
Java.perform(function() {
    var DatabaseReference = Java.use("com.google.firebase.database.DatabaseReference");
    DatabaseReference.setValue.overload("java.lang.Object").implementation = function(value) {
        console.log("[Firebase DB] setValue: " + JSON.stringify(value));
        return this.setValue(value);
    };
});
```

### Intercept SMS Sending

Sketchware does not provide a built-in SMS block in the standard edition. Users who send SMS call Android's `SmsManager` directly via a Java code block:

```javascript
Java.perform(function() {
    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.implementation = function(dest, sc, text, sentIntent, deliveredIntent) {
        console.log("[SMS] To: " + dest + " Body: " + text);
        this.sendTextMessage(dest, sc, text, sentIntent, deliveredIntent);
    };
});
```

## Sketchware vs. Sketchware Pro

| Aspect | Sketchware (original) | Sketchware Pro |
|--------|----------------------|----------------|
| Status | Abandoned (~2020) | Actively maintained, open source |
| Package | `com.besome.sketch` | `com.sketchware.remod` |
| Source code | Closed source | [Public on GitHub](https://github.com/Sketchware-Pro/Sketchware-Pro) |
| Custom blocks | No | Yes |
| Local libraries | No | Yes (import `.jar` / `.aar`) |
| Kotlin support | No | Yes (Java code blocks with Kotlin) |
| AAB output | No | Yes (minApi26 build) |
| Built-in library count | ~4 (AppCompat, Firebase, AdMob, Maps) | ~80+ |
| Android Studio export | Yes (zip) | Yes (zip) |
| Free | Yes | Yes |

Generated APK output from both variants is functionally identical -- standard Android structure, same class patterns, same absence of obfuscation. The distinction matters for identifying which tool built the IDE artifact on a device, not for analyzing the built APK.

## Malware Context

Sketchware and Sketchware Pro attract low-to-moderate skill threat actors. The block interface removes programming barriers, the Firebase integration is one-click, and the Sketchware community provides extensive tutorials that malware authors repurpose.

### Arsink / Spider-RAT

The most documented Sketchware-built malware family. First collected August 2023, initially analyzed by ASEC as "Arsink4Rat" with a variant called Spider-RAT distributed through Telegram. Zimperium's 2024 analysis tracked the campaign to 1,216 unique APK samples, 317 Firebase C2 endpoints, and approximately 45,000 infected devices across 143 countries.

The developer posted YouTube tutorials demonstrating Sketchware Pro app development before using the same workflow to build the RAT.

| Aspect | Details |
|--------|---------|
| Builder | Sketchware Pro |
| Distribution | Telegram channels, impersonation of Google / WhatsApp / YouTube |
| C2 | Firebase Realtime Database + Firebase Storage; Google Apps Script for large file uploads to Drive |
| Capabilities | SMS harvest (including OTP), call logs, contacts, microphone recording, photo exfiltration, file ops, device control (flashlight, wallpaper, vibration, TTS), phone call initiation, external storage wipe |
| Persistence | Foreground service + hidden launcher icon |
| Detection | `Trojan/Arsink` (AhnLab), `Android.Trojan.Arsink` variants |
| Analysis | [Zimperium -- The Rise of Arsink RAT](https://zimperium.com/blog/the-rise-of-arsink-rat), [ASEC trend report](https://asec.ahnlab.com/en/85089/), [ASEC Korean deep-dive](https://asec.ahnlab.com/ko/91275/) |

### ASEC Documented Categories

ASEC identified four categories of malicious Sketchware-built apps beyond Arsink:

| Category | Behavior |
|----------|----------|
| File deletion | Delete files from SD card and system paths |
| RAT / remote control | Remote shell, file access, device control |
| Game system manipulation | Cheat tools or rigged games used as lures |
| Unnecessary / adware | Aggressive ad display, unwanted installs |

### Why Sketchware Appeals to Malware Authors

- **Zero programming requirement** -- block interface, no Java knowledge needed
- **Full Firebase integration in one click** -- instant C2 with no server infrastructure
- **Android Studio export** -- prototype in Sketchware, then move to Studio for advanced features
- **Active tutorial ecosystem** -- thousands of YouTube and blog tutorials covering dangerous APIs
- **No attribution metadata** -- unlike App Inventor, Sketchware does not embed author email in the package name

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Standard DEX (Java bytecode) |
| Decompilation | Clean with jadx -- near-complete recovery |
| String recovery | Full -- all literals plaintext |
| Control flow | Sequential, predictable, minimal abstractions |
| Hooking | Standard Java hooks, high effectiveness |
| Patching | Easy -- smali edit or jadx + recompile |
| Obfuscation ceiling | None -- framework applies no obfuscation |
| Overall difficulty | **Very Easy** |

The primary challenge with Sketchware apps is not reverse engineering difficulty -- it is recognizing the app as Sketchware-built in the first place, since there is no mandatory runtime fingerprint. Once identified, analysis is straightforward.

## References

- [Sketchware Pro -- GitHub](https://github.com/Sketchware-Pro/Sketchware-Pro)
- [Sketchware Pro -- Official Site](https://sketchware.pro/)
- [Sketchware Pro Built-in Libraries Source](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/main/app/src/main/java/mod/jbk/build/BuiltInLibraries.java)
- [Zimperium -- The Rise of Arsink RAT](https://zimperium.com/blog/the-rise-of-arsink-rat)
- [ASEC -- Trend Report: Malicious Apps and Distribution Tools](https://asec.ahnlab.com/en/85089/)
- [ASEC -- Sketchware-based Malware Analysis (Korean)](https://asec.ahnlab.com/ko/91275/)
- [jadx -- Dex to Java Decompiler](https://github.com/skylot/jadx)
