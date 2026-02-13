# B4A (Basic4Android)

B4A is a RAD (Rapid Application Development) tool from Anywhere Software that compiles a Visual Basic-like language into standard Java bytecode. The resulting APK contains regular DEX files with fully decompilable Java classes -- jadx produces clean output with predictable naming patterns. From a reverse engineering perspective, B4A apps are among the easiest Android targets: no native code, no custom runtimes, no bytecode formats to decode. The entire application logic sits in standard Dalvik bytecode wrapped in B4A's generated class hierarchy.

B4A has become one of the most popular frameworks for commodity Android malware. Its drag-and-drop IDE requires no programming experience, making it accessible to low-skilled threat actors. The IRATA banking trojan, Copybara variants, and numerous SMS stealers targeting Middle Eastern and South Asian users are built with B4A.

## Architecture

B4A compiles BASIC source code through this pipeline:

```
B4A BASIC source (.b4a) → Java code generation → javac → DEX compilation → Standard APK
```

The output is a conventional Android APK with no embedded runtime, no interpreter, and no custom bytecode format. The generated Java code follows rigid structural patterns that make it immediately recognizable when decompiled.

### Generated Class Structure

| Class | Purpose |
|-------|---------|
| `b4a_main` | Main activity, entry point |
| `b4a_<modulename>` | Each B4A module becomes a class with this prefix |
| `anywheresoftware.b4a.BA` | Core orchestrator class -- manages events, lifecycle, module communication |
| `anywheresoftware.b4a.BALayout` | Layout management |
| `anywheresoftware.b4a.objects.*` | Wrapper classes for Android components (views, drawables, streams) |
| `anywheresoftware.b4a.phone.*` | Phone API wrappers (SMS, contacts, call log, telephony) |
| `anywheresoftware.b4a.net.*` | Networking wrappers (HTTP, FTP, SMTP) |

### Event Handler Naming Convention

B4A generates event handler methods using an underscore-delimited naming convention:

| B4A Source | Generated Java Method |
|------------|-----------------------|
| `Sub Activity_Create(FirstTime As Boolean)` | `_activity_create(boolean)` |
| `Sub Activity_Resume` | `_activity_resume()` |
| `Sub Activity_Pause(UserClosed As Boolean)` | `_activity_pause(boolean)` |
| `Sub Button1_Click` | `_button1_click()` |
| `Sub Timer1_Tick` | `_timer1_tick()` |

Methods containing an underscore are preserved during B4A's built-in obfuscation. Methods without an underscore get renamed in release (obfuscated) builds. This means event handlers and lifecycle methods always retain their original names, even in obfuscated samples.

## Identification

| Indicator | Location |
|-----------|----------|
| `anywheresoftware.b4a.*` | Package prefix in DEX -- core B4A runtime classes |
| `anywheresoftware.b4a.BA` | Central orchestrator class, present in every B4A app |
| `b4a_main` | Generated main activity class |
| `assets/*.bal` | B4A layout files (binary format) |
| `b4a_<name>` classes | Each B4A code module generates a class with this prefix |
| B4A library references | `anywheresoftware.b4a.objects.*`, `anywheresoftware.b4a.phone.*` |

```bash
unzip -l target.apk | grep -iE "(\.bal|anywheresoftware)"
```

Quick class check with jadx:

```bash
jadx --no-res -d output/ target.apk
grep -r "anywheresoftware.b4a" output/ | head -5
```

## Analysis Workflow

### Decompilation

Standard jadx decompilation works without any special tooling:

```bash
jadx -d decompiled/ target.apk
```

The decompiled output contains clean Java code. B4A's code generation produces straightforward, sequential logic without complex abstractions.

### Navigating Generated Code

1. **Start at `b4a_main`** -- this is the entry point, equivalent to the main Activity
2. **Look for `_activity_create`** -- this is where initialization logic runs (network setup, service starts, permission requests)
3. **Trace event handlers** -- `_button_click`, `_timer_tick`, `_httpjob_responsesuccess` reveal the app's behavior flow
4. **Check the `BA` class** -- `anywheresoftware.b4a.BA` orchestrates all module communication and event dispatching
5. **Search for `anywheresoftware.b4a.phone`** -- these wrappers handle SMS, contacts, call logs, and telephony operations

### Decompiled Code Patterns

B4A-generated code follows predictable patterns. A typical HTTP request in decompiled output:

```java
public void _httpjob_responsesuccess(Object response) {
    this._result = ((HttpJob) response).GetString();
    anywheresoftware.b4a.BA.Log("Response: " + this._result);
}
```

SMS operations appear as:

```java
public void _sendsms(String number, String body) {
    this._sms.Send(number, body);
}
```

### Obfuscation Handling

B4A's built-in obfuscation (enabled in release mode) renames subs that lack an underscore. Event handlers like `_activity_create` and `_button1_click` are never renamed because the underscore signals B4A to preserve them. The obfuscation is weak -- class structure, string literals, and API calls remain fully visible.

## Hooking

B4A apps use standard Java classes in DEX. All standard Android Frida hooks work without modification:

```javascript
Java.perform(function() {
    var ba = Java.use("anywheresoftware.b4a.BA");
    ba.LogImpl.implementation = function(tag, msg, logLevel) {
        console.log("[B4A Log] " + msg);
        this.LogImpl(tag, msg, logLevel);
    };
});
```

Hook specific module methods:

```javascript
Java.perform(function() {
    var main = Java.use("com.example.app.b4a_main");
    main._activity_create.implementation = function(firstTime) {
        console.log("[B4A] Activity_Create called, firstTime=" + firstTime);
        this._activity_create(firstTime);
    };
});
```

### Intercepting Network Operations

B4A apps commonly use the `HttpJob` class for networking:

```javascript
Java.perform(function() {
    var HttpJob = Java.use("anywheresoftware.b4a.http.HttpModule$HttpJob");
    HttpJob.Download.implementation = function(url) {
        console.log("[B4A HTTP] Download: " + url);
        this.Download(url);
    };
});
```

### Intercepting SMS Operations

For malware analysis, hooking SMS-related classes is critical:

```javascript
Java.perform(function() {
    var PhoneSms = Java.use("anywheresoftware.b4a.phone.PhoneSms");
    PhoneSms.Send.implementation = function(number, body) {
        console.log("[B4A SMS] To: " + number + " Body: " + body);
        this.Send(number, body);
    };
});
```

## SSL Pinning

B4A networking uses standard Java HTTP libraries (OkHttp or `HttpURLConnection`) under the hood. Standard Java-layer SSL bypass scripts work:

```javascript
Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[SSL] Bypassed for: " + host);
        return untrustedChain;
    };
});
```

No framework-specific bypass required. Objection's `android sslpinning disable` also works out of the box.

## Malware Context

B4A is one of the most prolific frameworks for commodity Android malware. The low barrier to entry -- a visual IDE with drag-and-drop components and BASIC syntax -- means threat actors with minimal programming skills can build functional malware.

### IRATA (Iranian Remote Access Trojan)

IRATA is the most documented B4A malware family. First discovered in August 2022 following smishing campaigns targeting Iranian users, it has since expanded to target users in Italy and other regions.

| Aspect | Details |
|--------|---------|
| Framework | B4A (Basic4Android) |
| Distribution | SMS phishing (smishing) with links to fake government websites |
| Capabilities | SMS interception, contact harvesting, call log collection, USSD execution |
| C2 | Firebase Cloud Messaging for command dispatch |
| Identification | `anywheresoftware.b4a.*` classes, `CallLogWrapper` for call log exfiltration |
| Analysis reference | [muha2xmad technical analysis](https://muha2xmad.github.io/malware-analysis/irata/) |

The decompiled IRATA code reveals `anywheresoftware.b4a.phone.*` wrapper classes used to collect call logs (date, type, duration, number), contacts (name, number, times contacted, email), and intercept SMS messages.

### Copybara / BRATA Variants

The BRATA banking trojan family includes variants built with the B4A/B4X suite. These use B4A's rapid development capabilities to quickly iterate on phishing overlays for banking apps.

### Common B4A Malware Patterns

| Category | Prevalence | Typical Behavior |
|----------|-----------|-----------------|
| SMS stealers | Very high | Intercept OTP codes, forward to C2 |
| Banking phishing | High | Overlay fake login screens, harvest credentials |
| RATs | Moderate | Remote device control via Firebase or raw TCP |
| Contact harvesters | High | Exfiltrate contact lists for spam campaigns |
| USSD fraud | Moderate | Execute USSD codes for airtime/balance theft |

### Regional Distribution

B4A malware is heavily concentrated in:

- **Iran** -- IRATA and related banking trojans distributed via smishing
- **Middle East** -- SMS stealers targeting Arabic-speaking users
- **South Asia** -- Commodity RATs and SMS interceptors targeting Indian and Pakistani users
- **North Africa** -- Low-sophistication spyware and contact harvesters

### Why B4A Appeals to Malware Authors

- **Zero programming barrier** -- BASIC syntax with visual IDE, drag-and-drop UI builder
- **Full Android API access** -- SMS, contacts, call logs, telephony, camera all accessible through B4A wrappers
- **Standard APK output** -- no unusual runtime dependencies that might trigger heuristic detection
- **Rapid iteration** -- hot-reload development via B4A Bridge companion app
- **Active community** -- B4X forums provide extensive tutorials and code snippets that malware authors repurpose

## RE Difficulty Assessment

| Aspect | Rating |
|--------|--------|
| Code format | Standard DEX (Java bytecode) |
| Decompilation | Near-perfect with jadx |
| String recovery | Full -- all string literals visible |
| Control flow | Clear, sequential, predictable patterns |
| Hooking | Standard Java hooks, high effectiveness |
| Patching | Easy -- smali modification or jadx + recompile |
| Obfuscation ceiling | Weak -- B4A's built-in obfuscation is minimal |
| Overall difficulty | **Easy** (rank 5/28) |

B4A apps are among the easiest Android targets to reverse engineer. The generated code is predictable, decompilation is clean, and all standard Android RE tools work without modification. The primary analysis effort is understanding B4A's naming conventions and class hierarchy, which are consistent across all B4A apps.

## References

- [B4A -- Anywhere Software](https://www.b4x.com/b4a.html)
- [B4A Core Libraries Source -- GitHub](https://github.com/AnywhereSoftware/B4A)
- [IRATA Technical Analysis -- muha2xmad](https://muha2xmad.github.io/malware-analysis/irata/)
- [IRATA -- Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/apk.irata)
- [Copybara Android Banking Trojan -- TineXta Cyber](https://www.tinextacyber.com/wp-content/uploads/2024/07/2406-CopyBara-Android.pdf)
- [Iranian Mobile Banking Malware Campaign -- Zimperium](https://zimperium.com/blog/unveiling-the-persisting-threat-iranian-mobile-banking-malware-campaign-extends-its-reach)
- [B4A Code Obfuscation -- B4X Forum](https://www.b4x.com/android/forum/threads/code-obfuscation.13773/)
