# Intent Hijacking

Intercepting or redirecting intents meant for another app component. Possible when an app sends implicit intents or exports components without proper protection. The attacker's app registers to handle the same intent and receives data meant for the legitimate component.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | None (exploits component export misconfiguration) |
    | Condition | Target app uses implicit intents or exports components without restrictions |

## Variants

### Implicit Intent Interception

When an app sends an implicit intent (no target component specified), Android resolves it to any matching component. If a malicious app declares a matching `<intent-filter>`, it can receive the intent.

```xml
<activity android:name=".MaliciousActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.target.app.CUSTOM_ACTION" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

If the target app sends `new Intent("com.target.app.CUSTOM_ACTION")` without specifying a component, the system may route it to the malicious activity. If multiple handlers exist, the user sees a chooser dialog (which social engineering can handle).

### Activity Hijacking via `startActivityForResult`

When an app starts an implicit activity expecting a result, the malicious activity can return crafted data:

1. Target app calls `startActivityForResult()` with implicit intent
2. Malicious activity catches the intent
3. Malicious activity reads any extras (potentially sensitive data)
4. Malicious activity returns a crafted result to influence the caller's behavior

### Exported Component Abuse

Components declared with `android:exported="true"` (or with an intent filter, which implies export on API < 31) can be started by any app:

```java
Intent intent = new Intent();
intent.setComponent(new ComponentName("com.target.app", "com.target.app.InternalActivity"));
startActivity(intent);
```

This can reach activities not designed for external use: admin panels, debug screens, data viewers.

### Intent Redirection

A more powerful variant where a vulnerable app is tricked into launching its own non-exported components on behalf of the attacker. [Oversecured's systematic research](https://blog.oversecured.com/Android-Access-to-app-protected-components/) found this in more than 80% of analyzed apps. The attack flow:

1. Attacker sends an intent to an exported activity that accepts an "inner intent" parameter
2. The exported activity extracts the inner intent and calls `startActivity()` with it
3. Since the call originates from within the app's own process, non-exported components are reachable

This is particularly dangerous because it grants access to content providers, WebViews, and internal activities that were never designed for external interaction. [Oversecured's Samsung research](https://blog.oversecured.com/Two-weeks-of-securing-Samsung-devices-Part-1/) used this to access system-level components on Samsung devices, and their [Google apps audit](https://blog.oversecured.com/Oversecured-Apps-Care-Part-1-Vulnerability-disclosure-of-225-Google-apps/) found widespread intent redirection across 225 Google applications.

### Arbitrary Code Execution via Package Contexts

[Oversecured documented](https://blog.oversecured.com/Android-arbitrary-code-execution-via-third-party-package-contexts) how Android's package context resolution can be exploited for arbitrary code execution. By manipulating how Android resolves and loads code from third-party package contexts, an attacker can execute arbitrary code within the target app's process, inheriting all its permissions and data access.

### Service Hijacking

An implicit intent to bind a service can be intercepted by a malicious service. The malicious service then receives all IPC calls meant for the legitimate service.

On Android 5.0+, implicit intents to services throw an exception, forcing explicit binding. This largely eliminates this variant on modern devices.

### Ordered Broadcast Interception

See [Broadcast Theft](broadcast-theft.md) for broadcast-specific interception.

## Real-World Impact

| Vulnerability Type | Example |
|-------------------|---------|
| OAuth redirect interception | Malicious app registers for the OAuth callback URI scheme, stealing authorization codes |
| Payment intent interception | Intercepting payment processing intents to redirect to attacker-controlled handlers |
| File sharing interception | Registering for `ACTION_SEND` to capture files shared between apps |
| Deep link hijacking | See [Deep Link Exploitation](deep-link-exploitation.md) |

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 5.0 (API 21) | Implicit intents to services throw `IllegalArgumentException` | Does not affect activities or broadcast receivers |
| Android 12 (API 31) | Components with intent filters must explicitly declare `android:exported` | Developers often set `exported="true"` to resolve build errors |
| Android 12+ | `PendingIntent` mutability must be declared (`FLAG_MUTABLE` / `FLAG_IMMUTABLE`) | Apps requiring `FLAG_MUTABLE` (notifications, MediaSession) remain vulnerable if base intent is not fully specified |

## Detection During Analysis

??? example "Static Indicators"

    - Implicit intents sent with sensitive data in extras
    - Components with `android:exported="true"` that handle sensitive operations
    - Activities without `android:permission` protection that accept external input
    - `PendingIntent` creation without `FLAG_IMMUTABLE`
    - Custom URI schemes without proper validation
    - Activities that extract and launch "inner intents" from extras (intent redirection)

??? example "Dynamic Indicators"

    - Exported activities reachable via `adb shell am start` that expose internal functionality
    - PendingIntents intercepted via notification or widget that accept modified base intents
    - Implicit intents routed to unexpected handler apps

[Oversecured's interception of implicit intents guide](https://blog.oversecured.com/Interception-of-Android-implicit-intents/) provides detailed technical coverage of implicit intent resolution mechanics and exploitation patterns.

## Pending Intent Vulnerabilities

A `PendingIntent` wraps an intent and grants the recipient permission to execute it as if it came from the original sender, with the sender's identity and permissions. When a `PendingIntent` is created as mutable (`FLAG_MUTABLE`), the recipient can modify the base intent before executing it -- changing the target component, adding extras, or altering the action.

### Attack Flow

1. A privileged app (e.g., system service, banking app) creates a `PendingIntent` for a notification action, widget update, or `MediaSession` callback
2. The `PendingIntent` is delivered to a less-privileged context -- a notification visible to all apps, a widget host, or an IPC call
3. The attacker's app receives or intercepts the `PendingIntent`
4. If the `PendingIntent` is mutable and was created with an implicit or empty base intent, the attacker fills in or modifies the intent fields
5. The attacker calls `PendingIntent.send()` with a modified intent
6. Android executes the modified intent under the original sender's identity, with all of the sender's permissions

### Why This Is Dangerous

The `PendingIntent` carries the sender's UID and permission set. When the attacker triggers it with a modified intent, the system treats it as an action by the original app. This means:

- If the sender holds `MANAGE_EXTERNAL_STORAGE`, the attacker can read/write arbitrary files
- If the sender is a system app, the attacker can launch non-exported system components
- If the sender holds `INTERNET` and the attacker doesn't, the attacker can exfiltrate data through the sender's network access

### Vulnerable Patterns

```java
PendingIntent pi = PendingIntent.getActivity(
    context, 0, new Intent(), PendingIntent.FLAG_MUTABLE
);
```

An empty base intent with `FLAG_MUTABLE` is the worst case. The attacker has full control over the intent that gets executed under the sender's identity.

A safer pattern uses `FLAG_IMMUTABLE` and a fully specified explicit intent:

```java
Intent explicit = new Intent(context, SpecificActivity.class);
explicit.setPackage("com.myapp");
PendingIntent pi = PendingIntent.getActivity(
    context, 0, explicit, PendingIntent.FLAG_IMMUTABLE
);
```

### Research References

[Oversecured's PendingIntent research](https://blog.oversecured.com/Android-Exploring-the-PendingIntent-Vulnerabilities/) documented this class of vulnerability across major Android apps, finding mutable PendingIntents with empty or implicit base intents in system components, OEM apps, and popular third-party applications. Google's own [security bulletin](https://source.android.com/docs/security/bulletin) has patched multiple PendingIntent issues in system services.

Android 12 (API 31) requires explicit mutability declaration (`FLAG_MUTABLE` or `FLAG_IMMUTABLE`), which forces developers to consciously decide. However, apps that need mutable PendingIntents (e.g., for inline reply in notifications, `MediaSession` callbacks) remain vulnerable if the base intent is not fully specified.

## Families Using This Technique

| Family | Technique | Target |
|--------|-----------|--------|
| [Anatsa](../malware/families/anatsa.md) | Abuses exported activities in banking apps to launch internal transfer screens | European banking apps |
| [Vultur](../malware/families/vultur.md) | Exploits exported components to trigger screen recording and keylogging setup | Banking and crypto apps |
| [SpyNote](../malware/families/spynote.md) | Launches exported activities of target apps to extract stored data and credentials | Enterprise and banking apps |
| [Cerberus](../malware/families/cerberus.md) | Intercepts OAuth redirect intents by registering competing intent filters for custom URI schemes | Banking apps using OAuth flows |
| [SharkBot](../malware/families/sharkbot.md) | Hijacks Automated Transfer System flows by injecting intents into banking app exported components | European banking apps |
| [Joker](../malware/families/joker.md) | Intercepts SMS intents and notification listeners to steal OTPs and subscription confirmations | Premium SMS services |

## Testing for Intent Vulnerabilities

### Enumerating Exported Components with Drozer

Drozer is the standard tool for auditing Android IPC attack surfaces. Install it on a test device or emulator and connect via ADB.

List all exported activities:

```bash
dz> run app.activity.info -a com.target.app -u
```

List all exported services:

```bash
dz> run app.service.info -a com.target.app -u
```

List all exported broadcast receivers:

```bash
dz> run app.broadcast.info -a com.target.app -u
```

List all exported content providers:

```bash
dz> run app.provider.info -a com.target.app -u
```

### Testing Intent Injection

Launch an exported activity with crafted extras:

```bash
dz> run app.activity.start --component com.target.app com.target.app.InternalActivity \
    --extra string secret_data "injected_value"
```

Send an intent to an exported broadcast receiver:

```bash
dz> run app.broadcast.send --action com.target.app.SENSITIVE_ACTION \
    --extra string token "attacker_token"
```

### Checking for Intent Redirection

Search the decompiled source for activities that extract an intent from extras and launch it:

```java
Intent inner = getIntent().getParcelableExtra("next_intent");
startActivity(inner);
```

This pattern allows an attacker to send any intent as the `next_intent` extra, and the vulnerable app will launch it from its own process, reaching non-exported components.

### PendingIntent Audit

Search the codebase for `PendingIntent` creation and check:

1. Is `FLAG_MUTABLE` used? If so, is the base intent fully explicit (component and package set)?
2. Is the base intent empty (`new Intent()`)? This is exploitable.
3. Is the `PendingIntent` exposed through notifications, widgets, or IPC? These are reachable by attackers.

### ADB-Based Quick Tests

Without Drozer, use ADB directly to probe exported components:

```bash
adb shell am start -n com.target.app/.ExportedActivity \
    --es sensitive_key "test_value"

adb shell am broadcast -a com.target.app.CUSTOM_ACTION \
    --es data "injected"

adb shell am startservice -n com.target.app/.ExportedService
```

If these commands successfully trigger functionality that should be internal-only, the app has an intent hijacking vulnerability.
