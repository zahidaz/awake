# BIND_ACCESSIBILITY_SERVICE

The single most powerful permission in Android malware. An accessibility service can observe and interact with every element on screen, read notifications, perform gestures, and type text into any field. Modern banking trojans treat this as the primary goal: once granted, full device takeover is possible without any other permission.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_ACCESSIBILITY_SERVICE` |
| Protection Level | `signature` |
| Grant Method | Settings > Accessibility > toggle on |
| Introduced | API 16 (Android 4.1) |

The `signature` protection level means only the system can bind to an accessibility service. The app declares the service in its manifest; the user enables it manually through system settings. No runtime permission dialog appears. Android shows a full-screen warning explaining the access being granted.

## What It Enables

An accessibility service receives `AccessibilityEvent` callbacks and can use `AccessibilityNodeInfo` to traverse and interact with the UI tree of any foreground app.

### Capabilities

| Capability | API | Impact |
|-----------|-----|--------|
| Read screen content | `AccessibilityNodeInfo.getText()` | Keylogging, credential theft |
| Perform clicks | `performAction(ACTION_CLICK)` | Auto-grant permissions, confirm installs |
| Perform gestures | `GestureDescription` (API 24+) | Swipe, scroll, interact with any UI |
| Fill text fields | `Bundle(ACTION_SET_TEXT)` | Inject text into any input |
| Read notifications | `FLAG_RETRIEVE_INTERACTIVE_WINDOWS` | OTP interception |
| Capture screen | `takeScreenshot()` (API 30+) | Screenshot any app |
| Control display | `GLOBAL_ACTION_LOCK_SCREEN` (API 28+) | Lock screen to hide activity |
| Enumerate windows | `getWindows()` | Detect which app is in foreground |

### Effective Permission Escalation

With accessibility alone, malware can:

- Grant itself other permissions by navigating to Settings > Apps and clicking "Allow"
- Install additional APKs by clicking through install dialogs
- Disable Play Protect by navigating to Play Store settings
- Prevent its own uninstall by detecting Settings navigation and pressing Back/Home
- Perform on-device fraud (ODF) by operating banking apps directly

## Abuse in Malware

Nearly every modern Android banking trojan requires accessibility. The typical flow:

1. App installed (sideloaded or via dropper on Play Store)
2. Social engineering overlay prompts user to enable accessibility
3. Once enabled, malware auto-grants itself remaining permissions
4. Malware operates autonomously: overlay attacks, OTP interception, automated transactions

### Notable Families

| Family | Accessibility Usage |
|--------|-------------------|
| [Anatsa](../../malware/families/anatsa.md) (TeaBot) | Auto-grants permissions, performs ATS (Automated Transfer System) fraud |
| [Cerberus](../../malware/families/cerberus.md) / [Alien](../../malware/families/alien.md) | Overlay injection, keylogging, OTP theft, anti-uninstall |
| [SharkBot](../../malware/families/sharkbot.md) | ATS fraud via accessibility, auto-fills transfer details |
| [Joker](../../malware/families/joker.md) | Auto-subscribes to premium services by clicking through WAP billing pages |
| [Medusa](../../malware/families/medusa.md) (TangleBot) | Full RAT capabilities via accessibility, screen streaming |
| [Xenomorph](../../malware/families/xenomorph.md) | Overlay + accessibility for complete ATS chain |
| [Hook](../../malware/families/hook.md) | VNC-like remote access built on accessibility events |

## Android Version Changes

**Android 7 (API 24)**: `GestureDescription` API added, enabling gesture-based interaction beyond simple clicks.

**Android 11 (API 30)**: restricted which apps appear in accessibility settings for apps targeting API 30+. Apps must declare `isAccessibilityTool="true"` in metadata or their service is hidden. Sideloaded apps targeting older APIs bypass this.

**Android 13 (API 33)**: restricted settings introduced. Apps installed from outside recognized app stores cannot navigate users to accessibility settings. The system blocks the intent and shows a "Restricted setting" dialog. Bypassed by session-based installers or targeting API < 33.

**Android 15 (API 35)**: expanded restricted settings enforcement, harder to bypass with older targetSdkVersion.

## Detection

In the manifest:

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

The `accessibility_config.xml` reveals scope:

```xml
<accessibility-service
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:canRetrieveWindowContent="true"
    android:canPerformGestures="true"
    android:accessibilityFlags="flagRetrieveInteractiveWindows" />
```

Red flags: `typeAllMask` event types, `canRetrieveWindowContent`, `canPerformGestures`, `flagRetrieveInteractiveWindows`.

## Further Reading

- Google's [AccessibilityService reference](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService)
- ThreatFabric's banking trojan reports document accessibility abuse patterns extensively
- [MITRE T1453](https://attack.mitre.org/techniques/T1453/) covers this at a taxonomic level
