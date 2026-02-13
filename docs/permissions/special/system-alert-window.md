# SYSTEM_ALERT_WINDOW

Allows drawing windows on top of all other apps. This is the foundation of overlay attacks: malware draws a fake login screen over a legitimate banking app and captures whatever the user types. The most common credential-stealing technique in Android banking malware.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.SYSTEM_ALERT_WINDOW` |
| Protection Level | `signature\|appop\|pre23\|development` |
| Grant Method | Settings > Apps > Special access > Display over other apps |
| Introduced | API 1 |

Before Android 6.0, this was a normal install-time permission. Since API 23, users must manually toggle it in settings. On Android 6-7, apps could auto-grant by using `TYPE_TOAST` windows as a loophole (patched in Android 8).

## What It Enables

The app can create windows using `WindowManager.addView()` with types that render above all other applications:

| Window Type | Behavior |
|-------------|----------|
| `TYPE_APPLICATION_OVERLAY` (API 26+) | Standard overlay, above apps but below system UI |
| `TYPE_PHONE` (deprecated API 26) | Pre-Oreo overlay type |
| `TYPE_SYSTEM_ALERT` (deprecated API 26) | Pre-Oreo overlay type |
| `TYPE_TOAST` (restricted API 26) | Exploitable for grantless overlays on Android 6-7 |

Overlays can be:

- **Fully opaque**: replaces the visible UI entirely (phishing)
- **Transparent/passthrough**: invisible layer capturing touches (tapjacking)
- **Partial**: covers just input fields or buttons

## Abuse in Malware

### Credential Phishing (Overlay Attack)

1. Malware monitors foreground app using `UsageStatsManager` or accessibility
2. When a target banking app opens, malware draws a fake login screen on top
3. User enters credentials into the overlay thinking it's the real app
4. Malware sends credentials to C2

The overlay is typically a WebView loading HTML styled to match the target app. Malware families maintain "injection" or "webfake" lists: HTML templates for hundreds of banking apps, downloaded from C2 on demand.

### Tapjacking

A transparent overlay captures touch events, or an overlay briefly appears to trick the user into tapping a specific location on a dialog behind it (e.g., a permission grant dialog).

### Blocking UI

Overlay covering the entire screen, preventing user from navigating to Settings to uninstall or revoke permissions.

### Notable Families

| Family | Overlay Usage |
|--------|--------------|
| [BankBot](../../malware/families/bankbot.md) | Pioneered overlay-based credential theft on Android |
| [Cerberus](../../malware/families/cerberus.md) | HTML injection overlays for 200+ banking apps |
| [Anubis](../../malware/families/anubis.md) | Overlay + keylogger combination |
| [Ermac](../../malware/families/ermac.md) | Overlay kit with frequently updated target list |
| [Hydra](../../malware/families/hydra.md) | Overlay-based phishing with WebView injection |
| [TsarBot](../../malware/families/tsarbot.md) | Overlay attacks targeting 750+ banking and crypto apps |
| [Antidot](../../malware/families/antidot.md) | Overlay injection with multilingual phishing templates |
| [Brokewell](../../malware/families/brokewell.md) | Overlay-based credential capture with screen streaming |
| [Klopatra](../../malware/families/klopatra.md) | Overlay phishing for banking credential theft |
| [Albiriox](../../malware/families/albiriox.md) | Overlay attacks with dynamic target list from C2 |
| [Herodotus](../../malware/families/herodotus.md) | WebView overlay injection for banking apps |
| [BingoMod](../../malware/families/bingomod.md) | Overlay phishing combined with on-device fraud |
| [Crocodilus](../../malware/families/crocodilus.md) | Overlay-driven credential theft with accessibility abuse |
| [BTMOB RAT](../../malware/families/btmob.md) | Overlay attacks paired with screen streaming capabilities |

## Android Version Changes

**Android 6.0 (API 23)**: moved from install-time to special permission. Google Play apps with this permission were auto-granted until Android 8.

**Android 7.1**: `TYPE_TOAST` windows still usable without the permission.

**Android 8.0 (API 26)**: `TYPE_TOAST` exploit patched. Deprecated `TYPE_PHONE`, `TYPE_SYSTEM_ALERT`. Added `TYPE_APPLICATION_OVERLAY`, which renders below critical system windows (permission dialogs), partially mitigating tapjacking.

**Android 10 (API 29)**: overlays cannot appear on top of other app activities if the overlay app doesn't have focus.

**Android 12 (API 31)**: overlays become untouchable by default when shown over sensitive system dialogs. System adds `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` to notify apps.

Post-Android 12, apps using accessibility can bypass overlay restrictions by performing gestures directly, making `BIND_ACCESSIBILITY_SERVICE` the more potent path.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
```

In code, look for:

```java
WindowManager.LayoutParams params = new WindowManager.LayoutParams(
    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
    PixelFormat.TRANSLUCENT
);
windowManager.addView(overlayView, params);
```

Red flags: `TYPE_APPLICATION_OVERLAY` combined with `UsageStatsManager.queryUsageStats()` (foreground app detection) or accessibility event monitoring.
