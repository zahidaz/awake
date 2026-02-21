# FOREGROUND_SERVICE_MEDIA_PROJECTION

Foreground service type declaration required on Android 14 (API 34) for any service that uses MediaProjection to capture the device screen. Before Android 14, a generic `FOREGROUND_SERVICE` permission was sufficient. Now, apps must explicitly declare `foregroundServiceType="mediaProjection"` in the manifest, and the system enforces that only services with this type can call `MediaProjection.createVirtualDisplay()`. Every banking trojan with screen streaming capability must declare this type or lose its core fraud feature on Android 14+.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (manifest declaration) |
| Introduced | API 34 (Android 14) |
| Depends On | [`FOREGROUND_SERVICE`](foreground-service.md) |
| User Visibility | MediaProjection consent dialog (separate from permission) |

The permission itself is auto-granted. The user-facing gate is the MediaProjection consent dialog that appears when the app calls `MediaProjectionManager.createScreenCaptureIntent()`. This dialog explicitly shows "Start recording or casting with [app]?" and requires a tap to approve.

## What It Enables

### Manifest Declaration

```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION" />

<service
    android:name=".ScreenCaptureService"
    android:foregroundServiceType="mediaProjection"
    android:exported="false" />
```

### Screen Capture Service

```java
public class ScreenCaptureService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, buildNotification());

        MediaProjectionManager mpm = (MediaProjectionManager) getSystemService(MEDIA_PROJECTION_SERVICE);
        MediaProjection projection = mpm.getMediaProjection(resultCode, data);
        VirtualDisplay display = projection.createVirtualDisplay(
            "capture", width, height, dpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            surface, null, null
        );
        return START_STICKY;
    }
}
```

### Required Chain

1. App declares `FOREGROUND_SERVICE_MEDIA_PROJECTION` in manifest
2. App starts a foreground service with `foregroundServiceType="mediaProjection"`
3. App shows `createScreenCaptureIntent()` system dialog
4. User approves the dialog
5. App receives a `MediaProjection` token
6. App creates a `VirtualDisplay` that captures the screen

## Abuse in Malware

### Screen Streaming for On-Device Fraud

Banking trojans use MediaProjection to stream the device screen to the operator in real time. The operator watches the victim's screen and issues commands through accessibility services or VNC-style remote control.

| Family | MediaProjection Usage |
|--------|----------------------|
| [Octo](../../malware/families/octo.md) | Adaptive-FPS screenshot streaming (1/sec default) |
| [Vultur](../../malware/families/vultur.md) | AlphaVNC + ngrok, later custom protocol |
| [SpyNote](../../malware/families/spynote.md) | Live screen sharing with bidirectional control |
| [Medusa](../../malware/families/medusa.md) | VNC-based real-time streaming |
| [Brokewell](../../malware/families/brokewell.md) | Real-time screen mirroring |
| [Gigabud](../../malware/families/gigabud.md) | Screen recording via accessibility trigger |
| [BTMOB RAT](../../malware/families/btmob.md) | Live screen streaming to C2 |
| [Hook](../../malware/families/hook.md) | Screen capture alongside VNC remote access |
| [BRATA](../../malware/families/brata.md) | Screen recording to local storage, then exfiltration |

### Consent Dialog Bypass

The MediaProjection consent dialog is the main defense. Malware bypasses it through:

| Technique | Mechanism |
|-----------|-----------|
| [Accessibility auto-approve](../../attacks/accessibility-abuse.md) | Accessibility service detects the consent dialog and clicks "Start now" |
| [Tapjacking](../../attacks/tapjacking.md) | Overlay covers the consent dialog, tricking user into tapping "approve" |
| Social engineering | "Screen sharing is required to verify your identity" |
| One-time approval abuse | Android 14 made MediaProjection tokens single-use, but malware re-triggers the dialog |

### Android 14 Impact on Malware

Android 14 introduced two changes that directly affect banking trojans:

1. **MediaProjection tokens are single-use**: Each screen capture session requires fresh user consent. Malware cannot reuse a token across app restarts.
2. **Foreground service type required**: Services without `foregroundServiceType="mediaProjection"` crash when calling MediaProjection APIs.

Malware adapted by declaring the correct foreground service type (trivial manifest change) and using accessibility to re-approve the consent dialog after each restart.

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 5.0 | 21 | MediaProjection API introduced | Screen capture possible for third-party apps |
| 5.0 | 21 | Consent dialog required | User must approve each capture session |
| 10 | 29 | MediaProjection requires `FOREGROUND_SERVICE` | Must run as foreground service to capture |
| 14 | 34 | `FOREGROUND_SERVICE_MEDIA_PROJECTION` required | Must declare specific foreground service type |
| 14 | 34 | Tokens are single-use | Cannot reuse approval across sessions |
| 14 | 34 | Consent notification shown in status bar | User sees persistent indicator during capture |

## Detection Indicators

### Manifest Signals

- `FOREGROUND_SERVICE_MEDIA_PROJECTION` combined with `BIND_ACCESSIBILITY_SERVICE`
- `foregroundServiceType="mediaProjection"` on services that also handle network communication
- MediaProjection + overlay permissions (`SYSTEM_ALERT_WINDOW`) in apps that are not screen recording utilities

### Behavioral Signals

- `createScreenCaptureIntent()` triggered immediately after accessibility service is enabled
- Screenshot data transmitted to remote servers via C2 channel
- MediaProjection service running alongside accessibility-based input injection

## See Also

- [Screen Capture](../../attacks/screen-capture.md)
- [FOREGROUND_SERVICE](foreground-service.md)
- [BIND_ACCESSIBILITY_SERVICE](../special/bind-accessibility-service.md)
