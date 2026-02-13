# FOREGROUND_SERVICE

Allows running a service with a persistent notification that the system prioritizes over background processes. Used by malware to maintain long-running operations: C2 connections, screen monitoring, SMS interception, and data exfiltration that must survive Android's background execution limits.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.FOREGROUND_SERVICE` |
| Protection Level | `normal\|instant` |
| Grant Method | Automatically at install time |
| Introduced | API 28 (Android 9.0) |

Before Android 9, any app could call `startForeground()` without declaring this permission. Android 9 made the permission declaration mandatory.

## What It Enables

A foreground service runs with higher priority than regular background processes. Android will not kill it under memory pressure (or kills it last). The trade-off is a persistent notification visible to the user.

```java
Notification notification = new Notification.Builder(this, CHANNEL_ID)
    .setContentTitle("App Running")
    .setSmallIcon(R.drawable.icon)
    .build();
startForeground(1, notification);
```

## Abuse in Malware

### Persistent Background Operation

Combined with `RECEIVE_BOOT_COMPLETED`, this creates persistent malware that:

1. Starts on boot via boot receiver
2. Launches a foreground service
3. Maintains C2 connection indefinitely
4. Monitors foreground apps for overlay timing
5. Survives most battery optimization kills

### Notification Disguise

Malware disguises the mandatory notification as something benign:

- "Optimizing battery..."
- "Security scan in progress"
- "System update"
- Minimized/transparent notification that's barely visible

On Android 13+, users can long-press to dismiss foreground service notifications, but the service continues running.

### Notable Families

| Family | Foreground Service Usage |
|--------|------------------------|
| [SpyNote](../../malware/families/spynote.md) | Persistent notification disguised as system update, maintains RAT connectivity |
| [Gigabud](../../malware/families/gigabud.md) | Foreground service for continuous screen recording and data exfiltration |
| [BTMOB RAT](../../malware/families/btmob.md) | Foreground service to maintain persistent C2 connection and screen streaming |
| [LightSpy](../../malware/families/lightspy.md) | Foreground service keeps modular surveillance plugins active |

### Foreground Service Types

Android 10+ requires declaring the foreground service type:

| Type | Declaration | Malware Use |
|------|------------|-------------|
| `location` | `android:foregroundServiceType="location"` | Continuous GPS tracking |
| `camera` | `android:foregroundServiceType="camera"` | Covert recording |
| `microphone` | `android:foregroundServiceType="microphone"` | Audio surveillance |
| `dataSync` | `android:foregroundServiceType="dataSync"` | Data exfiltration |
| `mediaPlayback` | `android:foregroundServiceType="mediaPlayback"` | Disguise (no actual media) |
| `connectedDevice` | `android:foregroundServiceType="connectedDevice"` | Disguise |

Android 14 (API 34) enforces type-specific permissions: a `camera` foreground service requires `CAMERA` permission to actually be granted.

## Android Version Changes

**Android 8.0 (API 26)**: background execution limits. Apps can no longer run services freely in the background. `startForegroundService()` introduced as the replacement.

**Android 9.0 (API 28)**: `FOREGROUND_SERVICE` permission required in manifest.

**Android 10 (API 29)**: foreground service types introduced.

**Android 12 (API 31)**: restrictions on starting foreground services from the background. Must use exact alarms, high-priority FCM, or user interaction to start.

**Android 14 (API 34)**: type-specific foreground service permissions enforced. `dataSync` type limited to 6 hours.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
```

The `foregroundServiceType` in the service declaration reveals the claimed purpose. Mismatch between the declared type and actual app functionality is suspicious.
