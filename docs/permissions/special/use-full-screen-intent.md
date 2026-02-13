# USE_FULL_SCREEN_INTENT

Allows launching a full-screen activity from a notification when the device is locked. Designed for alarm clocks and incoming calls, but abused by malware to display phishing screens or social engineering prompts on locked devices.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.USE_FULL_SCREEN_INTENT` |
| Protection Level | `normal` (API 29-33), `special` (API 34+) |
| Grant Method | Automatic (API 29-33), Settings toggle (API 34+) |
| Introduced | API 29 (Android 10) |

## What It Enables

A notification with a full-screen intent launches an activity that appears over the lock screen:

```java
Intent fullScreenIntent = new Intent(this, PhishingActivity.class);
PendingIntent fullScreenPendingIntent = PendingIntent.getActivity(this, 0,
    fullScreenIntent, PendingIntent.FLAG_IMMUTABLE);

Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
    .setFullScreenIntent(fullScreenPendingIntent, true)
    .build();
```

When the notification fires and the device is locked, the activity appears immediately over the lock screen without the user unlocking.

## Abuse in Malware

### Lock Screen Phishing

Display a fake login screen, system alert, or security warning while the device is locked. The user wakes their device and sees a convincing prompt before reaching their home screen.

### Social Engineering

Show "urgent security update" or "account compromised" messages that prompt the user to enter credentials or enable accessibility.

### Distraction Screen

Display a fake "updating" or "loading" screen over the lock screen while the malware performs on-device fraud in the background.

## Android Version Changes

**Android 10 (API 29)**: permission introduced as `normal` (auto-granted).

**Android 14 (API 34)**: changed to a special permission requiring explicit user grant. Apps targeting API 34+ must request through Settings. Existing apps keep their grant until they update targetSdkVersion.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.USE_FULL_SCREEN_INTENT" />
```

Look for `setFullScreenIntent()` calls in notification builders. Any app that isn't an alarm, timer, or communication app using this is suspicious.
