# REQUEST_IGNORE_BATTERY_OPTIMIZATIONS

Allows requesting exemption from Android's battery optimization (Doze mode). When granted, the app's background processes are not restricted by the system, allowing persistent operation. Used by malware to maintain C2 connections and background monitoring without being killed by the OS.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (to request), user confirms via dialog |
| Introduced | API 23 (Android 6.0) |

The permission allows the app to show a system dialog asking the user to whitelist it from battery optimization. The user must confirm.

```java
Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
intent.setData(Uri.parse("package:" + getPackageName()));
startActivity(intent);
```

## Abuse in Malware

### Persistence

Battery optimization (Doze mode) kills background processes to save battery. Malware needs to stay alive for:

- Maintaining C2 connections
- Monitoring for target apps (overlay timing)
- SMS interception
- Continuous data exfiltration

Without this exemption, the OS may kill the malware's background service after minutes of inactivity.

### Social Engineering

Malware presents fake dialogs before the system prompt: "This app requires battery optimization disabled to function properly." The user sees the malware's explanation, then the system dialog, and clicks "Allow."

## Android Version Changes

**Android 6.0 (API 23)**: Doze mode introduced. This permission added.

**Android 7.0 (API 24)**: Doze mode becomes more aggressive (activates even when device is moving).

**Android 13+**: Google Play restricts apps that request this without justification.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
```

Combined with `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`, and `INTERNET`, this completes a persistence stack: boot start, foreground service, battery exemption, network access.
