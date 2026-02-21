# RECEIVE_USER_PRESENT

Normal permission that allows an app to receive the `ACTION_USER_PRESENT` broadcast when the user unlocks the device screen. Auto-granted at install. Malware uses this as a trigger to launch phishing overlays, fake lock screens, and credential harvesting at the exact moment the user is actively looking at their device. Unlike [`RECEIVE_BOOT_COMPLETED`](receive-boot-completed.md) which fires once at startup, `USER_PRESENT` fires on every unlock, giving malware repeated opportunities to present malicious UI.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_USER_PRESENT` (pre-API 26 implicit) |
| Protection Level | `normal` |
| Grant Method | Automatically at install time |
| Introduced | API 1 |
| Broadcast | `android.intent.action.USER_PRESENT` |
| User Visibility | None |
| Play Store Policy | No restrictions |

On Android 8.0+, manifest-registered receivers for `USER_PRESENT` no longer work for background apps. Malware must register the receiver dynamically from a running service or use it in combination with a foreground service.

## What It Enables

### Broadcast Receiver

```java
public class UnlockReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_USER_PRESENT.equals(intent.getAction())) {
            // Device just unlocked - user is looking at screen
        }
    }
}
```

The broadcast fires after the user successfully passes the lock screen (PIN, pattern, fingerprint, face unlock). It does not fire on screen-on without unlock.

### Timing Properties

| Event | Broadcast | When |
|-------|----------|------|
| Screen turns on | `ACTION_SCREEN_ON` | Immediately when screen activates |
| User unlocks | `ACTION_USER_PRESENT` | After successful authentication |
| Screen turns off | `ACTION_SCREEN_OFF` | When screen deactivates |

The gap between `SCREEN_ON` and `USER_PRESENT` is the lock screen duration. Malware targeting the unlock moment specifically uses `USER_PRESENT` rather than `SCREEN_ON` to ensure the user has completed authentication and is actively engaging with the device.

## Abuse in Malware

### Overlay Trigger on Unlock

The most common abuse pattern. When the user unlocks their device, they expect to see their home screen or the last app they were using. Malware intercepts this moment to display phishing UI:

```java
public class UnlockReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_USER_PRESENT.equals(intent.getAction())) {
            Intent overlay = new Intent(context, PhishingActivity.class);
            overlay.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(overlay);
        }
    }
}
```

The overlay appears instantly after unlock, before the user can interact with any other app. This is particularly effective for:

- Fake system update prompts ("Critical security update required")
- Fake Google Play warnings ("Verify your Google account")
- Banking credential harvesters ("Session expired, please log in")
- [Fake biometric prompts](../../attacks/fake-biometric-prompts.md) requesting PIN/pattern re-entry

### Fake Lock Screen Attacks

[TsarBot](../../malware/families/tsarbot.md) uses `USER_PRESENT` to trigger a fake lock screen overlay that captures the victim's PIN or unlock pattern. [Documented by Cleafy](https://www.cleafy.com/cleafy-labs/tsarbot-on-the-rise-with-over-750-banking-and-crypto-app-targets), the attack flow:

1. `USER_PRESENT` broadcast fires on device unlock
2. TsarBot immediately displays a fake lock screen overlay matching the device's real lock screen
3. The victim sees what appears to be the lock screen again and re-enters their PIN/pattern
4. TsarBot captures the PIN/pattern and exfiltrates it to C2
5. The fake lock screen dismisses, showing the real home screen
6. The victim assumes the first unlock "didn't work" and continues normally

The stolen PIN/pattern enables ATM withdrawal via [NFC relay](../../attacks/nfc-relay.md) or device unlock during remote access sessions.

### Persistence Fallback

`USER_PRESENT` serves as a persistence mechanism alongside [`RECEIVE_BOOT_COMPLETED`](receive-boot-completed.md). If the malware's background service is killed by the system:

1. Boot receiver restarts the service after reboot
2. `USER_PRESENT` receiver restarts it on every screen unlock
3. `CONNECTIVITY_CHANGE` receiver restarts it on network state change

This triple-redundancy pattern is documented on the [Persistence Techniques](../../attacks/persistence-techniques.md) page. The `USER_PRESENT` receiver is the most reliable of the three because it fires frequently (every time the user picks up their phone) and does not require any special permissions.

### Ransomware Display

Ransomware families use `USER_PRESENT` to ensure the ransom note is always visible:

1. User unlocks device
2. `USER_PRESENT` fires
3. Malware immediately re-launches the ransom overlay
4. User cannot access any app without seeing the ransom demand

Combined with [`DISABLE_KEYGUARD`](disable-keyguard.md) and Device Admin, this creates a persistent ransom screen that survives reboots and unlock attempts.

### Families Using USER_PRESENT

| Family | Usage |
|--------|-------|
| [TsarBot](../../malware/families/tsarbot.md) | Fake lock screen overlay on unlock to capture PIN/pattern. Targets 750+ banking and crypto apps. |
| [GodFather](../../malware/families/godfather.md) | Triggers fake Google Play Protect overlay on unlock |
| [Cerberus](../../malware/families/cerberus.md) | Overlay injection timing aligned with unlock events |
| [Rafel RAT](../../malware/families/rafelrat.md) | Ransomware note re-display on every unlock |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | `ACTION_USER_PRESENT` introduced | Broadcast on every device unlock |
| 8.0 | 26 | Implicit broadcast restrictions | Manifest-declared `USER_PRESENT` receivers no longer work for background apps. Must register dynamically from a running service. |
| 8.0 | 26 | Foreground service requirement | Background services that register the receiver must display a notification |

The Android 8.0 restriction is the most significant change. Pre-8.0 malware could declare the receiver in the manifest and receive the broadcast without any running component. Post-8.0, malware needs a foreground service or uses accessibility service events as an alternative unlock detection mechanism.

### Workarounds Post-Android 8.0

```java
public class PersistentService extends Service {
    private BroadcastReceiver unlockReceiver;

    @Override
    public void onCreate() {
        super.onCreate();
        unlockReceiver = new UnlockReceiver();
        IntentFilter filter = new IntentFilter(Intent.ACTION_USER_PRESENT);
        registerReceiver(unlockReceiver, filter);
    }
}
```

The service must be a foreground service with a visible notification. Malware disguises this notification as a system notification or uses a low-priority notification channel to minimize visibility.

## Detection Indicators

### Manifest Signals

```xml
<receiver android:name=".UnlockReceiver">
    <intent-filter>
        <action android:name="android.intent.action.USER_PRESENT" />
    </intent-filter>
</receiver>
```

On pre-Android 8.0 targets, a manifest-declared `USER_PRESENT` receiver. On Android 8.0+, look for dynamic registration in service code.

### Behavioral Signals

- Activity launch immediately after `USER_PRESENT` broadcast
- Overlay or full-screen activity displayed within 200ms of unlock
- `FLAG_ACTIVITY_NEW_TASK` combined with `USER_PRESENT` handling
- Service restarts triggered by unlock events (persistence pattern)
- Fake lock screen UI components (PIN pad, pattern grid) created in `USER_PRESENT` handler

### Permission Combinations

| Combination | Indicates |
|------------|-----------|
| `USER_PRESENT` + `SYSTEM_ALERT_WINDOW` | Overlay attack on unlock |
| `USER_PRESENT` + `BIND_ACCESSIBILITY_SERVICE` | Modern overlay trigger with input injection |
| `USER_PRESENT` + `BIND_DEVICE_ADMIN` | Ransomware persistence |
| `USER_PRESENT` + `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` | Triple-redundancy persistence |

## See Also

- [Overlay Attacks](../../attacks/overlay-attacks.md)
- [Fake Biometric Prompts](../../attacks/fake-biometric-prompts.md)
- [Persistence Techniques](../../attacks/persistence-techniques.md)
- [RECEIVE_BOOT_COMPLETED](receive-boot-completed.md)
- [DISABLE_KEYGUARD](disable-keyguard.md)
