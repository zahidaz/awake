# DISABLE_KEYGUARD

Normal permission that allows an app to dismiss the lock screen (keyguard) programmatically. Auto-granted at install. Malware uses this to keep the device unlocked during remote fraud operations, ensure overlays remain visible, and prevent the lock screen from interrupting automated transfer sessions. While Android has progressively restricted what this permission can do, it remains relevant for older devices and complements other lock screen manipulation techniques.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.DISABLE_KEYGUARD` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 1 |
| User Visibility | None |
| Play Store Policy | No restrictions |

## What It Enables

### KeyguardManager Lock Screen Dismissal

```java
KeyguardManager km = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
KeyguardManager.KeyguardLock lock = km.newKeyguardLock("MalwareTag");
lock.disableKeyguard();
```

On older Android versions (pre-8.0), this call immediately dismisses the lock screen. On Android 8.0+, the behavior was restricted to dismiss only non-secure keyguards (no PIN/pattern/password set).

### Activity-Based Dismissal (Android 8.0+)

```java
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
    setShowWhenLocked(true);
    setTurnScreenOn(true);
    KeyguardManager km = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
    km.requestDismissKeyguard(this, null);
}
```

`requestDismissKeyguard()` shows the lock screen authentication UI rather than bypassing it. The user must still enter their PIN/pattern. However, `setShowWhenLocked(true)` allows an activity to display on top of the lock screen, enabling overlay attacks before the user unlocks.

## Abuse in Malware

### Fraud Session Maintenance

During [ATS](../../attacks/automated-transfer-systems.md) fraud, the device must remain unlocked while the operator navigates banking apps. Malware combines `DISABLE_KEYGUARD` with:

- `WAKE_LOCK` to keep the screen on
- Accessibility service to prevent lock screen activation
- `FLAG_KEEP_SCREEN_ON` on malicious activities

### Lock Screen Overlays

Using `setShowWhenLocked(true)`, malware can display activities over the lock screen:

| Pattern | Purpose |
|---------|---------|
| Fake system alert | Display "update required" or "security warning" before user unlocks |
| Credential phishing | Show fake lock screen or banking login on device wake |
| Ransomware note | Display ransom demand as persistent lock screen overlay |

### Device Admin Lock Screen Abuse

While `DISABLE_KEYGUARD` dismisses the lock screen, Device Admin API can set or change it. Combined:

1. `DevicePolicyManager.resetPassword()` sets a new PIN (pre-Android 8.0)
2. `DISABLE_KEYGUARD` dismisses the lock screen for the malware's own operations
3. User cannot unlock with their original credentials

This combination was used by early ransomware families like [Svpeng](../../malware/families/svpeng.md) and LockerPin.

### Families Using Lock Screen Manipulation

| Family | Technique |
|--------|-----------|
| [BRATA](../../malware/families/brata.md) | Keeps device unlocked during on-device fraud sessions |
| [Octo](../../malware/families/octo.md) | Black screen overlay + keyguard dismissal for hidden remote access |
| [Hook](../../malware/families/hook.md) | VNC sessions require unlocked device |
| [BingoMod](../../malware/families/bingomod.md) | Screen manipulation during ATS fraud |
| [Rafel RAT](../../malware/families/rafelrat.md) | Lock screen ransomware + DeviceAdmin PIN change |
| [Svpeng](../../malware/families/svpeng.md) | Pioneer of lock screen ransomware |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | `DISABLE_KEYGUARD` introduced | Full lock screen dismissal |
| 5.0 | 21 | Smart Lock (trusted agents, trusted places) | Additional lock screen bypass vectors for malware to exploit |
| 8.0 | 26 | `disableKeyguard()` limited to non-secure keyguards | Cannot bypass PIN/pattern/password lock screens |
| 8.1 | 27 | `requestDismissKeyguard()` introduced | Shows authentication UI instead of bypassing |
| 8.1 | 27 | `setShowWhenLocked(true)` | Activities can display over lock screen without dismissing it |
| 9 | 28 | `resetPassword()` deprecated for Device Admin | Ransomware cannot change PIN via Device Admin on Android 9+ |
| 10 | 29 | Device Admin `resetPassword()` fully removed | Lock screen PIN manipulation requires Device Owner (MDM) |

The progressive restrictions mean `DISABLE_KEYGUARD` is most dangerous on Android 7.1 and below. On modern devices, malware relies on accessibility services for lock screen manipulation instead.

## Detection Indicators

### Manifest Signals

- `DISABLE_KEYGUARD` combined with `WAKE_LOCK` and `SYSTEM_ALERT_WINDOW`
- `DISABLE_KEYGUARD` alongside `BIND_DEVICE_ADMIN` (ransomware indicator)
- Activities declaring `showWhenLocked` or `turnScreenOn` attributes

### Behavioral Signals

- `KeyguardLock.disableKeyguard()` calls during active C2 sessions
- `setShowWhenLocked(true)` in activities displaying credential forms or alerts
- Repeated screen wake + keyguard dismiss cycles indicating automated operations

## See Also

- [Device Admin Abuse](../../attacks/device-admin-abuse.md)
- [Device Wipe & Ransomware](../../attacks/device-wipe-ransomware.md)
- [Overlay Attacks](../../attacks/overlay-attacks.md)
- [WAKE_LOCK](wake-lock.md)
