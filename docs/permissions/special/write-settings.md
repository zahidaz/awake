# WRITE_SETTINGS

Allows modifying system-level settings. Can change default ringtone, screen brightness, screen timeout, and other global settings. Less commonly abused than other special permissions, but can be used to weaken device security or annoy the user into performing actions.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.WRITE_SETTINGS` |
| Protection Level | `signature\|appop\|pre23\|preinstalled` |
| Grant Method | Settings > Apps > Special access > Modify system settings |
| Introduced | API 1 |

Before Android 6.0, this was a normal permission. Since API 23, it requires a Settings toggle.

## What It Enables

Modify values in `Settings.System`:

```java
Settings.System.putInt(getContentResolver(),
    Settings.System.SCREEN_OFF_TIMEOUT, 2147483647); // prevent screen off
```

Accessible settings include:

| Setting | Impact |
|---------|--------|
| `SCREEN_OFF_TIMEOUT` | Prevent screen from turning off (keep screen on for overlay display) |
| `SCREEN_BRIGHTNESS` | Change brightness |
| `SOUND_EFFECTS_ENABLED` | Disable/enable sound effects |
| `RINGTONE` | Change ringtone |
| `AIRPLANE_MODE_ON` | Toggle airplane mode (limited on newer Android) |

## Abuse in Malware

### Preventing Screen Lock

Set `SCREEN_OFF_TIMEOUT` to maximum value to keep the screen on while performing on-device fraud or displaying overlays.

### Disabling Security

On older Android versions, some security-related settings were writable. Modern Android moved most sensitive settings to `Settings.Global` and `Settings.Secure`, which require higher privileges.

## Android Version Changes

**Android 6.0 (API 23)**: moved to special permission.

**Android 7.0+**: `AIRPLANE_MODE_ON` moved to `Settings.Global`, no longer writable by apps.

Most useful system settings have been progressively locked down, reducing the attack surface of this permission.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_SETTINGS" />
```

Low priority indicator on its own. Most abuse scenarios require combination with other permissions.
