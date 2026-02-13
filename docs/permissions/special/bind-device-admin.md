# BIND_DEVICE_ADMIN

Grants device administration capabilities: locking the screen, wiping data, enforcing password policies, and preventing its own uninstallation. Early Android malware (2013-2016) used device admin heavily for ransomware and persistence. Modern malware prefers accessibility services, but device admin still appears in some families.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_DEVICE_ADMIN` |
| Protection Level | `signature` |
| Grant Method | User must explicitly activate via system dialog |
| Introduced | API 8 (Android 2.2) |

The app declares a `DeviceAdminReceiver` in its manifest. When the app requests activation, Android shows a full-screen dialog listing all the capabilities the admin is requesting. The user must explicitly confirm.

## What It Enables

| Capability | API Method | Impact |
|-----------|-----------|--------|
| Lock screen | `lockNow()` | Immediately lock device |
| Set password | `resetPassword()` | Force a lock screen password |
| Wipe device | `wipeData()` | Factory reset, destroying all data |
| Set password quality | `setPasswordQuality()` | Enforce password complexity |
| Monitor failed attempts | `setMaximumFailedPasswordsForWipe()` | Auto-wipe after N failed attempts |
| Disable camera | `setCameraDisabled()` | Block camera use |
| Prevent uninstall | Implicit | Device admin apps cannot be uninstalled until deactivated |

## Abuse in Malware

### Ransomware

The primary abuse case historically. Malware activates device admin, then:

1. Locks the screen with `lockNow()`
2. Changes the password with `resetPassword()`
3. Displays ransom message
4. Threatens `wipeData()` if ransom is not paid

### Anti-Uninstall

A device admin app cannot be uninstalled through normal means. The user must first navigate to Settings > Security > Device Administrators and deactivate the admin, then uninstall. Malware using accessibility can prevent the user from reaching these settings.

### Notable Families

| Family | Device Admin Usage |
|--------|-------------------|
| Obad | First major device admin abuse (2013). Hid itself from admin list using a vulnerability. |
| Koler | Police ransomware. Lock screen with fake law enforcement message. |
| Simplocker | File encryption + device admin lock. |
| LokiBot | Activates ransomware mode via device admin when user tries to revoke. |
| [Cerberus](../../malware/families/cerberus.md) | Optional device admin for anti-uninstall. |
| [Rafel RAT](../../malware/families/rafelrat.md) | DeviceAdmin for ransomware lock screen, password reset, and device wipe |
| [BRATA](../../malware/families/brata.md) | Factory reset via `wipeData()` after completing fraud to destroy evidence |
| [BingoMod](../../malware/families/bingomod.md) | Device wipe after on-device fraud to erase forensic traces |

## Android Version Changes

**Android 7.0 (API 24)**: `resetPassword()` deprecated for device admin. Only device owner (MDM) or profile owner can reset passwords.

**Android 9.0 (API 28)**: device admin policies for password quality, password expiration, and other features deprecated in favor of managed profiles. Device admin is being phased out for enterprise use in favor of Android Enterprise.

**Android 10+ (API 29+)**: `resetPassword()` completely removed for device admin apps. Ransomware using this technique only works on older Android versions.

## Detection

In the manifest:

```xml
<receiver android:name=".AdminReceiver"
    android:permission="android.permission.BIND_DEVICE_ADMIN">
    <meta-data android:name="android.app.device_admin"
        android:resource="@xml/device_admin" />
    <intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />
    </intent-filter>
</receiver>
```

The `device_admin.xml` declares requested policies:

```xml
<device-admin>
    <uses-policies>
        <force-lock />
        <wipe-data />
        <reset-password />
    </uses-policies>
</device-admin>
```

Any non-MDM app requesting `force-lock`, `wipe-data`, or `reset-password` policies is suspicious.
