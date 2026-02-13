# Runtime Permission Manipulation

Granting permissions without user interaction. Once malware obtains [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md), it can navigate Settings screens, tap "Allow" buttons, and toggle switches to escalate from a single permission to full device control. Every modern Android banking trojan uses some variant of this technique.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | `BIND_ACCESSIBILITY_SERVICE` (user must enable manually) |
    | Trigger | Initial social engineering to enable accessibility |

    The only user interaction needed is enabling the accessibility service. Everything after that is automated.

## Accessibility-Based Auto-Grant

The core technique: the malware's accessibility service programmatically navigates system Settings and interacts with UI elements to grant itself additional permissions.

### View Tree Navigation

The accessibility service calls `getRootInActiveWindow()` to obtain the root `AccessibilityNodeInfo` of the current screen, then traverses the view tree searching for specific text labels or resource IDs matching permission toggles.

```java
AccessibilityNodeInfo root = getRootInActiveWindow();
List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByText("Allow");
for (AccessibilityNodeInfo node : nodes) {
    node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
}
```

### Settings Navigation Flow

The malware opens specific Settings screens via intents, then uses accessibility to manipulate them:

| Permission Target | Intent Action | UI Interaction |
|-------------------|---------------|----------------|
| Overlay (`SYSTEM_ALERT_WINDOW`) | `Settings.ACTION_MANAGE_OVERLAY_PERMISSION` | Toggle switch to ON |
| Install unknown apps | `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` | Toggle switch to ON |
| Notification access | `Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS` | Toggle switch to ON |
| Battery optimization | `Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS` | Select app, tap "Allow" |
| Default SMS app | `Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT` | Select malware app |
| Device admin | `Settings.ACTION_ADD_DEVICE_ADMIN` | Tap "Activate" |

### Runtime Permission Dialogs

For standard runtime permissions (camera, contacts, location, SMS), the malware triggers the system permission dialog and immediately clicks "Allow" via accessibility before the user can react.

```java
@Override
public void onAccessibilityEvent(AccessibilityEvent event) {
    if (event.getPackageName().equals("com.google.android.packageinstaller") ||
        event.getPackageName().equals("com.android.permissioncontroller")) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        List<AccessibilityNodeInfo> allowButtons =
            root.findAccessibilityNodeInfosByViewId(
                "com.android.permissioncontroller:id/permission_allow_button");
        if (!allowButtons.isEmpty()) {
            allowButtons.get(0).performAction(AccessibilityNodeInfo.ACTION_CLICK);
        }
    }
}
```

The malware monitors for the `com.android.permissioncontroller` package in `TYPE_WINDOW_STATE_CHANGED` events, then locates and clicks the "Allow" button. On some Android versions, the button IDs differ (`permission_allow_foreground_only_button`, `permission_allow_always_button`), so families like [ERMAC](../malware/families/ermac.md) and [Hook](../malware/families/hook.md) enumerate multiple possible IDs.

## Default SMS App Exploitation

Android grants `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, and `RECEIVE_MMS` automatically to whichever app the user designates as the default SMS handler. Malware exploits this by requesting default SMS status:

1. Launch `Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT` with its own package
2. Use accessibility to tap "Yes" on the confirmation dialog
3. Receive all SMS permissions automatically without individual grants
4. Intercept OTPs and bank verification codes
5. Optionally revert to the original SMS app after capturing needed data

Families including [Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md), and [FluBot](../malware/families/flubot.md) use this approach to gain SMS access without triggering individual permission prompts.

## Session-Based Installer Bypass (Android 13+)

Android 13 introduced "Restricted Settings" to block sideloaded apps from enabling accessibility services and notification listeners. Apps installed via `ACTION_VIEW` (the standard sideload path) are flagged as restricted. However, apps installed via `PackageInstaller` session-based API are treated as marketplace-installed and exempt.

### How Droppers Exploit This

The dropper app uses the session-based installation API to install its payload, mimicking how legitimate app stores install apps:

```java
PackageInstaller installer = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams params =
    new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_SET_INSTALL);
int sessionId = installer.createSession(params);
PackageInstaller.Session session = installer.openSession(sessionId);

OutputStream out = session.openWrite("payload", 0, -1);
InputStream in = getAssets().open("payload.apk");
byte[] buffer = new byte[65536];
int len;
while ((len = in.read(buffer)) != -1) {
    out.write(buffer, 0, len);
}
session.fsync(out);
out.close();

Intent intent = new Intent(this, InstallReceiver.class);
PendingIntent pending = PendingIntent.getBroadcast(this, sessionId, intent,
    PendingIntent.FLAG_MUTABLE);
session.commit(pending.getIntentSender());
```

The OS cannot distinguish between a dropper using this API and a legitimate marketplace. The payload installs without the "Restricted Settings" flag, and the user can enable accessibility services normally.

### Notable Droppers

[ThreatFabric documented SecuriDropper](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions) in October 2023 as the first dropper-as-a-service using this technique. Since then, it has become standard practice across the MaaS ecosystem.

| Dropper / Family | Year | Notes |
|------------------|------|-------|
| BugDrop | 2022 | Early proof-of-concept before Android 13 release |
| SecuriDropper | 2023 | First DaaS offering session-based bypass |
| [SpyNote](../malware/families/spynote.md) | 2024 | [Adopted session-based installation](https://cryptax.medium.com/android-spynote-bypasses-restricted-settings-breaks-many-re-tools-8791b3e6bf38) for accessibility bypass |
| [Anatsa](../malware/families/anatsa.md) | 2024 | Play Store droppers with session-based payload delivery |
| [Medusa](../malware/families/medusa.md) | 2024 | Updated dropper chain using session-based install |

!!! danger "Android 14 and 15"

    Android 14 did not fix this bypass. The same session-based technique works. Android 15 expanded restricted settings enforcement but still struggles to differentiate legitimate session-based installs from malicious ones.

## Biometric Downgrade to PIN

[Chameleon](../malware/families/chameleon.md) introduced a technique in late 2023 to [force the device from biometric authentication to PIN entry](https://www.threatfabric.com/blogs/android-banking-trojan-chameleon-is-back-in-action). The C2 sends an `interrupt_biometric` command, and the malware uses accessibility to:

1. Navigate to Settings > Security > Biometric
2. Disable fingerprint and face unlock
3. Force the device to fall back to PIN/password authentication
4. Capture the PIN via keylogging when the user next unlocks

This works because disabling biometrics is a Settings toggle, accessible via the same accessibility-based UI manipulation used for permission grants. See also: [Fake Biometric Prompts](fake-biometric-prompts.md) for overlay-based PIN capture.

## Family Comparison

| Family | Auto-Grant | SMS Takeover | Session Install | Biometric Downgrade | Restricted Settings Bypass |
|--------|------------|-------------|-----------------|--------------------|-----------------------------|
| [Cerberus](../malware/families/cerberus.md) | Yes | Yes (default SMS) | No (pre-dates it) | No | N/A |
| [ERMAC](../malware/families/ermac.md) | Yes | Via accessibility | No | No | Via dropper |
| [Hook](../malware/families/hook.md) | Yes | Via accessibility | Yes | No | Yes |
| [Medusa](../malware/families/medusa.md) | Yes | Broadcast receiver | Yes | No | Yes |
| [Anatsa](../malware/families/anatsa.md) | Yes | No (ATS-focused) | Yes | No | Yes |
| [Xenomorph](../malware/families/xenomorph.md) | Yes | Via accessibility | No | No | Via dropper |
| [Chameleon](../malware/families/chameleon.md) | Yes | No | Yes (Zombinder) | Yes | Yes |
| [SpyNote](../malware/families/spynote.md) | Yes | Via accessibility | Yes | No | Yes |

## Android Version Timeline

| Version | Change | Malware Adaptation |
|---------|--------|-------------------|
| Android 6 | Runtime permissions introduced | Malware auto-clicks "Allow" via accessibility |
| Android 8 | `TYPE_APPLICATION_OVERLAY` replaces `TYPE_SYSTEM_ALERT` | Accessibility grants the new overlay permission |
| Android 10 | Background activity launch restrictions | Foreground service workaround |
| Android 11 | Auto-revoke unused permissions | Malware periodically re-grants via accessibility |
| Android 11 | One-time permissions for camera/mic/location | Auto-grant repeats each session |
| Android 12 | Approximate vs precise location choice | Accessibility selects "Precise" option |
| Android 13 | Restricted settings for sideloaded apps | Session-based installer bypass |
| Android 13 | Notification permission now requires explicit grant | Auto-clicked via accessibility |
| Android 14 | Restricted settings expanded but session bypass persists | No change in dropper behavior |
| Android 15 | Expanded restricted settings enforcement | Session-based bypass partially patched |

## Detection During Analysis

??? example "Static Indicators"

    - `BIND_ACCESSIBILITY_SERVICE` in manifest
    - `findAccessibilityNodeInfosByText` or `findAccessibilityNodeInfosByViewId` in decompiled code
    - References to `com.android.permissioncontroller` or `com.google.android.packageinstaller`
    - `PackageInstaller.Session` usage in dropper components
    - Intent actions targeting Settings screens (`ACTION_MANAGE_OVERLAY_PERMISSION`, etc.)

??? example "Dynamic Indicators"

    - Rapid succession of permission grants after accessibility is enabled
    - Settings app opened programmatically without user navigation
    - Default SMS app changed immediately after accessibility grant
    - Permission dialogs appearing and disappearing within milliseconds

## Cross-References

- [Accessibility Abuse](accessibility-abuse.md) -- the enabling technique for all permission manipulation
- [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) -- permission details and grant flow
- [Overlay Attacks](overlay-attacks.md) -- often enabled by auto-granted `SYSTEM_ALERT_WINDOW`
- [SMS Interception](sms-interception.md) -- downstream abuse after SMS permissions are obtained
- [Fake Biometric Prompts](fake-biometric-prompts.md) -- alternative PIN capture via overlay rather than biometric downgrade
