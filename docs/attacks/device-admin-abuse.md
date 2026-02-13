# Device Admin Abuse

Exploiting the Device Administration API to prevent app removal, lock the screen, or wipe the device. A device admin app cannot be uninstalled until the user manually deactivates it through Settings, which malware actively obstructs through UI manipulation and social engineering.

See also: [Device Wipe & Ransomware](device-wipe-ransomware.md), [Persistence Techniques](persistence-techniques.md), [Accessibility Abuse](accessibility-abuse.md)

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`BIND_DEVICE_ADMIN`](../permissions/special/bind-device-admin.md) declared in manifest |
    | Condition | User must explicitly activate the app as device admin through a system prompt |
    | Component | `DeviceAdminReceiver` subclass registered in manifest |

## How It Works

### Device Administration API

The `DevicePolicyManager` API was designed for enterprise MDM (Mobile Device Management) solutions to enforce security policies on company devices. It grants elevated privileges: locking the screen, setting password requirements, encrypting storage, wiping the device, disabling the camera.

Any app can request device admin status, but the user must explicitly approve it through a system-managed activation screen. Once activated, the app cannot be uninstalled until device admin is deactivated first.

### Implementation

The malware declares a `DeviceAdminReceiver` and a device admin policy XML:

```xml
<receiver
    android:name=".AdminReceiver"
    android:permission="android.permission.BIND_DEVICE_ADMIN"
    android:exported="true">
    <meta-data
        android:name="android.app.device_admin"
        android:resource="@xml/device_admin_policies" />
    <intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />
    </intent-filter>
</receiver>
```

Policy XML (`res/xml/device_admin_policies.xml`):

```xml
<device-admin>
    <uses-policies>
        <force-lock />
        <wipe-data />
        <reset-password />
        <limit-password />
        <disable-camera />
        <watch-login />
    </uses-policies>
</device-admin>
```

Programmatic activation request:

```java
ComponentName adminComponent = new ComponentName(this, AdminReceiver.class);
Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
    "Enable security features to protect your device");
startActivity(intent);
```

## Attack Patterns

### Anti-Uninstall Persistence

The primary abuse case. Once activated as device admin, the app resists removal. If the user navigates to Settings > Apps and tries to uninstall, Android displays "This app is an active device administrator and must be deactivated before uninstalling."

The user must go to Settings > Security > Device Administrators, find the app, and deactivate it. Malware blocks this in several ways:

- **Accessibility overlay**: monitors for the device admin settings screen and immediately navigates the user away or displays a blocking overlay
- **Screen lock on deactivation attempt**: the `onDisableRequested()` callback fires before deactivation, and the malware immediately locks the screen
- **Repeated reactivation**: if the user manages to deactivate, the malware immediately requests activation again via an aggressive loop of activation intents

??? example "Anti-Deactivation via Screen Lock"

    ```java
    public class AdminReceiver extends DeviceAdminReceiver {
        @Override
        public CharSequence onDisableRequested(Context context, Intent intent) {
            DevicePolicyManager dpm = (DevicePolicyManager)
                context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            dpm.lockNow();
            return "Deactivating will leave your device unprotected";
        }
    }
    ```

### Screen Lock Manipulation

Forcing a PIN or password lock to hold the device hostage. The malware calls `lockNow()` to immediately lock the screen, or `resetPassword()` to set a new lock screen password the victim doesn't know.

```java
DevicePolicyManager dpm = (DevicePolicyManager)
    getSystemService(Context.DEVICE_POLICY_SERVICE);
ComponentName admin = new ComponentName(this, AdminReceiver.class);

dpm.resetPassword("attacker_pin_1234", 0);
dpm.lockNow();
```

`resetPassword()` was restricted in Android 7.0 (API 24) -- it can no longer change an existing password, only set one when none exists. Android 8.0+ (API 26) deprecated it entirely for device admins, moving this capability to Device Owner only.

### Factory Reset (Scorched Earth)

Wiping the entire device as anti-forensics or retaliation after completing fraud. `wipeData()` triggers a full factory reset with no user confirmation.

```java
DevicePolicyManager dpm = (DevicePolicyManager)
    getSystemService(Context.DEVICE_POLICY_SERVICE);
dpm.wipeData(0);
```

[BRATA](../malware/families/brata.md) performs a factory reset after completing a fraudulent bank transfer to destroy evidence. The victim loses all data, and forensic analysis of the device becomes impossible without chip-off techniques.

### Camera Disabling

`setCameraDisabled()` prevents all apps from using the camera. Rarely used by malware, but observed in ransomware-style campaigns as an additional pressure tactic alongside screen locking.

### Login Monitoring

`setMaximumFailedPasswordsForWipe()` configures automatic device wipe after N failed unlock attempts. Malware can set this to a low number (e.g., 3) so that a victim who forgot the attacker-set PIN inadvertently triggers a wipe.

## Social Engineering for Activation

The system activation dialog cannot be customized, but malware controls everything around it. Common approaches:

- **Fake security app**: presents as antivirus or system cleaner, tells the user admin access is required for "full protection"
- **Fake system update**: displays an urgent update notification that leads to the activation prompt
- **Persistent nagging**: shows the activation prompt repeatedly in a loop until the user complies, with accessibility service pressing Back being intercepted
- **Misleading explanation**: the `EXTRA_ADD_EXPLANATION` string displayed on the activation prompt is controlled by the malware. Phrased as a security necessity

## Device Owner vs Device Admin vs Profile Owner

| Aspect | Device Admin | Device Owner | Profile Owner |
|--------|-------------|-------------|---------------|
| Activation | User grants via Settings | ADB or NFC provisioning (factory-fresh only) | MDM enrollment |
| Removal | User can deactivate | Cannot be removed without factory reset | User can remove managed profile |
| Capabilities | Lock, wipe, password policy | Full device control, silent app install, kiosk mode | Work profile isolation |
| Malware Use | Common (pre-Android 9) | Rare (requires factory state) | Not observed in malware |
| API Level | 8+ | 21+ | 21+ |

Device Owner is strictly more powerful than Device Admin but requires provisioning on a factory-fresh device via `adb shell dpm set-device-owner` or NFC bump during setup wizard. Malware cannot achieve Device Owner status on a device the victim is already using.

## Samsung Knox Abuse

Samsung Knox provides additional enterprise APIs beyond stock Android. On Samsung devices, a Device Admin with Knox license can:

- Prevent USB debugging from being enabled
- Block installation from unknown sources at the system level
- Set a custom recovery message shown on the lock screen
- Control VPN configuration
- Prevent factory reset via hardware buttons

Knox abuse has been observed in targeted attacks against enterprises using Samsung fleets. The attacker gains Knox admin rights and locks down the device more aggressively than standard Android APIs allow.

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 2.2 (API 8) | Device Administration API introduced | No restrictions on third-party use |
| Android 5.0 (API 21) | Device Owner and Profile Owner introduced (more powerful than basic device admin) | Malware continues using basic device admin for anti-uninstall |
| Android 7.0 (API 24) | `resetPassword()` can no longer change an existing password | Only works when no password is set |
| Android 8.0 (API 26) | `resetPassword()` deprecated for device admin; camera disable restricted | Shift to accessibility for equivalent capabilities |
| Android 9.0 (API 28) | Device admin deprecation begins: `resetPassword()`, `setCameraDisabled()` deprecated for third-party apps | Malware shifts to accessibility service abuse |
| Android 10 (API 29) | Device admin cannot set password quality requirements on devices with existing screen lock | Anti-uninstall still works |
| Android 14 (API 34) | Deprecated policies actively blocked for apps targeting API 34+; most policy methods throw `SecurityException` | Apps targeting lower API levels unaffected; anti-uninstall via admin activation still functional |

## Modern Replacement: Accessibility Service

As device admin capabilities were deprecated, malware shifted to [accessibility service abuse](accessibility-abuse.md) for the same goals:

| Goal | Device Admin Method | Accessibility Replacement |
|------|-------------------|--------------------------|
| Prevent uninstall | Admin activation blocks removal | Navigate away from uninstall screen |
| Lock screen | `lockNow()` | `GLOBAL_ACTION_LOCK_SCREEN` (API 28+) |
| Intercept password | `watchLogin` policy | Keylogging via accessibility events |
| Block Settings access | Limited | Full control over Settings navigation |
| Persist on device | Cannot remove active admin | Cannot disable accessibility without navigating Settings |

Accessibility service provides strictly more capability with fewer restrictions than device admin. The transition was complete by approximately 2020 -- modern families rarely bother with device admin.

!!! info "Device Admin is a Legacy Technique"

    If you encounter device admin abuse in a sample dated 2021 or later, it is almost certainly a secondary mechanism alongside [accessibility service abuse](accessibility-abuse.md). Prioritize reversing the accessibility service component -- it will contain the core malicious logic.

## Families Using This Technique

| Family | Device Admin Use | Era |
|--------|-----------------|-----|
| [BRATA](../malware/families/brata.md) | Factory reset after fraud, anti-uninstall | 2019-2022 |
| [Cerberus](../malware/families/cerberus.md) | Anti-uninstall, screen lock on deactivation attempt | 2019-2020 |
| [Anubis](../malware/families/anubis.md) | Screen lock (ransomware mode), anti-uninstall | 2017-2020 |
| [BankBot](../malware/families/bankbot.md) | Anti-uninstall persistence, primary defense mechanism | 2016-2018 |
| [SpyNote](../malware/families/spynote.md) | Anti-uninstall, combined with accessibility | 2020-present |
| [Ermac](../malware/families/ermac.md) | Anti-uninstall fallback alongside accessibility | 2021-2022 |
| [Rafel RAT](../malware/families/rafelrat.md) | Screen lock for ransomware, device wipe | 2022-present |
| [TrickMo](../malware/families/trickmo.md) | Screen lock after credential theft | 2020-2022 |
| [Hydra](../malware/families/hydra.md) | Anti-uninstall persistence | 2019-2021 |
| [GodFather](../malware/families/godfather.md) | Legacy persistence, largely replaced by accessibility | 2021-2022 |

## Deactivation and Removal

### Via ADB

If the device has USB debugging enabled, deactivate device admin remotely:

```bash
adb shell dpm remove-active-admin com.malware/.AdminReceiver
```

List all active device admins:

```bash
adb shell dumpsys device_policy
```

Force-stop and uninstall after deactivation:

```bash
adb shell am force-stop com.malware
adb shell pm uninstall com.malware
```

### Via Safe Mode

!!! tip "Safe Mode Bypass"

    Boot into Safe Mode (hold power button, long-press "Power Off" to get Safe Mode option). Third-party apps are disabled, which neutralizes the malware's accessibility service and overlay defenses. Navigate to Settings > Security > Device Administrators, deactivate the malware, then uninstall. This is the most reliable removal path when the malware blocks deactivation through UI manipulation.

### Via Settings (If Possible)

Settings > Security > Device Administrators > find the malware entry > Deactivate. If the malware uses accessibility to block this, disable the accessibility service first under Settings > Accessibility.

## Detection During Analysis

??? example "Static Indicators"

    - `DeviceAdminReceiver` in manifest with `BIND_DEVICE_ADMIN` permission
    - Policy XML requesting `wipe-data`, `force-lock`, or `reset-password`
    - `DevicePolicyManager` API calls in decompiled code
    - `onDisableRequested()` override that performs blocking actions

??? example "Dynamic Indicators"

    - App requesting device admin activation on first launch
    - Screen locking when user navigates to device admin settings
    - `dpm` commands visible in logcat during admin operations
    - Factory reset triggered after completing fraudulent transactions
