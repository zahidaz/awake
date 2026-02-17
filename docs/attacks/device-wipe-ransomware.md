# Device Wipe & Ransomware

Destroying data, locking devices, and encrypting files on Android for extortion or evidence destruction. Android ransomware has evolved from simple screen lockers (2013) through PIN-changing lockers to file-encrypting variants, while banking trojans adopted factory reset as a post-fraud cleanup technique to destroy forensic evidence.

See also: [Device Admin Abuse](device-admin-abuse.md), [Accessibility Abuse](accessibility-abuse.md), [Persistence Techniques](persistence-techniques.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1471](https://attack.mitre.org/techniques/T1471/) | Data Encrypted for Impact | Impact |
    | [T1662](https://attack.mitre.org/techniques/T1662/) | Data Destruction | Impact |
    | [T1640](https://attack.mitre.org/techniques/T1640/) | Generate Fraudulent Advertising Revenue | Impact |
    | [T1629.002](https://attack.mitre.org/techniques/T1629/002/) | Impair Defenses: Device Lockout | Defense Evasion |

    T1471 covers file encryption ransomware (Simplocker, DoubleLocker, SOVA v5). T1662 covers factory reset as evidence destruction (BRATA, BingoMod). T1629.002 covers screen locking and PIN changing as device lockout.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Factory reset | `BIND_DEVICE_ADMIN` with `wipeData` policy, or root access |
    | PIN change | `BIND_DEVICE_ADMIN` with `resetPassword` policy (pre-Android 8.0), or `BIND_ACCESSIBILITY_SERVICE` |
    | File encryption | `READ_EXTERNAL_STORAGE` + `WRITE_EXTERNAL_STORAGE` (pre-Android 11), or `MANAGE_EXTERNAL_STORAGE` |
    | Screen lock | `SYSTEM_ALERT_WINDOW` (overlay), or `BIND_DEVICE_ADMIN`, or `BIND_ACCESSIBILITY_SERVICE` |

## Post-Fraud Factory Reset

Banking trojans use factory reset as an evidence destruction technique. After completing an unauthorized transfer, the malware wipes the device to eliminate forensic artifacts (SMS transaction confirmations, banking app logs, the malware itself).

### BRATA

[BRATA](../malware/families/brata.md) (Brazilian Remote Access Tool, Android) pioneered post-fraud device wiping. [Cleafy documented](https://www.cleafy.com/cleafy-labs/how-ta-is-pushing-brata) the behavior in January 2022: after completing a fraudulent wire transfer, BRATA executes a factory reset via `DevicePolicyManager.wipeData()` to remove all traces. The wipe also serves as a kill switch if the malware detects analysis (emulator, debugger, low number of installed apps).

```java
DevicePolicyManager dpm = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
dpm.wipeData(DevicePolicyManager.WIPE_EXTERNAL_STORAGE);
```

### BingoMod

[BingoMod](../malware/families/bingomod.md), [documented by Cleafy in July 2024](https://www.cleafy.com/cleafy-labs/bingomod-the-new-android-rat-that-steals-money-and-wipes-data), follows BRATA's model with a self-destruction mechanism designed to eradicate traces of activity and hinder forensic analysis. BingoMod establishes a socket-based connection with C2 infrastructure to receive up to 40 commands remotely, including device wipe. The malware's functionality includes erasing external storage and can initiate complete factory resets through its remote access capabilities.

### Other Families with Wipe Capability

| Family | Wipe Trigger | Method | Source |
|--------|-------------|--------|--------|
| [BRATA](../malware/families/brata.md) | Post-fraud or analysis detection | `DevicePolicyManager.wipeData()` | [Cleafy](https://www.cleafy.com/cleafy-labs/how-ta-is-pushing-brata) |
| [BingoMod](../malware/families/bingomod.md) | Post-fraud evidence destruction | Remote wipe via C2 command | [Cleafy](https://www.cleafy.com/cleafy-labs/bingomod-the-new-android-rat-that-steals-money-and-wipes-data) |
| [Cerberus](../malware/families/cerberus.md) | C2 kill command | Device admin wipe | [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/apk.cerberus) |
| [Rafel RAT](../malware/families/rafelrat.md) | C2 command, ransomware module | Device admin wipe + file encryption | [Check Point](https://research.checkpoint.com/2024/rafel-rat-android-malware/) |

## Android Ransomware Evolution

[ESET's whitepaper "Android Ransomware: From Android Defender to DoubleLocker"](https://web-assets.esetstatic.com/wls/2018/02/Android_Ransomware_From_Android_Defender_to_Doublelocker.pdf) traces the complete history.

### Screen Lockers (2013-2015)

The earliest Android ransomware displayed persistent full-screen overlays that the user could not dismiss, demanding payment to "unlock" the device.

**Koler** (April 2014): [Police-themed ransomware](https://www.kaspersky.com/resource-center/threats/koler-police-ransomware-virus) that displayed a localized law enforcement warning based on the victim's geographic location. A US victim saw an FBI warning; European victims saw Europol branding. Distributed primarily through adult content sites. Demanded $100-$300 via MoneyPak. [Infected approximately 200,000 Android devices](https://www.knowbe4.com/ransomware-knowledgebase/kolera), with 75% in the United States.

Screen lockers used `SYSTEM_ALERT_WINDOW` to display persistent overlays. Early variants could be removed by booting into safe mode and uninstalling the app. More sophisticated variants registered as device administrators to resist uninstall.

### PIN Lockers (2015-2017)

**LockerPin** (September 2015): [ESET discovered](https://www.welivesecurity.com/2015/09/10/aggressive-android-ransomware-spreading-in-the-usa/) the first Android ransomware that changed the device's lock screen PIN using `DevicePolicyManager.resetPassword()`. Once the PIN was changed, even the malware authors could not unlock it without knowing the new randomly generated PIN. The only recovery options were factory reset (losing all data) or ADB access on a rooted/debug-enabled device to delete the PIN file.

```java
DevicePolicyManager dpm = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
dpm.resetPassword(randomPin, DevicePolicyManager.RESET_PASSWORD_REQUIRE_ENTRY);
```

### File Encryption (2014-Present)

**Simplocker** (June 2014): The first Android ransomware to actually encrypt files. Scanned external storage for media files (images, documents, video) and encrypted them with AES. Demanded ransom in Ukrainian hryvnia, indicating Ukrainian origin. C2 communication routed through Tor `.onion` addresses.

**DoubleLocker** (October 2017): [ESET documented](https://www.welivesecurity.com/2017/10/13/doublelocker-innovative-android-malware/) the first Android ransomware combining both file encryption and PIN lock. Based on the Svpeng banking trojan's accessibility service code. DoubleLocker:

1. Encrypted user files with AES
2. Changed the device PIN to a random value
3. Demanded 0.0130 BTC (~$54 at the time) within 24 hours
4. Spread as a fake Adobe Flash Player update
5. Reactivated its ransom screen every time the user pressed the Home button via accessibility service

### Modern Ransomware Techniques

**MalLocker.B** (October 2020): [Microsoft documented](https://www.microsoft.com/en-us/security/blog/2020/10/08/sophisticated-new-android-malware-marks-the-latest-evolution-of-mobile-ransomware/) a novel screen locking technique that did not require `SYSTEM_ALERT_WINDOW` or device admin. MalLocker.B used two mechanisms in combination:

1. **Call notification abuse**: Used the system "call" notification (normally for incoming calls) to display a window covering the entire screen
2. **`onUserLeaveHint()` override**: Intercepted Home and Recents button presses to relaunch the ransom screen, preventing the user from switching away

This bypassed all previous platform mitigations against screen-locking ransomware because it used legitimate notification APIs rather than overlays or device admin policies.

**SOVA v5** (2022): [Cleafy documented](https://www.cleafy.com/cleafy-labs/sova-malware-is-back-and-is-evolving-rapidly) the addition of a ransomware module to the SOVA banking trojan. Version 5 uses AES encryption to lock all files on infected devices, appending the `.enc` extension. SOVA demonstrated the convergence of banking trojan and ransomware functionality: a single malware performing overlay attacks, cookie stealing, 2FA interception, VNC remote access, and file encryption.

## Screen Lock Mechanisms

| Mechanism | Android Versions | Bypass |
|-----------|-----------------|--------|
| `SYSTEM_ALERT_WINDOW` overlay | All (restricted 6.0+) | Safe mode boot, ADB uninstall |
| Device admin `resetPassword()` | Pre-8.0 (deprecated) | Factory reset, ADB on rooted device |
| Accessibility home button interception | 7.0+ | ADB uninstall, safe mode |
| Call notification + `onUserLeaveHint()` | 10+ | ADB uninstall |
| Accessibility service as home launcher | 7.0+ | ADB disable accessibility, safe mode |

### `resetPassword()` Deprecation

Android 8.0 (Oreo) deprecated `DevicePolicyManager.resetPassword()` for device admin apps. The method only works for device owner or profile owner apps (managed device scenarios). This eliminated the PIN-locking ransomware vector for non-rooted devices running Android 8.0+.

However, accessibility-based approaches remain viable. Malware with accessibility service access can navigate to `Settings > Security > Screen Lock` and change the PIN through UI interaction, bypassing the API restriction entirely.

## Scoped Storage Impact

Android 10 introduced scoped storage, and Android 11 enforced it. Apps can no longer freely access files on external storage without explicit user grants via `SAF` (Storage Access Framework) or `MANAGE_EXTERNAL_STORAGE` (restricted on Play Store).

| Storage Model | Ransomware Impact |
|---------------|------------------|
| Pre-Android 10 | `READ/WRITE_EXTERNAL_STORAGE` grants access to all shared files |
| Android 10 (optional) | Scoped storage opt-in; most apps still use legacy |
| Android 11+ (enforced) | Only app-private files accessible without `MANAGE_EXTERNAL_STORAGE` |
| Android 11+ with `MANAGE_EXTERNAL_STORAGE` | Full access, but Play Store restricts approval to file managers |

Sideloaded ransomware can still request `MANAGE_EXTERNAL_STORAGE` and trick users into granting it. But the Play Store distribution vector for file-encrypting ransomware is effectively closed.

## Families by Capability

| Family | Screen Lock | PIN Change | File Encryption | Factory Reset | Era |
|--------|:-----------:|:----------:|:---------------:|:-------------:|-----|
| Koler | Overlay | No | No | No | 2014 |
| Simplocker | No | No | AES | No | 2014 |
| LockerPin | No | Yes (`resetPassword`) | No | No | 2015 |
| DoubleLocker | Accessibility | Yes (`resetPassword`) | AES | No | 2017 |
| MalLocker.B | Call notification | No | No | No | 2020 |
| [BRATA](../malware/families/brata.md) | No | No | No | `wipeData()` | 2022 |
| SOVA v5 | No | No | AES (`.enc`) | No | 2022 |
| [BingoMod](../malware/families/bingomod.md) | No | No | No | Remote wipe | 2024 |
| [Rafel RAT](../malware/families/rafelrat.md) | Overlay | Yes | AES | `wipeData()` | 2024 |

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 2.2 | 8 | [Device Administration API](https://developer.android.com/guide/topics/admin/device-admin) introduced | `wipeData()` and `resetPassword()` accessible |
| 5.0 | 21 | SELinux enforcing for all domains | Root-based wipe harder without exploit |
| 6.0 | 23 | `SYSTEM_ALERT_WINDOW` requires explicit grant (sideloaded) | Overlay-based lockers need user interaction |
| 7.0 | 24 | `resetPassword()` requires current password if one is set | PIN change harder if device already has PIN |
| 8.0 | 26 | [`resetPassword()` deprecated](https://developer.android.com/about/versions/oreo/android-8.0-changes#dp) for device admin | PIN-locking ransomware vector eliminated for 8.0+ |
| 9.0 | 28 | [Device admin deprecation begins](https://developer.android.com/about/versions/pie/android-9.0-changes-all#device_security_changes) | Fewer legitimate uses, easier to flag abuse |
| 10 | 29 | [Scoped storage](https://developer.android.com/about/versions/10/privacy/changes#scoped-storage) introduced (opt-in) | File encryption scope reduced |
| 11 | 30 | Scoped storage enforced | Ransomware cannot access shared files without `MANAGE_EXTERNAL_STORAGE` |
| 12 | 31 | [Overlay restrictions over system windows](https://developer.android.com/about/versions/12/behavior-changes-all#untrusted-touch-events) | Harder to maintain persistent full-screen lock |
| 14 | 34 | [Foreground service type declarations required](https://developer.android.com/about/versions/14/changes/fgs-types-required) | Malicious services more visible in manifest |

## Detection During Analysis

??? example "Static Indicators"

    - `BIND_DEVICE_ADMIN` with `wipeData` or `resetPassword` in device admin XML
    - `DevicePolicyManager.wipeData()` or `resetPassword()` calls
    - AES/RSA encryption imports (`javax.crypto.*`) combined with file enumeration
    - `MANAGE_EXTERNAL_STORAGE` permission in sideloaded apps
    - `SYSTEM_ALERT_WINDOW` combined with `onBackPressed()` suppression
    - `onUserLeaveHint()` override in activity (MalLocker.B technique)
    - Bitcoin or cryptocurrency wallet address strings
    - Ransom note templates in string resources or assets

??? example "Dynamic Indicators"

    - Device admin activation prompt during app install
    - Sudden PIN/pattern lock change
    - Files renamed with new extensions (`.enc`, `.locked`, `.cry`)
    - Full-screen overlay that persists across Home/Recents presses
    - Factory reset triggered without user interaction
    - `DevicePolicyManager` API calls during or after banking app interaction
    - Network traffic to Tor `.onion` addresses (Simplocker-era C2)
