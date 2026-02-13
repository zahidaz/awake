# Work Profile Abuse

Exploiting Android Enterprise features to access corporate data, bypass MDM controls, or leverage enterprise APIs for malicious purposes. Work profiles create a separate managed environment on the device, but the isolation boundary has known weaknesses, and the powerful DPC APIs available to device administrators represent an attractive attack surface.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Capability | Device Owner, Profile Owner, or access to cross-profile intents |
    | Target | Enterprise-managed Android devices |

## Android Enterprise Architecture

### Managed Profiles

Android work profiles (introduced in Android 5.0) create a separate user space on the device with its own app instances, data storage, and encryption keys. The work profile runs under a distinct Linux user ID, providing process-level isolation from the personal profile.

| Component | Personal Profile | Work Profile |
|-----------|-----------------|--------------|
| Linux user | User 0 | User 10+ (managed profile) |
| App data | `/data/user/0/` | `/data/user/10/` |
| Encryption | Device credentials | Separate work challenge (optional) |
| App instances | User-installed | MDM-provisioned |
| Contacts | Personal contacts | Corporate directory |
| Clipboard | Accessible | Cross-profile copy restricted by policy |

### Administration Modes

| Mode | Scope | Provisioning | Capabilities |
|------|-------|-------------|-------------|
| Profile Owner (PO) | Work profile only | QR code, NFC, managed Google account | App management, restrictions within work profile |
| Device Owner (DO) | Entire device | Factory reset provisioning, zero-touch | Full device control, all DPC APIs |
| COPE (Company Owned, Personally Enabled) | Device + work profile | Factory reset provisioning | DO on device, PO on work profile |

### Device Policy Controller (DPC) APIs

The `DevicePolicyManager` class exposes powerful APIs to profile/device owners:

| API | Capability | Abuse Potential |
|-----|-----------|-----------------|
| `setPasswordQuality()` | Enforce password policy | Force weak password for easier brute-force |
| `resetPassword()` | Set device password (deprecated API 26) | Lock user out, set known password |
| `wipeData()` | Factory reset device | Ransomware, evidence destruction |
| `setKeyguardDisabled()` | Disable lockscreen (DO only) | Remove device protection |
| `installCaCert()` | Install trusted CA certificate | MITM all TLS traffic |
| `setAlwaysOnVpnPackage()` | Force VPN | Route all traffic through attacker VPN |
| `addCrossProfileIntentFilter()` | Allow intents across profiles | Exfiltrate work data to personal apps |
| `setScreenCaptureDisabled()` | Disable screenshots | Can also be enabled to allow capture |
| `setCameraDisabled()` | Disable camera | Denial of service |
| `addUserRestriction()` | Restrict user actions | Prevent uninstall, factory reset, USB debug |
| `setPermissionGrantState()` | Grant/deny permissions for managed apps | Auto-grant dangerous permissions silently |

## Cross-Profile Data Access

### Intent Filters

By default, intents cannot cross the profile boundary. However, the DPC can add cross-profile intent filters using `addCrossProfileIntentFilter()`. Legitimate use: opening a work link in a personal browser. Malicious use: exfiltrating corporate data to personal-side malware.

A malicious profile owner can configure filters to forward sensitive intents (containing URIs, file paths, or extras with corporate data) to apps in the personal profile where MDM has no visibility.

### Content Provider Leakage

Content providers are isolated per profile. However, several vectors allow cross-profile data access:

| Vector | Mechanism | Impact |
|--------|-----------|--------|
| Cross-profile intent with URI grant | `FLAG_GRANT_READ_URI_PERMISSION` across profiles | Read work-side content provider data |
| Contacts provider | Work contacts visible to personal dialer (by default) | Corporate directory exposed |
| Calendar provider | Cross-profile calendar sharing (configurable) | Meeting data leakage |
| Clipboard | Cross-profile paste allowed on some configurations | Copy-paste data exfiltration |

### CVE-2025-22442: APK Injection into Work Profile

[Disclosed in April 2025](https://medium.com/@threatspotlight/how-to-exploit-cve-2025-22442-to-install-an-apk-in-an-android-work-profile-ee8d5345f841), this vulnerability (rated HIGH) allowed a malicious user to install arbitrary APKs into the work profile during device activation. Present in Android 13, 14, and 15, the flaw existed for approximately 10 years before patching.

During the work profile provisioning flow, a user could deliberately install any APK into the managed profile. The MDM cannot detect these unauthorized apps because the management agent has not yet completed setup. Installed apps then operate within the work profile with access to all corporate data the profile contains.

## MDM Exploitation and Bypass

### Compromising the DPC

If an attacker gains control of the Device Policy Controller app itself, they inherit all DPC APIs. Attack vectors:

| Vector | Description |
|--------|------------|
| DPC app vulnerability | Bugs in the MDM agent (WebView RCE, insecure IPC) grant DPC privileges |
| DPC communication intercept | MITM between DPC and MDM server to inject malicious policies |
| DPC replacement | On rooted devices, replace the DPC with a trojanized version |
| Provisioning intercept | Intercept QR code or NFC provisioning to enroll a rogue MDM |

### Removing MDM

Users on BYOD devices can remove the work profile at any time (this is by design). On company-owned devices, device owner mode prevents removal, but:

| Bypass | Approach |
|--------|----------|
| Factory reset | Removes DO, but FRP (Factory Reset Protection) may prevent re-setup |
| ADB `dpm remove-active-admin` | Requires USB debugging enabled |
| Bootloader unlock + reflash | Destroys all data, defeats FRP |
| Exploit privilege escalation | Root access can remove DO programmatically |
| CVE-2024-43093 | [Android privilege escalation](https://thehackernews.com/2024/11/google-warns-of-actively-exploited-cve.html) (Android 11-14) could bypass system restrictions |

### Silent Permission Granting

A profile owner can use `setPermissionGrantState()` to silently grant runtime permissions to managed apps without any user interaction or dialog:

```java
DevicePolicyManager dpm = getSystemService(DevicePolicyManager.class);
ComponentName admin = new ComponentName(this, MyDeviceAdmin.class);

dpm.setPermissionGrantState(admin, "com.managed.app",
    Manifest.permission.ACCESS_FINE_LOCATION,
    DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED);
```

This is the only legitimate mechanism in Android for granting permissions without user consent. A compromised DPC can grant any runtime permission to any app in its managed profile silently.

## Enterprise-Targeted Malware

### Cerberus MDM Awareness

[Cerberus](../malware/families/cerberus.md) variants [detected since 2024](https://cyble.com/blog/hidden-in-plain-sight-errorfathers-deadly-deployment-of-cerberus/) include MDM detection logic. When the malware detects a managed device, it adapts its behavior:

- Avoids triggering DPC-enforced compliance checks
- Targets corporate banking and ERP apps found in work profiles
- Uses accessibility to interact with work-profile apps without triggering MDM alerts

### Pegasus and Enterprise Targets

[Pegasus](../malware/families/pegasus.md) operates with zero-click exploits that bypass both personal and work profile isolation. On managed devices, Pegasus extracts data from both profiles because it operates at kernel level, below the profile isolation boundary. The [NSO Group has specifically marketed Pegasus](https://en.wikipedia.org/wiki/Pegasus_(spyware)) for targeting corporate executives and government officials whose devices run enterprise MDM.

### Hermit

[Hermit](../malware/families/hermit.md), [attributed to Italian vendor RCS Lab](https://www.darkreading.com/mobile-security/android-spyware-hermit-discovered-in-targeted-attacks), is an enterprise-grade spyware with approximately 25 downloadable modules. Deployed via ISP cooperation (network-level injection), it can operate regardless of work profile isolation because it achieves root access or exploits platform vulnerabilities to bypass sandboxing entirely.

Hermit was deployed against [government officials and business executives in Kazakhstan, Italy, and Syria](https://corrata.com/pegasus-predator-hermit-spyware-nso-and-its-clones/). Its modular architecture allows post-deployment capability expansion, downloading only the modules needed for the specific target.

## BYOD Attack Surface

Bring Your Own Device deployments expand the attack surface because personal-side malware coexists on the same physical device as corporate data.

| Attack | Vector | Impact |
|--------|--------|--------|
| Keylogging across profiles | Accessibility service runs system-wide | Capture work credentials typed in work apps |
| Screen capture | MediaProjection API or accessibility | Record work app screens |
| Clipboard monitoring | System clipboard is shared (default on many configs) | Intercept copied corporate data |
| Network monitoring | VPN or proxy on personal side | Intercept work profile network traffic |
| DNS manipulation | Change DNS to attacker-controlled server | Redirect corporate URLs |

The accessibility service is particularly dangerous in BYOD because it operates at the system level, spanning both personal and work profiles. A malicious app installed on the personal side with accessibility enabled can read and interact with work profile app UIs.

## Android Enterprise Security Model Limitations

| Limitation | Detail |
|-----------|--------|
| Accessibility spans profiles | An accessibility service enabled system-wide can interact with both profiles |
| VPN scope | Personal-side VPN can capture work profile traffic if work profile has no separate VPN |
| Hardware shared | Camera, microphone, sensors are shared resources; personal malware can record during work use |
| Notification shade | Both profile notifications appear in the same notification shade |
| Profile isolation is user-space | Kernel exploits bypass profile boundaries entirely |

## Detection During Analysis

??? example "Static Indicators"

    - `BIND_DEVICE_ADMIN` in manifest
    - `DevicePolicyManager` API calls in code
    - `addCrossProfileIntentFilter` usage
    - Checks for `isProfileOwnerApp()` or `isDeviceOwnerApp()`
    - References to managed profile user IDs

??? example "Dynamic Indicators"

    - DPC APIs invoked without legitimate enterprise context
    - Cross-profile intents observed carrying sensitive data
    - Permission grants via `setPermissionGrantState` without user interaction
    - CA certificate installation without user consent

## Cross-References

- [Device Admin Abuse](device-admin-abuse.md) -- device admin API exploitation (predecessor to Android Enterprise)
- [Accessibility Abuse](accessibility-abuse.md) -- accessibility spans the profile boundary, enabling cross-profile attacks
- [Persistence Techniques](persistence-techniques.md) -- device owner mode is the strongest persistence mechanism on Android
- [Pegasus](../malware/families/pegasus.md) -- operates below profile isolation via kernel exploits
- [Hermit](../malware/families/hermit.md) -- enterprise-targeted modular spyware
