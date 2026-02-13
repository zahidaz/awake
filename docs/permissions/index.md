# Android Permissions

Android's permission system controls access to sensitive data and device capabilities. Permissions define what an app can do once installed, and what an attacker gains when a user grants them.

This section covers permissions across all protection levels relevant to security research, not just the "dangerous" category.

## Permission Categories

### Dangerous Permissions (Runtime)

Require explicit user grant. Most malware requests several of these.

| Category | Abuse Scenarios |
|----------|----------------|
| [Calendar](calendar/index.md) | Event data exfiltration, schedule reconnaissance |
| [Call Log](call-log/index.md) | Call history theft, contact mapping |
| [Camera](camera/index.md) | Covert photo/video capture |
| [Contacts](contacts/index.md) | Contact exfiltration, social graph mapping |
| [Location](location/index.md) | Real-time tracking, geofencing |
| [Microphone](microphone/index.md) | Audio surveillance |
| [Phone](phone/index.md) | IMEI harvesting, call interception, premium dialing |
| [Sensors](sensors/index.md) | Biometric data theft |
| [Activity Recognition](activity-recognition/index.md) | User behavior profiling |
| [SMS](sms/index.md) | OTP interception, premium SMS fraud, C2 channel |
| [Storage](storage/index.md) | File exfiltration, payload dropping |
| [Nearby Devices](nearby-devices/index.md) | Device tracking, proximity attacks |

### Special Permissions

Require a settings toggle rather than a runtime dialog. Some of the most powerful permissions available.

| Category | Abuse Scenarios |
|----------|----------------|
| [Special Permissions](special/index.md) | Overlay attacks, accessibility takeover, silent app installs, notification interception |

### Normal Permissions (Auto-Granted)

Granted silently at install time. Often overlooked but critical for malware operation.

| Category | Abuse Scenarios |
|----------|----------------|
| [Normal (Abusable)](normal/index.md) | Boot persistence, C2 communication, app enumeration, battery optimization bypass |

## Permission Escalation Patterns

Malware rarely requests all permissions at install. Instead, it escalates through stages:

| Stage | Permissions | Technique |
|-------|-------------|-----------|
| Install | `INTERNET`, `RECEIVE_BOOT_COMPLETED`, `WAKE_LOCK` | Normal permissions, auto-granted, establish persistence and C2 |
| Social engineering | `BIND_ACCESSIBILITY_SERVICE` | Instructs user to enable in Settings, often with fake security prompts |
| Accessibility-granted | `SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`, `REQUEST_INSTALL_PACKAGES` | Accessibility service clicks through permission dialogs automatically |
| Runtime prompts | `SMS`, `CONTACTS`, `PHONE`, `CAMERA` | Granted via fake explanations or accessibility auto-grant |
| Special | `BIND_DEVICE_ADMIN`, `BIND_NOTIFICATION_LISTENER_SERVICE` | Enabled via Settings or accessibility for maximum device control |

[Accessibility abuse](../attacks/accessibility-abuse.md) is the key escalation vector. Once granted, it can auto-approve every other permission dialog, making it the single most critical permission for malware operations.

## Android Version Impact

| Version | Permission Change | Impact on Malware |
|---------|-------------------|-------------------|
| Android 6 (API 23) | Runtime permissions introduced | Malware must request dangerous permissions individually |
| Android 8 (API 26) | Background execution limits | Requires `FOREGROUND_SERVICE` for persistent operation |
| Android 10 (API 29) | Background location restricted | Requires `ACCESS_BACKGROUND_LOCATION` as separate grant |
| Android 11 (API 30) | Auto-revoke unused permissions, scoped storage | Malware must maintain active usage or request `MANAGE_EXTERNAL_STORAGE` |
| Android 12 (API 31) | Approximate location option, Bluetooth permissions split | Additional permission prompts for location and nearby devices |
| Android 13 (API 33) | Notification permission required, media permissions split | Must request `POST_NOTIFICATIONS` explicitly |
| Android 14 (API 34) | Restricted implicit intents, foreground service types required | Must declare specific `foregroundServiceType` |
| Android 15 (API 35) | Restricted settings enforcement | Multi-step process to enable accessibility for sideloaded apps |

## Minimum Viable Permission Sets

The smallest permission set that enables each malware category:

| Malware Type | Minimum Permissions |
|-------------|-------------------|
| Banking trojan (overlay) | `INTERNET` + `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE` + `RECEIVE_SMS` |
| Banking trojan (ATS) | `INTERNET` + `BIND_ACCESSIBILITY_SERVICE` |
| Spyware | `INTERNET` + `CAMERA` + `RECORD_AUDIO` + `ACCESS_FINE_LOCATION` + `READ_CONTACTS` |
| SMS fraud | `INTERNET` + `SEND_SMS` + `RECEIVE_SMS` |
| Ransomware | `INTERNET` + `BIND_DEVICE_ADMIN` + storage permissions |
| Clipper | `INTERNET` + `BIND_ACCESSIBILITY_SERVICE` (or foreground clipboard access) |

[Medusa](../malware/families/medusa.md) v2 demonstrated the trend toward reduced permission footprints, dropping from 21 to 5 permissions while maintaining full functionality by relying more heavily on accessibility services for capabilities that previously required dedicated permissions.
