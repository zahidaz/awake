# Normal Permissions (Abusable)

Permissions with `normal` protection level, granted automatically at install time with no user prompt. Most are harmless, but several are critical for malware persistence, reconnaissance, and operation.

These permissions are the foundation of malware operation. They're invisible to the user during installation and provide the infrastructure layer that everything else depends on.

## Permissions

| Permission | Abuse Potential | Criticality |
|-----------|-----------------|-------------|
| [RECEIVE_BOOT_COMPLETED](receive-boot-completed.md) | Persistence: auto-start after device reboot | High: survives reboot |
| [INTERNET](internet.md) | C2 communication, data exfiltration, required by virtually all malware | Essential: no malware operates without it |
| [FOREGROUND_SERVICE](foreground-service.md) | Long-running background operations, persistent connections, continuous monitoring | High: Android 8+ requires this for background work |
| [QUERY_ALL_PACKAGES](query-all-packages.md) | App enumeration: identify installed security tools, banking apps for targeting | High: drives overlay target selection |
| [REQUEST_IGNORE_BATTERY_OPTIMIZATIONS](request-ignore-battery-optimizations.md) | Prevent OS from killing background processes | Medium: ensures persistent operation |
| [WAKE_LOCK](wake-lock.md) | Keep CPU active, ensure background operations complete | Medium: prevents sleep during operations |

## Why Normal Permissions Matter

A typical banking trojan's manifest contains 4-6 of these normal permissions. Combined, they provide:

- **Persistence**: `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` keeps the malware alive across reboots
- **Communication**: `INTERNET` enables C2 connectivity
- **Targeting**: `QUERY_ALL_PACKAGES` identifies which banking apps to overlay
- **Reliability**: `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` + `WAKE_LOCK` prevents the OS from killing the malware process

None of these trigger a user prompt. The user has no visibility into the malware receiving these capabilities.
