# Special Permissions

Permissions outside the standard dangerous permission model that are heavily abused in malware. These require special user actions to grant (settings toggles, installer prompts) rather than runtime dialogs.

## Permissions

| Permission | Abuse Potential | Malware Usage |
|-----------|-----------------|---------------|
| [SYSTEM_ALERT_WINDOW](system-alert-window.md) | Draw over other apps, enabling overlay attacks, credential phishing, tapjacking | Most banking trojans |
| [WRITE_SETTINGS](write-settings.md) | Modify system settings, change default apps, disable security features | Rare in modern malware |
| [REQUEST_INSTALL_PACKAGES](request-install-packages.md) | Install APKs, sideload malware, dropper functionality | Droppers, multi-stage families |
| [REQUEST_DELETE_PACKAGES](request-delete-packages.md) | Uninstall apps, remove security software | Anti-AV behavior |
| [MANAGE_EXTERNAL_STORAGE](manage-external-storage.md) | Full filesystem access, bypass scoped storage restrictions | Spyware, ransomware |
| [BIND_ACCESSIBILITY_SERVICE](bind-accessibility-service.md) | Full UI interaction: keylogging, auto-granting permissions, device takeover | Nearly all modern families |
| [BIND_NOTIFICATION_LISTENER_SERVICE](bind-notification-listener-service.md) | Read all notifications, intercept OTPs, exfiltrate messages | [Alien](../../malware/families/alien.md), [Mamont](../../malware/families/mamont.md), [FireScam](../../malware/families/firescam.md) |
| [BIND_DEVICE_ADMIN](bind-device-admin.md) | Device administration: lock device, wipe data, enforce policies | [BRATA](../../malware/families/brata.md), [Rafel RAT](../../malware/families/rafelrat.md), [BingoMod](../../malware/families/bingomod.md) |
| [PACKAGE_USAGE_STATS](package-usage-stats.md) | App usage data, track user behavior, identify active apps for overlay timing | Overlay-based families |
| [USE_FULL_SCREEN_INTENT](use-full-screen-intent.md) | Launch activities over lock screen, phishing on locked devices | [TrickMo](../../malware/families/trickmo.md), [TsarBot](../../malware/families/tsarbot.md) |

## Granting Mechanism

Unlike dangerous permissions that show a simple dialog, special permissions require the user to navigate to Android Settings:

| Permission | How It's Granted | How Malware Obtains It |
|-----------|-----------------|----------------------|
| `SYSTEM_ALERT_WINDOW` | Settings > Apps > Special access > Display over other apps | Social engineering prompt, or auto-granted for Play Store installs (pre-Android 10) |
| `BIND_ACCESSIBILITY_SERVICE` | Settings > Accessibility > [App Name] | Persistent fake prompts claiming the app needs "accessibility" for security |
| `BIND_DEVICE_ADMIN` | Settings > Security > Device admin apps | Often combined with ransomware lock to prevent removal |
| `REQUEST_INSTALL_PACKAGES` | Settings > Apps > Special access > Install unknown apps | Requested as part of "update" flow |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Settings > Apps > Special access > Notification access | Presented as needed for "message security" |

On Android 13+, [Restricted Settings](https://developer.android.com/about/versions/13/changes/restricted-settings) blocks sideloaded apps from directly requesting accessibility and notification listener. Malware bypasses this through session-based installation or by convincing users to manually navigate through the extra confirmation step.
