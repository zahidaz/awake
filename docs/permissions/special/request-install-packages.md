# REQUEST_INSTALL_PACKAGES

Allows an app to initiate APK installations. Used by malware as a dropper mechanism: the first-stage app downloads a payload APK and triggers installation. The user still sees an install confirmation dialog, but social engineering handles that.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.REQUEST_INSTALL_PACKAGES` |
| Protection Level | `signature\|appop` |
| Grant Method | Settings > Apps > Special access > Install unknown apps |
| Introduced | API 26 (Android 8.0) |

Before Android 8.0, sideloading was a single global toggle ("Unknown sources"). Android 8 changed this to per-app: each app must be individually authorized to install APKs.

## What It Enables

The app can call `Intent(Intent.ACTION_INSTALL_PACKAGE)` or use `PackageInstaller` session APIs to trigger APK installation. The user sees a system install confirmation screen.

On Android 12+, apps can use `PackageInstaller.Session` to silently update themselves if they are the "installer of record" for the package being updated.

## Abuse in Malware

### Dropper Pattern

1. Dropper published on Play Store (disguised as a utility)
2. Dropper passes Play Protect because it contains no malicious code
3. After install, dropper downloads malware APK from C2
4. Dropper prompts user to enable "Install unknown apps"
5. Dropper triggers installation of the payload
6. Payload requests accessibility and overlay permissions

### Multi-Stage Delivery

Families like [SharkBot](../../malware/families/sharkbot.md) and [Anatsa](../../malware/families/anatsa.md) use this flow. The Play Store listing is clean. The malicious payload arrives after installation, often delayed to avoid automated analysis.

### Session-Based Install Bypass

On Android 13+, apps installed via session-based `PackageInstaller.Session` are not subject to restricted settings. The installed payload can request accessibility service access. Malware actively exploits this by using session-based installation rather than `ACTION_VIEW` intents.

### Notable Families

| Family | Dropper / Install Abuse |
|--------|------------------------|
| [SharkBot](../../malware/families/sharkbot.md) | Play Store dropper downloads and installs payload APK post-install |
| [Anatsa](../../malware/families/anatsa.md) | Play Store droppers disguised as PDF/cleaner apps, delayed payload delivery |
| [PlainGnome](../../malware/families/plaingnome.md) | Two-stage dropper architecture with separate surveillance payload |
| [Brokewell](../../malware/families/brokewell.md) | Session-based installer to bypass Android 13 restricted settings |
| [BlankBot](../../malware/families/blankbot.md) | Session-based `PackageInstaller` to bypass Android 13+ sideload restrictions |

## Android Version Changes

**Android 8.0 (API 26)**: per-app install permission introduced.

**Android 13 (API 33)**: restricted settings block sideloaded apps from accessing accessibility and notification listener. Session-based installers bypass this.

**Android 14 (API 34)**: tightened session-based installer restrictions, requiring specific intent filter declarations.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
```

Any non-app-store app requesting this is worth investigating. Legitimate use cases outside of app stores and enterprise MDM are rare.
