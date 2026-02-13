# QUERY_ALL_PACKAGES

Allows an app to see all installed packages on the device. Used by malware for reconnaissance: identifying installed banking apps (to prepare overlays), detecting security software (to avoid or disable it), and fingerprinting the device.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.QUERY_ALL_PACKAGES` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time |
| Introduced | API 30 (Android 11) |

Before Android 11, all apps could freely enumerate installed packages using `PackageManager.getInstalledPackages()`. Android 11 introduced package visibility filtering: by default, apps can only see a limited set of other apps.

## What It Enables

With this permission, `PackageManager.getInstalledPackages()` returns the full list of installed apps. Without it, only apps matching the declaring app's `<queries>` manifest element or meeting automatic visibility criteria are returned.

Apps can also use targeted `<queries>` elements instead of this broad permission:

```xml
<queries>
    <package android:name="com.target.banking.app" />
</queries>
```

## Abuse in Malware

### Target List Matching

Banking trojans use installed app enumeration to determine which overlay injections to download from C2. Instead of downloading templates for all 500+ supported banks, the malware only fetches overlays for apps actually installed on the device.

### Security Software Detection

Malware checks for the presence of antivirus, MDM, and security analysis tools:

| Package Pattern | Tool |
|----------------|------|
| `com.avast.*`, `com.avg.*` | Avast/AVG antivirus |
| `com.bitdefender.*` | Bitdefender |
| `org.malwarebytes.*` | Malwarebytes |
| `com.lookout.*` | Lookout |
| `de.robv.android.xposed.*` | Xposed framework |
| `eu.faircode.netguard` | NetGuard firewall |

If detected, malware may avoid activating, attempt to uninstall the tool (via accessibility), or warn the C2 operator.

### Environment Detection

Checking for analysis environment indicators:

| Package | Indicates |
|---------|-----------|
| `com.android.vending` absent | Non-standard ROM or emulator |
| `com.google.android.gms` absent | No Google Play Services |
| Common emulator packages | Automated analysis sandbox |

### Targeted `<queries>` Alternative

Sophisticated malware avoids `QUERY_ALL_PACKAGES` (which triggers Play Store review scrutiny) and instead lists target packages in `<queries>`:

```xml
<queries>
    <package android:name="com.chase.sig.android" />
    <package android:name="com.bankofamerica.cashpromobile" />
    <package android:name="com.wells.fargo.mobile" />
</queries>
```

This is less conspicuous but reveals the target list in the manifest.

## Android Version Changes

**Android 11 (API 30)**: package visibility filtering introduced. `QUERY_ALL_PACKAGES` added as the opt-out.

**Android 11+**: Google Play policy restricts use of `QUERY_ALL_PACKAGES` to apps where core functionality requires it (e.g., launchers, device managers, security apps). Apps that don't justify it face rejection.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
```

Or check for extensive `<queries>` entries listing banking/financial apps, which reveals targeting intent without needing the broad permission.
