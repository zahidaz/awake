# REQUEST_DELETE_PACKAGES

Allows an app to request uninstallation of other apps. The user sees a confirmation dialog. Used by malware to remove antivirus, security tools, or competing malware from the device.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.REQUEST_DELETE_PACKAGES` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time |
| Introduced | API 26 (Android 8.0) |

## What It Enables

```java
Intent intent = new Intent(Intent.ACTION_DELETE);
intent.setData(Uri.parse("package:com.security.app"));
startActivity(intent);
```

This shows the system uninstall confirmation dialog for the target package. The user must confirm.

## Abuse in Malware

### Removing Security Software

Malware can prompt uninstallation of antivirus or security tools:

1. Detect installed security apps (via [`QUERY_ALL_PACKAGES`](../normal/query-all-packages.md))
2. Trigger uninstall dialog for each one
3. If the malware has accessibility, click "OK" on the confirmation automatically

### Removing Competing Malware

Some malware families uninstall competing trojans from the device.

### Combined with Accessibility

With [`BIND_ACCESSIBILITY_SERVICE`](bind-accessibility-service.md), the malware can click through uninstall confirmations without user interaction, making this effectively a silent uninstall capability.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.REQUEST_DELETE_PACKAGES" />
```

Combined with `QUERY_ALL_PACKAGES` and accessibility, indicates targeted removal of other apps.
