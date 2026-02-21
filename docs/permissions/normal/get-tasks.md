# GET_TASKS

Deprecated permission that allowed an app to retrieve information about all running tasks on the device, including the foreground application. This was the original mechanism for [overlay attacks](../../attacks/overlay-attacks.md): malware polled `getRunningTasks()` to detect when a banking app was in the foreground, then instantly displayed a phishing overlay on top of it. Deprecated in Android 5.0 (API 21) and restricted to return only the caller's own tasks, but the permission remains in many malware manifests for backward compatibility with older devices.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.GET_TASKS` |
| Protection Level | `normal` (pre-API 21) |
| Grant Method | Automatically at install time |
| Introduced | API 1 |
| Deprecated | API 21 (Android 5.0) |
| Replaced By | [`PACKAGE_USAGE_STATS`](../special/package-usage-stats.md) (`UsageStatsManager`), Accessibility events |

## What It Enables

### Pre-Android 5.0

```java
ActivityManager am = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(1);
String foregroundPackage = tasks.get(0).topActivity.getPackageName();
```

This returned the package name of whatever app was currently in the foreground. With a 500ms polling loop, malware could detect app switches in near real-time.

### Post-Android 5.0

`getRunningTasks()` only returns the caller's own tasks. Third-party apps can no longer see other apps' foreground state through this API. The method still exists but is neutered.

## Abuse in Malware

### The Original Overlay Trigger

Before Android 5.0, `GET_TASKS` was the key enabler for the overlay attack pattern that defines modern banking trojans:

```java
while (true) {
    ActivityManager am = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
    List<RunningTaskInfo> tasks = am.getRunningTasks(1);
    String pkg = tasks.get(0).topActivity.getPackageName();

    if (targetBanks.contains(pkg)) {
        showPhishingOverlay(pkg);
    }
    Thread.sleep(500);
}
```

The attack flow:

1. Malware runs a background service polling `getRunningTasks()` every 500ms
2. User opens their banking app
3. Malware detects the banking app's package name in the foreground
4. Malware immediately launches a `TYPE_SYSTEM_ALERT` overlay matching the bank's login screen
5. User enters credentials into the overlay, thinking it's the real app
6. Credentials are sent to C2

### Historical Significance

`GET_TASKS` was so central to the first generation of Android banking trojans that Google's deprecation in Android 5.0 forced the entire malware ecosystem to adapt. The three replacement techniques, each with their own trade-offs:

| Technique | Permission | Introduced | Limitations |
|-----------|-----------|------------|-------------|
| `getRunningTasks()` | `GET_TASKS` (normal) | API 1 | Deprecated API 21, returns only own tasks |
| `UsageStatsManager` | [`PACKAGE_USAGE_STATS`](../special/package-usage-stats.md) (appop) | API 21 | Requires user toggle in Settings, polling-based with ~1s delay |
| Accessibility events | [`BIND_ACCESSIBILITY_SERVICE`](../special/bind-accessibility-service.md) | API 4 | Requires user enablement, but provides real-time foreground detection |
| `REAL_GET_TASKS` | signature | API 21 | System apps only, not available to third-party malware |

The malware ecosystem overwhelmingly moved to [accessibility-based overlay triggering](../../attacks/accessibility-abuse.md) because it provides real-time foreground detection, input injection, and many other capabilities in a single permission.

### First-Generation Banking Trojans

| Family | Era | GET_TASKS Usage |
|--------|-----|----------------|
| [Marcher](../../malware/families/marcher.md) | 2013-2018 | `getRunningTasks()` for foreground detection in early versions, migrated to accessibility in later versions |
| [Svpeng](../../malware/families/svpeng.md) | 2013-2017 | Polled running tasks for overlay injection targeting Russian banking apps |
| [BankBot](../../malware/families/bankbot.md) | 2016-2018 | Task polling for overlay trigger, later versions added `UsageStatsManager` fallback |
| [Anubis](../../malware/families/anubis.md) | 2017+ | Dual approach: `UsageStatsManager` primary, `GET_TASKS` fallback for older devices |

### Still Declared in Modern Malware

Many current malware families still declare `GET_TASKS` in their manifest even though they primarily use accessibility or `UsageStatsManager`:

- Backward compatibility with Android 4.x devices still in use in some regions
- Belt-and-suspenders approach: try `GET_TASKS` first, fall back to other methods
- Copy-paste from older codebases and malware builder kits that haven't been cleaned up
- No cost to declaring it (normal permission, auto-granted, no user prompt)

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | `GET_TASKS` introduced | Full foreground app visibility for any app |
| 5.0 | 21 | `getRunningTasks()` restricted to own tasks | Overlay trigger mechanism broken for third-party apps |
| 5.0 | 21 | `UsageStatsManager` introduced | Replacement requires user enablement in Settings |
| 5.0 | 21 | `REAL_GET_TASKS` (signature) introduced | System apps retain full task visibility |
| 5.1 | 22 | `getRecentTasks()` also restricted | Closed the last workaround for foreground detection via task APIs |

## Detection Indicators

### Manifest Signals

```xml
<uses-permission android:name="android.permission.GET_TASKS" />
```

On modern samples (targeting API 21+), the presence of `GET_TASKS` is a backward-compatibility indicator suggesting the malware originated from or targets older Android versions. Combined with:

- [`SYSTEM_ALERT_WINDOW`](../special/system-alert-window.md) = overlay attack toolkit
- [`PACKAGE_USAGE_STATS`](../special/package-usage-stats.md) = dual-method foreground detection
- [`BIND_ACCESSIBILITY_SERVICE`](../special/bind-accessibility-service.md) = modern overlay trigger
- `INTERNET` = C2 for credential exfiltration

### Static Analysis

- `ActivityManager.getRunningTasks()` calls in decompiled code
- Polling loops with `Thread.sleep()` or `Handler.postDelayed()` around task queries
- Package name string lists containing banking app identifiers near task-checking code
- Conditional overlay launch logic triggered by foreground package matching

## See Also

- [Overlay Attacks](../../attacks/overlay-attacks.md)
- [PACKAGE_USAGE_STATS](../special/package-usage-stats.md)
- [SYSTEM_ALERT_WINDOW](../special/system-alert-window.md)
- [BIND_ACCESSIBILITY_SERVICE](../special/bind-accessibility-service.md)
