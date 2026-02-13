# PACKAGE_USAGE_STATS

Allows querying app usage statistics: which apps were used, when, and for how long. Used by malware to detect when a target banking app is in the foreground, triggering [overlay attacks](../../attacks/overlay-attacks.md) at the right moment.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.PACKAGE_USAGE_STATS` |
| Protection Level | `signature\|privileged\|development\|appop` |
| Grant Method | Settings > Apps > Special access > Usage access |
| Introduced | API 21 (Android 5.0) |

## What It Enables

Access to `UsageStatsManager`:

```java
UsageStatsManager usm = (UsageStatsManager) getSystemService(Context.USAGE_STATS_SERVICE);
long time = System.currentTimeMillis();
List<UsageStats> stats = usm.queryUsageStats(
    UsageStatsManager.INTERVAL_DAILY, time - 1000 * 60, time);
```

Also enables `UsageEvents` for more granular event tracking:

```java
UsageEvents events = usm.queryEvents(startTime, endTime);
while (events.hasNextEvent()) {
    UsageEvents.Event event = new UsageEvents.Event();
    events.getNextEvent(event);
    if (event.getEventType() == UsageEvents.Event.MOVE_TO_FOREGROUND) {
        String pkg = event.getPackageName();
    }
}
```

## Abuse in Malware

### Foreground Detection for Overlays

The primary abuse case. Malware polls `UsageStatsManager` every 1-2 seconds to check which app is in the foreground:

1. Poll `queryUsageStats()` or `queryEvents()`
2. Check if the foreground package matches a target (banking app)
3. If match found, display overlay immediately

This is the non-accessibility method for triggering overlays. Less efficient than accessibility events (requires polling) but doesn't require the user to enable an accessibility service.

### User Behavior Profiling

Track which apps the user opens, when, and for how long. Useful for:

- Determining the best time to display social engineering prompts
- Identifying high-value targets (banking apps that are actively used)
- Detecting security tools being launched

### App Installation Tracking

`UsageEvents` includes `PACKAGE_INSTALLED` and `PACKAGE_REMOVED` events, revealing when apps are installed or uninstalled.

## Android Version Changes

**Android 5.0 (API 21)**: `UsageStatsManager` introduced with this permission.

**Android 5.1+**: some vendors (Samsung, Huawei) modified the default grant behavior, making it easier or harder to access depending on the OEM.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.PACKAGE_USAGE_STATS" />
```

Combined with `SYSTEM_ALERT_WINDOW` or `INTERNET`, indicates overlay attack infrastructure. The polling pattern (repeated `queryUsageStats` calls in a service or scheduled task) is a strong behavioral indicator.
