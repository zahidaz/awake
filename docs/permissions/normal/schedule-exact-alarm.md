# SCHEDULE_EXACT_ALARM

Permission controlling access to exact-time alarm scheduling via `AlarmManager`. Malware uses exact alarms for reliable C2 callback scheduling, periodic data exfiltration, and persistent task execution that survives Doze mode restrictions. On Android 12 (API 31) this became a special permission requiring user opt-in through Settings. On Android 13+ (`USE_EXACT_ALARM`) it was re-simplified for certain app categories. The shift from unrestricted to gated access directly impacts malware persistence strategies.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.SCHEDULE_EXACT_ALARM` |
| Protection Level | Normal (API 31-32), requires Settings opt-in |
| Grant Method | Auto-granted on API 31, revocable by user in Settings > Alarms & Reminders |
| Introduced | API 31 (Android 12) |
| Related | `USE_EXACT_ALARM` (API 33+, auto-granted for alarm/timer/calendar apps) |
| User Visibility | Listed under Settings > Apps > Special app access > Alarms & reminders |

### Distinction: SCHEDULE_EXACT_ALARM vs USE_EXACT_ALARM

| Permission | API | Grant Method | Use Case |
|-----------|-----|-------------|----------|
| `SCHEDULE_EXACT_ALARM` | 31+ | Granted by default on 31-32, user-revocable in Settings. On 33+, denied by default for newly installed apps targeting API 33+ | Any app needing exact timing |
| `USE_EXACT_ALARM` | 33+ | Auto-granted, not revocable | Only alarm clocks, timers, and calendar apps |

On Android 14+ (API 34), apps targeting SDK 33+ that request `SCHEDULE_EXACT_ALARM` are denied by default and must direct the user to Settings to enable it. This broke malware that relied on exact alarms being auto-granted.

## What It Enables

### Exact Alarm Scheduling

```java
AlarmManager alarmManager = (AlarmManager) getSystemService(ALARM_SERVICE);
Intent intent = new Intent(this, C2PollReceiver.class);
PendingIntent pending = PendingIntent.getBroadcast(this, 0, intent,
    PendingIntent.FLAG_IMMUTABLE);
alarmManager.setExactAndAllowWhileIdle(
    AlarmManager.ELAPSED_REALTIME_WAKEUP,
    SystemClock.elapsedRealtime() + intervalMs,
    pending
);
```

`setExactAndAllowWhileIdle()` fires at the precise scheduled time even during Doze mode. This is the critical method for malware: it guarantees execution regardless of the device's power-saving state.

### Alarm Types

| Method | Doze Behavior | Timing | Malware Use |
|--------|--------------|--------|-------------|
| `setExact()` | Deferred during Doze | Exact when not in Doze | C2 polling outside Doze |
| `setExactAndAllowWhileIdle()` | Fires during Doze (limited rate) | Exact, even in Doze | Primary persistence mechanism |
| `setAlarmClock()` | Always fires (treated as user-visible) | Exact | Backup mechanism, shows alarm icon in status bar |
| `setInexactRepeating()` | Batched during Doze | Inexact | Fallback for apps without exact alarm permission |

## Abuse in Malware

### Persistence via Alarm Scheduling

Malware registers exact alarms to schedule periodic tasks:

| Task | Interval | Purpose |
|------|----------|---------|
| C2 beacon | 5-60 minutes | Maintain contact with command server |
| Data exfiltration | 15-60 minutes | Upload collected SMS, contacts, location |
| Overlay check | 1-5 minutes | Monitor foreground app for target banking apps |
| Keepalive | 1-15 minutes | Restart killed services |
| Payload update | 6-24 hours | Check for updated malware configuration |

### Families Using Exact Alarms

| Family | Usage | Details |
|--------|-------|---------|
| [Cerberus](../../malware/families/cerberus.md) | C2 beacon, overlay scheduling | Periodic polls to C2 for target app list updates |
| [Hook](../../malware/families/hook.md) | Service keepalive | Restarts VNC and accessibility services on alarm triggers |
| [SpyNote](../../malware/families/spynote.md) | Data exfiltration scheduling | Periodic upload of collected surveillance data |
| [GodFather](../../malware/families/godfather.md) | C2 polling | Exact alarms for reliable C2 communication |
| [Octo](../../malware/families/octo.md) | Keepalive | Ensures MediaProjection service stays active |
| [Anubis](../../malware/families/anubis.md) | Scheduling | Task scheduling for credential theft workflows |

### Workarounds After Android 14 Restriction

When `SCHEDULE_EXACT_ALARM` is denied by default on Android 14+:

| Workaround | Mechanism |
|-----------|-----------|
| `setAlarmClock()` | Always allowed, but shows alarm icon in status bar. Some malware accepts this tradeoff. |
| `WorkManager` | Inexact but reliable periodic tasks. Less precise but no special permission needed. |
| Accessibility auto-grant | Navigate to Settings and enable exact alarm permission via accessibility service |
| `setInexactRepeating()` | Batched inexact alarms. Less reliable but works without permission. |
| Firebase Cloud Messaging | Push-based wakeup from server. No alarm permission needed. |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 6.0 | 23 | Doze mode introduced | `setExact()` deferred during Doze. `setExactAndAllowWhileIdle()` added as workaround. |
| 12 | 31 | `SCHEDULE_EXACT_ALARM` permission introduced | Granted by default, user-revocable in Settings |
| 13 | 33 | `USE_EXACT_ALARM` added | Auto-granted for alarm/timer/calendar apps only |
| 14 | 34 | `SCHEDULE_EXACT_ALARM` denied by default for apps targeting API 33+ | Malware must redirect user to Settings or use workarounds |

## Detection Indicators

### Manifest Signals

- `SCHEDULE_EXACT_ALARM` combined with `RECEIVE_BOOT_COMPLETED` and `INTERNET`
- `USE_EXACT_ALARM` requested by apps that are not alarm clocks, timers, or calendar apps
- `BroadcastReceiver` registrations for alarm-triggered intents alongside C2-related code

### Behavioral Signals

- `setExactAndAllowWhileIdle()` calls with intervals under 15 minutes (aggressive polling)
- Alarm receivers that start network operations or foreground services
- Repeated `setAlarmClock()` calls without displaying an actual alarm UI

## See Also

- [Persistence Techniques](../../attacks/persistence-techniques.md)
- [RECEIVE_BOOT_COMPLETED](receive-boot-completed.md)
- [REQUEST_IGNORE_BATTERY_OPTIMIZATIONS](request-ignore-battery-optimizations.md)
