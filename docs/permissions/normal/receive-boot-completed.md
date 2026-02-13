# RECEIVE_BOOT_COMPLETED

The primary persistence mechanism on Android. This normal-protection-level permission is granted silently at install time -- no user prompt, no settings toggle, no review hurdle. It allows an app to receive a broadcast when the device finishes booting, at which point the app can start services, schedule tasks, and establish C2 connections. Virtually every persistent Android malware uses this permission. Without it, the malware would die on reboot, requiring the user to manually re-launch it.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_BOOT_COMPLETED` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 1 |
| User Visibility | None -- not shown in permission dialogs or special access settings |
| Play Store Policy | No restrictions (extremely common in legitimate apps) |

The `normal` protection level is the key factor. Unlike `dangerous` permissions that require runtime consent or special permissions that need user toggling in Settings, `RECEIVE_BOOT_COMPLETED` is granted the moment the APK is installed. The user has no opportunity to deny it and is never informed that the app can auto-start on boot.

## What It Enables

The app registers a `BroadcastReceiver` for `ACTION_BOOT_COMPLETED`. After the device boots, the system delivers this broadcast to all registered receivers. The receiver then starts services, schedules alarms, or initiates any background operation.

### Boot Receiver Implementation

```java
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Intent serviceIntent = new Intent(context, C2Service.class);
            context.startForegroundService(serviceIntent);
        }
    }
}
```

### Manifest Registration

```xml
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />

<receiver
    android:name=".BootReceiver"
    android:exported="true"
    android:enabled="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
```

The `exported="true"` attribute is required for the receiver to receive system broadcasts. The receiver is invoked by the system itself, not by other apps.

## Related Broadcasts

Malware rarely relies on `BOOT_COMPLETED` alone. For redundancy and to cover edge cases (direct boot, app updates, timezone changes), families register for multiple boot-like and system-event broadcasts:

| Broadcast | When Fired | Permission Required | Notes |
|-----------|------------|-------------------|-------|
| `ACTION_BOOT_COMPLETED` | After full system boot and user unlock | `RECEIVE_BOOT_COMPLETED` | Primary persistence trigger |
| `ACTION_LOCKED_BOOT_COMPLETED` | After direct boot, before user unlock (API 24+) | `RECEIVE_BOOT_COMPLETED` | Runs earlier than BOOT_COMPLETED, useful for device-encrypted storage scenarios |
| `ACTION_MY_PACKAGE_REPLACED` | After the app itself is updated | None | Ensures malware restarts after self-update from C2 |
| `ACTION_PACKAGE_REPLACED` | After any package on device is updated | None | Broader trigger, fires frequently |
| `ACTION_USER_PRESENT` | After user unlocks the screen | None | Fires on every unlock, useful as a fallback if boot receiver was killed |
| `ACTION_POWER_CONNECTED` | When charger is connected | None | Frequent event, used as a wakeup trigger |
| `ACTION_TIMEZONE_CHANGED` | When device timezone changes | None | Obscure trigger, less likely to be filtered |
| `ACTION_CONNECTIVITY_CHANGE` | When network state changes | `ACCESS_NETWORK_STATE` | Fires frequently, good for re-establishing C2 after network drops |

Registering for multiple events creates a resilient persistence net. Even if the system kills the malware's background service, the next broadcast will restart it.

## Combined Persistence Patterns

### Boot + Foreground Service

The standard pattern: boot receiver starts a foreground service that maintains persistent C2 connection, monitors for target apps, and keeps the malware operational:

```java
public class C2Service extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification notification = buildSilentNotification();
        startForeground(1, notification);
        connectToC2();
        startOverlayMonitoring();
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
```

`START_STICKY` tells the system to restart the service if it is killed due to memory pressure. Combined with the boot receiver, this creates a self-healing persistence loop.

### Boot + WorkManager

Post-API 26 background limits make raw background services unreliable. Modern malware uses `WorkManager` for persistent scheduling that survives boot, doze mode, and app standby:

```java
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        PeriodicWorkRequest c2Work = new PeriodicWorkRequest.Builder(
            C2Worker.class, 15, TimeUnit.MINUTES
        ).setConstraints(
            new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
        ).build();

        WorkManager.getInstance(context)
            .enqueueUniquePeriodicWork("c2", ExistingPeriodicWorkPolicy.KEEP, c2Work);
    }
}
```

### Boot + AlarmManager

Older pattern, still effective. `AlarmManager` schedules repeating alarms that fire even when the app is not running. Combined with boot receiver for re-scheduling after reboot:

```java
AlarmManager alarmManager = (AlarmManager) context.getSystemService(ALARM_SERVICE);
PendingIntent pending = PendingIntent.getBroadcast(
    context, 0, new Intent(context, C2Receiver.class),
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
);
alarmManager.setExactAndAllowWhileIdle(
    AlarmManager.RTC_WAKEUP,
    System.currentTimeMillis() + 60000,
    pending
);
```

`setExactAndAllowWhileIdle` fires even during Doze mode (with frequency restrictions), making it useful for maintaining C2 beacons.

## Abuse in Malware

`RECEIVE_BOOT_COMPLETED` is foundational infrastructure -- it does not perform the attack directly but ensures the attack components survive reboots. It is present in virtually every persistent Android malware family.

### Notable Families

| Family | Boot Persistence Usage | Source |
|--------|----------------------|--------|
| [Cerberus](../../malware/families/cerberus.md) | Boot receiver restarts overlay monitoring service and C2 connection, leaked source code made this pattern widely copied | [ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld) |
| [Hook](../../malware/families/hook.md) | Boot persistence for VNC-based remote access and overlay injection engine | [ThreatFabric](https://www.threatfabric.com/blogs) |
| [GodFather](../../malware/families/godfather.md) | Boot receiver restarts accessibility-based monitoring and WebSocket C2 channel | [Cyble](https://cyble.com/blog/) |
| [Octo](../../malware/families/octo.md) | Boot-triggered foreground service for screen streaming, keylogging, and remote access | [ThreatFabric](https://www.threatfabric.com/blogs) |
| [Medusa](../../malware/families/medusa.md) | Boot persistence for screen recording, remote access, and SMS interception | [Cleafy](https://www.cleafy.com/cleafy-labs/) |
| [Hydra](../../malware/families/hydra.md) | Boot receiver re-establishes C2 connection and overlay injection service | [ThreatFabric](https://www.threatfabric.com/blogs) |
| [SharkBot](../../malware/families/sharkbot.md) | Boot persistence for ATS fraud engine and credential interception service | [NCC Group](https://www.nccgroup.com/research-blog/sharkbot-a-new-generation-android-banking-trojan-being-distributed-on-google-play-store/) |
| [SpyNote](../../malware/families/spynote.md) | Boot receiver ensures persistent RAT functionality, also registers for LOCKED_BOOT_COMPLETED | [F-Secure](https://www.f-secure.com/en/articles/take-a-note-of-spynote-malware) |
| [Rafel RAT](../../malware/families/rafelrat.md) | Boot persistence combined with battery optimization exemption for continuous operation, found in 120+ campaigns | [Check Point](https://research.checkpoint.com/2024/rafel-rat-android-malware-from-espionage-to-ransomware-operations/) |

### Permission Combination as Threat Signal

`RECEIVE_BOOT_COMPLETED` is normal in legitimate apps (alarm clocks, messaging apps, fitness trackers). The malware signal comes from its combination with other permissions:

| Combination | Threat Pattern |
|-------------|---------------|
| `RECEIVE_BOOT_COMPLETED` + `BIND_ACCESSIBILITY_SERVICE` | Boot persistence for accessibility-based attack (overlay, keylogging, ATS) |
| `RECEIVE_BOOT_COMPLETED` + `SYSTEM_ALERT_WINDOW` + `INTERNET` | Persistent overlay attack infrastructure |
| `RECEIVE_BOOT_COMPLETED` + `READ_SMS` + `RECEIVE_SMS` + `INTERNET` | Persistent SMS interception and exfiltration |
| `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` + `WAKE_LOCK` | Persistent background operation (C2 beacon, data exfiltration) |
| `RECEIVE_BOOT_COMPLETED` + `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Aggressive persistence -- resists Doze and app standby |
| `RECEIVE_BOOT_COMPLETED` + `CAMERA` + `RECORD_AUDIO` + `ACCESS_FINE_LOCATION` | Spyware/RAT persistence (Rafel RAT, SpyNote pattern) |

A "utility" app declaring `RECEIVE_BOOT_COMPLETED` alongside accessibility or overlay permissions should be treated as suspicious by default. See the MITRE ATT&CK Mobile technique [T1624.001: Event Triggered Execution - Broadcast Receivers](https://attack.mitre.org/techniques/T1624/001/) for the formal taxonomy.

## Android Version Changes

### Android 3.1 (API 12)

Apps in "stopped state" (freshly installed, never opened by the user) do not receive `BOOT_COMPLETED`. The user must launch the app at least once. This prevents malware from activating purely through silent installation, but all sideloading-based attacks involve social engineering to open the app immediately after install, making this a trivial hurdle in practice.

### Android 8.0 (API 26)

Background execution limits. Apps targeting API 26+ cannot start background services from broadcast receivers. `BOOT_COMPLETED` receivers still fire, but they must use `startForegroundService()` instead of `startService()`. The foreground service must show a notification within 5 seconds. Malware adapted by creating minimal/silent notifications (low-priority channels, empty titles) or using `WorkManager` for scheduled tasks that do not require a visible notification.

### Android 12 (API 31)

Foreground service launch restrictions from the background. Apps cannot start foreground services while in the background except from specific allowed contexts -- and `BOOT_COMPLETED` receivers are one of those exempted contexts. This means the boot receiver remains a reliable way to start foreground services, even on Android 12+.

### Android 13 (API 33)

`FOREGROUND_SERVICE` types must be declared in the manifest. Malware must specify the `foregroundServiceType` attribute (e.g., `dataSync`, `location`, `mediaPlayback`). This adds a static analysis indicator but does not prevent the technique -- malware simply declares an appropriate type.

### Android 14 (API 34)

Additional restrictions on implicit broadcasts for apps targeting API 34. However, `BOOT_COMPLETED` is a protected broadcast sent by the system and remains deliverable to statically registered receivers. The `FOREGROUND_SERVICE_DATA_SYNC` type now requires the `FOREGROUND_SERVICE_DATA_SYNC` permission (normal protection level, auto-granted).

## Frida Monitoring Script

Monitor boot receiver registrations and service starts triggered by boot:

```javascript
Java.perform(function () {
    var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");

    BroadcastReceiver.onReceive.implementation = function (context, intent) {
        var action = intent.getAction();
        if (action !== null) {
            var bootActions = [
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.LOCKED_BOOT_COMPLETED",
                "android.intent.action.MY_PACKAGE_REPLACED",
                "android.intent.action.USER_PRESENT",
                "android.intent.action.QUICKBOOT_POWERON"
            ];
            for (var i = 0; i < bootActions.length; i++) {
                if (action === bootActions[i]) {
                    console.log("[Boot] Receiver triggered: " + this.getClass().getName());
                    console.log("  action: " + action);
                    break;
                }
            }
        }
        this.onReceive(context, intent);
    };

    var ContextWrapper = Java.use("android.content.ContextWrapper");

    ContextWrapper.startForegroundService.implementation = function (intent) {
        var component = intent.getComponent();
        console.log("[Service] startForegroundService called");
        if (component !== null) {
            console.log("  target: " + component.getClassName());
        }
        return this.startForegroundService(intent);
    };

    ContextWrapper.startService.implementation = function (intent) {
        var component = intent.getComponent();
        console.log("[Service] startService called");
        if (component !== null) {
            console.log("  target: " + component.getClassName());
        }
        return this.startService(intent);
    };
});
```

## Detection Indicators

**Manifest signals:**

```xml
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />

<receiver android:name=".BootReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
```

**Escalated indicators (multiple boot-like receivers):**

```xml
<receiver android:name=".PersistReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
        <action android:name="android.intent.action.LOCKED_BOOT_COMPLETED" />
        <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
        <action android:name="android.intent.action.USER_PRESENT" />
    </intent-filter>
</receiver>
```

Multiple boot-like actions in a single receiver's intent filter is a strong malware signal -- legitimate apps rarely need to cover this many restart triggers.

**Static analysis targets:**

- Boot receiver classes that immediately start a `Service` or `ForegroundService`
- `START_STICKY` return value in `onStartCommand()` (service auto-restart)
- `AlarmManager.setExactAndAllowWhileIdle()` scheduled from boot receiver
- `WorkManager.enqueueUniquePeriodicWork()` called from boot receiver
- `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` alongside boot completion (aggressive persistence)
- `PowerManager.WakeLock` acquisition in boot receiver chain

See also: [Persistence Techniques](../../attacks/persistence-techniques.md) | [C2 Communication](../../attacks/c2-techniques.md)
