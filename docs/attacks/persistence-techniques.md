# Persistence Techniques

Surviving device reboots, app kills, and user attempts at removal. Android's process lifecycle aggressively terminates background apps to conserve resources, so malware must actively fight to stay alive. The most resilient families layer multiple persistence mechanisms, ensuring that if one is killed, another restarts it.

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1624.001](https://attack.mitre.org/techniques/T1624/001/) | Event Triggered Execution: Broadcast Receivers | Persistence |
    | [T1541](https://attack.mitre.org/techniques/T1541/) | Foreground Persistence | Persistence, Defense Evasion |
    | [T1398](https://attack.mitre.org/techniques/T1398/) | Boot or Logon Initialization Scripts | Persistence |
    | [T1626.001](https://attack.mitre.org/techniques/T1626/001/) | Abuse Elevation Control Mechanism: Device Administrator Permissions | Privilege Escalation |

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Boot persistence | [`RECEIVE_BOOT_COMPLETED`](../permissions/normal/receive-boot-completed.md) (normal permission, auto-granted) |
    | Background execution | [`FOREGROUND_SERVICE`](../permissions/normal/foreground-service.md) (normal permission, auto-granted) |
    | Battery exemption | [`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`](../permissions/normal/request-ignore-battery-optimizations.md) |
    | Anti-uninstall | [`BIND_DEVICE_ADMIN`](../permissions/special/bind-device-admin.md) (requires user activation) |
    | Self-restart | [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) (system manages lifecycle) |

## Boot Receiver

The simplest and most common persistence method. Registering a `BroadcastReceiver` for `BOOT_COMPLETED` causes Android to start the malware's component every time the device boots.

```xml
<receiver android:name=".BootReceiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
        <action android:name="android.intent.action.QUICKBOOT_POWERON" />
        <action android:name="com.htc.intent.action.QUICKBOOT_POWERON" />
    </intent-filter>
</receiver>
```

```java
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Intent serviceIntent = new Intent(context, MalwareService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent);
        } else {
            context.startService(serviceIntent);
        }
    }
}
```

Multiple boot actions are registered because some OEMs (HTC, Xiaomi) fire vendor-specific boot broadcasts in addition to or instead of the standard one.

## Foreground Service

Android 8+ kills background services within minutes. The standard workaround is a foreground service, which requires a visible notification but is protected from the system's background execution limits.

??? example "Stealth Foreground Service with Hidden Notification"

    ```java
    public class PersistentService extends Service {
        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            NotificationChannel channel = new NotificationChannel(
                "stealth", " ", NotificationManager.IMPORTANCE_MIN);
            channel.setShowBadge(false);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);

            Notification notification = new Notification.Builder(this, "stealth")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle(" ")
                .build();
            startForeground(1, notification);
            return START_STICKY;
        }

        @Override
        public IBinder onBind(Intent intent) {
            return null;
        }
    }
    ```

The notification channel uses `IMPORTANCE_MIN` and a blank name to make the notification as invisible as possible. `START_STICKY` tells Android to restart the service if the system kills it. [SpyNote](../malware/families/spynote.md) and [Anubis](../malware/families/anubis.md) both rely on this pattern.

## Scheduled Execution

### JobScheduler

Schedules work that survives process death. The system manages when the job runs based on constraints (network, charging, idle).

```java
ComponentName serviceName = new ComponentName(context, MalwareJobService.class);
JobInfo jobInfo = new JobInfo.Builder(1337, serviceName)
    .setPersisted(true)
    .setPeriodic(15 * 60 * 1000)
    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
    .build();

JobScheduler scheduler = context.getSystemService(JobScheduler.class);
scheduler.schedule(jobInfo);
```

`setPersisted(true)` makes the job survive reboots (requires `RECEIVE_BOOT_COMPLETED`). The minimum periodic interval is 15 minutes on Android 7+.

### AlarmManager

For more precise timing. `setExactAndAllowWhileIdle()` fires even during Doze mode, though Android 12+ restricts exact alarms and requires `SCHEDULE_EXACT_ALARM` or `USE_EXACT_ALARM`.

```java
AlarmManager alarmManager = context.getSystemService(AlarmManager.class);
Intent intent = new Intent(context, WakeUpReceiver.class);
PendingIntent pending = PendingIntent.getBroadcast(
    context, 0, intent, PendingIntent.FLAG_IMMUTABLE);
alarmManager.setExactAndAllowWhileIdle(
    AlarmManager.ELAPSED_REALTIME_WAKEUP,
    SystemClock.elapsedRealtime() + 60_000,
    pending);
```

### AccountManager Sync Adapter

An underused but effective persistence method. The malware registers as a sync adapter for a custom account type. Android's sync framework periodically triggers the adapter, providing reliable execution without visible notifications.

The sync adapter runs in its own process and benefits from the system's built-in retry and scheduling logic. [Mandrake](../malware/families/mandrake.md) used this technique to maintain periodic C2 communication.

## Accessibility Service Persistence

An active [accessibility service](accessibility-abuse.md) is managed by the system and automatically restarted if it crashes. As long as the user doesn't manually revoke the toggle in Settings, the service persists indefinitely across reboots.

This makes accessibility the most reliable persistence mechanism available without root. The malware can also use accessibility to prevent its own removal -- detecting when the user navigates to Settings > Apps and pressing "Back" or "Home" before they can reach the uninstall button.

## Anti-Uninstall Techniques

### Device Admin

Activating as a device administrator prevents uninstallation. The user must deactivate the admin first, but the malware can use accessibility to block navigation to the deactivation screen.

[Cerberus](../malware/families/cerberus.md) combined device admin with accessibility: any attempt to open device admin settings triggers the accessibility service to press Home, making deactivation nearly impossible without ADB or safe mode.

### Hiding from Launcher

Removing the launcher `Activity` from the manifest (or disabling the component at runtime) hides the app from the app drawer. The user can still find it in Settings > Apps, but most users won't think to look there.

```java
PackageManager pm = getPackageManager();
pm.setComponentEnabledSetting(
    new ComponentName(this, LauncherActivity.class),
    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
    PackageManager.DONT_KILL_APP);
```

[Joker](../malware/families/joker.md), [FluBot](../malware/families/flubot.md), and many RATs use this immediately after initial execution.

## Firmware-Level Persistence

### Pre-installed Malware

[Triada](../malware/families/triada.md) achieved persistence by infecting the device firmware during manufacturing. The malware was embedded in the system partition (read-only at runtime), surviving factory resets and any user-level remediation. Only reflashing the firmware with a clean image removes it.

This represents the most resilient form of persistence on Android. Discovered in budget devices where supply chain compromise occurred at the factory or during distribution.

### Root-Based System Installation

[Pegasus](../malware/families/pegasus.md) and other state-sponsored malware use exploit chains to gain root, then install themselves as a system app in `/system/app/` or `/system/priv-app/`. System apps persist across factory resets and receive elevated privileges. Short of reflashing the firmware, the malware is permanent.

## Battery Optimization Exemption

Android's Doze mode and App Standby buckets restrict background execution. Malware requests exemption:

```java
Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
intent.setData(Uri.parse("package:" + getPackageName()));
startActivity(intent);
```

This shows a system dialog. Some families use accessibility to auto-tap "Allow" on this dialog. Others disguise the request behind a fake loading screen so the user doesn't realize what they're approving.

## OEM-Specific Persistence

Chinese OEMs (Xiaomi, Huawei, Oppo, Vivo) maintain their own autostart managers that independently restrict background apps. Even with `RECEIVE_BOOT_COMPLETED` and battery optimization disabled, these OEMs may kill the app unless it is whitelisted in their proprietary autostart list.

Malware targeting these regions often includes OEM-specific code that detects the manufacturer and launches the appropriate settings intent to guide (or force via accessibility) the user into whitelisting the app.

!!! tip "OEM Autostart Managers"

    When testing on Xiaomi, Huawei, Oppo, or Vivo devices, check for autostart whitelist entries under OEM-specific settings. Malware that works reliably in the wild on these devices has likely solved the OEM background-kill problem -- look for `Build.MANUFACTURER` checks and vendor-specific `Intent` actions in the decompiled code.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 1.0 | 1 | `BOOT_COMPLETED` broadcast available | Basic boot persistence from day one |
| 5.0 | 21 | `JobScheduler` introduced | Persistent scheduled execution surviving process death |
| 8.0 | 26 | [Background service limits](https://developer.android.com/about/versions/oreo/background) | Services killed within minutes; foreground service with notification required |
| 8.0 | 26 | [Implicit broadcast restrictions](https://developer.android.com/about/versions/oreo/background#broadcasts) | `BOOT_COMPLETED` exempt, still delivered to manifest receivers |
| 10 | 29 | [Background activity launch restrictions](https://developer.android.com/guide/components/activities/background-starts) | Cannot start activities from background; use `USE_FULL_SCREEN_INTENT` or accessibility |
| 10 | 29 | Background location limits | Foreground service with `location` type required |
| 12 | 31 | [Foreground service launch restrictions](https://developer.android.com/about/versions/12/foreground-services) | Cannot start foreground service from background except via boot receiver, alarm, or accessibility |
| 12 | 31 | [Exact alarm restrictions](https://developer.android.com/about/versions/12/behavior-changes-12#exact-alarm-permission) | `SCHEDULE_EXACT_ALARM` or `USE_EXACT_ALARM` required |
| 13 | 33 | `POST_NOTIFICATIONS` runtime permission required | Social engineer the grant, or use silent channels created pre-upgrade |
| 14 | 34 | [Foreground service type requirements](https://developer.android.com/about/versions/14/changes/fgs-types-required) | Must declare specific foreground service type in manifest |
| 15 | 35 | Further restrictions on foreground service types | Some types (e.g., `dataSync`) limited to 6 hours |

Each restriction pushed malware toward more creative solutions. The overall trend is layering multiple persistence methods so that at least one survives the increasingly aggressive background restrictions.

!!! info "Layered Persistence"

    Modern banking trojans never rely on a single persistence mechanism. Expect to find at least two or three methods in any sample -- typically a boot receiver combined with a foreground service and [accessibility service](accessibility-abuse.md) persistence. Disabling only one layer during analysis may give the false impression that the malware has been neutralized.

## Persistence Method Comparison

| Method | Survives Reboot | Survives Force Stop | Stealth | Reliability | Min Android |
|--------|:-:|:-:|--------|-------------|:-:|
| Boot receiver | Yes | No | High | High | All |
| Foreground service | No | No | Low (notification) | High | 8+ |
| JobScheduler | Yes (persisted) | No | High | Medium | 5+ |
| AlarmManager | No | No | High | Medium | All |
| Sync adapter | Yes | No | High | Medium | All |
| Accessibility service | Yes | Yes (if enabled) | Medium | Very high | 4.1+ |
| Device admin | N/A (anti-uninstall) | N/A | Low | High | All |
| System app / firmware | Yes | Yes | Very high | Permanent | All |

## Families by Persistence Strategy

| Family | Primary Persistence | Secondary | Anti-Uninstall |
|--------|-------------------|-----------|----------------|
| [Triada](../malware/families/triada.md) | Firmware | System app | Factory reset resistant |
| [Pegasus](../malware/families/pegasus.md) | Root + system install | Multiple | Survives factory reset |
| [SpyNote](../malware/families/spynote.md) | Foreground service | Boot receiver | Hides from launcher |
| [Anubis](../malware/families/anubis.md) | Boot receiver | Foreground service | Device admin |
| [Cerberus](../malware/families/cerberus.md) | Accessibility | Boot receiver | Device admin + accessibility block |
| [Joker](../malware/families/joker.md) | JobScheduler | Boot receiver | Hides from launcher |
| [Hook](../malware/families/hook.md) | Foreground service | Boot receiver + accessibility | Device admin |
| [FluBot](../malware/families/flubot.md) | Boot receiver | Foreground service | Hides from launcher, accessibility block |
| [Mandrake](../malware/families/mandrake.md) | Sync adapter | Boot receiver | Hides from launcher |
| [GodFather](../malware/families/godfather.md) | Accessibility | Foreground service | Accessibility block |

## Detection During Analysis

??? example "Static Indicators"

    - `RECEIVE_BOOT_COMPLETED` in manifest with a `BroadcastReceiver`
    - `FOREGROUND_SERVICE` with `IMPORTANCE_MIN` or `IMPORTANCE_NONE` notification channels
    - `DeviceAdminReceiver` declared in manifest
    - `SyncAdapter` and `AccountAuthenticator` XML metadata
    - `setComponentEnabledSetting()` calls targeting launcher activity
    - `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` in manifest

??? example "Dynamic Indicators"

    - Service immediately started after boot broadcast received
    - Notification channel created with empty name or minimal importance
    - Device admin activation prompt shown shortly after install
    - Navigation to autostart manager or battery optimization settings via intent
    - Accessibility service preventing navigation to app management screens
