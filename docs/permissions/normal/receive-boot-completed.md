# RECEIVE_BOOT_COMPLETED

Allows an app to receive the `ACTION_BOOT_COMPLETED` broadcast after the device finishes booting. The primary persistence mechanism for Android malware: register a receiver, get started on every reboot without user interaction.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_BOOT_COMPLETED` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time |
| Introduced | API 1 |

Normal protection level means no user prompt, no settings toggle. Granted silently.

## What It Enables

The app registers a `BroadcastReceiver` for `ACTION_BOOT_COMPLETED`. After device boot, the system sends this broadcast to all registered receivers. The receiver can then start a service, schedule alarms, or begin any background operation.

```java
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            context.startForegroundService(new Intent(context, MalwareService.class));
        }
    }
}
```

Manifest registration:

```xml
<receiver android:name=".BootReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
```

## Abuse in Malware

Virtually every persistent Android malware uses this permission. Without it, the malware would stop running after a reboot, requiring the user to re-launch it.

Combined with `FOREGROUND_SERVICE`, the boot receiver starts a persistent foreground service that maintains C2 connections, monitors for target apps, and keeps the malware operational.

### Related Broadcasts

Malware often registers for additional boot-like broadcasts for redundancy:

| Broadcast | When Fired |
|-----------|------------|
| `ACTION_BOOT_COMPLETED` | After full system boot |
| `ACTION_LOCKED_BOOT_COMPLETED` | After direct boot (before user unlock, API 24+) |
| `ACTION_MY_PACKAGE_REPLACED` | After app is updated |
| `ACTION_PACKAGE_REPLACED` | After any package is updated |

### Notable Families

| Family | Boot Persistence Usage |
|--------|----------------------|
| [Cerberus](../../malware/families/cerberus.md) | Boot receiver restarts overlay monitoring and C2 service |
| [Hook](../../malware/families/hook.md) | Boot persistence for VNC-based remote access and overlay engine |
| [GodFather](../../malware/families/godfather.md) | Registers boot receiver to restart accessibility-based monitoring |
| [Octo](../../malware/families/octo.md) | Boot-triggered service for screen streaming and keylogging |
| [Medusa](../../malware/families/medusa.md) | Boot persistence for screen recording and remote access |
| [Hydra](../../malware/families/hydra.md) | Boot receiver re-establishes C2 connection and overlay injection |
| [SharkBot](../../malware/families/sharkbot.md) | Boot persistence for ATS fraud engine and credential interception |
| [SpyNote](../../malware/families/spynote.md) | Boot receiver ensures persistent RAT functionality across reboots |
| [Rafel RAT](../../malware/families/rafelrat.md) | Boot persistence for remote access, SMS interception, and ransomware |

## Android Version Changes

**Android 3.1 (API 12)**: apps in "stopped state" (freshly installed, never opened) do not receive `BOOT_COMPLETED`. The user must launch the app at least once. This prevents malware from activating purely through installation, but all sideloading-based attacks involve social engineering to open the app anyway.

**Android 8.0 (API 26)**: background execution limits. `BOOT_COMPLETED` receivers still work, but they cannot start background services directly. Must use `startForegroundService()` instead.

**Android 13 (API 33)**: `FOREGROUND_SERVICE` types must be declared. Malware must specify what foreground service type to use.

## Detection

The permission itself is common in legitimate apps (alarm clocks, messaging apps, etc.), so its presence alone is not suspicious. Combined with `INTERNET`, `FOREGROUND_SERVICE`, and sensitive permissions like `READ_SMS` or `BIND_ACCESSIBILITY_SERVICE`, it indicates persistence infrastructure.
