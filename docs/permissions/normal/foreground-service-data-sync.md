# FOREGROUND_SERVICE_DATA_SYNC

Foreground service type declaration required on Android 14 (API 34) for services that perform data synchronization. Before Android 14, any foreground service could transfer data in the background. Now the system enforces that services performing sync operations must declare `foregroundServiceType="dataSync"` in their manifest. Spyware and banking trojans use this type for persistent data exfiltration services that upload stolen contacts, SMS, files, and location data to C2 servers while displaying a minimal notification.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.FOREGROUND_SERVICE_DATA_SYNC` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (manifest declaration) |
| Introduced | API 34 (Android 14) |
| Depends On | [`FOREGROUND_SERVICE`](foreground-service.md) |
| User Visibility | Persistent foreground service notification |
| Play Store Policy | Android 15 (API 35) restricts dataSync usage; most apps should migrate to alternative APIs |

## What It Enables

### Manifest Declaration

```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />

<service
    android:name=".DataExfilService"
    android:foregroundServiceType="dataSync"
    android:exported="false" />
```

### Data Sync Service

```java
public class DataExfilService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, buildMinimalNotification(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        uploadStolenData();
        return START_STICKY;
    }
}
```

### Legitimate vs Malicious Usage

| Legitimate | Malicious |
|-----------|-----------|
| Cloud file sync (Dropbox, Google Drive) | Continuous exfiltration of SMS, contacts, call logs to C2 |
| Email sync | Periodic upload of recorded audio, photos, screenshots |
| Database replication | Streaming location data to tracking server |
| Backup services | Bulk upload of files from device storage |

## Abuse in Malware

### Persistent Data Exfiltration

The `dataSync` foreground service type gives malware a legitimate-looking reason to maintain a persistent background service that transfers data. Combined with a minimal-priority notification, the service runs indefinitely:

| Family | Data Exfiltrated | Method |
|--------|-----------------|--------|
| [SpyNote](../../malware/families/spynote.md) | SMS, contacts, call logs, location, files | Persistent foreground service with C2 upload |
| [Hermit](../../malware/families/hermit.md) | Full device data (messages, media, location, calls) | Continuous sync to operator infrastructure |
| [LightSpy](../../malware/families/lightspy.md) | Modular data collection (25+ plugin types) | Foreground service for persistent collection |
| [EagleMsgSpy](../../malware/families/eaglemsgspy.md) | Messages, screenshots, audio, location | Periodic sync to surveillance infrastructure |
| [KoSpy](../../malware/families/kospy.md) | SMS, call logs, location, files, audio, screenshots | Firebase-based sync service |
| [PJobRAT](../../malware/families/pjobrat.md) | Documents, chat messages, contacts | Background upload to C2 |

### Notification Minimization

Malware creates the required foreground notification with `IMPORTANCE_MIN` to minimize visibility:

- Notification text mimics system services ("Syncing data...", "Cloud backup in progress")
- Small icon matches system icons
- No sound, no vibration, no heads-up display
- Grouped into a notification channel named "System" or "Sync"

### Android 15 Restrictions

Google announced that `dataSync` foreground services will be restricted on Android 15 (API 35). Apps should migrate to:

- `WorkManager` for deferrable sync
- `DownloadManager` for large file transfers
- User-initiated data transfer jobs

This change will force malware to adopt alternative persistence mechanisms for data exfiltration on Android 15+.

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 8.0 | 26 | Foreground services require notification | Data exfiltration services become visible |
| 12 | 31 | Foreground service launch restrictions from background | Cannot start foreground service while app is in background (exceptions for broadcast receivers, etc.) |
| 14 | 34 | `FOREGROUND_SERVICE_DATA_SYNC` required | Must declare specific type for data sync services |
| 14 | 34 | Foreground service timeout (~24 hours for dataSync) | Long-running sync services are stopped by the system |
| 15 | 35 | `dataSync` type deprecated for most apps | Migration to `WorkManager` and alternatives required |

The 24-hour timeout on Android 14 means malware must restart its sync service periodically. Combined with [`RECEIVE_BOOT_COMPLETED`](receive-boot-completed.md) and [`SCHEDULE_EXACT_ALARM`](schedule-exact-alarm.md), the service restarts after timeout or reboot.

## Detection Indicators

### Manifest Signals

- `FOREGROUND_SERVICE_DATA_SYNC` combined with surveillance permissions (`READ_SMS`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `RECORD_AUDIO`)
- `dataSync` foreground service alongside `INTERNET` and no legitimate cloud sync functionality
- Notification channel named "System", "Sync", or "Background" with `IMPORTANCE_MIN`

### Behavioral Signals

- Foreground service uploading data to non-standard servers (not Google, Dropbox, etc.)
- Periodic data uploads correlating with SMS receipt, call completion, or location changes
- `IMPORTANCE_MIN` notification on a service that transfers large amounts of data

## See Also

- [Data Exfiltration](../../attacks/data-exfiltration.md)
- [Persistence Techniques](../../attacks/persistence-techniques.md)
- [FOREGROUND_SERVICE](foreground-service.md)
- [RECEIVE_BOOT_COMPLETED](receive-boot-completed.md)
