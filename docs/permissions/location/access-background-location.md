# ACCESS_BACKGROUND_LOCATION

Allows an app to receive location updates when it has no visible activity or foreground service. This is the permission that separates passive location checks from persistent tracking. Critical for stalkerware, spyware, and any implant that needs to log the victim's movements continuously without user interaction.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACCESS_BACKGROUND_LOCATION` |
| Protection Level | `dangerous` |
| Permission Group | `LOCATION` |
| Grant Method | Settings page redirect (Android 11+) or runtime dialog (Android 10) |
| Introduced | API 29 (Android 10) |

## What It Enables

Without this permission, location updates are only delivered while the app has a visible activity or a foreground service with type `location`. With it, the app receives location updates regardless of its lifecycle state.

Background location works through:

- `FusedLocationProviderClient.requestLocationUpdates()` with a `PendingIntent` that fires even when the app is killed
- `GeofencingClient.addGeofences()` for enter/exit/dwell triggers on geographic regions
- `LocationManager.requestLocationUpdates()` targeting background delivery
- `WorkManager` or `JobScheduler` tasks that read `getLastKnownLocation()` during execution

The precision of background location depends on which foreground permission was granted:

| Foreground Permission | Background Result |
|----------------------|-------------------|
| `ACCESS_FINE_LOCATION` + `ACCESS_BACKGROUND_LOCATION` | GPS-accuracy updates in background |
| `ACCESS_COARSE_LOCATION` + `ACCESS_BACKGROUND_LOCATION` | Approximate updates in background |
| `ACCESS_FINE_LOCATION` only (user chose approximate on Android 12+) | Approximate updates in background |

## Abuse in Malware

### Persistent Stalkerware Tracking

This is the primary stalkerware permission. Without it, the app must maintain a visible foreground notification to keep tracking, which alerts the victim. With background location, tracking is invisible. The app registers a `PendingIntent`-based location request that survives app process death and continues to fire at configured intervals.

Stalkerware logging pattern:

1. Register `PendingIntent` for location updates every 5-15 minutes
2. `BroadcastReceiver` fires on each update
3. Location is written to a local database
4. Periodic sync job pushes accumulated locations to C2
5. If the process is killed, the `PendingIntent` re-triggers it

### Geofence-Based Payload Activation

Advanced malware uses `GeofencingClient` with background location to trigger actions when the victim enters a specific area. Use cases:

- Banking trojan activates overlay attacks only when the device is in the target country
- Targeted implant begins full surveillance when the victim arrives at a location of interest
- Ransomware holds off deployment until the victim is in a jurisdiction where payment is likely

Geofences survive app restart and process death, making them reliable persistent triggers.

### Continuous Intelligence Collection

Nation-state implants log location continuously to build movement profiles. The data reveals:

- Home and work addresses (most frequent nighttime and daytime locations)
- Daily routine and travel patterns
- Meetings with other tracked targets (co-location analysis)
- Travel to sensitive locations (government buildings, embassies, protest sites)

### Notable Families

| Family | Background Location Usage |
|--------|--------------------------|
| Pegasus (NSO Group) | Continuous background GPS logging with encrypted exfiltration |
| Predator (Cytrox) | Background tracking tied to C2 tasking commands |
| FlexiSPY | Configurable background polling interval, route reconstruction |
| TheTruthSpy | Persistent background tracking marketed for "partner monitoring" |
| Cerberus | Background geofencing combined with overlay injection |
| Monokle (STC) | Background location as part of full surveillance toolkit |
| [PhoneSpy](../../malware/families/phonespy.md) | Background tracking with location history stored in local SQLite |

## Android Version Changes

**Android 10 (API 29)**: `ACCESS_BACKGROUND_LOCATION` introduced. Apps targeting API 29+ must request it explicitly. The runtime dialog shows "Allow all the time" as an option when background location is requested alongside foreground location. Apps targeting API 28 or below automatically receive background access when granted foreground location (compatibility behavior).

**Android 11 (API 30)**: Incremental grants enforced. The system blocks requesting `ACCESS_BACKGROUND_LOCATION` in the same dialog as foreground permissions. The app must first obtain foreground location, then separately request background. The second request opens the app's Settings page where the user manually selects "Allow all the time." This two-step flow significantly reduces the background location grant rate.

**Android 11 (API 30)**: Auto-revoke (hibernation) introduced. If the app is not used for several months, all permissions including background location are automatically revoked. Malware that hides its launcher icon may still have its permissions revoked.

**Android 12 (API 31)**: The approximate location toggle compounds the restriction. Even if background location is granted, the user may have selected approximate only, limiting background updates to coarse accuracy.

**Android 13 (API 33)**: Foreground service type enforcement tightened. Apps declaring `foregroundServiceType="location"` must hold `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION`. This does not replace `ACCESS_BACKGROUND_LOCATION` but affects the foreground service workaround.

**Android 14 (API 34)**: Foreground service types are now mandatory. Apps must declare `foregroundServiceType` in the manifest and hold the corresponding permissions at runtime. The `location` type requires active location permissions.

## Workarounds When Background Location Is Denied

| Technique | Mechanism | Limitations |
|-----------|-----------|-------------|
| Foreground service with notification | Declare `foregroundServiceType="location"` with a persistent notification | Visible to user, can be dismissed on Android 13+ |
| WorkManager periodic tasks | Schedule recurring work that reads `getLastKnownLocation()` | Subject to battery optimization, may get stale location |
| AlarmManager + `setExactAndAllowWhileIdle()` | Wake the app at exact intervals to grab location | Doze mode limits frequency, gets killed quickly |
| Push notification trigger | FCM message triggers location read in message handler | Brief execution window, unreliable for continuous tracking |
| Companion device pairing | Use `CompanionDeviceManager` to exempt from background restrictions | Requires user interaction, device pairing step |
| Accessibility service abuse | Read location from other apps' UI or maintain process priority | Requires accessibility grant, heavily scrutinized |

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
```

The presence of `ACCESS_BACKGROUND_LOCATION` in any app that is not a navigation, fitness tracking, or family safety app is a strong red flag.

Key indicators during analysis:

| Signal | What to Look For |
|--------|-----------------|
| Manifest | `ACCESS_BACKGROUND_LOCATION` + `RECEIVE_BOOT_COMPLETED` + `INTERNET` |
| PendingIntent registration | `requestLocationUpdates()` with `PendingIntent` instead of `LocationCallback` |
| Geofence setup | `addGeofences()` calls, especially with coordinates matching country boundaries |
| Database storage | Local SQLite tables storing latitude, longitude, timestamp, accuracy columns |
| Service declarations | `foregroundServiceType="location"` combined with minimal or deceptive notification text |
| Boot receiver | `BroadcastReceiver` for `BOOT_COMPLETED` that re-registers location requests |

Apps that request background location but have no visible mapping, navigation, or fitness UI are almost certainly collecting location for exfiltration. Cross-reference the requested permissions with the app's declared functionality to identify the mismatch.
