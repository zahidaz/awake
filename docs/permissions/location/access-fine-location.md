# ACCESS_FINE_LOCATION

Grants GPS-precision location access (within ~3 meters) using GPS, GLONASS, WiFi positioning, cell tower triangulation, and the fused location provider. The single most valuable permission for stalkerware and a common request in banking trojans that use geofencing to activate in target regions.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACCESS_FINE_LOCATION` |
| Protection Level | `dangerous` |
| Permission Group | `LOCATION` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Access to the `FusedLocationProviderClient` (Google Play Services) or the platform `LocationManager` for high-accuracy location updates.

```java
FusedLocationProviderClient client = LocationServices.getFusedLocationProviderClient(context);
client.requestLocationUpdates(
    new LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 10000).build(),
    locationCallback,
    Looper.getMainLooper()
);
```

Available location sources:

| Provider | Accuracy | Battery Cost | Notes |
|----------|----------|-------------|-------|
| GPS (`gps`) | ~3m | High | Requires clear sky view, slow cold start |
| Network (`network`) | ~30-100m | Low | WiFi + cell tower |
| Fused (`fused`) | ~3-100m | Variable | Google Play Services, balances accuracy vs battery |
| Passive (`passive`) | Varies | None | Piggybacks on other apps' location requests |

With `ACCESS_FINE_LOCATION`, an app can:

- Request continuous GPS updates at arbitrary intervals
- Get last known location without waiting for a fix
- Set up geofences that trigger callbacks on region entry/exit
- Access WiFi scan results (required since Android 8.1 for `WifiManager.getScanResults()`)
- Read nearby BLE beacon data for indoor positioning

## Abuse in Malware

### Stalkerware and Domestic Surveillance

Stalkerware families poll `FusedLocationProviderClient` at intervals between 1 and 15 minutes, logging each fix with timestamp, accuracy, speed, and bearing. Logs are exfiltrated to C2 or stored locally for later retrieval. Some families (FlexiSPY, mSpy, Cerberus) offer real-time location streaming to the operator's dashboard.

### Geofenced Banking Trojans

Banking trojans like Anubis, Alien, and Ermac request fine location to determine if the device is in a target country. If the coordinates fall outside the target zone, the malware either stays dormant or uninstalls itself. This defeats sandbox analysis since emulators and analysis environments typically report default or US-based coordinates.

```java
Location loc = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
if (loc != null && isTargetCountry(loc.getLatitude(), loc.getLongitude())) {
    activateOverlayAttacks();
}
```

### Tracking for Physical Operations

Nation-state implants (FinFisher, Pegasus) use fine location to track the physical movements of targets. Location history combined with other sensor data (accelerometer, barometer) can reveal building floor, transportation mode, and whether the target is stationary or moving.

### Notable Families

| Family | Location Usage |
|--------|---------------|
| [Pegasus](../../malware/families/pegasus.md) (NSO Group) | Continuous GPS tracking, location history exfiltration |
| [Cerberus](../../malware/families/cerberus.md) | Real-time location streaming, geofenced activation |
| [Anubis](../../malware/families/anubis.md) | Geofencing to avoid non-target regions and sandboxes |
| FlexiSPY | GPS polling with configurable intervals, route logging |
| FurBall (APT-C-50) | Periodic location collection for surveillance campaigns |
| [Hermit](../../malware/families/hermit.md) (RCS Lab) | High-frequency location sampling tied to C2 tasking |
| [LightSpy](../../malware/families/lightspy.md) | Dedicated location plugin with configurable polling intervals |
| [EagleMsgSpy](../../malware/families/eaglemsgspy.md) | Real-time GPS tracking for law enforcement surveillance |
| [BoneSpy](../../malware/families/bonespy.md) | Location collection as part of Gamaredon-linked mobile surveillance |
| [PlainGnome](../../malware/families/plaingnome.md) | GPS tracking in second-stage payload for targeted espionage |
| [GuardZoo](../../malware/families/guardzoo.md) | Military GPS tracking, exfiltrates location data from armed forces personnel |
| [KoSpy](../../malware/families/kospy.md) | Periodic location harvesting for North Korean intelligence collection |
| [AridSpy](../../malware/families/aridspy.md) | Location tracking in multi-stage spyware targeting Middle Eastern users |

## Android Version Changes

**Android 6.0 (API 23)**: Location became a runtime permission. Prior to this, declaring it in the manifest was sufficient. Granting `ACCESS_FINE_LOCATION` implicitly granted `ACCESS_COARSE_LOCATION` (same permission group behavior).

**Android 8.0 (API 26)**: Background location throttled. Apps in the background receive location updates only a few times per hour. Foreground services bypass this throttle.

**Android 8.1 (API 27)**: `WifiManager.getScanResults()` now requires `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` in addition to `ACCESS_WIFI_STATE`. WiFi-based location became tied to location permissions.

**Android 10 (API 29)**: Background location split into `ACCESS_BACKGROUND_LOCATION`. Apps targeting API 29+ must request it separately. Foreground-only location is the default. The permission dialog offers "Allow all the time" only if background location is also requested.

**Android 11 (API 30)**: Incremental location grants. The system forces a two-step flow: foreground first, then background via Settings. `ACCESS_BACKGROUND_LOCATION` cannot be requested alongside foreground permissions in the same dialog.

**Android 12 (API 31)**: Approximate location toggle. When an app requests `ACCESS_FINE_LOCATION`, the user can downgrade to approximate only. The system returns a location fuzzed to ~1.5km. Apps must request both `ACCESS_FINE_LOCATION` and `ACCESS_COARSE_LOCATION` to show the precision toggle. If only fine is requested, the system may deny entirely.

**Android 12 (API 31)**: New `currentLocation()` API as a one-shot alternative to `requestLocationUpdates()`. Intended to reduce persistent location access, but malware can still call it repeatedly.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

High-risk combinations:

| Combination | Indicates |
|-------------|-----------|
| `ACCESS_FINE_LOCATION` + `ACCESS_BACKGROUND_LOCATION` + `INTERNET` | Continuous location exfiltration |
| `ACCESS_FINE_LOCATION` + `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` | Persistent tracking surviving reboot |
| `ACCESS_FINE_LOCATION` + `CAMERA` + `RECORD_AUDIO` + `READ_SMS` | Full surveillance suite (stalkerware) |
| `ACCESS_FINE_LOCATION` alone with overlay permissions | Banking trojan with geofencing |

In dynamic analysis, watch for `requestLocationUpdates()` calls with high frequency intervals (under 60 seconds) and `addGeofences()` calls that define regions matching known target countries.
