# Location Permissions

Location permissions expose the device's physical position through GPS, WiFi, cell tower triangulation, and fused providers. From an offense perspective, location data enables stalkerware tracking, spyware geolocation reporting, geofenced payload activation, and victim profiling.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [ACCESS_FINE_LOCATION](access-fine-location.md) | GPS-precision tracking, stalkerware, geofence-triggered payloads |
| [ACCESS_COARSE_LOCATION](access-coarse-location.md) | Approximate location via network, city-level victim profiling |
| [ACCESS_BACKGROUND_LOCATION](access-background-location.md) | Continuous tracking without foreground UI, persistent stalkerware |

## Permission Model

Android splits location into two axes: precision (fine vs coarse) and timing (foreground vs background).

**Precision**: `ACCESS_FINE_LOCATION` provides GPS-level accuracy (within meters). `ACCESS_COARSE_LOCATION` uses WiFi and cell towers for approximately 1-2km accuracy. Since Android 12, users can downgrade a fine location request to approximate at grant time.

**Timing**: Before Android 10, any location permission worked regardless of app state. Android 10 introduced `ACCESS_BACKGROUND_LOCATION` as a separate grant. Without it, an app only receives location updates while it has a visible activity or foreground service with the `location` type.

**Grant flow on Android 12+**:

1. App requests `ACCESS_FINE_LOCATION` and `ACCESS_COARSE_LOCATION`
2. User sees dialog with "Precise" / "Approximate" toggle
3. User selects "While using the app" or "Only this time"
4. Background location must be requested separately and directs the user to Settings

## Why Location Tracking Matters for Malware

### Stalkerware and Spyware

Location is the highest-value data point for stalkerware. Continuous GPS tracking reveals a target's home address, workplace, daily routine, and travel patterns. Commercial spyware (Pegasus, Predator) and consumer stalkerware (Cerberus, TheTruthSpy) both prioritize location collection. Many stalkerware families implement their own location polling loop using `FusedLocationProviderClient` to balance accuracy against battery drain.

### Geofenced Payload Activation

Banking trojans and targeted implants use geofencing to activate only in specific countries or regions. The malware checks the victim's coordinates against a target area before deploying its overlay attacks or exfiltrating data. This avoids triggering sandbox analysis (most sandboxes report locations in the US or default to null island at 0,0) and limits exposure to researchers outside the target region.

### Victim Profiling

Even coarse location data reveals which country and city the victim is in. Malware uses this to select the correct phishing overlay language, target the right banking apps, or decide whether to self-destruct to avoid analysis in non-target regions.

## Play Store Policy

Google Play requires apps using background location to demonstrate core functionality that depends on it. Since 2020, apps must submit a declaration form and pass review. Most stalkerware and spyware distribute through sideloading, third-party stores, or MDM-based installation to bypass these restrictions.

## Bypass Techniques

| Technique | How It Works |
|-----------|-------------|
| Foreground service abuse | Declare a `location`-type foreground service with a persistent notification to maintain foreground location access without `ACCESS_BACKGROUND_LOCATION` |
| WorkManager polling | Schedule periodic work that briefly requests location during execution windows |
| AlarmManager wakeups | Wake the app at intervals to grab a location fix before the system kills the process |
| WiFi scan results | Use `ACCESS_WIFI_STATE` to scan nearby access points and geolocate via public WiFi databases without location permission |
| Cell tower info | Read `TelephonyManager` cell info (requires `ACCESS_FINE_LOCATION` or `READ_PHONE_STATE` on older APIs) to triangulate position |
| IP geolocation | Query an external service to resolve the device's IP to an approximate location with no permissions at all |
