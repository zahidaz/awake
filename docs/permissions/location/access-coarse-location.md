# ACCESS_COARSE_LOCATION

Grants network-based approximate location with roughly 1-2km accuracy using WiFi access points and cell tower data. Less useful than fine location for stalkerware but sufficient for country/city-level victim profiling, geofenced payload activation, and sandbox evasion.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACCESS_COARSE_LOCATION` |
| Protection Level | `dangerous` |
| Permission Group | `LOCATION` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Access to the network location provider (`LocationManager.NETWORK_PROVIDER`) and the fused provider at `PRIORITY_BALANCED_POWER_ACCURACY` or `PRIORITY_LOW_POWER`. Returns coordinates fuzzed to approximately a 1-2km radius around the actual position.

```java
FusedLocationProviderClient client = LocationServices.getFusedLocationProviderClient(context);
client.requestLocationUpdates(
    new LocationRequest.Builder(Priority.PRIORITY_BALANCED_POWER_ACCURACY, 60000).build(),
    locationCallback,
    Looper.getMainLooper()
);
```

With `ACCESS_COARSE_LOCATION`, an app can:

- Get network-derived position (WiFi + cell triangulation)
- Access WiFi scan results (since Android 8.1)
- Scan for BLE devices (`BluetoothLeScanner`)
- Detect nearby WiFi networks (`WifiManager.getScanResults()`)
- Use the `NETWORK_PROVIDER` in `LocationManager`

It cannot:

- Access the GPS provider directly
- Get accuracy better than approximately 1-2km through legitimate API calls
- Set up geofences (requires `ACCESS_FINE_LOCATION`)

## Abuse in Malware

### Fallback Location Strategy

Malware commonly requests both `ACCESS_FINE_LOCATION` and `ACCESS_COARSE_LOCATION`. If the user (on Android 12+) downgrades to approximate location, the malware still gets coarse data. Some families check the granted permission level and adjust their behavior, using coarse data for country-level decisions and deferring precision-dependent operations.

### Country and Region Detection

Coarse location is sufficient for determining which country or city the victim is in. Banking trojans use this to:

- Select the right overlay injection target from their phishing kit
- Choose the correct language for social engineering prompts
- Decide whether to activate at all (avoid non-target regions)
- Report victim geography to C2 for campaign segmentation

### Sandbox Evasion

Analysis sandboxes often return null or default coordinates (0.0, 0.0 or US-based locations). Checking for coarse location anomalies is a lightweight evasion technique. If the reported location does not match the device's MCC/MNC (mobile country/network codes from `TelephonyManager`), the malware assumes it is running in an analysis environment.

### WiFi Environment Fingerprinting

With `ACCESS_COARSE_LOCATION`, the app can call `WifiManager.getScanResults()` to enumerate all visible WiFi networks. This produces a fingerprint of the local RF environment:

- BSSID list reveals the physical location via public WiFi geolocation databases
- SSID names can identify corporate networks, government facilities, or specific targets
- Signal strength patterns create a unique fingerprint of the location even without coordinates

### Notable Families

| Family | Coarse Location Usage |
|--------|----------------------|
| Joker | Region check before activating premium SMS fraud |
| Harly | Country detection for subscription scam targeting |
| GriftHorse | Location-based selection of premium number to dial |
| SharkBot | Geographic filtering to target specific banking regions |
| Xenomorph | Coarse geofencing for overlay activation decisions |

## Android Version Changes

**Android 6.0 (API 23)**: Became a runtime permission. Before this, manifest declaration was sufficient.

**Android 8.0 (API 26)**: Background apps receive coarse location updates only a few times per hour due to background execution limits.

**Android 8.1 (API 27)**: WiFi scan results now require either `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION`. Previously only `ACCESS_WIFI_STATE` was needed.

**Android 10 (API 29)**: Background location access split out into `ACCESS_BACKGROUND_LOCATION`. Coarse location alone only works while the app is in the foreground or running a foreground service.

**Android 12 (API 31)**: The approximate location toggle changed the dynamic significantly. Apps requesting `ACCESS_FINE_LOCATION` and `ACCESS_COARSE_LOCATION` together show a dialog with a precision toggle. The user can grant only approximate location, which means the app effectively receives coarse-level data even though it requested fine. If an app requests only `ACCESS_COARSE_LOCATION`, the dialog has no precision toggle and grants approximate by default.

**Android 12 (API 31)**: `ACCESS_COARSE_LOCATION` returns coordinates fuzzed to a ~1.5km radius cell. The fuzzing is consistent for a period (the same approximate location is returned for the same cell), which means temporal correlation can still reveal movement patterns at city-block granularity.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
```

When `ACCESS_COARSE_LOCATION` appears without `ACCESS_FINE_LOCATION`, the app either legitimately needs only approximate data or is trying to reduce its permission footprint to avoid scrutiny. Many malware families request both, so a coarse-only request is less common and may indicate a more targeted approach.

Watch for:

- `ACCESS_COARSE_LOCATION` combined with `TelephonyManager` calls (MCC/MNC checks) for region-based payload selection
- WiFi scanning patterns that enumerate all nearby access points immediately after location grant
- Location checks followed by conditional code paths that exit or self-delete based on geographic result
- Network requests to IP geolocation APIs as a secondary location source alongside coarse permission
