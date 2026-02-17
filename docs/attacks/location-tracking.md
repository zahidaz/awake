# Location Tracking & Geofencing

Collecting device location data for victim surveillance, movement tracking, and geographically targeted malware activation. Location is a core data collection capability for every major spyware family and a common activation gate for banking trojans that only operate in target countries. Unlike most attack techniques that require complex permission escalation, coarse location data can be derived without any device permissions at all through IP geolocation and cell tower inference.

See also: [`ACCESS_FINE_LOCATION`](../permissions/location/access-fine-location.md), [`ACCESS_COARSE_LOCATION`](../permissions/location/access-coarse-location.md), [`ACCESS_BACKGROUND_LOCATION`](../permissions/location/access-background-location.md), [Anti-Analysis Techniques](anti-analysis-techniques.md#geographic-and-locale-checks), [Play Store Evasion](play-store-evasion.md#geographic-targeting)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1430](https://attack.mitre.org/techniques/T1430/) | Location Tracking | Collection, Discovery |
    | [T1430.001](https://attack.mitre.org/techniques/T1430/001/) | Remote Device Management Services | Collection, Discovery |
    | [T1430.002](https://attack.mitre.org/techniques/T1430/002/) | Impersonate SS7 Nodes | Collection, Discovery |
    | [T1627.001](https://attack.mitre.org/techniques/T1627/001/) | Geofencing | Defense Evasion |

    T1430 covers GPS, cell tower, and WiFi-based location collection. T1627.001 covers SIM/locale/IP geofencing used to restrict malware activation to target regions.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Fine location | `ACCESS_FINE_LOCATION` runtime permission (GPS, ~3m accuracy) |
    | Coarse location | `ACCESS_COARSE_LOCATION` runtime permission (cell/WiFi, ~50-300m) |
    | Background location | `ACCESS_BACKGROUND_LOCATION` (Android 10+), separate grant |
    | Cell tower info | `ACCESS_FINE_LOCATION` for `getAllCellInfo()`, `READ_PHONE_STATE` for older APIs |
    | No permission needed | IP geolocation (server-side), SIM operator codes, system locale |

    Malware that only needs to know the victim's country does not need location permissions at all. `TelephonyManager.getSimCountryIso()` and server-side IP geolocation provide country-level targeting with zero permissions.

## Location Data Collection Methods

### GPS (Fine Location)

The most precise location source, accurate to approximately 3 meters outdoors. Requires `ACCESS_FINE_LOCATION` and a clear view of satellites. Indoor accuracy degrades significantly.

??? example "FusedLocationProvider Request"

    ```java
    FusedLocationProviderClient client = LocationServices.getFusedLocationProviderClient(context);

    LocationRequest request = LocationRequest.create()
        .setPriority(LocationRequest.PRIORITY_HIGH_ACCURACY)
        .setInterval(30000)
        .setFastestInterval(10000);

    client.requestLocationUpdates(request, new LocationCallback() {
        @Override
        public void onLocationResult(LocationResult result) {
            Location loc = result.getLastLocation();
            exfiltrate(loc.getLatitude(), loc.getLongitude(), loc.getAccuracy());
        }
    }, Looper.getMainLooper());
    ```

`FusedLocationProviderClient` from Google Play Services is the preferred API for most malware because it intelligently combines GPS, WiFi, cell towers, and sensors to maximize accuracy while minimizing battery drain. Heavy GPS polling is a telltale sign of surveillance -- legitimate apps use the fused provider.

### Network-Based (Coarse Location)

Cell tower triangulation and WiFi BSSID lookup provide 50-300 meter accuracy with `ACCESS_COARSE_LOCATION`. Faster than GPS (no satellite lock required) and works indoors.

Android 12 introduced the choice between approximate and precise location in the permission dialog. Malware requesting only `ACCESS_COARSE_LOCATION` still gets sufficient accuracy for city-level tracking and movement pattern analysis.

### Cell Tower Information

`TelephonyManager` exposes cell tower identifiers that can be resolved to geographic coordinates using public databases like [OpenCellID](https://opencellid.org/) or Google's geolocation API.

??? example "Cell Tower Info Extraction"

    ```java
    TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
    List<CellInfo> cells = tm.getAllCellInfo();
    for (CellInfo cell : cells) {
        if (cell instanceof CellInfoLte) {
            CellIdentityLte id = ((CellInfoLte) cell).getCellIdentity();
            int mcc = id.getMccString() != null ? Integer.parseInt(id.getMccString()) : -1;
            int mnc = id.getMncString() != null ? Integer.parseInt(id.getMncString()) : -1;
            int lac = id.getTac();
            int cid = id.getCi();
            exfiltrate(mcc, mnc, lac, cid);
        }
    }
    ```

The MCC/MNC/LAC/CID tuple uniquely identifies a cell tower. Malware exfiltrates these raw values to C2, where server-side lookup resolves them to coordinates. This provides 100-1000 meter accuracy without any GPS usage or Google Play Services dependency.

### WiFi BSSID Mapping

WiFi access point MAC addresses (BSSIDs) are mapped to geographic coordinates in databases maintained by Google, Apple, and Mozilla. Scanning nearby WiFi networks and sending BSSIDs to a geolocation API provides 10-50 meter accuracy indoors.

Since Android 9, WiFi scan results are throttled (4 scans per 2 minutes in foreground, 1 scan per 30 minutes in background). Since Android 10, `ACCESS_FINE_LOCATION` is required to get scan results at all.

### Passive Location Provider

The passive location provider piggybacks on location requests made by other apps. Instead of actively querying GPS or network providers, the malware registers for passive updates and receives location data whenever any other app on the device requests location.

```java
LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
lm.requestLocationUpdates(LocationManager.PASSIVE_PROVIDER, 0, 0, locationListener);
```

This is stealthier than active location requests because it generates zero additional battery drain and no GPS activation. The tradeoff is unpredictable update frequency -- the malware only gets data when other apps happen to request location.

### IP Geolocation

Server-side IP geolocation requires no device permission. The C2 server resolves the client's public IP to a geographic location using commercial databases (MaxMind, IPinfo, IP2Location). Accuracy ranges from city-level (ISP-assigned IP blocks) to country-level.

Malware uses IP geolocation for two purposes:

1. **Activation gating**: C2 checks the client IP before delivering payloads, blocking requests from non-target countries or known VPN/cloud IP ranges
2. **Approximate tracking**: logging victim IP-derived location when precise GPS data is unavailable

## Background Location Tracking

Background location is the critical capability for persistent surveillance. Each Android version has progressively restricted background location access, and each restriction has forced malware to develop new workarounds.

### Android Version Restrictions

| Version | Restriction | Impact |
|---------|------------|--------|
| Android 8 (API 26) | Background location throttled to a few updates per hour | Active GPS polling from background services degraded |
| Android 8 (API 26) | Background service execution limits | Long-running location services killed; foreground service required |
| Android 10 (API 29) | `ACCESS_BACKGROUND_LOCATION` as separate permission | User must explicitly grant background location in addition to foreground |
| Android 11 (API 30) | Background location can only be granted from Settings | No runtime dialog -- user must navigate to Settings manually |
| Android 12 (API 31) | Approximate vs precise location choice in permission dialog | User can grant only approximate location, degrading tracking precision |
| Android 13 (API 33) | Foreground service type `location` must be declared | Manifest must include `foregroundServiceType="location"` |
| Android 14 (API 34) | `USE_EXACT_ALARM` restricted | Periodic alarm-based location polling requires justification |
| Android 15 (API 35) | Enhanced background location audit in Play Store review | Play Store scrutiny on `ACCESS_BACKGROUND_LOCATION` usage increased |

### Malware Workarounds

**Foreground service with location type**: The primary workaround. The malware starts a foreground service declared with `foregroundServiceType="location"` and maintains a persistent (often misleading) notification. The notification is disguised as a system process, battery optimization, or connectivity service.

**WorkManager periodic requests**: Scheduling periodic location collection through `WorkManager`, which survives process death and respects Doze mode constraints while still executing periodically. Each work request grabs the last known location and exfiltrates it.

```java
PeriodicWorkRequest locationWork = new PeriodicWorkRequest.Builder(
    LocationWorker.class, 15, TimeUnit.MINUTES)
    .setConstraints(new Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .build())
    .build();

WorkManager.getInstance(context).enqueueUniquePeriodicWork(
    "loc_sync", ExistingPeriodicWorkPolicy.KEEP, locationWork);
```

**Boot receiver with location request**: Registering `RECEIVE_BOOT_COMPLETED` to restart location tracking after device reboot. The receiver starts a foreground service that re-registers for location updates.

**Accessibility-based auto-grant**: Malware with accessibility service access navigates the Settings UI to grant `ACCESS_BACKGROUND_LOCATION` without genuine user consent. This is particularly effective on Android 11+ where background location requires a Settings toggle rather than a runtime dialog -- the accessibility service opens the Settings page and taps the correct option.

**AlarmManager wake-ups**: Using exact alarms (`AlarmManager.setExactAndAllowWhileIdle()`) to wake the device from Doze mode and capture a location fix at fixed intervals.

### Stalkerware Persistence

Commercial stalkerware (Cerberus rebranded as "monitoring software", FlexiSpy, mSpy, Cocospy) maintains persistent background location through a combination of techniques:

- Foreground service with `IMPORTANCE_MIN` notification (barely visible)
- `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` to avoid Doze mode killing
- `RECEIVE_BOOT_COMPLETED` for restart after reboot
- Device admin enrollment to resist uninstallation
- Hiding the app icon from the launcher

The result is continuous location streaming at 30-second to 5-minute intervals, surviving reboots, battery optimization, and user attempts to find and remove the app.

## Geofencing-Based Malware Activation

Geofencing is the most operationally significant use of location in Android malware. Rather than tracking victims, it determines where malware should and should not operate. This is both an evasion technique (avoid analysis environments) and a targeting mechanism (only attack users in profitable regions).

### SIM Operator Code Checks (MCC/MNC)

The most reliable device-side geofencing method. The Mobile Country Code (MCC) and Mobile Network Code (MNC) are set by the physical SIM card and cannot be spoofed without inserting a SIM from the target country.

```java
TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
String simCountry = tm.getSimCountryIso();
String networkCountry = tm.getNetworkCountryIso();
String simOperator = tm.getSimOperator();
```

| API | What It Returns | Spoofing Difficulty |
|-----|----------------|---------------------|
| `getSimCountryIso()` | ISO country code from SIM (e.g., "de") | High -- requires physical SIM from that country |
| `getNetworkCountryIso()` | ISO country code from current network registration | High -- VPN does not change this |
| `getSimOperator()` | MCC+MNC string (e.g., "26201" for Telekom DE) | High -- SIM-bound |
| `getNetworkOperator()` | MCC+MNC of current network | High -- requires roaming on target network |

This is why banking trojans targeting German banks check for German SIMs, and analysts need German SIMs to trigger the malware. [MITRE ATT&CK documents this as T1627.001 (Geofencing)](https://attack.mitre.org/techniques/T1627/001/).

### Locale-Based Activation

```java
String language = Locale.getDefault().getLanguage();
String country = Locale.getDefault().getCountry();
```

Checking the system language and region. Less reliable than SIM checks because users can change these in Settings, but useful as an additional signal. Some families combine locale with SIM checks -- both must match for activation.

### Server-Side IP Geofencing

The C2 server checks the client's source IP against geolocation databases before delivering payloads. This is the hardest geofencing method for analysts to bypass because the logic runs entirely server-side.

Behaviors include:

- Returning HTTP 404 or empty responses for non-target IPs
- Serving a benign APK to non-target regions and a malicious APK to targets
- Blocking known VPN, cloud, and datacenter IP ranges
- Requiring the device IP to match the SIM country (IP from Germany + German SIM = deliver payload)

### GPS-Based Geofencing

Some families use the Android `GeofencingClient` API or manual coordinate comparison to activate only within specific geographic boundaries.

```java
GeofencingClient client = LocationServices.getGeofencingClient(context);
Geofence geofence = new Geofence.Builder()
    .setRequestId("target_zone")
    .setCircularRegion(latitude, longitude, radiusMeters)
    .setExpirationDuration(Geofence.NEVER_EXPIRE)
    .setTransitionTypes(Geofence.GEOFENCE_TRANSITION_ENTER)
    .build();
```

This is less common in commodity malware (GPS requires permissions and satellite access) but observed in targeted spyware that activates surveillance only when the victim enters specific locations.

### Real-World Geofencing Examples

| Family | Geofencing Method | Targeting Behavior |
|--------|------------------|-------------------|
| [Anatsa](../malware/families/anatsa.md) | SIM country + IP geofencing | Targets UK, DE, ES, SK, SI, CZ. [Avoids Eastern European and Chinese IP ranges](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach) |
| [Mandrake](../malware/families/mandrake.md) | C2-side geofencing | [Server decides payload delivery based on device profile](https://securelist.com/mandrake-apps-return-to-google-play/113147/). Non-target regions never receive malware |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | SIM + locale | [Specifically targets Thailand and Vietnam](https://www.group-ib.com/blog/goldpickaxe-fraud/). Checks for Thai/Vietnamese SIM and language |
| [Anatsa](../malware/families/anatsa.md) | Installed app check | Scans for banking apps from target countries as secondary geofence |
| [GodFather](../malware/families/godfather.md) | System language | [Avoids activating on devices with Russian, Azerbaijani, Uzbek, Kazakh, Kyrgyz, Tajik, Armenian, or Belarusian languages](https://www.group-ib.com/blog/godfather-trojan/) |
| [Cerberus](../malware/families/cerberus.md) | SIM + locale | Avoided activating in CIS countries |
| [Mamont](../malware/families/mamont.md) | SIM country | Targets Russian-speaking countries specifically |

## Location as Intelligence

### Stalkerware and Physical Surveillance

Stalkerware apps provide real-time location dashboards showing victim movements on a map. Features include:

- Live GPS tracking with configurable polling intervals
- Location history with timestamped breadcrumb trails
- Geofence alerts when the victim enters or leaves defined areas
- Address resolution (reverse geocoding) for each location point
- Speed and altitude data for travel pattern analysis

[Kaspersky reported](https://securelist.com/state-of-stalkerware-2024/115385/) 13,279 unique users affected by stalkerware in 2024, but actual numbers are higher because stalkerware is designed to be undetectable.

### State-Sponsored Location Collection

Every major state-sponsored spyware platform collects location as a core surveillance function:

| Family | Location Capability | Details |
|--------|-------------------|---------|
| [Pegasus](../malware/families/pegasus.md) | GPS + cell + WiFi | Real-time location streaming and historical tracking. [Amnesty International's forensic methodology](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/) documents location collection as a standard capability |
| [Predator](../malware/families/predator.md) | GPS + cell + WiFi | [Five-module architecture includes location harvesting](https://blog.talosintelligence.com/mercenary-intellexa-predator/) |
| [Hermit](../malware/families/hermit.md) | GPS + cell tower | [RCS Lab spyware collects location alongside call/SMS interception](https://www.lookout.com/threat-intelligence/article/hermit-spyware-discovery) |
| [FinSpy](../malware/families/finspy.md) | GPS + cell + WiFi | Location tracking module with configurable intervals |
| [EagleMsgSpy](../malware/families/eaglemsgspy.md) | GPS | Chinese law enforcement surveillance tool with location collection |

### Combining Location with Sensor Data

Advanced spyware correlates location with other sensor data to build comprehensive victim profiles:

- **Accelerometer + location**: Determine if the victim is walking, driving, or stationary
- **WiFi probe requests + location**: Map physical movements through WiFi networks encountered
- **Barometer + GPS**: Floor-level positioning inside buildings
- **Cell tower transitions**: Movement patterns even without GPS

## Location Spoofing Detection

Some malware and many commercial apps check for mock location providers to detect analysis environments where analysts use fake GPS to trigger geofenced behavior.

### Detection Techniques

```java
private boolean isMockLocation(Location location) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
        return location.isFromMockProvider();
    }
    return Settings.Secure.getString(
        getContentResolver(),
        Settings.Secure.ALLOW_MOCK_LOCATION).equals("1");
}
```

| Check | API | Android Version |
|-------|-----|----------------|
| Mock provider flag | `Location.isFromMockProvider()` | 18+ |
| Mock location setting | `Settings.Secure.ALLOW_MOCK_LOCATION` | Deprecated in API 23, removed in 31 |
| Mock provider flag (new) | `Location.isMock()` | 31+ |
| Provider list check | `LocationManager.getProviders()` for non-standard providers | All |

### Why This Matters for Analysis

Analysts frequently use mock location apps (Fake GPS, GPS Joystick) or emulator location spoofing to trigger geofenced malware. If the malware checks `isFromMockProvider()`, mock location will not work. Workarounds:

- Use Frida to hook `isFromMockProvider()` and return `false`
- Use a rooted device with Magisk module that patches the mock location flag at framework level
- Use a physical device with a SIM from the target country instead of mock GPS
- Modify the emulator's location through the emulator controls (not via mock provider API)

## Families with Location Tracking

| Family | Type | Location Methods | Purpose |
|--------|------|-----------------|---------|
| [Pegasus](../malware/families/pegasus.md) | State-sponsored | GPS, cell, WiFi, passive | Real-time surveillance, movement tracking |
| [Predator](../malware/families/predator.md) | State-sponsored | GPS, cell, WiFi | Targeted surveillance |
| [Hermit](../malware/families/hermit.md) | State-sponsored | GPS, cell tower | Law enforcement surveillance |
| [FinSpy](../malware/families/finspy.md) | State-sponsored | GPS, cell, WiFi | Dissident/journalist targeting |
| [SpyNote](../malware/families/spynote.md) | RAT | GPS, cell | Full device surveillance including location |
| [SpyAgent](../malware/families/spyagent.md) | Spyware | GPS | Location tracking alongside crypto wallet theft |
| [PJobRAT](../malware/families/pjobrat.md) | Targeted | GPS | Military/government personnel targeting |
| [GuardZoo](../malware/families/guardzoo.md) | Targeted | GPS | Military targeting in Middle East |
| [AridSpy](../malware/families/aridspy.md) | Targeted | GPS | Middle East espionage |
| [BoneSpy](../malware/families/bonespy.md) | State-sponsored | GPS, cell | Russian-linked surveillance of Central Asian targets |
| [PlainGnome](../malware/families/plaingnome.md) | State-sponsored | GPS | Gamaredon group, targets Russian-speaking in former Soviet states |
| [KoSpy](../malware/families/kospy.md) | State-sponsored | GPS | North Korean APT targeting Korean/English speakers |
| [LightSpy](../malware/families/lightspy.md) | State-sponsored | GPS, WiFi | Chinese-linked, modular with dedicated location plugin |
| [EagleMsgSpy](../malware/families/eaglemsgspy.md) | Law enforcement | GPS | Chinese police surveillance tool |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | Banking | SIM + locale geofencing | Activates only in Thailand/Vietnam |
| [Anatsa](../malware/families/anatsa.md) | Banking | SIM + IP geofencing | Targets specific European countries |
| [GodFather](../malware/families/godfather.md) | Banking | Language check | Avoids CIS countries |
| [Cerberus](../malware/families/cerberus.md) | Banking | SIM + locale | Avoided CIS countries |
| [SpyLoan](../malware/families/spyloan.md) | Predatory lending | GPS | Collects victim location for intimidation and debt collection |
| [DCHSpy](../malware/families/dchspy.md) | Spyware | GPS | Location tracking as part of surveillance suite |
| [FireScam](../malware/families/firescam.md) | Spyware | GPS | Telegram impersonation with location exfiltration |

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 1.0 | 1 | `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` introduced | Location available to any installed app |
| 6.0 | 23 | [Runtime permissions](https://developer.android.com/training/permissions/requesting) for location | User must grant explicitly; [accessibility](accessibility-abuse.md) auto-grants |
| 8.0 | 26 | [Background location throttled](https://developer.android.com/about/versions/oreo/background-location-limits) to a few updates per hour | Active GPS polling from background services degraded |
| 8.0 | 26 | [Background service execution limits](https://developer.android.com/about/versions/oreo/background) | Persistent location services killed; foreground service required |
| 9.0 | 28 | WiFi scan throttling (foreground: 4/2min, background: 1/30min) | WiFi BSSID-based positioning rate-limited |
| 10 | 29 | [`ACCESS_BACKGROUND_LOCATION`](https://developer.android.com/about/versions/10/privacy/changes#app-access-device-location) as separate permission | User must explicitly grant background location in addition to foreground |
| 10 | 29 | `ACCESS_FINE_LOCATION` required for WiFi scan results | WiFi positioning requires location permission |
| 11 | 30 | [Background location can only be granted from Settings](https://developer.android.com/about/versions/11/privacy/location) | No runtime dialog; [accessibility](accessibility-abuse.md) navigates Settings to grant |
| 11 | 30 | One-time location permission option | Location access revoked after app backgrounded |
| 12 | 31 | [Approximate vs precise location](https://developer.android.com/about/versions/12/behavior-changes-12#approximate-location) choice in permission dialog | User can grant only coarse location, degrading tracking precision |
| 12 | 31 | Bluetooth scan no longer requires location permission | Reduces legitimate reasons to request location |
| 13 | 33 | [Foreground service type `location` required](https://developer.android.com/about/versions/14/changes/fgs-types-required) in manifest | Service must declare intent in manifest |
| 14 | 34 | Stricter foreground service type enforcement | `USE_EXACT_ALARM` restricted for periodic polling |
| 15 | 35 | Enhanced background location audit, Play Store review hardened | Play Store scrutiny on `ACCESS_BACKGROUND_LOCATION` increased |

## Detection During Analysis

??? example "Static Indicators"

    - `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `ACCESS_BACKGROUND_LOCATION` in manifest
    - `foregroundServiceType="location"` in service declaration
    - `FusedLocationProviderClient` or `LocationManager.requestLocationUpdates()` calls
    - `TelephonyManager.getAllCellInfo()`, `getCellLocation()`, or `getNeighboringCellInfo()`
    - `TelephonyManager.getSimCountryIso()`, `getNetworkCountryIso()`, `getSimOperator()` for geofencing
    - `Locale.getDefault()` combined with conditional execution paths
    - `GeofencingClient` or `Geofence.Builder` usage
    - `WifiManager.getScanResults()` for BSSID-based positioning
    - `LocationManager.PASSIVE_PROVIDER` usage (piggyback tracking)

??? example "Dynamic Indicators"

    - Periodic location requests from a background service or WorkManager
    - Cell tower info (`getAllCellInfo()`) exfiltrated to C2
    - WiFi scan results sent to external geolocation APIs
    - Network requests to IP geolocation services (ipinfo.io, ip-api.com, MaxMind)
    - Location data appearing in C2 traffic (latitude/longitude pairs, MCC/MNC/LAC/CID tuples)
    - App behavior changing based on SIM country or system locale
    - Foreground service with location type running with misleading notification text

??? example "Frida: Hook Location Updates"

    ```javascript
    Java.perform(function() {
        var LocationManager = Java.use("android.location.LocationManager");
        LocationManager.requestLocationUpdates.overload(
            "java.lang.String", "long", "float", "android.location.LocationListener"
        ).implementation = function(provider, minTime, minDist, listener) {
            console.log("[*] requestLocationUpdates: provider=" + provider +
                " interval=" + minTime + "ms minDist=" + minDist + "m");
            return this.requestLocationUpdates(provider, minTime, minDist, listener);
        };

        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getSimCountryIso.implementation = function() {
            var result = this.getSimCountryIso();
            console.log("[*] getSimCountryIso() = " + result);
            return result;
        };
        TelephonyManager.getNetworkCountryIso.implementation = function() {
            var result = this.getNetworkCountryIso();
            console.log("[*] getNetworkCountryIso() = " + result);
            return result;
        };
        TelephonyManager.getSimOperator.implementation = function() {
            var result = this.getSimOperator();
            console.log("[*] getSimOperator() = " + result);
            return result;
        };
    });
    ```

??? example "Frida: Spoof SIM Country for Geofence Bypass"

    ```javascript
    Java.perform(function() {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getSimCountryIso.implementation = function() {
            console.log("[*] getSimCountryIso() spoofed to 'de'");
            return "de";
        };
        TelephonyManager.getNetworkCountryIso.implementation = function() {
            console.log("[*] getNetworkCountryIso() spoofed to 'de'");
            return "de";
        };
        TelephonyManager.getSimOperator.implementation = function() {
            console.log("[*] getSimOperator() spoofed to '26201'");
            return "26201";
        };
    });
    ```

    This spoofs device-side checks but will not bypass server-side IP geofencing. Combine with a VPN exit node in the target country for full geofence bypass. Note that some families cross-validate SIM country against IP geolocation, so both must be consistent.

??? example "Frida: Bypass Mock Location Detection"

    ```javascript
    Java.perform(function() {
        var Location = Java.use("android.location.Location");

        Location.isFromMockProvider.implementation = function() {
            return false;
        };

        try {
            Location.isMock.implementation = function() {
                return false;
            };
        } catch(e) {}
    });
    ```
