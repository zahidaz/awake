# ACCESS_WIFI_STATE

Normal permission granting read access to WiFi network information including SSID, BSSID, signal strength, connection state, and historically MAC addresses. Auto-granted at install with no user prompt. Spyware and data broker SDKs use this for device fingerprinting and coarse location inference (WiFi-based positioning), while banking trojans use it for network environment profiling to detect sandboxes and researcher networks.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACCESS_WIFI_STATE` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 1 |
| User Visibility | None |
| Play Store Policy | No restrictions (extremely common in legitimate apps) |

## What It Enables

### WiFi Network Information

```java
WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);
WifiInfo info = wifiManager.getConnectionInfo();

String ssid = info.getSSID();
String bssid = info.getBSSID();
int rssi = info.getRssi();
int linkSpeed = info.getLinkSpeedMbps();
int frequency = info.getFrequency();
String macAddress = info.getMacAddress();
```

### WiFi Scan Results

With `ACCESS_WIFI_STATE` and location permission, apps can enumerate nearby access points:

```java
List<ScanResult> results = wifiManager.getScanResults();
for (ScanResult ap : results) {
    String ssid = ap.SSID;
    String bssid = ap.BSSID;
    int level = ap.level;
}
```

Nearby BSSID/signal strength data enables WiFi-based positioning accurate to 10-50 meters, even without GPS.

## Abuse in Malware

### Device Fingerprinting

WiFi information creates a persistent device fingerprint:

| Data Point | Fingerprinting Value |
|------------|---------------------|
| Connected SSID | Identifies the network (home, work, public) |
| Connected BSSID | Uniquely identifies the specific access point |
| MAC address | Unique device identifier (restricted on Android 10+) |
| Scan results (nearby APs) | Location fingerprint based on visible access points |
| Link speed / frequency | Network capability profiling |

### WiFi-Based Location

Even without GPS or `ACCESS_FINE_LOCATION`, WiFi scan results can be correlated against public databases (Google, Mozilla Location Service, WiGLE) to determine physical location. Data broker SDKs embedded in legitimate apps systematically collect this data.

### Sandbox/Emulator Detection

Banking trojans check WiFi state to detect analysis environments:

| Check | Emulator Indicator |
|-------|-------------------|
| SSID | "AndroidWifi", "VirtualWifi", or null |
| BSSID | `02:00:00:00:00:00` or null |
| MAC address | `02:00:00:00:00:00` (Android 10+ returns this for privacy) |
| Connection state | Often disconnected in sandboxes |
| Scan results | Empty or single result in emulators |

### Families Using WiFi Reconnaissance

| Family | Usage |
|--------|-------|
| [SpinOk](../../malware/families/spinok.md) | Environment detection as part of anti-analysis |
| [Goldoson](../../malware/families/goldoson.md) | WiFi/Bluetooth scan data collection for location inference |
| [Hermit](../../malware/families/hermit.md) | WiFi network profiling as part of surveillance suite |
| [Pegasus](../../malware/families/pegasus.md) | WiFi-based positioning alongside GPS tracking |
| [Cerberus](../../malware/families/cerberus.md) | Emulator detection via WiFi state checks |
| [GodFather](../../malware/families/godfather.md) | Network environment profiling |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | Permission introduced | Full WiFi state access |
| 6.0 | 23 | WiFi scan requires location permission | Scan results gated behind `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` |
| 8.0 | 26 | Background scan throttling | WiFi scans limited to 2-3 per hour for background apps |
| 10 | 29 | MAC address randomization enabled by default | `getMacAddress()` returns `02:00:00:00:00:00` for non-system apps |
| 12 | 31 | `NEARBY_WIFI_DEVICES` introduced | Separates WiFi device discovery from location access |
| 13 | 33 | Scan results require `NEARBY_WIFI_DEVICES` or location permission | Further restricts scan-based reconnaissance |

MAC address randomization (Android 10) was the most significant restriction. Before Android 10, the real hardware MAC was accessible, providing a permanent device identifier. After Android 10, non-system apps receive a placeholder value, breaking MAC-based fingerprinting.

## Detection Indicators

### Manifest Signals

- `ACCESS_WIFI_STATE` combined with `INTERNET` in apps with no legitimate network management purpose
- `ACCESS_WIFI_STATE` + `ACCESS_FINE_LOCATION` in non-navigation/non-mapping apps (WiFi-based location tracking)
- Data collection patterns: WiFi info transmitted to remote servers alongside device identifiers

### Behavioral Signals

- `WifiManager.getScanResults()` called frequently alongside location APIs
- WiFi BSSID/SSID data appearing in network traffic payloads
- WiFi state checks used as conditional branching for malware activation (sandbox evasion)
