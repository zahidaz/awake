# NEARBY_WIFI_DEVICES

Allows discovering nearby Wi-Fi networks and performing Wi-Fi Direct operations. Wi-Fi scan results (SSIDs and BSSIDs) can be used for location inference since Wi-Fi access point positions are mapped in global databases.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.NEARBY_WIFI_DEVICES` |
| Protection Level | `dangerous` |
| Permission Group | `NEARBY_DEVICES` |
| Grant Method | Runtime permission dialog |
| Introduced | API 33 (Android 13) |

Before Android 13, Wi-Fi scanning required `ACCESS_FINE_LOCATION`. Like `BLUETOOTH_SCAN`, apps can declare `neverForLocation` to opt out of location derivation.

## What It Enables

- Scan for nearby Wi-Fi networks (`WifiManager.startScan()`)
- Get scan results: SSID, BSSID, signal strength, frequency, channel
- Wi-Fi Direct (P2P) device discovery and connection
- Wi-Fi Aware (NAN) ranging and messaging

## Abuse in Malware

### Location Without GPS

Wi-Fi BSSIDs map to known geographic positions in databases maintained by Google, Apple, and commercial providers (WiGLE). Scanning nearby Wi-Fi networks reveals the device's location without GPS or location permissions (if `neverForLocation` is not declared).

### Network Reconnaissance

Enumerate nearby Wi-Fi networks to:

- Identify enterprise networks (SSID naming patterns)
- Detect home network names
- Map network infrastructure for further attacks

### Wi-Fi Direct Data Exfiltration

Use Wi-Fi Direct to transfer data to a nearby attacker-controlled device at high speed, bypassing internet-based monitoring.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" />
```

Check for `neverForLocation`. Without it, the app may derive location from Wi-Fi scan results.
