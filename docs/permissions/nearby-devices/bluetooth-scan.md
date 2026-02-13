# BLUETOOTH_SCAN

Allows discovering nearby Bluetooth devices via BLE (Bluetooth Low Energy) and classic Bluetooth scanning. Scan results reveal nearby device names, MAC addresses, and BLE advertisement data, which can be used for physical tracking and location inference.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BLUETOOTH_SCAN` |
| Protection Level | `dangerous` |
| Permission Group | `NEARBY_DEVICES` |
| Grant Method | Runtime permission dialog |
| Introduced | API 31 (Android 12) |

Before Android 12, Bluetooth scanning required `ACCESS_FINE_LOCATION`. Android 12 introduced `BLUETOOTH_SCAN` as a dedicated permission. Apps can declare `android:usesPermissionFlags="neverForLocation"` to assert they won't use scan results for location inference, avoiding the location permission requirement.

## What It Enables

```java
BluetoothLeScanner scanner = BluetoothAdapter.getDefaultAdapter().getBluetoothLeScanner();
scanner.startScan(new ScanCallback() {
    @Override
    public void onScanResult(int callbackType, ScanResult result) {
        String deviceName = result.getDevice().getName();
        String macAddress = result.getDevice().getAddress();
        int rssi = result.getRssi();
        byte[] scanRecord = result.getScanRecord().getBytes();
    }
});
```

Scan results contain:

| Data | Use |
|------|-----|
| Device name | Identify device type and owner |
| MAC address | Persistent device identifier (randomized on modern devices) |
| RSSI | Signal strength, proximity estimation |
| Advertisement data | Service UUIDs, manufacturer data, beacon payloads |
| Device type | Classic Bluetooth, BLE, or dual-mode |

## Abuse in Malware

### Physical Tracking

BLE beacons (iBeacon, Eddystone) are deployed in retail, transit, and public spaces. An app scanning for beacons can determine indoor location without GPS.

### Device Fingerprinting

Nearby Bluetooth devices (headphones, smartwatches, car systems) create a signature of the user's environment. This fingerprint persists even when the user changes location.

### Location Inference

Bluetooth scan results can be mapped to physical locations using databases of BLE beacon positions (maintained by Google, Apple, and commercial providers).

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
```

Check for `neverForLocation` flag. Without it, the app can use scan results for location, which may need additional scrutiny.
