# BLUETOOTH_ADVERTISE

Allows the device to broadcast BLE (Bluetooth Low Energy) advertisements, making it visible to nearby Bluetooth scanners. Limited abuse potential compared to scanning, but can be used for device impersonation or beacon spoofing.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BLUETOOTH_ADVERTISE` |
| Protection Level | `dangerous` |
| Permission Group | `NEARBY_DEVICES` |
| Grant Method | Runtime permission dialog |
| Introduced | API 31 (Android 12) |

## What It Enables

Broadcast custom BLE advertisements:

```java
BluetoothLeAdvertiser advertiser = BluetoothAdapter.getDefaultAdapter().getBluetoothLeAdvertiser();
AdvertiseData data = new AdvertiseData.Builder()
    .addServiceUuid(ParcelUuid.fromString("your-service-uuid"))
    .build();
advertiser.startAdvertising(settings, data, callback);
```

## Abuse in Malware

No major malware families have been publicly documented abusing `BLUETOOTH_ADVERTISE` specifically. The permission was introduced in Android 12, splitting the monolithic `BLUETOOTH` and `BLUETOOTH_ADMIN` permissions into more granular ones. However, the underlying BLE advertising capability has been available since Android 5.0, and several theoretical and emerging abuse patterns exist.

### Beacon Spoofing

Broadcast fake BLE beacon advertisements to trigger actions in nearby devices or apps that respond to specific beacon UUIDs. An infected device can impersonate an iBeacon, Eddystone, or AltBeacon to trigger location-based actions in nearby apps:

```java
BluetoothLeAdvertiser advertiser = BluetoothAdapter.getDefaultAdapter()
    .getBluetoothLeAdvertiser();

AdvertiseSettings settings = new AdvertiseSettings.Builder()
    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
    .setConnectable(false)
    .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
    .build();

byte[] manufacturerData = new byte[]{
    0x02, 0x15,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x00, 0x01,
    0x00, 0x02,
    (byte) 0xC5
};

AdvertiseData data = new AdvertiseData.Builder()
    .addManufacturerData(0x004C, manufacturerData)
    .build();

advertiser.startAdvertising(settings, data, new AdvertiseCallback() {
    @Override
    public void onStartSuccess(AdvertiseSettings settingsInEffect) {
    }

    @Override
    public void onStartFailure(int errorCode) {
    }
});
```

This could trigger location-based retail promotions, unlock proximity-based features in target apps, or feed false location data to beacon-based indoor positioning systems.

### P2P Malware Communication

Infected devices could use BLE advertisements as a local communication channel between nearby infected devices, creating a mesh-like C2 that doesn't require internet access. Data can be encoded in the advertising payload (up to 31 bytes in legacy advertisements, or 255 bytes with extended advertising on Android 8+):

```java
byte[] c2Data = encryptAndEncode(commandPayload);

AdvertiseData data = new AdvertiseData.Builder()
    .addServiceData(
        ParcelUuid.fromString("0000FFFF-0000-1000-8000-00805F9B34FB"),
        c2Data
    )
    .build();

advertiser.startAdvertising(settings, data, callback);
```

Nearby infected devices scanning with [BLUETOOTH_SCAN](bluetooth-scan.md) can receive these broadcasts and decode commands. This creates an air-gapped C2 channel useful in environments with restricted internet access (corporate networks, classified facilities).

### Device Tracking Enablement

If the infected device broadcasts a known BLE identifier, the attacker can track its physical location using their own BLE scanners deployed in the target area. Unlike passive Bluetooth tracking (which relies on the device's random MAC rotation), an infected device broadcasting a fixed service UUID can be tracked persistently:

```java
AdvertiseData data = new AdvertiseData.Builder()
    .addServiceUuid(ParcelUuid.fromString(victimTrackingUuid))
    .setIncludeDeviceName(false)
    .build();

AdvertiseSettings settings = new AdvertiseSettings.Builder()
    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
    .setTimeout(0)
    .build();

advertiser.startAdvertising(settings, data, callback);
```

### AirTag-Style Tracker Abuse

An infected Android device can be turned into a covert BLE tracker by continuously advertising a stable identifier. The attacker deploys BLE scanners (or uses other infected devices) in the target's environment to triangulate the victim's location. Apple's Find My network abuse and the broader tracker stalking problem demonstrate the real-world viability of BLE-based tracking.

## Android Version Changes

**Pre-Android 12**: BLE advertising required `BLUETOOTH` and `BLUETOOTH_ADMIN` permissions (both normal/install-time). No runtime prompt was needed, making BLE advertising silently available to any installed app.

**Android 12 (API 31)**: `BLUETOOTH_ADVERTISE` introduced as a separate runtime permission in the `NEARBY_DEVICES` group. Apps must now request this permission at runtime before calling `BluetoothLeAdvertiser.startAdvertising()`. The `neverForLocation` flag can be set in the manifest to indicate the app does not use advertising for location purposes, which avoids requiring location permission alongside it.

**Android 13 (API 33)**: no significant changes to the advertising API, but the `NEARBY_DEVICES` permission group is more prominently displayed in system settings.

**Android 14 (API 34)**: background advertising restrictions tightened. Apps must have a foreground service or be in the foreground to maintain active BLE advertisements on some OEM implementations.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />
```

Expected in IoT, wearable companion, and proximity-based apps. Unusual in other app categories.

### Static Analysis Indicators

- `BluetoothLeAdvertiser` references and calls to `startAdvertising()`
- `AdvertiseData.Builder` construction with hardcoded service UUIDs or manufacturer data
- iBeacon-format manufacturer data with Apple's company ID (0x004C)
- `AdvertiseSettings` with `setTimeout(0)` indicating indefinite advertising
- Custom data encoded in service data fields (potential C2 channel)

### Dynamic Analysis Indicators

- App starts BLE advertising without user-initiated action
- BLE advertisements containing data payloads that change over time (C2 communication)
- Advertising started immediately after boot (combined with `RECEIVE_BOOT_COMPLETED`)
- Fixed service UUIDs that persist across app restarts (tracking beacon behavior)

### Permission Combination Red Flags

`BLUETOOTH_ADVERTISE` combined with [BLUETOOTH_SCAN](bluetooth-scan.md) enables bidirectional BLE mesh communication. When both are present with `INTERNET` and no Bluetooth peripheral UI, the app may be using BLE as a secondary C2 channel. Combined with [ACCESS_FINE_LOCATION](../location/access-fine-location.md) and [RECEIVE_BOOT_COMPLETED](../normal/receive-boot-completed.md), the pattern suggests persistent proximity tracking infrastructure.
