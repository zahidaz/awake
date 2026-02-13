# BLUETOOTH_CONNECT

Allows connecting to already-paired Bluetooth devices and accessing their data. Enables interacting with paired accessories, headphones, car systems, medical devices, and any other Bluetooth peripheral.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BLUETOOTH_CONNECT` |
| Protection Level | `dangerous` |
| Permission Group | `NEARBY_DEVICES` |
| Grant Method | Runtime permission dialog |
| Introduced | API 31 (Android 12) |

## What It Enables

- List paired devices via `BluetoothAdapter.getBondedDevices()`
- Connect to paired devices (RFCOMM, L2CAP, GATT)
- Read device properties (name, type, battery level)
- Transfer data over Bluetooth profiles (A2DP, HFP, SPP, OBEX)

## Abuse in Malware

### Data Exfiltration via Bluetooth

Transfer stolen data to a nearby attacker-controlled device via Bluetooth, bypassing network monitoring entirely.

### Paired Device Enumeration

List paired devices to identify:

- Car Bluetooth (reveals vehicle make/model)
- Medical devices (health information inference)
- Smart home devices (home automation fingerprinting)

### OBEX Push

Send files to paired devices via OBEX Object Push Profile. Could be used to deliver payloads to other devices in proximity.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
```

Common in legitimate apps that interact with Bluetooth accessories. Suspicious when combined with data collection permissions and no obvious Bluetooth functionality.
