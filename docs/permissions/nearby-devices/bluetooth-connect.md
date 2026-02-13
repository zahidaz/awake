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

### Notable Families

No widely documented malware families specifically abuse `BLUETOOTH_CONNECT` as a primary attack vector. Bluetooth-based exfiltration and reconnaissance remain theoretical or niche capabilities in the wild. The permission is primarily of concern in stalkerware context rather than banking trojans or commodity malware.

Commercial spyware platforms like [Pegasus](../../malware/families/pegasus.md) and [FinSpy](../../malware/families/finspy.md) have broad device access that includes Bluetooth capabilities, but these are incidental to their primary surveillance functions rather than a documented abuse of the `BLUETOOTH_CONNECT` permission specifically.

### Stalkerware Device Proximity Tracking

Stalkerware families use `BLUETOOTH_CONNECT` to enumerate paired devices and monitor which Bluetooth peripherals are in range. This provides the stalker with:

- **Location inference**: if the victim's phone connects to their car Bluetooth, the stalker knows they are driving. Connection to a home speaker means they are at home. Office peripherals indicate they are at work.
- **Social proximity**: detecting unfamiliar Bluetooth device names in the pairing list can indicate the victim has been in proximity to unknown devices (other people's phones, headphones).
- **Routine profiling**: logging Bluetooth connection/disconnection events over time builds a pattern of the victim's daily routine.

### Abuse Code Example

```java
public class BluetoothRecon {

    private final BluetoothAdapter adapter;
    private final Context context;

    public BluetoothRecon(Context context) {
        this.context = context;
        BluetoothManager manager = (BluetoothManager)
            context.getSystemService(Context.BLUETOOTH_SERVICE);
        this.adapter = manager.getAdapter();
    }

    public JSONArray enumeratePairedDevices() {
        JSONArray devices = new JSONArray();
        Set<BluetoothDevice> bonded = adapter.getBondedDevices();

        for (BluetoothDevice device : bonded) {
            try {
                JSONObject info = new JSONObject();
                info.put("name", device.getName());
                info.put("address", device.getAddress());
                info.put("type", classifyDeviceType(device.getBluetoothClass()));
                info.put("bond_state", device.getBondState());
                info.put("device_type", device.getType());
                devices.put(info);
            } catch (Exception e) {
            }
        }
        return devices;
    }

    private String classifyDeviceType(BluetoothClass btClass) {
        if (btClass == null) return "unknown";
        int major = btClass.getMajorDeviceClass();
        switch (major) {
            case BluetoothClass.Device.Major.AUDIO_VIDEO:
                return "audio_video";
            case BluetoothClass.Device.Major.COMPUTER:
                return "computer";
            case BluetoothClass.Device.Major.PHONE:
                return "phone";
            case BluetoothClass.Device.Major.HEALTH:
                return "health_device";
            case BluetoothClass.Device.Major.WEARABLE:
                return "wearable";
            default:
                return "other_" + major;
        }
    }

    public void monitorConnections() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_ACL_CONNECTED);
        filter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED);

        context.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent intent) {
                BluetoothDevice device = intent.getParcelableExtra(
                    BluetoothDevice.EXTRA_DEVICE);
                String action = intent.getAction();
                String event = BluetoothDevice.ACTION_ACL_CONNECTED.equals(action)
                    ? "connected" : "disconnected";
                reportToC2(device.getName(), device.getAddress(), event);
            }
        }, filter);
    }

    private void reportToC2(String name, String address, String event) {
    }
}
```

The code demonstrates two surveillance patterns: initial enumeration of all paired devices to build an inventory of the victim's Bluetooth ecosystem, and ongoing connection monitoring to track real-time proximity events.

## Android Version Changes

**Android 12 (API 31)**: `BLUETOOTH_CONNECT` introduced as part of the new granular Bluetooth permission model. Prior to Android 12, Bluetooth access was controlled by `BLUETOOTH` (normal permission) and `BLUETOOTH_ADMIN` (normal permission), neither of which required runtime approval. This was a significant security improvement.

**Pre-Android 12**: any app with the `BLUETOOTH` normal permission could enumerate paired devices and connect to them without user awareness. Stalkerware had unrestricted Bluetooth access.

**Android 12 (API 31)**: apps targeting API 31+ must request `BLUETOOTH_CONNECT` at runtime to interact with paired devices. The `BLUETOOTH_SCAN` permission is required separately for discovering new devices. The `BLUETOOTH_ADVERTISE` permission is required for making the device discoverable.

**Android 13 (API 33)**: no changes to the permission model, but enforcement is stricter. Apps that declare `BLUETOOTH_CONNECT` without a clear Bluetooth use case face additional Play Store scrutiny.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
```

Common in legitimate apps that interact with Bluetooth accessories. Suspicious when combined with data collection permissions and no obvious Bluetooth functionality.

### Analysis Indicators

- `getBondedDevices()` calls followed by network transmission of device names, addresses, and types indicate Bluetooth reconnaissance.
- `BroadcastReceiver` registrations for `ACTION_ACL_CONNECTED` and `ACTION_ACL_DISCONNECTED` without corresponding Bluetooth UI indicate connection monitoring for surveillance.
- Device classification logic (parsing `BluetoothClass` to identify device types like health, audio, wearable) suggests profiling intent beyond simple peripheral interaction.
- Combined with `BLUETOOTH_SCAN`, `ACCESS_FINE_LOCATION`, and `INTERNET`, the permission set indicates comprehensive device tracking. Legitimate Bluetooth apps typically need only `BLUETOOTH_CONNECT`.
- Periodic background enumeration of paired devices (via `AlarmManager` or `WorkManager`) without user-initiated Bluetooth interaction is a stalkerware pattern.

## See Also

- [BLUETOOTH_SCAN](bluetooth-scan.md) -- discovers new (unpaired) Bluetooth devices, providing broader environmental awareness
- [BLUETOOTH_ADVERTISE](bluetooth-advertise.md) -- makes the device discoverable, potentially enabling proximity-based payload delivery
- [NFC Relay](../../attacks/nfc-relay.md) -- related proximity-based attack technique that also bypasses network monitoring
