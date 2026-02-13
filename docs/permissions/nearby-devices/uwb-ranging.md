# UWB_RANGING

Allows using Ultra-Wideband (UWB) radio for precise distance measurement and spatial awareness. UWB provides centimeter-level accuracy for ranging between devices, unlike Bluetooth or Wi-Fi which offer only rough proximity estimates.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.UWB_RANGING` |
| Protection Level | `dangerous` |
| Permission Group | `NEARBY_DEVICES` |
| Grant Method | Runtime permission dialog |
| Introduced | API 31 (Android 12) |

UWB hardware is available on select devices: Pixel 6 Pro+, Samsung Galaxy S21+, and some other flagships.

## What It Enables

- Measure precise distance and angle to other UWB-equipped devices
- Indoor positioning with centimeter-level accuracy
- Secure ranging for access control (digital car keys, smart locks)

## Abuse in Malware

No known malware families abuse `UWB_RANGING`. This is due to several factors:

- UWB hardware is only present on premium devices (Pixel 6 Pro+, Samsung Galaxy S21+, select iPhones)
- The permission requires a paired UWB accessory or a second UWB-equipped device within range
- The installed base of UWB-capable Android devices remains small
- Bluetooth and Wi-Fi based proximity detection are far more accessible alternatives

### Precision Tracking (Theoretical)

If both the target's device and the attacker's device have UWB, the attacker can determine exact distance and direction. UWB provides centimeter-level accuracy with angle-of-arrival data, far more precise than Bluetooth RSSI-based ranging (which is accurate only to a few meters):

```java
UwbManager uwbManager = (UwbManager) getSystemService(UWB_SERVICE);
RangingParameters params = new RangingParameters(
    RangingParameters.CONFIG_UNICAST_DS_TWR,
    sessionId,
    new UwbComplexChannel(9, 11),
    peerDevices,
    RangingParameters.RANGING_UPDATE_RATE_AUTOMATIC
);

CancellationSignal cancellation = new CancellationSignal();
uwbManager.openRangingSession(params, Executors.newSingleThreadExecutor(),
    new RangingSession.Callback() {
        @Override
        public void onOpened(RangingSession session) {
            session.start(new PersistableBundle());
        }

        @Override
        public void onRangingResult(RangingSession session, RangingResult result) {
            if (result instanceof RangingResult.RangingResultPosition) {
                RangingResult.RangingResultPosition position =
                    (RangingResult.RangingResultPosition) result;
                float distanceMeters = position.getPosition().getDistance().getValue();
                float azimuth = position.getPosition().getAzimuth().getValue();
                float elevation = position.getPosition().getElevation().getValue();
                exfiltratePosition(distanceMeters, azimuth, elevation);
            }
        }
    }
);
```

### Access Control Relay (Theoretical)

UWB is used for secure ranging in digital car keys (BMW, Hyundai), smart locks, and payment terminals. A relay attack could potentially extend the UWB range, though UWB's time-of-flight design is specifically intended to resist relay attacks by detecting artificially added latency. Research from ETH Zurich and others has demonstrated theoretical relay attacks against UWB ranging by using custom hardware to minimize relay latency, but these require physical hardware, not just software exploitation.

### Device Fingerprinting (Theoretical)

UWB ranging reveals the physical position of nearby UWB-equipped devices with high precision. In a corporate or government environment, this data could map the physical layout of personnel carrying UWB-capable phones, identifying meeting patterns and proximity relationships.

## Android Version Changes

**Android 12 (API 31)**: `UWB_RANGING` introduced alongside the `UwbManager` system service. Initially supported on Pixel 6 Pro and Samsung Galaxy S21 Ultra.

**Android 13 (API 33)**: expanded UWB API with support for additional ranging configurations and multi-device sessions. More OEMs added UWB hardware to flagship devices.

**Android 14 (API 34)**: UWB API matured with improved session management, background ranging restrictions, and tighter integration with the digital car key framework. Apps must be in the foreground or have an active foreground service to maintain ranging sessions.

**Android 15**: further restrictions on background UWB usage and additional support for the FiRa consortium's UWB standards for interoperability.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.UWB_RANGING" />
```

Only expected in apps that interact with UWB peripherals (car keys, smart home, spatial audio). Very rare in the wild.

### Static Analysis Indicators

- References to `android.uwb.UwbManager` or `UwbManager.openRangingSession()`
- `RangingParameters` configuration objects
- `RangingSession.Callback` implementations that process distance and angle data
- `UwbComplexChannel` usage (configures the specific UWB channel and preamble code)

### Dynamic Analysis Indicators

- App attempts to access `UWB_SERVICE` system service
- Ranging session creation without a visible UWB-related UI
- Distance and angle data appearing in network traffic or local storage
- Repeated ranging session attempts on devices without UWB hardware (indicates probing for capability)

### Permission Combination Red Flags

`UWB_RANGING` combined with [BLUETOOTH_SCAN](bluetooth-scan.md) and [ACCESS_FINE_LOCATION](../location/access-fine-location.md) in a non-IoT app suggests multi-modal proximity tracking. Since UWB hardware is rare, the presence of `UWB_RANGING` in an app targeting a broad user base (rather than specific UWB accessories) is itself anomalous and warrants investigation.
