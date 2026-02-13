# Nearby Devices Permissions

Access to Bluetooth, Wi-Fi scanning, and Ultra-Wideband (UWB) for device discovery and communication. Introduced in Android 12 to replace the previous model where nearby device operations required location permissions.

Security relevance: Bluetooth scanning reveals nearby devices and can be used for physical tracking. Wi-Fi scanning reveals nearby networks, which can be used for location inference. BLE beacons enable indoor tracking.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [BLUETOOTH_SCAN](bluetooth-scan.md) | Discover nearby Bluetooth devices, physical tracking via BLE beacons |
| [BLUETOOTH_ADVERTISE](bluetooth-advertise.md) | Broadcast BLE advertisements, impersonate devices |
| [BLUETOOTH_CONNECT](bluetooth-connect.md) | Connect to paired Bluetooth devices, data exfiltration via Bluetooth |
| [NEARBY_WIFI_DEVICES](nearby-wifi-devices.md) | Scan Wi-Fi networks, location inference from BSSID/SSID |
| [UWB_RANGING](uwb-ranging.md) | Ultra-Wideband distance measurement, precise indoor positioning |

## Background

Before Android 12, Bluetooth and Wi-Fi scanning required `ACCESS_FINE_LOCATION` because scan results reveal the user's location (nearby BLE beacons, Wi-Fi BSSIDs map to known locations). Android 12 separated these into dedicated nearby device permissions, with an option to assert that the app won't derive location from scan results (`android:usesPermissionFlags="neverForLocation"`).

## BLE Beacon Tracking

BLE (Bluetooth Low Energy) beacons broadcast fixed identifiers at regular intervals. A malicious app with `BLUETOOTH_SCAN` can passively collect these identifiers and correlate them with known beacon databases to determine the target's indoor location with meter-level precision:

- **Retail environments** deploy dense beacon networks for customer analytics -- a scanning app can map exact in-store movement
- **Office buildings** increasingly use BLE for access control and indoor navigation, creating a grid of trackable reference points
- **Public transit** systems embed BLE beacons at stations and on vehicles, enabling route reconstruction without GPS
- **Custom-planted beacons** -- an operator can deploy small BLE beacons (under $5 each) near a target's home, workplace, or vehicle, then detect proximity through the compromised phone app

Unlike GPS, BLE tracking works indoors, underground, and in GPS-denied environments. It also consumes significantly less battery, making continuous scanning less likely to alert the target through unusual battery drain.

## Bluetooth Exfiltration Channel

`BLUETOOTH_CONNECT` enables data exfiltration over Bluetooth as an alternative to internet-based channels. This is operationally relevant when:

- The target's network traffic is monitored by a corporate firewall or national-level DPI (deep packet inspection)
- The device has no internet connectivity (airplane mode, restricted network)
- The operator wants to avoid leaving any network-layer artifacts (DNS queries, IP connections)

The exfiltration flow uses a nearby attacker-controlled device (phone, laptop, or Raspberry Pi) within Bluetooth range (~10m for standard BLE, up to ~100m with directional antennas). The implant establishes a Bluetooth serial connection or uses GATT (Generic Attribute Profile) to transfer collected data. This requires physical proximity, making it most practical for operations where the attacker has regular access to the target's environment -- a shared office, hotel, or regular meeting location.

## Wi-Fi SSID/BSSID for Indoor Positioning

`NEARBY_WIFI_DEVICES` enables Wi-Fi network scanning that provides location data without GPS through two mechanisms:

**BSSID geolocation** -- Every Wi-Fi access point broadcasts a unique BSSID (MAC address). Services like Google, Apple, and WiGLE maintain massive databases mapping BSSIDs to physical locations. A single Wi-Fi scan returning 5-10 visible BSSIDs can triangulate position to within 10-30 meters in urban areas.

**SSID fingerprinting** -- The set of visible network names creates a location fingerprint. Even without a BSSID database, repeated observations of the same SSID set indicate the target is in the same location. A home network's SSID appearing in scan results confirms the target is home. A corporate SSID confirms they are at the office.

This is why Android originally required `ACCESS_FINE_LOCATION` for Wi-Fi scanning -- the scan results are functionally equivalent to a GPS fix in populated areas.

## Stalkerware: Physical Proximity via BLE

Stalkerware apps abuse `BLUETOOTH_SCAN` for a particularly invasive form of tracking -- detecting when specific Bluetooth devices are near the target's phone. The stalker registers the Bluetooth MAC addresses of devices belonging to specific people (a coworker, a friend, an ex-partner), and the stalkerware alerts whenever those devices appear in scan results.

This enables the stalker to determine:

- Who the target is physically near, and how often
- Whether a specific person's device appears at the target's location outside expected hours
- When the target is near their own vehicle, home devices, or workplace peripherals

Combined with continuous BLE scanning in the background, this creates a social proximity graph -- not just where the target goes, but who they are with.
