# READ_PHONE_STATE

Grants access to telephony state: device identifiers (IMEI, MEID, IMSI), phone number, network operator, SIM state, and active call status. The most widely requested dangerous permission in Android malware history, used primarily for device fingerprinting and tracking across app installs.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_PHONE_STATE` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Access to `TelephonyManager` methods that return device and network identifiers:

| Method | Returns | Restricted Since |
|--------|---------|-----------------|
| `getDeviceId()` | IMEI (GSM) / MEID (CDMA) | Android 10 |
| `getImei()` | IMEI slot 0/1 | Android 10 |
| `getSubscriberId()` | IMSI | Android 10 |
| `getLine1Number()` | Phone number (carrier-dependent) | Android 11 |
| `getSimSerialNumber()` | ICCID | Android 10 |
| `getNetworkOperator()` | MCC+MNC | Not restricted |
| `getNetworkOperatorName()` | Carrier name | Not restricted |
| `getSimOperator()` | SIM MCC+MNC | Not restricted |
| `getCallState()` | Idle/ringing/offhook | Android 12 (use callback instead) |

```java
TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
String imei = tm.getImei();
String imsi = tm.getSubscriberId();
String phone = tm.getLine1Number();
String carrier = tm.getNetworkOperatorName();
```

The `PhoneStateListener` (deprecated API 31, replaced by `TelephonyCallback`) provides real-time call state changes, enabling detection of when the user is on a call, when calls begin and end, and the remote number on incoming calls.

## Abuse in Malware

### Device Fingerprinting

IMEI and IMSI form a persistent device+SIM fingerprint that survives app reinstalls and factory resets (IMEI) or follows the user across devices (IMSI follows the SIM). Malware uses this to:

- Uniquely identify victims in C2 databases
- Detect analysis environments (emulators return all-zero or sequential IMEIs)
- Prevent re-enrollment when a device is wiped and re-infected
- Track devices across different malware campaigns

### Emulator Detection

Common evasion check:

```java
String imei = tm.getImei();
if (imei == null || imei.equals("000000000000000") || imei.startsWith("35291100")) {
    return;
}
```

Emulators and analysis sandboxes often return null, zeroed, or well-known default IMEI values. Malware compares against a blocklist and refuses to execute on non-physical devices.

### Call State Monitoring

Monitoring `CALL_STATE_RINGING` and `CALL_STATE_OFFHOOK` allows malware to:

- Detect when the user is busy on a call (timing attacks for social engineering)
- Trigger call recording when combined with `RECORD_AUDIO`
- Suppress malicious activity during calls to avoid detection

### SIM Swap Detection

Some banking trojans monitor SIM changes via `getSubscriberId()` and `getSimSerialNumber()`. A changed IMSI or ICCID with the same IMEI indicates a SIM swap, which can trigger the malware to exfiltrate new SIM details to C2.

### Notable Families

| Family | Usage |
|--------|-------|
| [Pegasus](../../malware/families/pegasus.md) | Full telephony state collection as part of device profiling |
| [Cerberus](../../malware/families/cerberus.md) / [Alien](../../malware/families/alien.md) | IMEI as victim ID in C2, emulator detection |
| [Anubis](../../malware/families/anubis.md) | IMEI-based bot registration, call state monitoring |
| [Joker](../../malware/families/joker.md) | Device fingerprinting for premium subscription fraud |
| [FluBot](../../malware/families/flubot.md) | IMEI+carrier info sent to C2 on initial beacon |
| [Triada](../../malware/families/triada.md) | IMEI/IMSI exfiltration for ad fraud attribution |
| [GodFather](../../malware/families/godfather.md) | IMEI fingerprinting, post-Soviet language kill switch uses SIM locale |
| [Fakecalls](../../malware/families/fakecalls.md) | Call state monitoring for call interception and redirection |
| [SpyNote](../../malware/families/spynote.md) | Full telephony state collection, IMEI-based bot ID |
| [Mamont](../../malware/families/mamont.md) | Device fingerprinting for Russian-targeted campaigns |

## Android Version Changes

**Android 1.0 (API 1)**: `READ_PHONE_STATE` introduced. No runtime permission required. Any app with the manifest declaration could read IMEI, IMSI, phone number, and all telephony state.

**Android 6.0 (API 23)**: runtime permission required. Granting `READ_PHONE_STATE` granted the entire PHONE group, including `CALL_PHONE` and `READ_CALL_LOG` in early implementations.

**Android 9 (API 28)**: `READ_CALL_LOG` split into its own permission group. `READ_PHONE_STATE` no longer grants call log access.

**Android 10 (API 29)**: `getDeviceId()`, `getImei()`, `getSubscriberId()`, and `getSimSerialNumber()` restricted to apps with `READ_PRIVILEGED_PHONE_STATE` (signature|privileged). Third-party apps receive a `SecurityException`. This was the most significant restriction, eliminating IMEI harvesting for non-system apps.

**Android 11 (API 30)**: `getLine1Number()` requires `READ_PHONE_NUMBERS` (a separate permission) or the `READ_PHONE_STATE` permission is insufficient. Further tightened access to phone number.

**Android 12 (API 31)**: `PhoneStateListener` deprecated in favor of `TelephonyCallback`. Apps targeting API 31+ need `READ_PHONE_STATE` for call state callbacks but cannot get the incoming number without `READ_CALL_LOG`.

**Android 13 (API 33)**: no new restrictions on `READ_PHONE_STATE` itself, but Play Store policy enforcement tightened.

## Post-Android 10 Alternatives

With IMEI access removed, malware adapted:

| Alternative Identifier | Requires | Persistence |
|----------------------|----------|-------------|
| `Settings.Secure.ANDROID_ID` | No permission | Resets on factory reset, unique per app signing key |
| `ADVERTISING_ID` | No permission (Play Services) | User-resettable |
| `Build.SERIAL` | `READ_PHONE_STATE` (pre-10), restricted (10+) | Hardware-bound |
| Hardware MAC | Randomized since Android 10 | Not reliable |
| `MediaDrm` device unique ID | No permission | Persistent, hardware-bound |

`MediaDrm.getPropertyByteArray("deviceUniqueId")` with a Widevine provisioning ID has become the preferred fingerprinting method for post-Android 10 malware since it requires no permissions and is hardware-bound.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
```

On its own, `READ_PHONE_STATE` is common in legitimate apps. Strong indicators of abuse include combination with `INTERNET` and `RECEIVE_BOOT_COMPLETED`, immediate exfiltration of `TelephonyManager` data on first launch, and comparison of IMEI values against known emulator patterns in the code.

Look for `TelephonyManager` usage in static analysis, specifically calls to `getDeviceId()`, `getImei()`, and `getSubscriberId()` followed by network operations.
