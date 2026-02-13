# READ_PHONE_NUMBERS

Allows reading the device's own phone numbers (line numbers for all SIMs). Introduced in Android 8 as a less invasive alternative to `READ_PHONE_STATE` for apps that only need the phone number.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_PHONE_NUMBERS` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 26 (Android 8.0) |

## What It Enables

```java
TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
String phoneNumber = tm.getLine1Number();
```

Returns the phone number(s) associated with the device's SIM card(s). Note: this is not always populated, depending on the carrier and SIM configuration.

## Abuse in Malware

### Device Identification

The phone number serves as a persistent identifier for the victim. Malware sends this to C2 during initial registration to uniquely identify the infected device and enable targeted operations (e.g., sending SMS-based C2 commands to this number).

### Account Correlation

Phone numbers can be used to look up social media profiles, messaging accounts, and banking information.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_PHONE_NUMBERS" />
```

Less suspicious than `READ_PHONE_STATE` since it provides less data, but still enables device identification.
