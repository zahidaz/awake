# CALL_PHONE

Allows initiating phone calls programmatically without passing through the dialer UI. The call begins immediately with no user confirmation. Used by malware for premium-rate number fraud, USSD code execution that can modify carrier settings or drain prepaid balance, and as a revenue channel in early Android malware families.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.CALL_PHONE` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Direct call initiation via `ACTION_CALL` intent:

```java
Intent callIntent = new Intent(Intent.ACTION_CALL);
callIntent.setData(Uri.parse("tel:+19001234567"));
startActivity(callIntent);
```

The key distinction from `ACTION_DIAL` (which requires no permission) is that `ACTION_CALL` skips the dialer screen entirely. The call connects immediately.

USSD code execution works through the same mechanism:

```java
Intent ussdIntent = new Intent(Intent.ACTION_CALL);
ussdIntent.setData(Uri.parse("tel:%23%2306%23"));
startActivity(ussdIntent);
```

USSD codes are encoded as URI-escaped dial strings. The `#` character becomes `%23`, `*` becomes `%2A`.

| USSD Code | Effect |
|-----------|--------|
| `*#06#` | Display IMEI |
| `**21*[number]#` | Enable unconditional call forwarding |
| `##002#` | Disable all call forwarding |
| `*100#` | Check prepaid balance (carrier-dependent) |
| `*99#` | Subscribe to premium service (carrier-dependent) |

Starting API 26, `TelephonyManager.sendUssdRequest()` provides a programmatic USSD API with callback, giving malware structured access to USSD responses without parsing screen content.

## Abuse in Malware

### Premium Number Fraud

The original Android malware monetization model. Malware dials premium-rate numbers (typically international or short codes) that charge per-minute or per-call fees. Revenue splits between the premium number operator and the attacker.

The attack runs in the background or at night when the user is unlikely to notice. Some families mute the device audio before dialing and restore volume after hanging up.

### USSD Exploitation

USSD codes interact directly with the carrier network. Malware uses them to:

- **Forward calls**: redirect all incoming calls to an attacker number, enabling interception of voice-based OTPs and authentication callbacks
- **Drain balance**: execute carrier-specific USSD codes that purchase premium services or transfer prepaid credit
- **Wipe device**: on older Samsung devices, the USSD code `*2767*3855#` triggered a factory reset when processed through the dialer. This was demonstrated in 2012 by Ravi Borgaonkar and patched, but showed the destructive potential

### Call Forwarding Hijack

Setting up unconditional call forwarding via `**21*[attacker_number]#` redirects all incoming calls to the attacker. This intercepts:

- Bank callback verification calls
- Voice OTPs read by automated systems
- Two-factor authentication phone calls
- Calls from contacts (social engineering potential)

The victim's phone never rings. Combined with SMS forwarding, this provides complete telephony interception.

### Revenue Generation Comparison

| Method | Era | Revenue per Device |
|--------|-----|--------------------|
| Premium call fraud | 2010-2014 | $5-50/month |
| Premium SMS fraud | 2010-2016 | $1-10/message |
| Banking trojan (ATS) | 2018-present | $500-50,000/device |
| Ad fraud | 2015-present | $0.01-1/day |

Premium call fraud has largely been replaced by banking trojans, but still appears in malware targeting regions with weak carrier protections.

### Notable Families

| Family | Call Abuse |
|--------|-----------|
| GoldDream (2011) | One of the first to combine call initiation with SMS fraud |
| RuFraud | Premium number dialing targeting Russian carriers |
| Android.Trojan.MMarketPay | Automated premium service subscription via calls |
| FakePlayer | Premium SMS/call hybrid fraud |
| Acecard | Call forwarding setup to intercept bank verification calls |
| Svpeng | USSD-based balance drain on Russian carriers |

## Android Version Changes

**Android 1.0 (API 1)**: `CALL_PHONE` introduced with no runtime check. Manifest declaration was sufficient.

**Android 6.0 (API 23)**: runtime permission required. Users must explicitly grant the PHONE permission group.

**Android 6.0**: Google also patched the USSD factory reset vector for stock Android. USSD codes from intents are now shown in the dialer rather than executed directly for certain dangerous codes.

**Android 8.0 (API 26)**: `TelephonyManager.sendUssdRequest()` added, providing a proper API for USSD with callbacks. Requires `CALL_PHONE` permission.

**Android 10 (API 29)**: background activity launch restrictions. Apps cannot start `ACTION_CALL` from the background unless they have a foreground service or are in the foreground. This limits silent premium dialing.

**Google Play 2019**: `CALL_PHONE` restricted to apps declared as default dialer/phone handler or with approved use cases.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.CALL_PHONE" />
```

Look for `ACTION_CALL` intents in code (not `ACTION_DIAL`, which is benign). Hardcoded phone numbers, especially premium-rate prefixes or USSD patterns, are strong indicators. `tel:` URI strings with encoded USSD characters (`%23`, `%2A`) in the decompiled code point to carrier manipulation.

Combined with `MODIFY_AUDIO_SETTINGS` (to mute during calls) and `RECEIVE_BOOT_COMPLETED` (to schedule calls), this strongly suggests automated call fraud.
