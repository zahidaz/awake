# READ_SMS

Grants access to all SMS messages stored on the device. The primary use in malware is OTP interception -- reading one-time passwords sent by banks and online services to complete unauthorized transactions or account takeovers. Also used for SMS forwarding (exfiltrating entire message history to C2), contact harvesting from message metadata, and confirming premium service subscriptions. Despite years of platform restrictions and Google Play policy changes, SMS-based 2FA remains widespread enough that this permission is still a high-value target for banking trojans.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_SMS` |
| Protection Level | `dangerous` |
| Permission Group | `android.permission-group.SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |
| Play Store Policy | Restricted since January 2019 to default SMS handlers and approved use cases |

## What It Enables

Access to the SMS content provider at `content://sms/`. The app can read all stored messages across inbox, sent, drafts, and outbox:

```java
Cursor cursor = getContentResolver().query(
    Uri.parse("content://sms/inbox"),
    new String[]{"address", "body", "date", "read", "type"},
    null,
    null,
    "date DESC"
);

while (cursor.moveToNext()) {
    String sender = cursor.getString(cursor.getColumnIndex("address"));
    String body = cursor.getString(cursor.getColumnIndex("body"));
    long timestamp = cursor.getLong(cursor.getColumnIndex("date"));
}
cursor.close();
```

The SMS content provider schema:

| Field | Content | Abuse Value |
|-------|---------|-------------|
| `address` | Sender/recipient phone number | Contact graph extraction |
| `body` | Message text | OTP codes, personal data |
| `date` | Timestamp (milliseconds since epoch) | Timing attacks, recent OTP targeting |
| `read` | Read/unread status (0/1) | Target unread OTPs first |
| `type` | Inbox (1), Sent (2), Draft (3), Outbox (4) | Filter for incoming messages |
| `thread_id` | Conversation thread identifier | Group messages by contact |
| `person` | Contact ID if sender is in contacts | Cross-reference with contact data |

### Targeted OTP Query

Malware often filters for recent messages from known banking short codes or containing OTP patterns:

```java
String selection = "date > ? AND body LIKE ?";
String[] args = {
    String.valueOf(System.currentTimeMillis() - 120000),
    "%verification code%"
};
Cursor cursor = getContentResolver().query(
    Uri.parse("content://sms/inbox"),
    new String[]{"address", "body"},
    selection,
    args,
    "date DESC"
);
```

## Abuse in Malware

### OTP Interception

The primary abuse case. Banks and online services send authentication codes via SMS. Malware reads these to complete unauthorized transactions or account takeovers.

Two complementary approaches:

| Approach | Permission | Mechanism | Timing |
|----------|------------|-----------|--------|
| Retroactive | `READ_SMS` | Query `content://sms/inbox` for recent messages | After OTP arrives, with slight delay |
| Real-time | `RECEIVE_SMS` | `BroadcastReceiver` with `SMS_RECEIVED` action and high priority | Immediate, can suppress notification |

Most families use both: `RECEIVE_SMS` for real-time interception with notification suppression, and `READ_SMS` as a fallback to scan the inbox if the broadcast receiver misses a message.

### SMS Forwarding to C2

Malware reads the entire SMS inbox and forwards all messages to C2. This captures OTPs, bank transaction alerts, personal messages, and any SMS-based verification. Some families set up a periodic task (via `AlarmManager` or `WorkManager`) to continuously exfiltrate new messages.

### Premium SMS Subscription Fraud

[Joker](../../malware/families/joker.md) (also known as Bread) uses `READ_SMS` to intercept confirmation codes for premium service subscriptions it initiates silently. The malware simulates clicks on premium subscription web pages, reads the confirmation SMS code, and completes the subscription -- all without user awareness. Over 1,800 Joker-infected apps were removed from Google Play between 2017 and 2023, according to [Zimperium research](https://zimperium.com/blog/).

### SMS Worm Propagation

[FluBot](../../malware/families/flubot.md) read the victim's SMS history and contact list to craft targeted smishing messages, sending itself to all contacts via SMS. The worm spread across Europe from late 2020 until [Europol disrupted its infrastructure](https://www.europol.europa.eu/media-press/newsroom/news/takedown-of-sms-based-flubot-spyware-infecting-android-phones) in May 2022. FluBot replaced the default SMS app to intercept all incoming messages, capturing banking OTPs while simultaneously using the SMS channel for propagation.

### Notable Families

| Family | SMS Abuse | Source |
|--------|----------|--------|
| [FluBot](../../malware/families/flubot.md) | SMS worm: reads contacts, sends smishing messages, replaces default SMS app for OTP interception | [Europol](https://www.europol.europa.eu/media-press/newsroom/news/takedown-of-sms-based-flubot-spyware-infecting-android-phones) |
| [Cerberus](../../malware/families/cerberus.md) | OTP theft via SMS reading combined with notification listener for redundant capture | [ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld) |
| [Joker](../../malware/families/joker.md) | Reads SMS to extract confirmation codes for premium service subscriptions initiated silently | [Zscaler](https://www.zscaler.com/blogs/security-research/joker-playing-hide-and-seek-google-play) |
| [TrickMo](../../malware/families/trickmo.md) | Real-time SMS forwarding to bypass banking 2FA, 40+ variants identified with 16 droppers | [Zimperium](https://zimperium.com/blog/) |
| [BRATA](../../malware/families/brata.md) | SMS interception for banking fraud, prompts user to set malware as default SMS app, wipes device post-theft | [Cleafy](https://www.cleafy.com/cleafy-labs/mobile-banking-fraud-brata-strikes-again) |
| [MoqHao](../../malware/families/moqhao.md) | SMS-based distribution (smishing via Roaming Mantis), reads and exfiltrates SMS on infected devices | [McAfee](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/moqhao-evolution-new-variants-start-automatically-right-after-installation/) |
| [Anatsa](../../malware/families/anatsa.md) | SMS interception for transaction authorization codes during on-device fraud | [ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach) |

## Google Play SMS Policy Crackdown

In October 2018, Google [announced restrictions on SMS and Call Log permissions](https://android-developers.googleblog.com/2019/01/reminder-smscall-log-policy-changes.html). Enforcement began January 9, 2019:

- Only apps designated as the default SMS handler, Phone handler, or Assistant handler may declare `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, or Call Log permissions
- All other apps must remove these permissions from their manifest or submit a Permissions Declaration Form with justification
- Apps that failed to comply were removed from the Play Store
- Limited exemptions granted for specific use cases (e.g., backup apps, dual-SIM managers)

This policy [crippled many legitimate apps](https://www.androidpolice.com/2019/01/05/googles-new-sms-and-call-permission-policy-is-crippling-apps-used-by-millions/) but also forced malware to adapt. Post-2019 banking trojans increasingly shifted to:

- Notification listener for OTP capture (does not require SMS permission)
- Accessibility service to read notification content from the screen
- Overlay phishing of authenticator apps to capture TOTP codes
- Sideloading distribution to avoid Play Store policy entirely

## Alternatives When READ_SMS Is Unavailable

When `READ_SMS` is difficult to obtain (Play Store restrictions, user suspicion), malware uses alternative channels:

| Alternative | Permission Required | Mechanism | Limitations |
|-------------|-------------------|-----------|-------------|
| Notification listener | `BIND_NOTIFICATION_LISTENER_SERVICE` | Reads OTP from notification text | Requires user toggle in Settings, only sees notification content |
| Accessibility service | `BIND_ACCESSIBILITY_SERVICE` | Reads any on-screen text including SMS notifications | Requires user toggle, subject to restricted settings on Android 13+ |
| Overlay on authenticator | `SYSTEM_ALERT_WINDOW` | Phishes TOTP codes by overlaying Google Authenticator or similar apps | Only captures app-based 2FA, not SMS |
| Push notification interception | `BIND_NOTIFICATION_LISTENER_SERVICE` | Captures push-based OTPs from banking apps that moved away from SMS | Same limitations as notification listener |

The shift toward notification-based OTP interception has reduced reliance on `READ_SMS` in newer malware families. `BIND_NOTIFICATION_LISTENER_SERVICE` is easier to justify to the user ("We need notification access for this feature") and is not subject to Google Play's SMS policy. See [Notification Listener Abuse](../../attacks/notification-listener-abuse.md).

## Android Version Changes

### Android 4.4 (API 19)

Only the default SMS app can write to the SMS content provider. Non-default apps can still read all messages with `READ_SMS`. This was the first attempt to limit SMS abuse, but it only affected write operations.

### Android 6.0 (API 23)

Runtime permission required. Before this, `READ_SMS` was granted silently at install time. Under the original permission group model, granting `READ_SMS` also granted `RECEIVE_SMS`, `RECEIVE_MMS`, and `RECEIVE_WAP_PUSH` (all in the SMS group). This meant a single "Allow" tap gave malware the complete SMS interception toolkit.

### Android 8.0 (API 26)

Google Play policy begins restricting SMS permissions to apps with core SMS functionality. This predates the formal January 2019 enforcement but signals the direction. Apps must be declared as default SMS handler or have an approved use case.

### Android 10 (API 29)

Permission groups split to be more granular. `READ_SMS` no longer automatically grants access to Call Log or phone number data. Each permission in the SMS group must be individually justified, though granting one still prompts for the group on the runtime dialog.

### Android 13 (API 33)

Runtime permission model unchanged at the platform level, but Play Store review is significantly stricter about justifying SMS access. Photo picker and other scoped access APIs reduce legitimate reasons for broad permissions, making SMS permission requests more suspicious during review.

## Frida Monitoring Script

Monitor SMS content provider queries at runtime:

```javascript
Java.perform(function () {
    var ContentResolver = Java.use("android.content.ContentResolver");

    ContentResolver.query.overload(
        "android.net.Uri",
        "[Ljava.lang.String;",
        "java.lang.String",
        "[Ljava.lang.String;",
        "java.lang.String"
    ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
            console.log("[SMS Query] URI: " + uriStr);
            console.log("  projection: " + projection);
            console.log("  selection: " + selection);
            if (selectionArgs !== null) {
                console.log("  selectionArgs: " + selectionArgs);
            }
            console.log("  sortOrder: " + sortOrder);
            var trace = Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new());
            console.log("  caller: " + trace);
        }
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };

    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overload(
        "java.lang.String",
        "java.lang.String",
        "java.lang.String",
        "android.app.PendingIntent",
        "android.app.PendingIntent"
    ).implementation = function (dest, sc, text, sentIntent, deliveryIntent) {
        console.log("[SMS Send] to: " + dest);
        console.log("  body: " + text);
        this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
    };
});
```

## Detection Indicators

**Manifest signals:**

```xml
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.RECEIVE_SMS" />
```

**High-priority BroadcastReceiver registration (real-time interception):**

```xml
<receiver android:name=".SmsReceiver" android:exported="true">
    <intent-filter android:priority="999">
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

A `BroadcastReceiver` for `SMS_RECEIVED` with high priority (attempting to receive before the default SMS app) is a strong indicator of real-time SMS interception.

**High-confidence malware indicators** (combination of):

- `READ_SMS` + `RECEIVE_SMS` + `INTERNET` (SMS exfiltration)
- `READ_SMS` + `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` (persistent SMS monitoring)
- `SEND_SMS` + `READ_CONTACTS` (SMS worm propagation, FluBot pattern)
- `READ_SMS` + `RECEIVE_SMS` without being the default SMS app
- Content provider queries to `content://sms/` in background services
- String patterns matching OTP regex (`\b\d{4,8}\b`, "verification code", "confirmation code")

See also: [SMS Interception](../../attacks/sms-interception.md) | [Notification Listener Abuse](../../attacks/notification-listener-abuse.md)
