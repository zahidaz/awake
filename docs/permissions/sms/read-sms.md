# READ_SMS

Allows reading SMS messages stored on the device. Used by malware to intercept one-time passwords (OTPs), read authentication codes, and harvest personal communications. Often combined with `RECEIVE_SMS` for real-time interception.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_SMS` |
| Protection Level | `dangerous` |
| Permission Group | `SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Access to the SMS content provider at `content://sms/`. The app can read all stored messages: inbox, sent, drafts, and outbox.

```java
Cursor cursor = getContentResolver().query(
    Uri.parse("content://sms/inbox"),
    new String[]{"address", "body", "date"},
    null, null, "date DESC"
);
```

Each message contains:

| Field | Content |
|-------|---------|
| `address` | Sender phone number |
| `body` | Message text |
| `date` | Timestamp |
| `read` | Read/unread status |
| `type` | Inbox (1), Sent (2), Draft (3), Outbox (4) |

## Abuse in Malware

### OTP Interception

The primary abuse case. Banks and online services send authentication codes via SMS. Malware reads these to complete unauthorized transactions or account takeovers.

Two approaches:

1. **Retroactive**: `READ_SMS` to query the SMS database after the OTP arrives
2. **Real-time**: `RECEIVE_SMS` with a `BroadcastReceiver` to intercept messages as they arrive and optionally suppress the notification

### SMS Forwarding

Malware reads all incoming SMS and forwards them to C2. This captures not just OTPs but personal messages, bank transaction alerts, and any SMS-based verification.

### Contact Harvesting via SMS

Read SMS to extract phone numbers and names from message history, building a contact graph even without `READ_CONTACTS`.

### Notable Families

| Family | SMS Usage |
|--------|----------|
| FluBot | SMS interception + spreading via SMS phishing |
| Cerberus | OTP theft via SMS reading and notification listener |
| Joker | Read SMS to confirm premium service subscriptions |
| TrickMo (TrickBot mobile) | Real-time SMS forwarding to bypass 2FA |
| BRATA | SMS interception for banking fraud |

## Android Version Changes

**Android 4.4 (API 19)**: only the default SMS app can write to the SMS provider. Other apps can still read.

**Android 6.0 (API 23)**: runtime permission required. Granting `READ_SMS` also grants `RECEIVE_SMS`, `RECEIVE_MMS`, and `RECEIVE_WAP_PUSH` (same permission group). This changed in later versions.

**Android 8.0 (API 26)**: Google Play policy restricts SMS permissions to apps that need them for core functionality. Apps must be declared as default SMS handler or have an approved use case.

**Android 10 (API 29)**: `READ_SMS` no longer grants automatic access to call log or phone number. Permission groups were split to be more granular.

**Android 13 (API 33)**: runtime permission model unchanged, but Play Store review is stricter about justifying SMS access.

## Alternatives Used by Malware

When `READ_SMS` is difficult to obtain:

| Alternative | How It Works |
|-------------|-------------|
| Notification listener | Read OTPs from notification text without SMS permission |
| Accessibility service | Read SMS notification content from the screen |
| Google Authenticator overlay | Phish TOTP codes using overlay on authenticator apps |

The shift to notification-based OTP interception has reduced reliance on `READ_SMS` in newer malware families, since `BIND_NOTIFICATION_LISTENER_SERVICE` is easier to justify and harder for Google Play to flag.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_SMS" />
```

Combined with `RECEIVE_SMS`, `INTERNET`, and `RECEIVE_BOOT_COMPLETED`, this is a strong indicator of SMS-stealing malware. The presence of a `BroadcastReceiver` for `SMS_RECEIVED` with high priority confirms real-time interception intent.
