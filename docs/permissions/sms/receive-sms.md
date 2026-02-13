# RECEIVE_SMS

Allows receiving incoming SMS messages in real-time via a broadcast receiver. More valuable to attackers than `READ_SMS` because it captures messages the moment they arrive, enabling OTP interception before the user reads the notification.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_SMS` |
| Protection Level | `dangerous` |
| Permission Group | `SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Register a `BroadcastReceiver` for `android.provider.Telephony.SMS_RECEIVED`:

```java
public class SmsReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle bundle = intent.getExtras();
        Object[] pdus = (Object[]) bundle.get("pdus");
        for (Object pdu : pdus) {
            SmsMessage msg = SmsMessage.createFromPdu((byte[]) pdu);
            String sender = msg.getOriginatingAddress();
            String body = msg.getMessageBody();
        }
    }
}
```

Manifest registration:

```xml
<receiver android:name=".SmsReceiver" android:exported="true">
    <intent-filter android:priority="999">
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

The `android:priority="999"` ensures the malware's receiver runs before the default SMS app.

### Suppressing Messages

On Android < 4.4, any app with `RECEIVE_SMS` could call `abortBroadcast()` to prevent the SMS from reaching other receivers, including the default SMS app. The user never sees the message.

On Android 4.4+, only the default SMS app can abort. But the malware still reads the content and forwards it to C2. The user may see the message, but the OTP is already stolen.

## Abuse in Malware

### Real-Time OTP Theft

The primary use case. Malware intercepts banking OTPs within milliseconds:

1. Attacker initiates a fraudulent transaction on the victim's banking account
2. Bank sends OTP via SMS
3. Malware intercepts the SMS before the user reads it
4. Malware forwards OTP to C2
5. Attacker completes the transaction

### SMS Worm Propagation

FluBot used `RECEIVE_SMS` + `SEND_SMS` to create a self-spreading worm:

1. Receive incoming SMS
2. Extract the sender's number
3. Send a phishing SMS to that number with a malicious link
4. New victim installs the malware
5. Repeat

### C2 via SMS

Some malware uses SMS as a command-and-control channel. The C2 server sends commands via SMS, and the malware receives and executes them. This works even without internet connectivity and is harder to block with network-level security tools.

## Android Version Changes

**Android 4.4 (API 19)**: only default SMS app can abort broadcasts or write to SMS provider.

**Android 8.0 (API 26)**: implicit broadcast restrictions. `SMS_RECEIVED` is exempt and still delivered to manifest-registered receivers.

**Android 10 (API 29)**: apps must declare specific foreground service types. Background SMS interception still works via manifest-registered receivers.

### Notable Families

Nearly every banking trojan uses `RECEIVE_SMS` for OTP interception. See [Broadcast Theft](../../attacks/broadcast-theft.md) for the full family list.

| Family | SMS Interception Usage |
|--------|----------------------|
| [Cerberus](../../malware/families/cerberus.md) | 2FA OTP interception, SMS forwarding to C2 |
| [Hook](../../malware/families/hook.md) | OTP interception during ATS fraud |
| [GodFather](../../malware/families/godfather.md) | OTP theft across 400+ banking targets |
| [Anatsa](../../malware/families/anatsa.md) | OTP capture during automated transfers |
| [FluBot](../../malware/families/flubot.md) | OTP theft + SMS worm propagation (sends phishing to contacts) |
| [TrickMo](../../malware/families/trickmo.md) | Originally built as TrickBot's 2FA bypass component |
| [SpyNote](../../malware/families/spynote.md) | Full SMS surveillance (read, intercept, forward) |
| [Mamont](../../malware/families/mamont.md) | Highest-volume banker in 2024, SMS + notification interception |
| [TsarBot](../../malware/families/tsarbot.md) | OTP capture across 750+ targets |

## Detection

High-priority `SMS_RECEIVED` receiver in the manifest is the primary indicator. Combined with `INTERNET` and `SEND_SMS`, this is strong evidence of SMS-stealing or worm behavior.
