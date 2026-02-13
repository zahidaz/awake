# SEND_SMS

Allows sending SMS messages programmatically without user interaction. Used for premium SMS fraud (sending messages to premium-rate numbers), phishing distribution (sending malicious links to victim's contacts), and covert C2 communication.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.SEND_SMS` |
| Protection Level | `dangerous` |
| Permission Group | `SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

```java
SmsManager smsManager = SmsManager.getDefault();
smsManager.sendTextMessage("+1234567890", null, "message body", null, null);
```

The message is sent without any UI or confirmation dialog. The user may see it appear in their sent messages (depending on Android version and default SMS app behavior).

For long messages:

```java
ArrayList<String> parts = smsManager.divideMessage(longText);
smsManager.sendMultipartTextMessage(number, null, parts, null, null);
```

## Abuse in Malware

### Premium SMS Fraud

Sending messages to premium-rate short codes that charge the victim's phone bill. Each message costs $1-10. Malware sends messages in the background and may delete sent message records to cover tracks.

This was the dominant Android malware monetization method from 2010-2014 before banking trojans became more profitable.

### Smishing (SMS Phishing)

Sending phishing messages from the victim's phone to their contacts:

1. Malware reads contact list (via `READ_CONTACTS`)
2. Sends SMS to each contact with a malicious link
3. Recipients trust the message because it comes from a known number
4. Recipients click the link and install the malware

FluBot spread across Europe using this exact method, reaching millions of devices.

### C2 Channel

SMS as a backup command-and-control channel:

- Works without internet
- Not visible to network monitoring tools
- Messages can be deleted from the sent folder to hide evidence
- C2 server sends commands via SMS to victim's number

### Notable Families

| Family | SMS Usage |
|--------|----------|
| FakePlayer | First Android malware (2010). Premium SMS only. |
| [FluBot](../../malware/families/flubot.md) | SMS worm. Sent phishing to all contacts. Dismantled by Europol 2022. |
| [Joker](../../malware/families/joker.md) | Premium subscription via SMS and WAP billing. Thousands of Play Store variants. |
| [Harly](../../malware/families/harly.md) | Invisible subscription fraud via hidden WebView and SMS confirmation. |
| [GriftHorse](../../malware/families/grifthorse.md) | Premium SMS at scale. 10M+ victims. |
| [TrickMo](../../malware/families/trickmo.md) | SMS forwarding for 2FA bypass. |
| [MoqHao](../../malware/families/moqhao.md) | Smishing distribution to victim's contacts. Pan-Asian campaigns. |
| [Rafel RAT](../../malware/families/rafelrat.md) | SMS C2 channel as backup. Ransomware unlock via SMS. |
| [Anubis](../../malware/families/anubis.md) | SMS forwarding, premium SMS capability. |
| [SpyNote](../../malware/families/spynote.md) | Full SMS send/read/intercept. Mass deployment. |
| [Mamont](../../malware/families/mamont.md) | SMS forwarding for OTP exfiltration. |

## Android Version Changes

**Android 4.4 (API 19)**: introduced default SMS app concept. Non-default apps can still send SMS but may not be able to write to the SMS content provider.

**Android 5.1 (API 22)**: premium SMS protections. System warns user before sending to premium numbers.

**Google Play 2019**: restricted `SEND_SMS` to apps declared as default SMS handler or with approved use cases.

## Detection

`SEND_SMS` combined with `READ_CONTACTS` or `RECEIVE_SMS` suggests worm-like or phishing distribution behavior. Combined with `INTERNET`, suggests SMS data exfiltration or C2 relay.
