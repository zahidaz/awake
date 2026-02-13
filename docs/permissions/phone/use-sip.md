# USE_SIP

Allows using the SIP (Session Initiation Protocol) service for VoIP calls. Minimal security relevance in modern Android.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.USE_SIP` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 9 (Android 2.3) |

## What It Enables

Access to Android's built-in SIP stack for making and receiving VoIP calls through the `SipManager` API:

```java
SipManager sipManager = SipManager.newInstance(context);
SipProfile.Builder builder = new SipProfile.Builder("username", "sip.example.com");
builder.setPassword("password");
builder.setPort(5060);
SipProfile profile = builder.build();

Intent intent = new Intent();
intent.setAction("android.SipDemo.INCOMING_CALL");
PendingIntent pendingIntent = PendingIntent.getBroadcast(
    context, 0, intent, PendingIntent.FLAG_IMMUTABLE
);
sipManager.open(profile, pendingIntent, null);
sipManager.makeAudioCall(
    profile.getUriString(), "sip:target@sip.example.com", null, 30
);
```

Note: Android's native SIP support has been deprecated since Android 12 (API 31). Most VoIP apps use their own SIP or WebRTC stacks instead.

## Abuse in Malware

No known malware families abuse `USE_SIP` directly. The native SIP stack is rarely used by legitimate apps, let alone by malware. VoIP-based attacks use custom networking code or third-party SIP libraries rather than the Android-provided `SipManager`.

### Theoretical Abuse Scenarios

**Unauthorized VoIP Calls**: An app with `USE_SIP` could silently register a SIP account and place VoIP calls to premium-rate SIP URIs, generating charges on the attacker's SIP provider revenue share.

**Call Eavesdropping**: If the device is already registered with a SIP account, malware could listen for incoming SIP calls and record them. However, spyware families like [Hermit](../../malware/families/hermit.md), [Pegasus](../../malware/families/pegasus.md), and [FinSpy](../../malware/families/finspy.md) that record VoIP conversations do so by hooking into the audio subsystem or using accessibility services rather than the SIP API. These families intercept VoIP audio from apps like WhatsApp, Skype, and Viber at the audio mixer level, making `USE_SIP` irrelevant to their approach.

**Covert Communication Channel**: A malware C2 channel over SIP would blend with legitimate VoIP traffic, but in practice no families use this technique because HTTP/HTTPS and WebSocket provide more reliable and flexible C2 communication.

## Android Version Changes

**Android 2.3 (API 9)**: `USE_SIP` and the `SipManager` API introduced, providing native SIP calling without third-party libraries.

**Android 6.0 (API 23)**: became a runtime permission within the `PHONE` group.

**Android 12 (API 31)**: the native `SipManager` API was deprecated. Google recommended migrating to third-party SIP libraries or the `Otp` and `ConnectionService` APIs. Apps targeting API 31+ that still reference `SipManager` receive deprecation warnings.

**Android 14 (API 34)**: the deprecated SIP API remains functional but receives no updates or bug fixes. The API may be removed entirely in a future Android version.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.USE_SIP" />
```

Largely obsolete. Presence in modern apps (targeting API 31+) is unusual and warrants investigation, since the underlying API is deprecated.

### Static Analysis Indicators

- References to `android.net.sip.SipManager` or `android.net.sip.SipProfile`
- SIP URI strings in the format `sip:user@domain`
- `SipAudioCall` usage indicating active VoIP call handling

### Permission Combination Red Flags

`USE_SIP` combined with [RECORD_AUDIO](../microphone/record-audio.md) and `INTERNET` in a non-VoIP app is suspicious. However, this combination is more likely an indicator of an outdated app that has not updated its permission declarations than active malware.
