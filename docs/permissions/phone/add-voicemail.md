# ADD_VOICEMAIL

Allows adding voicemail messages to the device's voicemail content provider. Minimal security relevance.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ADD_VOICEMAIL` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 14 (Android 4.0) |

## What It Enables

Insert voicemail entries into the `VoicemailContract` content provider. Used by visual voicemail apps and carrier voicemail services.

```java
ContentValues values = new ContentValues();
values.put(VoicemailContract.Voicemails.NUMBER, "+1555012345");
values.put(VoicemailContract.Voicemails.DATE, System.currentTimeMillis());
values.put(VoicemailContract.Voicemails.DURATION, 30);
values.put(VoicemailContract.Voicemails.SOURCE_PACKAGE, getPackageName());
values.put(VoicemailContract.Voicemails.IS_READ, 0);
values.put(VoicemailContract.Voicemails.TRANSCRIPTION, "Call back urgently: 1-800-SCAM");
Uri voicemailUri = getContentResolver().insert(
    VoicemailContract.Voicemails.buildSourceUri(getPackageName()), values
);

OutputStream os = getContentResolver().openOutputStream(voicemailUri);
os.write(audioBytes);
os.close();
```

The API allows inserting both metadata (caller number, duration, transcription text) and the actual audio content as a binary stream attached to the voicemail URI.

## Abuse in Malware

No known malware families actively abuse `ADD_VOICEMAIL`. The permission has minimal real-world abuse for several reasons:

- The voicemail content provider is scoped -- apps can only insert voicemails under their own `SOURCE_PACKAGE`, limiting impersonation
- Visual voicemail UIs are not universally present on Android devices
- Social engineering via voicemail injection is less effective than SMS or notification-based approaches

### Theoretical Abuse Scenarios

**Fake Voicemail Injection**: An app could insert voicemail entries with spoofed caller numbers and pre-recorded audio designed to trick the user into calling a premium-rate number or revealing information. The transcription field is particularly useful for social engineering since many visual voicemail apps display the transcription text in notifications without requiring the user to listen to the audio.

**Vishing Amplification**: Combined with call interception capabilities like those in [Fakecalls](../../malware/families/fakecalls.md), injected voicemails could reinforce a voice phishing campaign by leaving fake "missed call" evidence from what appears to be a legitimate bank number.

## Android Version Changes

**Android 4.0 (API 14)**: `ADD_VOICEMAIL` and `VoicemailContract` introduced to support visual voicemail.

**Android 6.0 (API 23)**: became a runtime permission as part of the `PHONE` group. Granting any phone permission could grant `ADD_VOICEMAIL` depending on the system implementation.

**Android 8.0 (API 26)**: visual voicemail support expanded with `VoicemailContract.Status` for carrier integration. The permission remained relevant but only within the carrier voicemail ecosystem.

**Android 10 (API 29)**: phone permission group was split more granularly, but `ADD_VOICEMAIL` remains grouped with other phone permissions.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ADD_VOICEMAIL" />
```

Only expected in dialer and carrier voicemail apps.

### Static Analysis Indicators

- References to `VoicemailContract.Voicemails.CONTENT_URI` or `buildSourceUri()`
- `ContentValues` construction with voicemail-specific fields (`TRANSCRIPTION`, `DURATION`, `NUMBER`)
- Binary audio data written to a voicemail content URI

### Permission Combination Red Flags

`ADD_VOICEMAIL` alone is low risk. When combined with [CALL_PHONE](call-phone.md), [READ_PHONE_STATE](read-phone-state.md), and `INTERNET`, it could indicate an app attempting to build a comprehensive phone manipulation toolkit. In practice, this combination is more likely a legitimate dialer app than malware.
