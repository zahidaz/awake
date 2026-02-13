# ANSWER_PHONE_CALLS

Allows programmatically answering incoming phone calls. Can be used to silently answer calls from specific numbers (e.g., from a C2 operator) or to intercept calls.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ANSWER_PHONE_CALLS` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 26 (Android 8.0) |

## What It Enables

```java
TelecomManager tm = (TelecomManager) getSystemService(TELECOM_SERVICE);
tm.acceptRingingCall();
```

Auto-answers the currently ringing call. Combined with audio recording, enables call wiretapping.

## Abuse in Malware

### Call Wiretapping

Auto-answer incoming calls from the attacker's number, activate speakerphone, and record the ambient audio. The device becomes a remote listening device activated by calling it.

### Call Interception

Answer calls before the user can, potentially to intercept voice-based verification calls from banks.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ANSWER_PHONE_CALLS" />
```

Expected in dialer and call management apps only. Suspicious in any other context.
