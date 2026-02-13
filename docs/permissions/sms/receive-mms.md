# RECEIVE_MMS

Allows receiving incoming MMS (Multimedia Messaging Service) messages. MMS carries images, audio, video, and rich text between devices.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_MMS` |
| Protection Level | `dangerous` |
| Permission Group | `SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Receive MMS messages containing multimedia content. The app can intercept and process incoming MMS before the default messaging app.

## Abuse in Malware

### Content Interception

Intercept MMS messages containing photos, videos, or documents. Relevant for surveillance and data exfiltration.

### Historical: Stagefright

The Stagefright vulnerability (CVE-2015-1538 and related) allowed remote code execution through specially crafted MP4 files delivered via MMS. The media framework processed the attached content automatically upon MMS receipt, before the user even opened the message. This was one of the most significant Android vulnerabilities discovered, affecting approximately 950 million devices.

Google's response included monthly security patches (the Android Security Bulletin program started partly because of Stagefright) and changes to disable automatic MMS media processing.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.RECEIVE_MMS" />
```

Subject to the same Google Play SMS permission restrictions. Rarely requested by modern malware outside of stalkerware.
