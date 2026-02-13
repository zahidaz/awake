# WRITE_CALL_LOG

Allows inserting, modifying, and deleting call log entries. Can be used to hide evidence of calls made by malware (e.g., premium number calls, C2 voice calls) or to inject fake call records.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.WRITE_CALL_LOG` |
| Protection Level | `dangerous` |
| Permission Group | `CALL_LOG` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Write access to the `CallLog` content provider:

```java
getContentResolver().delete(
    CallLog.Calls.CONTENT_URI,
    CallLog.Calls.NUMBER + " = ?",
    new String[]{"+1234567890"}
);
```

## Abuse in Malware

### Evidence Removal

After making premium-rate calls or C2 voice calls, malware deletes the call log entries to hide activity from the user.

### Call Log Manipulation

Inject fake call records or modify timestamps to create alibis or frame targets.

## Android Version Changes

Subject to the same Google Play policy restrictions as SMS permissions since January 2019. Only default dialer/phone apps can access call log without scrutiny.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_CALL_LOG" />
```

Only expected in dialer and call management apps.
