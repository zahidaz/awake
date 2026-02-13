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

### Notable Families

| Family | Usage |
|--------|-------|
| [Fakecalls](../../malware/families/fakecalls.md) | Manipulates call logs as part of its vishing operation -- after intercepting calls to Korean banks and playing fake IVR audio, evidence of the intercepted calls must be cleaned |
| [GriftHorse](../../malware/families/grifthorse.md) | Premium SMS/call fraud family where call log cleanup hides evidence of premium-rate call charges |

Fakecalls is the most relevant family for `WRITE_CALL_LOG` abuse. Its call interception mechanism involves answering and redirecting calls to Korean bank numbers, and cleaning the call log is essential to preventing the victim from noticing that their outbound call to the bank was never actually connected. GriftHorse enrolled victims in premium services and cleaning call evidence reduced discovery speed.

Most banking trojans that interact with calls (via `CALL_PHONE` or `ANSWER_PHONE_CALLS`) do not explicitly request `WRITE_CALL_LOG` because the call log evidence is secondary to the fraud itself. The permission is most critical for premium-rate call fraud where the victim would notice unexpected outbound calls on their bill.

### Evidence Cleanup Pattern

The most common abuse of `WRITE_CALL_LOG` is removing traces of malicious call activity. After making premium-rate calls, C2 voice calls, or vishing calls, malware deletes the corresponding call log entries so the victim does not notice the unauthorized activity. This is especially important for malware that makes calls to premium numbers for revenue generation -- the call log entry would otherwise alert the victim and lead to faster detection.

### Abuse Code Example

```java
public class CallLogCleaner {

    private final ContentResolver resolver;

    public CallLogCleaner(ContentResolver resolver) {
        this.resolver = resolver;
    }

    public int deleteCallsByNumber(String number) {
        return resolver.delete(
            CallLog.Calls.CONTENT_URI,
            CallLog.Calls.NUMBER + " = ?",
            new String[]{number}
        );
    }

    public int deleteRecentOutgoing(int minutesAgo) {
        long cutoff = System.currentTimeMillis() - (minutesAgo * 60 * 1000L);
        return resolver.delete(
            CallLog.Calls.CONTENT_URI,
            CallLog.Calls.TYPE + " = ? AND " + CallLog.Calls.DATE + " > ?",
            new String[]{
                String.valueOf(CallLog.Calls.OUTGOING_TYPE),
                String.valueOf(cutoff)
            }
        );
    }

    public void injectFakeEntry(String number, String name, long timestamp, int duration) {
        ContentValues values = new ContentValues();
        values.put(CallLog.Calls.NUMBER, number);
        values.put(CallLog.Calls.CACHED_NAME, name);
        values.put(CallLog.Calls.DATE, timestamp);
        values.put(CallLog.Calls.DURATION, duration);
        values.put(CallLog.Calls.TYPE, CallLog.Calls.INCOMING_TYPE);
        values.put(CallLog.Calls.NEW, 0);
        resolver.insert(CallLog.Calls.CONTENT_URI, values);
    }

    public void cleanupAfterPremiumCall(String premiumNumber) {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
        }
        deleteCallsByNumber(premiumNumber);
    }
}
```

The code shows three patterns: targeted deletion of specific numbers (used after C2 or premium calls), time-based deletion of recent outgoing calls (used as a broad cleanup), and fake entry injection (used to create alibis or frame targets). The `cleanupAfterPremiumCall` method includes a delay to ensure the call log entry has been written by the system before attempting deletion.

## Android Version Changes

**Android 9.0 (API 28)**: `WRITE_CALL_LOG` separated into its own `CALL_LOG` permission group, distinct from the `PHONE` permission group. Previously, granting phone permissions could implicitly grant call log access.

**January 2019**: Google Play policy restricts call log permissions to apps declared as the default dialer or phone handler. Only default dialer/phone apps can access call log without scrutiny. Sideloaded malware and apps distributed through third-party stores are not subject to this restriction.

**Android 10 (API 29)**: further restrictions on call log access. Apps must hold the specific `WRITE_CALL_LOG` permission and cannot infer it from other phone-related permissions.

**Android 11 (API 30)**: no changes to the permission itself, but call screening and spam detection APIs provide alternative ways for legitimate apps to interact with calls without needing full call log write access.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_CALL_LOG" />
```

Only expected in dialer and call management apps.

### Analysis Indicators

- `ContentResolver.delete()` calls targeting `CallLog.Calls.CONTENT_URI` after outgoing call completion indicate evidence cleanup.
- Look for time-delayed deletion patterns -- malware typically waits a few seconds after a call ends before deleting the log entry to ensure the system has written it.
- `ContentResolver.insert()` calls to `CallLog.Calls.CONTENT_URI` from non-dialer apps indicate fake call log injection.
- Combined with `CALL_PHONE` and `INTERNET`, `WRITE_CALL_LOG` suggests the app makes programmatic calls and cleans up afterward.
- Hardcoded premium-rate number prefixes (e.g., country-specific premium service codes) alongside call log deletion logic are a strong indicator of toll fraud with evidence cleanup.
- This permission is rare in malware overall. Its presence alongside `CALL_PHONE` significantly increases the likelihood of premium-rate call fraud or vishing-related cleanup activity.

## See Also

- [READ_CALL_LOG](read-call-log.md) -- read access to call history, commonly paired with `WRITE_CALL_LOG` for full call log manipulation
- [CALL_PHONE](../phone/call-phone.md) -- programmatic call initiation that creates the call log entries the malware then needs to delete
- [ANSWER_PHONE_CALLS](../phone/answer-phone-calls.md) -- call interception capability that produces evidence requiring cleanup
- [SMS Interception](../../attacks/sms-interception.md) -- parallel evidence cleanup patterns exist in SMS-based attacks where malware deletes intercepted messages
