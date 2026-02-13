# PROCESS_OUTGOING_CALLS

Allows monitoring and redirecting outgoing phone calls. The app can see the number being dialed and optionally modify or cancel the call. Deprecated in Android 10.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.PROCESS_OUTGOING_CALLS` |
| Protection Level | `dangerous` |
| Permission Group | `CALL_LOG` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |
| Deprecated | API 29 (Android 10) |

## What It Enables

Receive `NEW_OUTGOING_CALL` broadcast before a call is placed:

```java
public class OutgoingCallReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String number = intent.getStringExtra(Intent.EXTRA_PHONE_NUMBER);
        // Can modify: setResultData(newNumber)
        // Can cancel: setResultData(null)
    }
}
```

## Abuse in Malware

### Call Redirection

Redirect calls to the bank's customer service number to an attacker-controlled number. The victim dials their bank, but the call goes to the attacker's call center.

### Call Monitoring

Log all outgoing calls (number, time) for surveillance.

### Premium Number Substitution

Replace outgoing call numbers with premium-rate numbers.

## Android Version Changes

**Android 10 (API 29)**: deprecated. Replaced by `CallRedirectionService` role, which requires the user to explicitly set the app as the call redirection handler. Existing apps targeting older APIs still receive the broadcast.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.PROCESS_OUTGOING_CALLS" />
```

Deprecated. Presence in modern apps targeting API 29+ is suspicious.
