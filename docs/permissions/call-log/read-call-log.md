# READ_CALL_LOG

Grants read access to the device's call history via the CallLog content provider. Used by spyware for surveillance, social graph reconstruction, and behavioral profiling. Google Play has restricted this permission since January 2019, limiting distribution of apps that request it to those declared as the default dialer or with an approved use case.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_CALL_LOG` |
| Protection Level | `dangerous` |
| Permission Group | `CALL_LOG` |
| Grant Method | Runtime permission dialog |
| Introduced | API 16 (Android 4.1) |

## What It Enables

Access to the call log content provider at `content://call_log/calls`. The app can query the complete call history stored on the device.

```java
Cursor cursor = getContentResolver().query(
    CallLog.Calls.CONTENT_URI,
    null, null, null,
    CallLog.Calls.DATE + " DESC"
);
```

Data available per call record:

| Field | Content |
|-------|---------|
| `NUMBER` | Phone number of the other party |
| `TYPE` | Incoming (1), outgoing (2), missed (3), voicemail (4), rejected (5), blocked (6) |
| `DATE` | Timestamp of the call |
| `DURATION` | Call duration in seconds |
| `CACHED_NAME` | Contact name (if matched at call time) |
| `CACHED_NUMBER_TYPE` | Number type (mobile, home, work) |
| `GEOCODED_LOCATION` | Geographic label for the number |
| `PHONE_ACCOUNT_ID` | SIM or VoIP account used |
| `IS_READ` | Whether the missed call notification was seen |

On most devices, the call log retains the last 500-1000 entries, depending on the manufacturer. Some OEMs keep significantly more.

## Abuse in Malware

### Surveillance and Monitoring

The primary use case in commercial spyware and stalkerware. Call logs provide a timestamped record of all voice communications. Spyware exfiltrates this data periodically to a C2 server, giving operators a real-time view of the target's calling activity.

Notable families:

| Family | Call Log Usage |
|--------|--------------|
| Pegasus (NSO) | Full call log exfiltration as part of comprehensive device surveillance |
| Predator (Cytrox) | Call history collection alongside other communication data |
| Hermit (RCS Lab) | Call log theft combined with call recording |
| PhoneSpy | Periodic call log dump to C2 |
| Dracarys (Meta attribution) | Call log exfiltration with contact and SMS data |
| GravityRAT | Call log theft targeting Indian and Pakistani users |

### Social Graph Mapping

Call frequency and duration data reveals relationship strength. By analyzing call logs from a compromised device, an attacker can identify:

- The target's closest contacts (highest call frequency and duration)
- Work relationships (calls during business hours, short duration)
- Personal relationships (evening/weekend calls, longer duration)
- New or unusual contacts (recent entries not in the contacts database)

When call logs from multiple compromised devices are correlated, entire organizational or social networks can be mapped.

### Behavioral Profiling

Call timing patterns reveal daily routines:

- Sleep schedule (gap in calls)
- Work hours (consistent call patterns)
- Travel (calls to/from unusual area codes, international numbers)
- Meeting schedules (periods of no calls followed by clusters)

### Contact Discovery

Phone numbers appearing in call logs but absent from the contacts database are especially interesting. These may represent:

- Burner phones
- Contacts the target has not saved (possibly sensitive)
- Numbers the target called once (services, temporary contacts)

## Android Version Changes

**Prior to API 16**: call log access was bundled with `READ_CONTACTS`. No separate permission existed.

**Android 4.1 (API 16)**: `READ_CALL_LOG` introduced as a separate permission, decoupled from contacts.

**Android 6.0 (API 23)**: runtime permission required. `READ_CALL_LOG` was initially part of the `PHONE` permission group.

**Android 9.0 (API 28)**: `CALL_LOG` became its own permission group, separate from `PHONE`. Granting `READ_PHONE_STATE` no longer implicitly granted call log access.

**Android 10 (API 29)**: further isolation. Call log access strictly requires `READ_CALL_LOG`. No other permission grants indirect access.

**Google Play Policy (January 2019)**: only apps declared as the default dialer or with an approved exception may request `READ_CALL_LOG`. This does not affect sideloaded apps or apps distributed outside Play Store.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_CALL_LOG" />
```

High-risk indicators:

- Any app that is not a dialer, contacts manager, or call screening service requesting this permission
- Combined with `INTERNET` and `RECEIVE_BOOT_COMPLETED`: periodic exfiltration with persistence
- Combined with `READ_CONTACTS` and `READ_SMS`: comprehensive communication surveillance
- `ContentResolver.query()` calls targeting `CallLog.Calls.CONTENT_URI` in background services
- Bulk queries with no date filtering (dumping entire call history rather than recent entries)
- Call log data being serialized to JSON/protobuf and written to files or sent over network
