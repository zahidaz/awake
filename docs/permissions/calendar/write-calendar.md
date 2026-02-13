# WRITE_CALENDAR

Allows creating, modifying, and deleting calendar events. Can be used for social engineering by injecting fake events with malicious links or phishing content into the victim's calendar.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.WRITE_CALENDAR` |
| Protection Level | `dangerous` |
| Permission Group | `CALENDAR` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Create, update, and delete events via `CalendarContract`:

```java
ContentValues values = new ContentValues();
values.put(CalendarContract.Events.TITLE, "Security Alert: Verify Your Account");
values.put(CalendarContract.Events.DESCRIPTION, "Click here: https://evil.com/phishing");
values.put(CalendarContract.Events.DTSTART, System.currentTimeMillis() + 3600000);
values.put(CalendarContract.Events.DTEND, System.currentTimeMillis() + 7200000);
values.put(CalendarContract.Events.CALENDAR_ID, 1);
values.put(CalendarContract.Events.EVENT_TIMEZONE, TimeZone.getDefault().getID());
getContentResolver().insert(CalendarContract.Events.CONTENT_URI, values);
```

## Abuse in Malware

### Calendar Spam / Phishing

Inject events containing phishing links into the victim's calendar. When the calendar notification fires, the user sees what appears to be a legitimate reminder with a malicious URL. This technique has been used in iOS calendar spam campaigns and applies equally to Android.

Malware can inject events with reminders set minutes in the future, creating urgency:

```java
ContentValues values = new ContentValues();
values.put(CalendarContract.Events.TITLE, "Account Locked - Verify Now");
values.put(CalendarContract.Events.DESCRIPTION, "https://attacker-domain.com/verify");
values.put(CalendarContract.Events.DTSTART, System.currentTimeMillis() + 60000);
values.put(CalendarContract.Events.DTEND, System.currentTimeMillis() + 120000);
values.put(CalendarContract.Events.CALENDAR_ID, 1);
values.put(CalendarContract.Events.EVENT_TIMEZONE, TimeZone.getDefault().getID());
values.put(CalendarContract.Events.HAS_ALARM, 1);
Uri eventUri = getContentResolver().insert(CalendarContract.Events.CONTENT_URI, values);

long eventId = Long.parseLong(eventUri.getLastPathSegment());
ContentValues reminder = new ContentValues();
reminder.put(CalendarContract.Reminders.EVENT_ID, eventId);
reminder.put(CalendarContract.Reminders.MINUTES, 0);
reminder.put(CalendarContract.Reminders.METHOD, CalendarContract.Reminders.METHOD_ALERT);
getContentResolver().insert(CalendarContract.Reminders.CONTENT_URI, reminder);
```

### Event Manipulation

Modify or delete existing events to disrupt a target's schedule (targeted harassment or sabotage).

### Calendar Data as Reconnaissance

Commercial spyware platforms that request both `READ_CALENDAR` and `WRITE_CALENDAR` use calendar access primarily for intelligence collection rather than injection. [Pegasus](../../malware/families/pegasus.md) exfiltrates calendar events and meeting details as part of its comprehensive data collection. [Hermit](../../malware/families/hermit.md) includes a dedicated calendar exfiltration module. [FinSpy](../../malware/families/finspy.md) performs full calendar exfiltration alongside contacts. While these families focus on reading, `WRITE_CALENDAR` is often requested alongside `READ_CALENDAR` because they belong to the same permission group.

### Notable Families

| Family | Calendar Usage |
|--------|---------------|
| [Pegasus](../../malware/families/pegasus.md) | Calendar event exfiltration for intelligence gathering |
| [Hermit](../../malware/families/hermit.md) | Modular calendar exfiltration via dedicated C2 module |
| [FinSpy](../../malware/families/finspy.md) | Full contacts and calendar exfiltration |

No major Android malware families are known to use calendar injection as a primary attack vector. The technique is more common in iOS calendar spam campaigns and adware than in banking trojans or spyware.

## Android Version Changes

**Android 4.0 (API 14)**: `CalendarContract` API introduced, replacing the older undocumented calendar URIs. This standardized how apps interact with calendar data.

**Android 6.0 (API 23)**: `WRITE_CALENDAR` became a runtime permission. Granting it also grants `READ_CALENDAR` since both belong to the `CALENDAR` permission group.

**Android 10 (API 29)**: permission group auto-granting was tightened. The system may still grant both calendar permissions together, but apps cannot silently escalate from read to write.

**Android 14 (API 34)**: apps targeting API 34+ that access calendar data must declare the precise data types accessed in the privacy manifest.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_CALENDAR" />
```

Less commonly requested than `READ_CALENDAR`. Any app requesting write access without clear calendar management functionality is suspicious.

### Static Analysis Indicators

Look for references to `CalendarContract.Events.CONTENT_URI` with `insert()` or `update()` operations. Calendar injection malware typically constructs `ContentValues` with hardcoded or C2-provided event titles containing URLs.

### Dynamic Analysis Indicators

- New calendar events appearing without user action
- Events with titles containing URLs or urgent language ("verify", "locked", "security alert")
- Reminders set with zero-minute delays to trigger immediate notifications
- Bulk event insertion in short time periods

### Permission Combination Red Flags

`WRITE_CALENDAR` combined with `INTERNET` and `RECEIVE_BOOT_COMPLETED` suggests an app that persists across reboots and injects calendar events with content fetched from a remote server.
