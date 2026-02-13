# READ_CALENDAR

Allows reading all calendar events, attendees, and reminders from the device's calendar provider. Primarily relevant to targeted spyware and stalkerware rather than commodity malware.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_CALENDAR` |
| Protection Level | `dangerous` |
| Permission Group | `CALENDAR` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Access to the `CalendarContract` content provider:

```java
Cursor cursor = getContentResolver().query(
    CalendarContract.Events.CONTENT_URI,
    new String[]{
        CalendarContract.Events.TITLE,
        CalendarContract.Events.DTSTART,
        CalendarContract.Events.EVENT_LOCATION,
        CalendarContract.Events.DESCRIPTION
    },
    null, null, null
);
```

Available data:

| Data | Field |
|------|-------|
| Event title | `Events.TITLE` |
| Start/end time | `Events.DTSTART`, `Events.DTEND` |
| Location | `Events.EVENT_LOCATION` |
| Description | `Events.DESCRIPTION` |
| Attendees | `Attendees.ATTENDEE_EMAIL`, `ATTENDEE_NAME` |
| Reminders | `Reminders.MINUTES`, `METHOD` |
| Calendar account | `Calendars.ACCOUNT_NAME` |

## Abuse in Malware

### Targeted Espionage

Spyware targeting specific individuals extracts calendar data to map:

- Daily schedule and routines
- Meeting locations (physical surveillance planning)
- Professional contacts via attendee lists
- Business travel patterns
- Conference call details and dial-in numbers

### Commercial Spyware

Nation-state spyware (Pegasus, Predator) and commercial stalkerware apps routinely exfiltrate calendar data as part of full device surveillance.

### Low Priority for Banking Trojans

Most banking malware does not request calendar permissions. The data has no direct value for financial fraud.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_CALENDAR" />
```

Calendar access combined with other surveillance permissions (location, microphone, camera, contacts) suggests spyware. Calendar access alone is common in legitimate productivity apps.
