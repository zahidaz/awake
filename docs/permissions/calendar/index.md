# Calendar Permissions

Access to calendar events, attendees, and reminders. Lower priority for most malware compared to SMS or contacts, but useful for targeted espionage: reading meeting details, attendee lists, and locations reveals a target's schedule and professional contacts.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [READ_CALENDAR](read-calendar.md) | Exfiltrate meeting details, schedules, attendee contact info |
| [WRITE_CALENDAR](write-calendar.md) | Inject fake events for social engineering, modify existing events |

## Spyware Families

Calendar exfiltration is a staple of targeted espionage toolkits:

| Family | Calendar Usage |
|--------|---------------|
| **Pegasus** (NSO Group) | Exfiltrates full calendar database including attendees, locations, and notes |
| **FinSpy** (Gamma Group) | Reads calendar entries as part of broad PIM (Personal Information Manager) harvesting |
| **Hermit** (RCS Lab) | Collects calendar data alongside contacts and messages for target profiling |
| **AridSpy** | Exfiltrates calendar events from compromised devices in targeted Middle Eastern operations |

## Attack Scenarios

**Meeting reconnaissance** -- Calendar entries reveal where a target will be, when, and with whom. For a high-value target, this enables physical surveillance planning, room bugging, or interception at known future locations.

**Executive surveillance** -- Corporate espionage operators harvest calendar data to map organizational structure. Recurring meetings with specific attendees reveal reporting lines, project teams, and decision-making circles that are not visible from an org chart alone.

**Social engineering with event details** -- Stolen calendar data fuels highly convincing pretexting. An attacker who knows the target has a "Q3 Budget Review with Sarah Chen at 2pm" can craft a phishing email referencing that exact meeting, dramatically increasing the success rate.

## WRITE_CALENDAR Abuse

`WRITE_CALENDAR` enables a subtle but effective attack vector: injecting phishing events directly into a target's calendar. The injected event includes a title like "Action Required: Verify Account" and a description containing a malicious URL. When the calendar fires a notification reminder, the target sees what appears to be a legitimate calendar event and clicks through.

This technique bypasses email-based phishing defenses entirely. The malicious link never passes through an email gateway, spam filter, or URL scanner. It surfaces through a trusted channel -- the user's own calendar notifications -- and inherits the implicit trust that users place in their personal schedule.
