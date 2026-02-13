# WRITE_CONTACTS

Allows creating, modifying, and deleting contacts on the device. Can be used to inject contacts for social engineering or modify existing contacts to redirect calls/messages.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.WRITE_CONTACTS` |
| Protection Level | `dangerous` |
| Permission Group | `CONTACTS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Full write access to the `ContactsContract` content provider:

- Create new contacts
- Modify existing contact details (phone numbers, emails)
- Delete contacts
- Modify contact photos

## Abuse in Malware

### Contact Poisoning

Modify a legitimate contact's phone number to redirect calls to an attacker-controlled number. When the victim calls "their bank," they reach the attacker instead.

### Social Engineering Setup

Inject a fake contact (e.g., "Bank Security" with the attacker's number) so that when the attacker calls, the victim sees a trusted name on caller ID.

### Evidence Destruction

Delete contacts to destroy evidence of communication or to disrupt the victim's phone.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_CONTACTS" />
```

Less commonly requested than `READ_CONTACTS`. Any app requesting write access without clear contact management functionality is suspicious.
