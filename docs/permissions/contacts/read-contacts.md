# READ_CONTACTS

Grants read access to the device's contact database via the Contacts content provider. Primary use in malware: bulk exfiltration of contact data for social graph mapping, building SMS worm target lists, and harvesting personal details for identity theft. FluBot famously used this to read all contacts and send phishing SMS to every number found.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_CONTACTS` |
| Protection Level | `dangerous` |
| Permission Group | `CONTACTS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Access to the Contacts content provider at `content://com.android.contacts/`. The app can query all stored contacts and their associated data.

```java
Cursor cursor = getContentResolver().query(
    ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
    new String[]{
        ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
        ContactsContract.CommonDataKinds.Phone.NUMBER
    },
    null, null, null
);
```

Data accessible per contact:

| Field | Content |
|-------|---------|
| Display name | Full contact name |
| Phone numbers | All stored numbers (mobile, work, home) |
| Email addresses | All associated emails |
| Organization | Company name, job title |
| Postal address | Physical addresses |
| Notes | Free-text notes field |
| Photo | Contact photo URI |
| Groups | Group membership (family, coworkers) |
| Account | Which account synced this contact (Google, Exchange) |
| Last contacted | Timestamp of last communication |

The contact database is relational. A single query can join across tables to extract raw contacts, data rows, and aggregated contacts in bulk. The `ContactsContract.Data` table holds everything: phone numbers, emails, structured names, organizations, and custom MIME-typed data rows added by third-party apps.

## Abuse in Malware

### Contact Exfiltration

The most common abuse pattern. Malware dumps all contacts and sends them to C2. This provides:

- Personal details for identity theft
- Phone numbers and emails for phishing campaigns
- Organizational data for targeting corporate environments

Exfiltration typically happens silently in a background service. The entire contacts database for an average user (hundreds of entries) is small enough to transmit in a single HTTP POST.

### SMS Worm Target Lists

FluBot (2021-2022) was the most prominent example. After installation, it read all contacts and sent phishing SMS to every phone number, directing recipients to download the malware. This contact-to-SMS pipeline enabled exponential spreading across Europe and Australia.

Other families using the same approach:

| Family | Contact Abuse |
|--------|--------------|
| [FluBot](../../malware/families/flubot.md) | Read all contacts, sent phishing SMS to each number. Explosive European spread. |
| [Medusa](../../malware/families/medusa.md) | Contact harvesting for SMS-based spreading |
| [Anatsa](../../malware/families/anatsa.md) | Contact exfiltration to C2 for targeted campaigns |
| [Hydra](../../malware/families/hydra.md) | Bulk contact dump for downstream phishing |
| [Anubis](../../malware/families/anubis.md) | Contact theft combined with SMS interception |
| [Crocodilus](../../malware/families/crocodilus.md) | Contact list injection: adds fake "Bank Support" entries |
| [SpyNote](../../malware/families/spynote.md) | Full contact exfiltration as part of surveillance |
| [MoqHao](../../malware/families/moqhao.md) | Contact harvesting for smishing distribution |
| [SpyLoan](../../malware/families/spyloan.md) | Bulk contact theft, weaponized for harassment and extortion of borrowers |
| [Rafel RAT](../../malware/families/rafelrat.md) | Contact exfiltration across 120+ campaigns |

### Social Graph Mapping

Contacts reveal relationship structures. Malware or spyware operators can reconstruct who knows whom by correlating contacts across compromised devices. This is especially valuable in targeted surveillance operations where the objective is mapping an entire network, not just a single target.

### Targeted Phishing

With access to contact names, an attacker can craft SMS or email messages that appear to come from a known contact. Combining `READ_CONTACTS` with `SEND_SMS` allows sending messages that reference the target by name, dramatically increasing phishing success rates.

## Android Version Changes

**Android 6.0 (API 23)**: runtime permission required. Prior to this, contacts access was granted at install time with no user interaction.

**Android 8.0 (API 26)**: granting `READ_CONTACTS` no longer automatically grants `GET_ACCOUNTS`. These were split into separate permissions, reducing the data exposed by a single grant.

**Android 11 (API 30)**: no functional changes, but the permissions auto-reset feature can revoke `READ_CONTACTS` for unused apps, limiting long-term passive collection.

**Android 15 (API 35)**: enhanced permission rationale requirements. The runtime dialog can show app-specific justification text.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_CONTACTS" />
```

High-risk indicator when combined with:

- `SEND_SMS`: SMS worm pattern (read contacts, send phishing)
- `INTERNET` + `RECEIVE_BOOT_COMPLETED`: background exfiltration with persistence
- `READ_SMS` + `READ_CALL_LOG`: full communication surveillance

Look for `ContentResolver.query()` calls targeting `ContactsContract` URIs in decompiled code. Bulk queries with no projection filtering (selecting all columns) suggest exfiltration rather than legitimate lookup. Background services or `WorkManager` tasks querying contacts without corresponding UI activity are strong indicators.
