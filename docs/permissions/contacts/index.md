# Contacts Permissions

Access to the device contact database and associated account information. Contacts are a high-value target for malware: they provide ready-made phone number lists for SMS worm propagation, social graph data for targeted phishing, and personal details (names, emails, addresses) for identity theft and reconnaissance.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [READ_CONTACTS](read-contacts.md) | Exfiltrate full contact database, build target lists for SMS worms, map social graph |
| [WRITE_CONTACTS](write-contacts.md) | Inject fake contacts, modify existing entries for social engineering |
| [GET_ACCOUNTS](get-accounts.md) | Enumerate accounts (Google, Exchange, etc.) on the device for account takeover or fingerprinting |

## Why Contacts Matter Offensively

The contacts database is not just a phone book. It stores structured relationships, communication metadata, and often cross-linked account identifiers. A single contacts dump yields:

- Phone numbers for SMS phishing distribution (FluBot, Medusa)
- Email addresses for spear-phishing campaigns
- Organization names and job titles for targeted attacks
- Social graph edges for mapping who knows whom
- Account identifiers tied to Google, WhatsApp, Telegram, and other services

## Play Store Policy

Google Play does not restrict contacts permissions as aggressively as SMS or Call Log. Apps can still request `READ_CONTACTS` with relatively weak justification (contact sync, social features). This makes contacts one of the easier dangerous permissions to abuse from a distribution standpoint.

## Common Permission Combinations

| Combination | Purpose |
|------------|---------|
| `READ_CONTACTS` + `SEND_SMS` | SMS worm propagation to all contacts |
| `READ_CONTACTS` + `INTERNET` | Contact exfiltration to C2 |
| `READ_CONTACTS` + `READ_SMS` | Full communication graph reconstruction |
| `READ_CONTACTS` + `GET_ACCOUNTS` | Link contacts to device accounts for identity mapping |
