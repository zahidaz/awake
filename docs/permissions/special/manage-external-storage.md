# MANAGE_EXTERNAL_STORAGE

Grants full access to all files on shared storage, bypassing Android's scoped storage restrictions introduced in Android 11. With this permission, an app can read, write, and delete any file on the device's external storage (except other apps' private directories).

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.MANAGE_EXTERNAL_STORAGE` |
| Protection Level | `signature\|appop` |
| Grant Method | Settings > Apps > Special access > All files access |
| Introduced | API 30 (Android 11) |

## What It Enables

Full access to `/sdcard/` and all shared storage, including:

- Documents, downloads, media files
- Other apps' publicly visible files
- WhatsApp media and databases (backup files)
- Filesystem-level operations (create, read, write, delete, enumerate)

Without this permission, apps targeting API 30+ are limited to their own app-specific directory and media accessed through `MediaStore`.

## Abuse in Malware

### Data Exfiltration

Access to all files on the device enables:

- WhatsApp database extraction (`/sdcard/WhatsApp/Databases/msgstore.db.crypt14`)
- Document theft (PDFs, spreadsheets, photos)
- Backup file access
- Browser download folder contents

### Payload Dropping

Write malicious APKs or DEX files to shared storage for later execution or social engineering-based installation.

### File Manipulation

Replace legitimate files with modified versions (supply chain attack at the file level).

## Android Version Changes

**Android 10 (API 29)**: scoped storage introduced. Apps targeting API 29 could opt out with `requestLegacyExternalStorage="true"`.

**Android 11 (API 30)**: scoped storage enforced. `MANAGE_EXTERNAL_STORAGE` added as the escape hatch for apps that genuinely need broad file access (file managers, backup tools, antivirus).

**Android 11+**: Google Play restricts this permission to apps that justify the need. Apps without a valid use case are rejected.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```

Any app that isn't a file manager, backup tool, or antivirus requesting this is worth investigating.
