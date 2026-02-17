# READ_EXTERNAL_STORAGE

Grants read access to files on shared/external storage (`/sdcard/`). Before scoped storage, this was a skeleton key to every file on the device's shared storage: photos, documents, downloads, WhatsApp databases, and any other app data stored externally. Deprecated in Android 13 in favor of granular media permissions (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`).

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_EXTERNAL_STORAGE` |
| Protection Level | `dangerous` |
| Permission Group | `STORAGE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 16 |
| Deprecated | API 33 (Android 13) |
| Max Target SDK Effect | API 32 (ignored if targeting API 33+) |

## What It Enables

On devices running Android 9 and below (or apps targeting API 28 and below), this permission grants read access to the entire `/sdcard/` directory tree:

```
/sdcard/
├── DCIM/           # Photos and camera output
├── Download/       # Browser and app downloads
├── Documents/      # User documents
├── Pictures/       # Screenshots, saved images
├── WhatsApp/       # WhatsApp media and databases
│   ├── Databases/  # Encrypted chat backups
│   └── Media/      # Shared photos, videos, voice notes
├── Telegram/       # Telegram downloads
├── Android/data/   # Other apps' external files (pre-API 30)
└── ...
```

On Android 10-12 with scoped storage active, the permission is limited to media files accessible through `MediaStore`. On Android 13+, it has no effect for apps targeting API 33.

## Abuse in Malware

### Photo and Document Theft

The most straightforward abuse. Malware recursively enumerates shared storage and exfiltrates files matching target extensions:

| Target | Path / Extension |
|--------|-----------------|
| Photos | `DCIM/`, `Pictures/`, `.jpg`, `.png` |
| Documents | `Documents/`, `Download/`, `.pdf`, `.docx`, `.xlsx` |
| Screenshots | `Pictures/Screenshots/` |
| Recordings | `Recordings/`, `.m4a`, `.3gp` |

Screenshots are particularly valuable because they may contain sensitive information: banking screens, authentication codes, private messages.

### Notable Families

| Family | Storage Abuse |
|--------|--------------|
| [Rafel RAT](../../malware/families/rafelrat.md) | SD card wipe capability, external storage enumeration and file exfiltration |
| [LightSpy](../../malware/families/lightspy.md) | Dedicated file manager plugin for browsing and exfiltrating external storage |
| [GuardZoo](../../malware/families/guardzoo.md) | Targets military mapping files (KMZ, WPT, KML) from armed forces personnel |
| [AridSpy](../../malware/families/aridspy.md) | Document theft from external storage in targeted espionage campaigns |

### WhatsApp Database Extraction

WhatsApp stores encrypted chat database backups at `/sdcard/WhatsApp/Databases/msgstore.db.crypt14`. With `READ_EXTERNAL_STORAGE`, malware can copy this file. While the database is encrypted, the key can be extracted from the app's private storage with root access, or the backup can be decrypted using the user's Google account backup key.

Families known to target WhatsApp data:

| Family | WhatsApp Targeting |
|--------|-------------------|
| GravityRAT | Exfiltrates WhatsApp backup databases |
| Dracarys | Steals WhatsApp media and documents |
| RatMilad | Targets WhatsApp and Telegram data directories |
| [PhoneSpy](../../malware/families/phonespy.md) | Harvests all media including WhatsApp images |

### Credential File Harvesting

Some apps store credentials, tokens, or configuration files on external storage (a developer mistake, but common). Malware scans for:

- `.json` files containing API keys or tokens
- `.pem` / `.key` files (certificates and private keys)
- Browser download folders for saved credential exports
- Password manager exports (CSV/JSON)

### Reconnaissance

Enumerating the file system reveals installed apps (by checking `Android/data/` subdirectories), user habits (photo metadata with GPS coordinates), and organizational context (document filenames and contents).

## Android Version Changes

**Android 4.4 (API 19)**: prior to this, `READ_EXTERNAL_STORAGE` was not enforced. Any app could read external storage without declaring the permission.

**Android 6.0 (API 23)**: became a runtime permission. Granting `READ_EXTERNAL_STORAGE` also granted `WRITE_EXTERNAL_STORAGE` (same permission group). This was tightened in later versions.

**Android 10 (API 29)**: scoped storage introduced. Apps targeting API 29 are restricted to their own external directory and `MediaStore`-accessible media. The `requestLegacyExternalStorage="true"` manifest flag opts out.

**Android 11 (API 30)**: scoped storage enforced. The legacy opt-out flag is ignored for apps targeting API 30+. `READ_EXTERNAL_STORAGE` only grants `MediaStore` access to media files (images, video, audio), not arbitrary files.

**Android 13 (API 33)**: `READ_EXTERNAL_STORAGE` deprecated. Apps targeting API 33+ must use `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, or `READ_MEDIA_AUDIO` instead. The old permission is silently ignored.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
```

Red flags:

- Combined with `INTERNET` and no clear media-display UI: likely exfiltration
- Recursive file enumeration in decompiled code (`File.listFiles()`, `File.walk()`)
- Hardcoded paths to WhatsApp, Telegram, or other app directories
- File extension filtering targeting documents and databases
- Apps targeting API 28 or lower on devices running Android 10+ (intentionally avoiding scoped storage)
- `requestLegacyExternalStorage="true"` in the application tag (opting out of scoped storage on API 29)
