# WRITE_EXTERNAL_STORAGE

Grants write access to shared/external storage (`/sdcard/`). Enables creating, modifying, and deleting files on the device's shared storage. Used by malware for payload dropping, file replacement attacks, and staging exfiltration data. Functionally deprecated in Android 11 with scoped storage enforcement.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.WRITE_EXTERNAL_STORAGE` |
| Protection Level | `dangerous` |
| Permission Group | `STORAGE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 4 |
| Deprecated | API 29 (Android 10) |
| Max Target SDK Effect | API 29 (no effect for apps targeting API 30+) |

## What It Enables

On Android 9 and below, full write access to the entire `/sdcard/` directory tree. The app can create, modify, and delete any file on shared storage.

On Android 10 (API 29) targeting API 29, the permission still works if the app sets `requestLegacyExternalStorage="true"`. Without this flag, the app is limited to its own scoped directory.

On Android 11+ (API 30+), `WRITE_EXTERNAL_STORAGE` has no effect regardless of target SDK. Apps can only write to:

- Their own app-specific external directory (`Android/data/<package>/`)
- `MediaStore` entries they created
- Locations granted via SAF (Storage Access Framework)

Historically, granting `WRITE_EXTERNAL_STORAGE` implicitly granted `READ_EXTERNAL_STORAGE` as well, since they were in the same permission group.

## Abuse in Malware

### Payload Dropping

Write malicious files to predictable locations for later use:

| Payload Type | Technique |
|-------------|-----------|
| APK files | Drop to `Download/` and prompt user to install via `REQUEST_INSTALL_PACKAGES` or social engineering |
| DEX files | Write to shared storage, load dynamically via `DexClassLoader` |
| Native libraries (.so) | Drop and load via `System.load()` with absolute path |
| Scripts | Stage shell scripts for execution via other exploit chains |

### Media File Jacking

Demonstrated by Symantec in 2019 against WhatsApp and Telegram. The attack works by monitoring shared storage with a `FileObserver` and replacing media files between the time they are written and when the receiving app displays them. For example:

1. WhatsApp saves an incoming image to `/sdcard/WhatsApp/Media/`
2. Malware detects the new file via `FileObserver`
3. Malware replaces the image with a modified version (altered bank account numbers in a payment screenshot, for instance)
4. User sees the manipulated image in the WhatsApp chat

This attack was viable on Android 9 and below. Scoped storage mitigated it by preventing cross-app file access.

### File Replacement

Beyond media jacking, write access enables replacing any file on shared storage:

- Swap legitimate APKs in the Downloads folder with trojanized versions
- Modify downloaded configuration files
- Alter documents before the user opens them
- Overwrite OTA update files if stored on external storage

### Staging for Exfiltration

Some malware writes collected data (screenshots, keylog output, recorded audio) to shared storage as a staging area before exfiltration. This avoids filling app-private storage and can survive app uninstall.

## Android Version Changes

**Android 4.4 (API 19)**: apps can write to their own app-specific directory on external storage (`Android/data/<package>/`) without `WRITE_EXTERNAL_STORAGE`. The permission is only needed for writing outside this directory.

**Android 6.0 (API 23)**: runtime permission required. Granting write implicitly granted read (same permission group).

**Android 10 (API 29)**: scoped storage introduced. `WRITE_EXTERNAL_STORAGE` deprecated. Apps targeting API 29 can opt out with `requestLegacyExternalStorage="true"`.

**Android 11 (API 30)**: scoped storage enforced. `WRITE_EXTERNAL_STORAGE` grants no additional access for apps targeting API 30+. The permission exists in the manifest but is ignored by the system. Apps needing broad write access must use `MANAGE_EXTERNAL_STORAGE`.

**Android 13 (API 33)**: the permission remains in the framework for backward compatibility but is effectively dead for modern apps.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

Key indicators:

- Combined with `REQUEST_INSTALL_PACKAGES`: payload drop and sideload pipeline
- `FileObserver` usage on shared storage directories: potential media file jacking
- Writing to paths outside the app's own `Android/data/` directory
- `requestLegacyExternalStorage="true"` in the application tag for apps targeting API 29
- Apps targeting API 28 or lower to retain full write access on modern devices
- `DexClassLoader` or `System.load()` with paths pointing to shared storage: dynamic payload loading from dropped files
