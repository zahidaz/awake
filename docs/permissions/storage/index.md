# Storage Permissions

Android's storage permission model has undergone more changes than any other permission group. The progression from unrestricted shared storage access to scoped storage to granular media permissions reflects repeated attempts to contain data theft and cross-app file access. Each transition introduced new restrictions and new bypass opportunities.

## Permission Evolution

| API Level | Android Version | Model |
|-----------|----------------|-------|
| 1-28 | 1.0 - 9.0 | `READ/WRITE_EXTERNAL_STORAGE` grants full `/sdcard/` access |
| 29 | 10 | Scoped storage introduced, opt-out via `requestLegacyExternalStorage` |
| 30 | 11 | Scoped storage enforced, `MANAGE_EXTERNAL_STORAGE` added as escape hatch |
| 33 | 13 | `READ_EXTERNAL_STORAGE` deprecated, replaced by granular media permissions |

## Permissions

| Permission | Status | Abuse Potential |
|-----------|--------|-----------------|
| [READ_EXTERNAL_STORAGE](read-external-storage.md) | Deprecated API 33 | Read all files on shared storage (photos, documents, app data) |
| [WRITE_EXTERNAL_STORAGE](write-external-storage.md) | Deprecated API 30 | Write files to shared storage, drop payloads, replace files |
| [READ_MEDIA_IMAGES](read-media-images.md) | API 33+ | Access photos and screenshots |
| [READ_MEDIA_VIDEO](read-media-video.md) | API 33+ | Access video files |
| [READ_MEDIA_AUDIO](read-media-audio.md) | API 33+ | Access audio files |

For unrestricted file access on Android 11+, see [MANAGE_EXTERNAL_STORAGE](../special/manage-external-storage.md).

## Offensive Relevance

Storage permissions are central to two attack patterns: **data theft** and **payload delivery**.

### Data Theft

Shared storage historically held everything users cared about: photos, downloads, documents, and critically, data from other apps that stored files externally. WhatsApp databases, Telegram media, browser downloads, and PDF documents were all accessible to any app with `READ_EXTERNAL_STORAGE`.

### Payload Dropping

Write access to shared storage enables dropping malicious APKs, DEX files, or native libraries to known paths. Combined with social engineering ("Please install this update") or `REQUEST_INSTALL_PACKAGES`, this provides a sideloading pipeline.

### Media File Jacking

Before scoped storage, a malicious app could monitor shared storage and replace files written by other apps between the time they were written and when the user opened them. This was demonstrated against WhatsApp and Telegram media files.

## Scoped Storage Bypass Techniques

Malware targeting newer Android versions uses several strategies:

| Technique | How It Works |
|-----------|-------------|
| `requestLegacyExternalStorage` | Opt out of scoped storage on API 29 (only works for apps targeting API 29) |
| `MANAGE_EXTERNAL_STORAGE` | Full file access on API 30+, requires special permission grant |
| `MediaStore` API abuse | Access media files through MediaStore without broad storage permission |
| SAF (Storage Access Framework) | Trick user into granting directory access via document picker |
| `preserveLegacyExternalStorage` | Maintain pre-existing storage access on upgrade to API 30 |
| Target API downgrade | Target API 28 or lower to avoid scoped storage entirely |
