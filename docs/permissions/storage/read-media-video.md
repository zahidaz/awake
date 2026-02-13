# READ_MEDIA_VIDEO

Allows reading video files from shared storage via `MediaStore`. Granular media permission introduced in Android 13.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_MEDIA_VIDEO` |
| Protection Level | `dangerous` |
| Permission Group | `READ_MEDIA_VISUAL` (Android 14+) |
| Grant Method | Runtime permission dialog |
| Introduced | API 33 (Android 13) |

## What It Enables

Query `MediaStore.Video` for all video files on the device. Includes metadata (duration, resolution, GPS coordinates, timestamps).

## Abuse in Malware

### Video Exfiltration

Steal personal videos for blackmail. Screen recordings may contain sensitive application usage.

### Large File Exfiltration

Videos are large files. Exfiltrating them requires significant bandwidth, making this less practical for high-volume operations but valuable for targeted surveillance.

### Notable Families

| Family | Usage |
|--------|-------|
| [SpyLoan](../../malware/families/spyloan.md) | Exfiltrates personal videos for blackmail against borrowers who default on predatory loans |

SpyLoan apps request video access under the guise of "identity verification" during the loan application process. If the borrower fails to repay, operators threaten to distribute private videos to the borrower's contacts.

### READ_EXTERNAL_STORAGE vs Granular Permissions

The majority of malware families that exfiltrate video files predate Android 13 and request `READ_EXTERNAL_STORAGE` for broad file access. SpyLoan is notable for targeting API 33+ with the granular permission because its Play Store distribution requires compliance with current API level targeting requirements.

- Families like [SpyNote](../../malware/families/spynote.md), [PJobRAT](../../malware/families/pjobrat.md), and [Hermit](../../malware/families/hermit.md) use `READ_EXTERNAL_STORAGE` for general file access that includes video
- Sideloaded malware often targets older API levels to avoid granular permission requirements entirely
- Play Store-distributed malware (like SpyLoan) must target recent API levels and declare `READ_MEDIA_VIDEO` explicitly

### Stalkerware

Stalkerware families commonly request `READ_MEDIA_VIDEO` to monitor the victim's recorded content. Screen recordings are particularly valuable as they may capture banking app usage, private messages, and authentication flows.

### Abuse Code Example

```java
public class VideoExfiltrator {

    private final ContentResolver resolver;

    public VideoExfiltrator(ContentResolver resolver) {
        this.resolver = resolver;
    }

    public List<VideoMetadata> enumerateVideos() {
        List<VideoMetadata> results = new ArrayList<>();
        String[] projection = {
            MediaStore.Video.Media._ID,
            MediaStore.Video.Media.DISPLAY_NAME,
            MediaStore.Video.Media.SIZE,
            MediaStore.Video.Media.DURATION,
            MediaStore.Video.Media.DATE_ADDED
        };

        Cursor cursor = resolver.query(
            MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
            projection,
            null, null,
            MediaStore.Video.Media.DATE_ADDED + " DESC"
        );

        if (cursor == null) return results;

        while (cursor.moveToNext()) {
            VideoMetadata meta = new VideoMetadata();
            meta.id = cursor.getLong(0);
            meta.name = cursor.getString(1);
            meta.size = cursor.getLong(2);
            meta.duration = cursor.getLong(3);
            meta.dateAdded = cursor.getLong(4);
            meta.uri = ContentUris.withAppendedId(
                MediaStore.Video.Media.EXTERNAL_CONTENT_URI, meta.id
            );
            results.add(meta);
        }
        cursor.close();
        return results;
    }

    public byte[] extractThumbnail(long videoId) {
        Uri uri = ContentUris.withAppendedId(
            MediaStore.Video.Media.EXTERNAL_CONTENT_URI, videoId
        );
        try {
            Bitmap thumb = resolver.loadThumbnail(uri, new Size(320, 240), null);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            thumb.compress(Bitmap.CompressFormat.JPEG, 60, baos);
            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }
}
```

Malware often exfiltrates video thumbnails first to minimize bandwidth usage, then selectively downloads full videos based on operator interest. The metadata enumeration provides duration, size, and timestamps that allow operators to prioritize targets.

## Android Version Changes

**Android 13 (API 33)**: `READ_MEDIA_VIDEO` introduced as a replacement for `READ_EXTERNAL_STORAGE` for video file access. Apps targeting API 33+ must request this specific permission.

**Android 14 (API 34)**: `READ_MEDIA_VIDEO` grouped with `READ_MEDIA_IMAGES` in the `READ_MEDIA_VISUAL` permission group. Granting one grants the other. Users can also grant partial access (select specific files) instead of full access through the photo picker.

**Pre-Android 13**: apps use `READ_EXTERNAL_STORAGE` which grants access to all media types, making video-specific abuse less distinguishable from general storage access.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
```

### Analysis Indicators

- Apps requesting `READ_MEDIA_VIDEO` combined with `INTERNET` and `FOREGROUND_SERVICE` but lacking video playback or editing UI are suspicious.
- Look for thumbnail extraction patterns -- malware that loads thumbnails for all videos without displaying them to the user is performing reconnaissance.
- Check for `ContentObserver` registration on `MediaStore.Video` to detect real-time monitoring of new video files.
- Bandwidth patterns are a strong indicator: video exfiltration produces large sustained uploads that stand out in network analysis.
- On Android 14+, granting `READ_MEDIA_IMAGES` also grants `READ_MEDIA_VIDEO`, so malware may only request images permission to silently gain video access.
- On pre-Android 13 samples, `READ_EXTERNAL_STORAGE` with `MediaStore.Video` queries achieves the same result -- the broader permission masks video-specific intent.

## See Also

- [READ_EXTERNAL_STORAGE](read-external-storage.md) -- the pre-Android 13 permission that granted access to all media types including video
- [READ_MEDIA_IMAGES](read-media-images.md) -- grouped with `READ_MEDIA_VIDEO` in the `READ_MEDIA_VISUAL` permission group on Android 14+
- [READ_MEDIA_AUDIO](read-media-audio.md) -- companion granular permission for audio access
- [Screen Capture](../../attacks/screen-capture.md) -- screen recordings accessed via this permission may reveal sensitive app usage
