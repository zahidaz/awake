# Camera Permissions

Camera access grants the ability to capture photos and video from device cameras without the user physically pressing a shutter button. In an offense context, this permission enables covert environmental surveillance: photographing the victim, recording their surroundings, and capturing documents or screens visible to the camera.

Stalkerware and state-sponsored spyware treat camera access as a core collection capability. Commercial spyware like Pegasus, Predator, and FinFisher all implement covert camera capture. Consumer-grade stalkerware apps marketed for "parental monitoring" or "employee tracking" rely on it heavily.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [CAMERA](camera.md) | Covert photo/video capture, environmental surveillance, QR code scanning for data exfiltration |

## Key Considerations

Unlike permission groups with multiple members (SMS, Phone), the camera group contains a single runtime permission. However, effective camera abuse typically requires combining it with other permissions:

| Combo | Purpose |
|-------|---------|
| `CAMERA` + `RECORD_AUDIO` | Video with audio surveillance |
| `CAMERA` + `INTERNET` | Real-time streaming or image exfiltration |
| `CAMERA` + `WRITE_EXTERNAL_STORAGE` | Save captured media to disk for later exfiltration |
| `CAMERA` + `FOREGROUND_SERVICE` (type `camera`) | Sustained capture from background (Android 14+) |
| `CAMERA` + `SYSTEM_ALERT_WINDOW` | Overlay to hide camera preview while capturing |

## Covert Capture Techniques

Silent camera capture requires suppressing the preview and shutter sound. Methods used by malware:

- **1x1 pixel preview surface**: create a `SurfaceView` or `TextureView` of 1x1 pixels, invisible to the user but sufficient for the camera API to operate
- **Camera2 API with ImageReader**: `ImageReader` as output surface with no preview, capturing directly to memory
- **Overlay window**: `SYSTEM_ALERT_WINDOW` places a transparent overlay that contains the preview surface, invisible to the user
- **Foreground service**: keeps the camera session alive when the app is not in the foreground

Shutter sound suppression varies by region. In Japan and South Korea, the shutter sound is mandatory at the firmware level and cannot be muted programmatically. In other regions, malware mutes media volume before capture.
