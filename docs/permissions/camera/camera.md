# CAMERA

Grants access to device cameras (front and rear) for photo and video capture. Used by spyware for covert environmental surveillance, capturing the victim's face, surroundings, and any documents or screens in view. One of the most privacy-invasive permissions, and a standard capability in both commercial spyware and stalkerware.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.CAMERA` |
| Protection Level | `dangerous` |
| Permission Group | `CAMERA` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Two camera APIs exist on Android:

### Camera1 (Deprecated)

```java
Camera camera = Camera.open(0);
camera.setPreviewTexture(surfaceTexture);
camera.startPreview();
camera.takePicture(null, null, pictureCallback);
```

Requires a preview surface. Malware uses a 1x1 pixel `SurfaceTexture` to satisfy this requirement invisibly.

### Camera2 (API 21+)

```java
CameraManager manager = (CameraManager) getSystemService(CAMERA_SERVICE);
manager.openCamera(cameraId, stateCallback, handler);
```

Camera2 supports `ImageReader` as an output target, enabling capture directly to a byte buffer without any visible preview. This is the preferred API for covert capture.

### CameraX (Jetpack)

Higher-level abstraction over Camera2. Some stalkerware uses CameraX for simpler implementation, though Camera2 provides more control for stealth.

### Available Data

| Capability | Details |
|-----------|---------|
| Still photos | Full sensor resolution, front and rear cameras |
| Video recording | Requires `MediaRecorder` or `MediaCodec`, up to device-supported resolution |
| Camera metadata | Lens intrinsics, sensor orientation, exposure data |
| Camera enumeration | Number of cameras, facing direction, capabilities |
| Depth data | On supported devices, ToF/structured light depth maps |

## Abuse in Malware

### Covert Photo Capture

The primary abuse case. Malware captures still images silently:

1. Open camera in a foreground service or with a transparent overlay
2. Use a 1x1 pixel preview surface or `ImageReader`-only output
3. Capture image to memory
4. Compress and exfiltrate to C2 via HTTPS
5. Release camera to avoid the in-use indicator on Android 12+

Timing matters. Sophisticated spyware captures when the screen is on (camera quality is better, and the user is likely facing the front camera) or on C2 command.

### Covert Video Recording

Sustained video capture generates large files and keeps the camera session open, increasing detection risk on Android 12+ due to the persistent indicator. Malware mitigates this by:

- Recording short clips (10-30 seconds) rather than continuous video
- Compressing aggressively before exfiltration
- Recording only when triggered by C2 or on a schedule
- Combining with `RECORD_AUDIO` for video with sound

### Environmental Surveillance

Rear camera captures the physical environment: room layout, documents on desks, computer screens, other people present. Front camera captures the user's face. Both contribute to intelligence collection in targeted espionage.

### QR Code / Screen Capture

Camera pointed at another screen can read QR codes, capture credentials displayed on monitors, or photograph authentication tokens. Some malware combines camera access with OCR to extract text from captured images.

### Notable Families

| Family | Camera Usage |
|--------|-------------|
| [Pegasus](../../malware/families/pegasus.md) (NSO Group) | Full camera control, covert capture on C2 command |
| [Predator](../../malware/families/predator.md) (Cytrox) | Camera and microphone surveillance |
| [FinSpy](../../malware/families/finspy.md) | Scheduled photo capture, video recording |
| Dendroid RAT | Remote camera activation, photo + video |
| DroidJack / SandroRAT | Live camera streaming to C2 |
| [Hermit](../../malware/families/hermit.md) (RCS Lab) | Camera capture as part of lawful intercept toolkit |
| [PhoneSpy](../../malware/families/phonespy.md) | Stalkerware with continuous camera access |
| [Mandrake](../../malware/families/mandrake.md) | Camera-based environment profiling |
| [BoneSpy](../../malware/families/bonespy.md) | Covert photo capture for Gamaredon-linked espionage operations |
| [PlainGnome](../../malware/families/plaingnome.md) | Camera capture in second-stage surveillance payload |
| [EagleMsgSpy](../../malware/families/eaglemsgspy.md) | Remote camera activation for law enforcement surveillance |
| [KoSpy](../../malware/families/kospy.md) | Camera capture for North Korean intelligence collection |
| [AridSpy](../../malware/families/aridspy.md) | Covert photo capture in multi-stage spyware framework |
| [PJobRAT](../../malware/families/pjobrat.md) | Camera access for military-targeted espionage in South Asia |
| [LightSpy](../../malware/families/lightspy.md) | Dedicated camera plugin for photo and video capture |
| [SpyNote](../../malware/families/spynote.md) | Remote camera activation and live streaming to operator |

## Android Version Changes

**Android 1.0 (API 1)**: `CAMERA` permission introduced. No runtime prompt.

**Android 6.0 (API 23)**: runtime permission required. User must explicitly grant.

**Android 9 (API 28)**: apps in the background cannot access the camera. Background camera use requires a foreground service. This was the first significant restriction on covert capture.

**Android 11 (API 30)**: one-time permissions introduced. Users can grant camera access for a single session only. The permission auto-revokes when the app moves to the background.

**Android 12 (API 31)**: privacy indicators added. A green dot appears in the status bar whenever the camera is in use. Users can see which app is accessing the camera by tapping the indicator. This is the single largest detection improvement for covert camera abuse.

**Android 12**: quick settings toggles to disable camera and microphone globally. Even with the permission granted, the hardware is blocked when the toggle is off.

**Android 14 (API 34)**: foreground service type `camera` required. Apps must declare `android:foregroundServiceType="camera"` in the manifest and in the `ServiceInfo`. Without this, camera access from a foreground service throws a `SecurityException`.

**Android 15 (API 35)**: further restrictions on foreground service types and background activity launches tighten the window for covert capture.

## Evasion of Privacy Indicators

The Android 12+ camera indicator is a significant obstacle. Known bypass approaches:

| Technique | Status |
|-----------|--------|
| Root + system app privileges | Bypass indicators entirely (system camera service) |
| Capture in sub-second bursts | Indicator appears briefly, easy to miss |
| Exploit camera HAL directly | Device-specific, requires kernel/vendor exploit |
| Use deprecated Camera1 API | Indicator still applies (not a bypass) |
| Disable indicator via ADB | Requires prior ADB access, `settings put` command |

On rooted devices or with a platform-level exploit, spyware can access the camera through the HAL layer or as a system process, avoiding the indicator entirely.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.CAMERA" />
```

Static analysis indicators:

- `CameraManager.openCamera()` or `Camera.open()` calls
- `ImageReader` allocated without a corresponding visible `SurfaceView` in any layout XML
- 1x1 dimension `SurfaceTexture` or `SurfaceView` creation
- Camera access combined with `INTERNET` permission and no camera-related UI in the app
- `MediaRecorder` configured with `VideoSource.CAMERA` in a service rather than an activity
- Foreground service declared with type `camera` but no user-facing camera feature

Runtime indicators on Android 12+: the green privacy indicator dot and the quick settings panel showing the accessing app.
