# Camera & Microphone Surveillance

Silent capture of audio and video from a compromised Android device. Spyware and banking trojans use the camera and microphone for ambient recording, live streaming, screenshot capture, and call recording. The objective ranges from targeted intelligence gathering (state-sponsored spyware like [Pegasus](../malware/families/pegasus.md)) to mass credential harvesting (banking trojans recording screen during login).

See also: [Screen Capture](screen-capture.md), [Keylogging](keylogging.md), [Accessibility Abuse](accessibility-abuse.md), [Call Interception](call-interception.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1429](https://attack.mitre.org/techniques/T1429/) | Audio Capture | Collection |
    | [T1512](https://attack.mitre.org/techniques/T1512/) | Video Capture | Collection |

    T1429 covers microphone-based audio recording and call recording. T1512 covers camera capture (photo and video). Both techniques are core collection capabilities for spyware and RATs.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Camera | `CAMERA` runtime permission + foreground service with `camera` type (Android 14+) |
    | Microphone | `RECORD_AUDIO` runtime permission + foreground service with `microphone` type (Android 14+) |
    | Screen capture | `MediaProjection` consent dialog (one-time) or `BIND_ACCESSIBILITY_SERVICE` for screenshot commands |
    | Background access | Foreground service must be started while app is in foreground; once running, persists in background |

## Camera Capture

### Silent Photography

Malware opens the camera API in the background to capture photos without any visible UI. On Android 9+, background camera access requires a foreground service started while the app was visible.

```java
CameraManager manager = (CameraManager) getSystemService(CAMERA_SERVICE);
manager.openCamera(cameraId, new CameraDevice.StateCallback() {
    @Override
    public void onOpened(CameraDevice camera) {
        CaptureRequest.Builder builder = camera.createCaptureRequest(
            CameraDevice.TEMPLATE_STILL_CAPTURE);
        builder.addTarget(imageReader.getSurface());
        camera.createCaptureSession(outputSurfaces, sessionCallback, handler);
    }
}, backgroundHandler);
```

[SpyNote](../malware/families/spynote.md) captures photos from both front and rear cameras on C2 command. [CYFIRMA's analysis](https://www.cyfirma.com/research/spynote-unmasking-a-sophisticated-android-malware/) documented the implementation: the malware uses a foreground service with `IMPORTANCE_MIN` notification to maintain camera access while appearing invisible in the notification shade.

### Video Recording

Continuous video recording uses `MediaRecorder` or `Camera2` API with an output surface writing to internal storage. The video file is chunked and exfiltrated to C2 in segments to avoid large file transfers that might alert the user to unusual data usage.

[Pegasus](../malware/families/pegasus.md) (Chrysaor on Android) provides full camera and video surveillance. [Lookout's 2017 technical analysis](https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf) documented how the native code component hooks into the camera process, with the Java layer coordinating surveillance functions. [Google's investigation](https://android-developers.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html) confirmed that once installed, a remote operator can surveil the victim's activities on the device and within the vicinity, leveraging the microphone, camera, and data collection capabilities.

## Microphone Recording

### Ambient Audio Capture

The most common audio surveillance technique. Malware starts `MediaRecorder` or `AudioRecord` with `AudioSource.MIC` to capture surrounding audio.

```java
MediaRecorder recorder = new MediaRecorder();
recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
recorder.setOutputFormat(MediaRecorder.OutputFormat.AAC_ADTS);
recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
recorder.setOutputFile(outputPath);
recorder.prepare();
recorder.start();
```

[SpyNote](../malware/families/spynote.md) uses a background service with `MediaRecorder` set to `AudioSource.MIC` to record ambient audio, [saving files to external storage](https://s4yed.github.io/posts/spy-note-android-malware-analysis/). On Android 9+, it uses a foreground service with minimal notification importance to maintain microphone access.

### Call Audio Recording

Recording phone calls is increasingly restricted. See [Call Interception](call-interception.md#call-recording) for the full Android version timeline. Malware workarounds include:

1. **Speakerphone + MIC**: Force speakerphone via accessibility service, then record ambient audio via microphone
2. **MediaProjection audio**: Capture system audio output including call audio (requires one-time consent dialog)
3. **Accessibility + MediaRecorder**: Detect call state via accessibility, start foreground service recording via `AudioSource.MIC`

### Live Audio Streaming

[Pegasus](../malware/families/pegasus.md) supports live audio surveillance triggered by receiving a call from an attacker-specified number. The malware silently answers and streams ambient audio captured by the device microphone back to the operator. The [addk.so native library](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analysis-chrysaor-keylogging-mechanism-shows-power-simple-malicious-code/) injects shellcode into the keyboard process memory space for keystroke capture alongside audio.

## Screen-Based Capture

### MediaProjection Screen Recording

`MediaProjection` captures the entire screen including all app content. Android requires a user consent dialog before granting access, but malware uses accessibility services to auto-tap "Start Now" on the consent prompt.

Once granted, `MediaProjection` provides a `VirtualDisplay` surface that mirrors the screen. The malware encodes frames as video or captures individual screenshots at intervals.

[LianSpy](https://securelist.com/lianspy-android-spyware/113253/), discovered by Kaspersky targeting Russian users (active since July 2021, reported August 2024), uses the `screencap` system command with root permissions to take screenshots instead of `MediaProjection`, leaving no trace of screenshot capture. LianSpy stores captured data on Yandex Disk as its C2 channel, searching for config files matching the regex `^frame_.+\.png$` every 30 seconds.

### Privacy Indicator Bypass

Android 12 introduced privacy indicators (green dot in status bar) when camera or microphone are active. [LianSpy bypasses this](https://www.bleepingcomputer.com/news/security/new-lianspy-malware-hides-by-blocking-android-security-feature/) by appending a cast value to the `icon_blacklist` Android secure setting parameter, preventing notification icons from appearing in the status bar.

### Accessibility-Based Screenshot

Malware with accessibility service access can use `AccessibilityService.takeScreenshot()` (Android 9+) to capture screen content without `MediaProjection`. This method does not trigger the privacy indicator since it operates through the accessibility framework rather than the camera/microphone APIs.

## State-Sponsored Spyware

Commercial and state-sponsored spyware represents the most sophisticated camera/microphone surveillance on Android.

| Family | Camera | Microphone | Screen | Key Technique | Source |
|--------|:------:|:----------:|:------:|---------------|--------|
| [Pegasus](../malware/families/pegasus.md) | Yes | Live stream | Yes | Framaroot exploit for privilege escalation, native hooks | [Lookout](https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf), [Google](https://android-developers.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html) |
| [Predator](../malware/families/predator.md) | Yes | Yes | Yes | Exploit chain delivery, 5-module architecture | [Cisco Talos](https://blog.talosintelligence.com/mercenary-intellexa-predator/) |
| [Hermit](../malware/families/hermit.md) | Yes | Yes | Yes | RCS Lab commercial spyware, ISP-level delivery | [Lookout](https://www.lookout.com/threat-intelligence/article/hermit-spyware-discovery) |
| [FinSpy](../malware/families/finspy.md) | Yes | Yes | Yes | Gamma Group, DexGuard-packed, targets dissidents | [Amnesty International](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/) |
| LianSpy | No | No | Yes (screencap) | Yandex Disk C2, privacy indicator bypass, root-level | [Kaspersky](https://securelist.com/lianspy-android-spyware/113253/) |
| [GuardZoo](../malware/families/guardzoo.md) | Yes | Yes | No | Houthi-targeting, Dendroid RAT fork | [Lookout](https://www.lookout.com/threat-intelligence/article/guardzoo-houthi-android-surveillanceware) |

## Banking Trojan Surveillance

Banking trojans use camera/microphone primarily for credential capture during fraud, not long-term surveillance.

| Family | Camera | Microphone | Screen | Purpose |
|--------|:------:|:----------:|:------:|---------|
| [SpyNote](../malware/families/spynote.md) | Both cameras | Ambient + call | MediaProjection | Full RAT with surveillance as primary function |
| [Hook](../malware/families/hook.md) | Yes | Yes | VNC stream | Remote access during ATS, screen dimmed to zero |
| [Octo](../malware/families/octo.md) | No | No | Screenshot stream | `SHIT_QUALITY` mode for bandwidth-efficient screen streaming |
| [Vultur](../malware/families/vultur.md) | No | No | Screen recording | AlphaVNC + ngrok for real-time remote access |
| [Crocodilus](../malware/families/crocodilus.md) | Yes | No | Black overlay | Camera for selfie capture, screen hidden during ATS |

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| Pre-6.0 | <23 | Camera/microphone permissions granted at install | Trivial access to both sensors |
| 6.0 | 23 | [Runtime permissions](https://developer.android.com/training/permissions/requesting) for `CAMERA` and `RECORD_AUDIO` | User must grant explicitly; [accessibility](accessibility-abuse.md) auto-grants |
| 9.0 | 28 | Background camera access restricted | Foreground service required; must be started while app is visible |
| 9.0 | 28 | `VOICE_CALL` audio source restricted | Call recording moves to `MIC` source workarounds |
| 10 | 29 | Background microphone access restricted | Foreground service required |
| 11 | 30 | [Foreground service must declare `camera`/`microphone` type](https://developer.android.com/about/versions/11/privacy/foreground-services) | Manifest declaration reveals intent |
| 12 | 31 | [Privacy indicators](https://developer.android.com/about/versions/12/behavior-changes-all#mic-camera-indicators) (green dot) for camera/microphone | Visual indicator to user; bypassed by LianSpy via `icon_blacklist` |
| 14 | 34 | [Foreground service type `camera`/`microphone` required](https://developer.android.com/about/versions/14/changes/fgs-types-required) | Cannot start camera/microphone FGS from background |
| 14 | 34 | Microphone FGS cannot launch from `BOOT_COMPLETED` | Breaks boot-time ambient recording |
| 15 | 35 | Camera FGS also blocked from `BOOT_COMPLETED` | Further restricts boot-time surveillance |

## Evasion Techniques

| Technique | Implementation | Used By |
|-----------|---------------|---------|
| Minimal notification | `IMPORTANCE_MIN` foreground service notification | [SpyNote](../malware/families/spynote.md), most spyware |
| Accessibility auto-grant | Tap through `MediaProjection` consent dialog | Banking trojans with accessibility |
| Root-level screencap | Use `screencap` binary instead of API | LianSpy |
| Privacy indicator bypass | Modify `icon_blacklist` setting | LianSpy |
| Scheduled capture | Only activate during specific C2-triggered windows | [Pegasus](../malware/families/pegasus.md), [Predator](../malware/families/predator.md) |
| Low-quality encoding | Reduce resolution/bitrate to minimize data usage | [Octo](../malware/families/octo.md) (`SHIT_QUALITY` mode) |

## Detection During Analysis

??? example "Static Indicators"

    - `CAMERA` + `RECORD_AUDIO` permissions without camera-related UI in the app
    - `MediaRecorder` or `AudioRecord` initialization in background services
    - `MediaProjection` `createScreenCaptureIntent()` without user-facing recording UI
    - Foreground service type `camera` or `microphone` in manifest
    - `screencap` or `screenrecord` command strings
    - `icon_blacklist` string in code (privacy indicator bypass)

??? example "Dynamic Indicators"

    - Camera LED activating without user-initiated camera action
    - Privacy indicator (green dot) appearing and disappearing rapidly
    - Foreground service running with camera/microphone type
    - Audio files or screenshots appearing in app-private storage
    - Network traffic spikes during ambient recording upload
    - `MediaProjection` consent dialog auto-dismissed
