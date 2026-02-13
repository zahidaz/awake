# RECORD_AUDIO

Grants access to the device microphone for audio capture. Used by spyware for ambient room recording, call recording, and environmental surveillance. Captures conversations, meetings, phone calls, and any sound within microphone range. A primary collection capability in both state-sponsored spyware and commercial stalkerware.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECORD_AUDIO` |
| Protection Level | `dangerous` |
| Permission Group | `MICROPHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

### MediaRecorder

```java
MediaRecorder recorder = new MediaRecorder();
recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
recorder.setOutputFormat(MediaRecorder.OutputFormat.AAC_ADTS);
recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
recorder.setOutputFile(outputPath);
recorder.prepare();
recorder.start();
```

Writes compressed audio directly to a file. Simplest approach but limited configuration.

### AudioRecord

```java
int bufferSize = AudioRecord.getMinBufferSize(44100,
    AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
AudioRecord recorder = new AudioRecord(MediaRecorder.AudioSource.MIC,
    44100, AudioFormat.CHANNEL_IN_MONO,
    AudioFormat.ENCODING_PCM_16BIT, bufferSize);
recorder.startRecording();
```

Raw PCM access. Malware uses this for real-time audio streaming to C2 or for applying custom compression before storage.

### Audio Sources

| Source | Constant | Captures |
|--------|----------|----------|
| `MIC` | 1 | Default microphone input |
| `VOICE_UPLINK` | 2 | Outgoing call audio (restricted) |
| `VOICE_DOWNLINK` | 3 | Incoming call audio (restricted) |
| `VOICE_CALL` | 4 | Both sides of a call (restricted) |
| `CAMCORDER` | 5 | Microphone optimized for video recording |
| `VOICE_RECOGNITION` | 6 | Tuned for speech recognition |
| `VOICE_COMMUNICATION` | 7 | Tuned for VoIP with echo cancellation |
| `UNPROCESSED` | 9 | Raw, unprocessed audio (API 24+) |

`VOICE_UPLINK`, `VOICE_DOWNLINK`, and `VOICE_CALL` are restricted to system apps since Android 9. Third-party apps cannot directly record call audio through these sources.

## Abuse in Malware

### Ambient Room Recording

The primary abuse case. Malware activates the microphone on schedule or on C2 command and records the surrounding environment. Captures conversations, meetings, and any audio within range.

Typical implementation:

1. C2 sends record command with duration
2. Foreground service starts with minimal notification
3. `AudioRecord` captures raw PCM at 8kHz mono (minimizes file size)
4. Audio encoded to AMR-NB or Opus for compression (8kHz AMR-NB produces roughly 1KB/second)
5. Compressed file exfiltrated to C2
6. Local file deleted

Some families stream audio in real-time over a WebSocket or TCP connection rather than recording and uploading, reducing local forensic evidence.

### Call Recording

Recording phone calls from third-party apps has been progressively restricted:

| Android Version | Call Recording Status |
|----------------|---------------------|
| Pre-9 | `VOICE_CALL` source available to third-party apps |
| 9 (API 28) | `VOICE_CALL`, `VOICE_UPLINK`, `VOICE_DOWNLINK` restricted to system apps |
| 10 (API 29) | `AudioRecord` during calls further restricted |
| 11+ | Accessibility-based call recording blocked for non-system apps |

Malware workarounds for call recording on modern Android:

- **Speakerphone capture**: if the call is on speaker, `AudioSource.MIC` captures both sides of the conversation from the room
- **Root + inject into incall process**: with root, malware injects into the telephony stack or audio HAL to capture call audio directly
- **Accessibility audio routing**: deprecated and blocked in Android 11+
- **System app spoofing**: on rooted devices, install as a system app in `/system/priv-app/` to access restricted audio sources

### Voice Activity Detection

Sophisticated spyware implements VAD (Voice Activity Detection) to only record when speech is detected, conserving battery and storage:

1. Continuous low-power monitoring of microphone input levels
2. When amplitude exceeds a speech threshold, full recording begins
3. Recording stops after a silence timeout
4. Only segments containing speech are exfiltrated

This dramatically reduces the volume of data while capturing all conversations.

### Notable Families

| Family | Audio Usage |
|--------|-----------|
| [Pegasus](../../malware/families/pegasus.md) | Ambient recording, call recording via exploit chain, real-time streaming |
| [Predator](../../malware/families/predator.md) | Ambient audio capture on C2 command |
| [FinSpy](../../malware/families/finspy.md) | Scheduled ambient recording, call recording on rooted devices |
| [Hermit](../../malware/families/hermit.md) | Ambient recording as lawful intercept capability |
| [KoSpy](../../malware/families/kospy.md) | Audio recording via plugin, DPRK state-sponsored |
| [AridSpy](../../malware/families/aridspy.md) | Ambient recording, exfiltrated to C2 |
| [GuardZoo](../../malware/families/guardzoo.md) | Audio recording targeting military personnel |
| [SpyNote](../../malware/families/spynote.md) | Live audio streaming, call recording. Most deployed RAT. |
| [Rafel RAT](../../malware/families/rafelrat.md) | Audio recording capability across 120+ campaigns |
| [PJobRAT](../../malware/families/pjobrat.md) | Audio recording targeting Taiwan military |
| [Mandrake](../../malware/families/mandrake.md) | Ambient recording with environment profiling |

## Android Version Changes

**Android 1.0 (API 1)**: `RECORD_AUDIO` introduced. No runtime prompt.

**Android 6.0 (API 23)**: runtime permission required. User must explicitly grant.

**Android 9 (API 28)**: background apps cannot access the microphone. A foreground service is required. `VOICE_CALL`, `VOICE_UPLINK`, and `VOICE_DOWNLINK` audio sources restricted to system apps only.

**Android 10 (API 29)**: foreground service must declare type `microphone` to access audio recording. Background microphone access without a foreground service silently returns empty audio buffers.

**Android 11 (API 30)**: one-time permissions. Users can grant microphone access for a single session only. Permission auto-revokes when the app moves to the background. Auto-reset of permissions for unused apps introduced, revoking `RECORD_AUDIO` after months of inactivity.

**Android 12 (API 31)**: privacy indicators. An orange dot appears in the status bar when the microphone is active. Quick settings toggle to globally disable the microphone hardware. Even with the permission granted, the mic returns silence when the toggle is off.

**Android 14 (API 34)**: foreground service type `microphone` must be declared both in the manifest and in `ServiceInfo` when starting the service. Missing declaration causes `SecurityException`.

**Android 15 (API 35)**: expanded enforcement of foreground service types and stricter background activity launch restrictions.

## Evasion of Privacy Indicators

The Android 12+ microphone indicator (orange dot) presents the same challenge as the camera indicator:

| Technique | Status |
|-----------|--------|
| Root + system app privileges | Bypass indicator, record as system process |
| Short burst recording | Indicator appears briefly; user may not notice |
| Record only when screen is off | Indicator not visible (but still present in quick settings) |
| Exploit audio HAL directly | Device-specific, requires kernel exploit |
| Disable indicator via ADB | `adb shell settings put` can suppress (requires prior access) |

The quick settings panel reveals the accessing app even when the indicator dot is not immediately visible, so sophisticated users can detect active recording. However, most users do not check quick settings during normal phone use.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.RECORD_AUDIO" />
```

Static analysis indicators:

- `AudioRecord` or `MediaRecorder` instantiation with `AudioSource.MIC` in a `Service` rather than an `Activity`
- Audio encoding to AMR-NB or Opus in code without a visible recording UI
- WebSocket or raw TCP connections carrying audio-sized payloads
- `RECORD_AUDIO` + `INTERNET` + `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` combination
- Foreground service declared with type `microphone` but no user-facing audio feature in the app
- Audio file creation in app-private directories with deletion after network upload

Runtime detection on Android 12+: the orange privacy indicator dot and the quick settings panel showing the accessing app.
