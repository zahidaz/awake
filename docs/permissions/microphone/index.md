# Microphone Permissions

Microphone access enables audio capture from the device's built-in microphones. In offensive use, this means ambient room recording, call recording, and environmental audio surveillance. The microphone is one of the highest-value collection targets in spyware because audio capture provides conversational content, environmental context, and biometric voiceprints.

Every major commercial spyware platform (Pegasus, Predator, FinFisher) implements ambient audio recording. Stalkerware treats it as a core feature alongside location tracking and camera capture.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [RECORD_AUDIO](record-audio.md) | Ambient recording, call recording, voice surveillance, environmental monitoring |

## Key Considerations

Like the camera group, the microphone group contains a single runtime permission. Effective abuse requires combining it with other capabilities:

| Combo | Purpose |
|-------|---------|
| `RECORD_AUDIO` + `CAMERA` | Video with audio surveillance |
| `RECORD_AUDIO` + `READ_PHONE_STATE` | Trigger recording on incoming/outgoing calls |
| `RECORD_AUDIO` + `INTERNET` | Real-time audio streaming or recorded file exfiltration |
| `RECORD_AUDIO` + `FOREGROUND_SERVICE` (type `microphone`) | Sustained recording from background (Android 14+) |
| `RECORD_AUDIO` + `CAPTURE_AUDIO_OUTPUT` (system only) | Record other apps' audio output including call audio |

## Covert Recording Techniques

Silent audio capture has fewer constraints than camera capture since there is no preview surface requirement. The main challenges are:

- **Background execution**: maintaining a recording session while the app is not in the foreground requires a foreground service, which shows a persistent notification
- **Audio indicators**: Android 12+ shows an orange dot when the microphone is active
- **Power consumption**: continuous recording drains battery noticeably
- **Storage**: raw audio generates significant data; malware compresses to opus/amr-nb before exfiltration

Malware addresses the foreground service notification by using a minimal or misleading notification (e.g., "Updating..."), or by leveraging accessibility to dismiss the notification. On rooted devices, the foreground service requirement can be bypassed entirely.
