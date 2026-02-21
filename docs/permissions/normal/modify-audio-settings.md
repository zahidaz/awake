# MODIFY_AUDIO_SETTINGS

Normal permission that allows an app to change global audio settings: volume levels, ringer mode, and audio routing. Auto-granted at install with no user interaction. Banking trojans use this to silently mute the device during on-device fraud, preventing the victim from hearing notification sounds, ringtones, or system alerts while unauthorized transactions execute in the background.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.MODIFY_AUDIO_SETTINGS` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 1 |
| User Visibility | None |
| Play Store Policy | No restrictions |

## What It Enables

### AudioManager Controls

```java
AudioManager am = (AudioManager) getSystemService(AUDIO_SERVICE);

am.setRingerMode(AudioManager.RINGER_MODE_SILENT);

am.setStreamVolume(AudioManager.STREAM_NOTIFICATION, 0, 0);
am.setStreamVolume(AudioManager.STREAM_RING, 0, 0);
am.setStreamVolume(AudioManager.STREAM_ALARM, 0, 0);
am.setStreamVolume(AudioManager.STREAM_SYSTEM, 0, 0);

am.setStreamMute(AudioManager.STREAM_NOTIFICATION, true);
```

| Stream | Constant | What It Controls |
|--------|----------|-----------------|
| `STREAM_NOTIFICATION` | 5 | App notifications, banking alerts, SMS sounds |
| `STREAM_RING` | 2 | Incoming call ringtone |
| `STREAM_ALARM` | 4 | Alarm clock sounds |
| `STREAM_SYSTEM` | 1 | System UI sounds (key clicks, lock sounds) |
| `STREAM_MUSIC` | 3 | Media playback |
| `STREAM_DTMF` | 8 | Dual-tone multi-frequency (dial pad tones) |

### Audio Routing

```java
am.setSpeakerphoneOn(false);
am.setBluetoothScoOn(false);
am.setMode(AudioManager.MODE_IN_COMMUNICATION);
```

Audio routing control allows malware to redirect audio output during call recording or VoIP interception.

## Abuse in Malware

### Silent Fraud Mode

The core abuse pattern: mute the device during [automated transfer system](../../attacks/automated-transfer-systems.md) fraud to prevent the victim from noticing unauthorized activity.

```java
public void enableSilentFraudMode(Context context) {
    AudioManager am = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
    am.setRingerMode(AudioManager.RINGER_MODE_SILENT);
    am.setStreamVolume(AudioManager.STREAM_NOTIFICATION, 0, 0);
    am.setStreamVolume(AudioManager.STREAM_RING, 0, 0);
    am.setStreamVolume(AudioManager.STREAM_ALARM, 0, 0);
    am.setStreamVolume(AudioManager.STREAM_SYSTEM, 0, 0);
}

public void restoreAudio(Context context, int[] savedVolumes) {
    AudioManager am = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
    am.setRingerMode(AudioManager.RINGER_MODE_NORMAL);
    am.setStreamVolume(AudioManager.STREAM_NOTIFICATION, savedVolumes[0], 0);
    am.setStreamVolume(AudioManager.STREAM_RING, savedVolumes[1], 0);
    am.setStreamVolume(AudioManager.STREAM_ALARM, savedVolumes[2], 0);
    am.setStreamVolume(AudioManager.STREAM_SYSTEM, savedVolumes[3], 0);
}
```

Malware saves original volume levels before muting and restores them after the fraud session completes. The temporary muting window is typically brief (the duration of the ATS transaction), minimizing the chance the victim notices their phone was silenced.

### Combined with Other Concealment

Device muting is one component of a multi-layered concealment strategy:

| Technique | Permission/API | Purpose |
|-----------|---------------|---------|
| Audio muting | `MODIFY_AUDIO_SETTINGS` | Suppress notification sounds during fraud |
| [Black screen overlay](../../attacks/notification-suppression.md#screen-blackout-during-fraud) | `SYSTEM_ALERT_WINDOW` | Hide screen activity from victim |
| [Notification dismissal](../../attacks/notification-suppression.md) | `BIND_NOTIFICATION_LISTENER_SERVICE` | Remove transaction alert notifications |
| [DND mode](../../attacks/notification-suppression.md#dnd-and-sound-manipulation) | `ACCESS_NOTIFICATION_POLICY` | Block all interruptions |
| Screen lock | `DISABLE_KEYGUARD` + `WAKE_LOCK` | Control screen state |

### Families Using Device Muting

| Family | Usage | Source |
|--------|-------|--------|
| SOVA | `startmute` C2 command sets device to silent during SMS interception and OTP theft | [muha2xmad](https://muha2xmad.github.io/malware-analysis/sova/) |
| [Vultur](../../malware/families/vultur.md) | Mute/unmute via remote FCM commands (41 new commands in 2024 update). Uses Accessibility for additional audio control | [Fox-IT/NCC Group](https://blog.fox-it.com/2024/03/28/android-malware-vultur-expands-its-wingspan/) |
| [Octo](../../malware/families/octo.md) | "BLACK" and "SILENT" modes during on-device fraud. Combines black overlay with device muting to completely conceal remote operations | [ThreatFabric](https://www.threatfabric.com/blogs/octo-new-odf-banking-trojan) |
| [Hook](../../malware/families/hook.md) | Screen dimmed to zero brightness + muted during VNC-based remote access sessions | [Zimperium](https://zimperium.com/blog/hook-version-3-the-banking-trojan-with-the-most-advanced-capabilities) |
| [FakeCalls](../../malware/families/fakecalls.md) | Mutes call-related audio while redirecting bank calls to attacker numbers. Prevents victim from hearing real call setup sounds | [Malwarebytes](https://www.malwarebytes.com/blog/news/2024/10/android-malware-fakecall-intercepts-your-calls-to-the-bank) |
| [DroidLock](../../malware/families/rafelrat.md) | Silences device during ransomware deployment and ransom overlay display | [Zimperium](https://zimperium.com/blog/total-takeover-droidlock-hijacks-your-device/) |
| [Crocodilus](../../malware/families/crocodilus.md) | Mutes device during black overlay remote control sessions | [ThreatFabric](https://www.threatfabric.com/blogs/exposing-crocodilus-new-device-takeover-malware-targeting-android-devices) |

### Call Audio Manipulation

During [call interception](../../attacks/call-interception.md) attacks, `MODIFY_AUDIO_SETTINGS` controls the audio path:

- `setSpeakerphoneOn(true)` enables ambient recording of the victim's side of calls
- `setMode(MODE_IN_COMMUNICATION)` routes audio through the VoIP path for interception
- `setStreamVolume(STREAM_VOICE_CALL, 0, 0)` silences call audio from the earpiece while recording continues

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | `MODIFY_AUDIO_SETTINGS` introduced | Full audio control from any app |
| 6.0 | 23 | `setStreamMute()` deprecated in favor of `adjustStreamVolume()` with `ADJUST_MUTE` | Functional change only, muting still possible |
| 7.0 | 24 | DND access requires `ACCESS_NOTIFICATION_POLICY` | `setRingerMode(SILENT)` may not suppress all notifications if DND not enabled |
| 8.0 | 26 | Notification channels introduced | Individual channel volumes partially override global muting for some apps |
| 12 | 31 | Audio focus improvements | Background apps may lose audio focus more aggressively |

Despite incremental changes, the core `setRingerMode(RINGER_MODE_SILENT)` and `setStreamVolume(..., 0, 0)` calls remain fully functional across all Android versions. There is no equivalent of the restrictions applied to other abused APIs. This permission remains one of the most permissive "normal" permissions in the Android framework.

## Detection Indicators

### Manifest Signals

```xml
<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
```

Low signal on its own. High signal when combined with:

- `BIND_ACCESSIBILITY_SERVICE` (on-device fraud toolkit)
- `SYSTEM_ALERT_WINDOW` (overlay + muting = concealed fraud)
- `BIND_NOTIFICATION_LISTENER_SERVICE` (full notification suppression stack)
- `FOREGROUND_SERVICE` + `INTERNET` (persistent background operation with C2)

### Behavioral Signals

- `setRingerMode(RINGER_MODE_SILENT)` calls triggered by C2 commands rather than user interaction
- Volume set to zero across all streams simultaneously (legitimate apps rarely mute every stream)
- Volume save/restore pattern around network activity (mute before fraud, restore after)
- Audio mode changes (`MODE_IN_COMMUNICATION`) in apps without VoIP functionality

### Frida: Monitor Audio Muting

```javascript
Java.perform(function() {
    var AudioManager = Java.use("android.media.AudioManager");

    AudioManager.setRingerMode.implementation = function(mode) {
        var modes = ["NORMAL", "SILENT", "VIBRATE"];
        console.log("[*] setRingerMode: " + modes[mode]);
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        ));
        return this.setRingerMode(mode);
    };

    AudioManager.setStreamVolume.overload("int", "int", "int").implementation = function(stream, index, flags) {
        var streams = {1: "SYSTEM", 2: "RING", 3: "MUSIC", 4: "ALARM", 5: "NOTIFICATION"};
        console.log("[*] setStreamVolume: " + (streams[stream] || stream) + " -> " + index);
        return this.setStreamVolume(stream, index, flags);
    };
});
```

## See Also

- [Notification Suppression](../../attacks/notification-suppression.md)
- [Automated Transfer Systems](../../attacks/automated-transfer-systems.md)
- [Screen Capture](../../attacks/screen-capture.md)
- [DISABLE_KEYGUARD](disable-keyguard.md)
- [WAKE_LOCK](wake-lock.md)
