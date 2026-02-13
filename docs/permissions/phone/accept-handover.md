# ACCEPT_HANDOVER

Allows an app to accept a call handover from another calling app. Part of the telecom framework for transferring active calls between different calling apps or from a cellular call to a VoIP app.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACCEPT_HANDOVER` |
| Protection Level | `dangerous` |
| Permission Group | `PHONE` |
| Grant Method | Runtime permission dialog |
| Introduced | API 28 (Android 9.0) |

## What It Enables

Accept incoming call handovers via `TelecomManager`. Used when a user wants to transfer a cellular call to a Wi-Fi calling or VoIP app.

The handover flow involves the originating app calling `TelecomManager.acceptHandover()` and the receiving app implementing a `ConnectionService` that handles the transferred call:

```java
TelecomManager telecomManager = (TelecomManager) getSystemService(TELECOM_SERVICE);
Uri callUri = Uri.fromParts("tel", phoneNumber, null);
telecomManager.acceptHandover(
    callUri,
    VideoProfile.STATE_AUDIO_ONLY,
    new PhoneAccountHandle(
        new ComponentName(context, MyConnectionService.class),
        "handover_account"
    )
);
```

The receiving `ConnectionService` must be registered with `TelecomManager` and declared in the manifest with the `BIND_TELECOM_CONNECTION_SERVICE` permission.

## Abuse in Malware

No known malware families abuse `ACCEPT_HANDOVER`. The permission has minimal attack surface because:

- The app must be registered as a legitimate `ConnectionService` with the telecom framework
- The handover must be initiated by a currently active call
- The user's device must support the handover protocol (carrier-dependent)
- The attack requires precise timing during an active call

### Theoretical Abuse Scenarios

**Call Hijacking During Handover**: A malicious app registered as a `ConnectionService` could intercept calls during the cellular-to-Wi-Fi handover transition. When a user moves from cellular coverage to Wi-Fi, their carrier may initiate a handover. A malicious app could accept this handover, silently routing the call through attacker infrastructure for eavesdropping or manipulation. This is conceptually similar to the call interception in [Fakecalls](../../malware/families/fakecalls.md), but triggered by a handover event rather than an outgoing dial.

**MitM on Call Audio**: After accepting a handover, the `ConnectionService` controls the audio path. The app could record the conversation, inject audio, or silently bridge the call through a relay server.

In practice, these scenarios require the user to have enabled the malicious `ConnectionService`, the carrier to support handovers, and an active call at the moment of handover -- a narrow set of conditions that makes this permission unattractive to malware developers compared to more reliable call interception methods.

## Android Version Changes

**Android 9.0 (API 28)**: `ACCEPT_HANDOVER` introduced as part of the `ConnectionService` framework for seamless call transitions between apps. This was designed for carriers and VoIP providers to offer Wi-Fi calling handover.

**Android 10 (API 29)**: the telecom framework added stricter validation for `ConnectionService` registrations, requiring apps to pass additional checks before receiving handover events.

**Android 13 (API 33)**: no significant changes to the handover API, but the broader telecom framework received security hardening that further limits unauthorized access to call state.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ACCEPT_HANDOVER" />
```

Only expected in calling/telecom apps.

### Static Analysis Indicators

- Implementation of `android.telecom.ConnectionService`
- Calls to `TelecomManager.acceptHandover()`
- `PhoneAccountHandle` registration with the telecom framework
- Manifest declaration of `BIND_TELECOM_CONNECTION_SERVICE`

### Permission Combination Red Flags

`ACCEPT_HANDOVER` combined with [RECORD_AUDIO](../microphone/record-audio.md) or `INTERNET` in a non-dialer app warrants investigation. When combined with [CALL_PHONE](call-phone.md) and [READ_PHONE_STATE](read-phone-state.md), the app has comprehensive call control capabilities. However, this combination is expected in legitimate VoIP and Wi-Fi calling applications.
