# Call Interception & Voice Phishing

Intercepting, redirecting, and faking phone calls on Android to conduct voice phishing (vishing) attacks. Unlike traditional phishing that targets text-based credentials, call interception exploits the inherent trust users place in voice communication with their bank. The victim dials their bank's real number, but the malware silently redirects the call to an attacker-controlled line where a human operator or pre-recorded IVR extracts sensitive information.

See also: [Phishing Techniques](phishing-techniques.md), [SMS Interception](sms-interception.md), [Accessibility Abuse](accessibility-abuse.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1616](https://attack.mitre.org/techniques/T1616/) | Call Control | Collection, Command and Control, Impact |
    | [T1429](https://attack.mitre.org/techniques/T1429/) | Audio Capture | Collection |

    T1616 covers making, forwarding, and blocking phone calls. T1429 applies when the interception involves recording call audio.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Call handler | Default phone handler role via [`BIND_TELECOM_CONNECTION_SERVICE`](../permissions/special/bind-telecom-connection-service.md) (user must approve) |
    | Permissions | `CALL_PHONE`, `READ_PHONE_STATE`, `BIND_ACCESSIBILITY_SERVICE` |
    | Alternative | [`CallRedirectionService`](../permissions/special/bind-call-redirection-service.md) role (Android 10+) |

## Call Redirection Techniques

### Default Call Handler Exploitation

The most powerful technique. When the malware becomes the default call handler, it manages the entire call lifecycle: dialing, connecting, displaying the in-call UI, and ending calls. This gives it complete control over what the user sees and hears.

[FakeCall](../malware/families/fakecalls.md) (also tracked as FakeCalls) pioneered this approach. [First reported by Kaspersky in April 2022](https://www.kaspersky.com/blog/fakecalls-banking-trojan/44072/), the malware prompts the user to set it as the default call handler during installation. Once approved:

1. User dials their bank's real phone number
2. FakeCall intercepts the outgoing call intent
3. The real call is cancelled silently
4. FakeCall displays a fake call UI showing the bank's real number
5. The call is routed to an attacker-controlled number
6. A human operator or pre-recorded IVR answers as the bank

The [fake call UI mimics the native Android dialer](https://www.bleepingcomputer.com/news/security/android-malware-fakecall-now-reroutes-bank-calls-to-attackers/) so convincingly that the victim sees their bank's name and number on screen while actually speaking to the attacker. [Zimperium's 2024 analysis](https://zimperium.com/blog/mishing-in-motion-uncovering-the-evolving-functionality-of-fakecall-malware/) documented expanded capabilities including accessibility service abuse for automatic permission grants, `MediaProjection` for screen streaming, and camera/photo capabilities.

### CallRedirectionService (Android 10+)

Android 10 replaced the deprecated `PROCESS_OUTGOING_CALLS` broadcast with `CallRedirectionService`, a dedicated API for legitimate call redirection (e.g., VoIP routing). Malware can register as a call redirection service:

```xml
<service android:name=".MaliciousRedirector"
    android:permission="android.permission.BIND_CALL_REDIRECTION_SERVICE">
    <intent-filter>
        <action android:name="android.telecom.CallRedirectionService" />
    </intent-filter>
</service>
```

The user must approve the app for the call redirection role via `RoleManager`. Once granted, the service receives `onPlaceCall()` for every outgoing call and can redirect it to any number via `redirectCall()`.

### USSD Code Forwarding

Malware with `CALL_PHONE` permission can silently dial USSD codes to enable unconditional call forwarding at the carrier level:

| USSD Code | Function |
|-----------|----------|
| `*21*[number]#` | Unconditional forwarding (all calls) |
| `*67*[number]#` | Forward when busy |
| `*61*[number]#` | Forward when unanswered |
| `*62*[number]#` | Forward when unreachable |
| `##21#` | Deactivate forwarding |

This technique works transparently at the network level. The victim's phone never rings; calls go directly to the attacker. No special permissions beyond `CALL_PHONE` are required because USSD codes are dialed as regular calls.

## VoIP-Based Interception

### Letscall

[ThreatFabric documented Letscall](https://www.threatfabric.com/blogs/letscall-new-sophisticated-vishing-toolset) in July 2023 as a sophisticated three-stage vishing toolkit targeting South Korean users.

| Stage | Component | Function |
|-------|-----------|----------|
| 1 | Downloader | Prepares device, installs spyware payload |
| 2 | Spyware | Establishes VoIP infrastructure using [ZEGOCLOUD](https://www.zegocloud.com/) WebRTC SDK |
| 3 | Call companion | Redirects calls to attacker call center, enables P2P voice/video |

The VoIP layer uses WebRTC with STUN/TURN servers (including Google's public STUN servers) for NAT traversal. The same P2P channel serves as both the voice call pathway and the C2 communication channel. Evasion included [Tencent Legu](../packers/tencent-legu.md) and Bangcle obfuscation, long ZIP directory names, and manifest corruption.

## Fake IVR Systems

Pre-recorded Interactive Voice Response systems that mimic a bank's phone menu. When the victim "calls their bank" (actually reaching the attacker), they hear:

1. Welcome message matching the bank's real greeting
2. Menu options ("Press 1 for account balance, Press 2 for card services...")
3. Prompts for card number, PIN, or OTP via keypad
4. Keypad input captured by the malware or VoIP system

[FakeCall](../malware/families/fakecalls.md) maintains recorded IVR audio for multiple Korean financial institutions. The recordings are convincing enough that victims enter their full card details and PINs via the phone keypad.

## Call Recording

### Android Version Restrictions

| Version | Change | Impact |
|---------|--------|--------|
| Pre-Android 9 | `MediaRecorder` + `AudioSource.VOICE_CALL` worked freely | Full call recording possible |
| Android 9 | `VOICE_CALL` audio source restricted | Apps must use `VOICE_RECOGNITION` or accessibility workarounds |
| Android 10 | Background microphone access restricted | Foreground service required |
| Android 11+ | Further restrictions on call recording APIs | Third-party call recording effectively blocked for legitimate apps |

### Malware Workarounds

Despite platform restrictions, malware achieves call recording through:

1. **Accessibility + MediaRecorder**: The accessibility service detects call state, then a foreground service records via `AudioSource.MIC` (captures the user's voice and speaker output in speakerphone mode)
2. **MediaProjection screen capture with audio**: Captures system audio output including the call (requires one-time user consent for the MediaProjection dialog)
3. **Speaker recording**: Forces speakerphone mode via accessibility, then records ambient audio via microphone

[SpyNote](../malware/families/spynote.md) uses a background service with `MediaRecorder` set to `AudioSource.MIC` to record call audio, [saving files to external storage](https://s4yed.github.io/posts/spy-note-android-malware-analysis/). On Android 9+, it uses a foreground service with `IMPORTANCE_MIN` notification to maintain microphone access.

## Call Log Manipulation

With `READ_CALL_LOG` and `WRITE_CALL_LOG` permissions, malware can:

- Read call history to identify banking calls
- Delete evidence of redirected or recorded calls
- Insert fake call log entries to maintain the illusion of a real bank call

```java
getContentResolver().delete(
    CallLog.Calls.CONTENT_URI,
    CallLog.Calls.NUMBER + " = ?",
    new String[]{attackerNumber}
);
```

## Families Using Call Interception

| Family | Technique | Targets | Source |
|--------|-----------|---------|--------|
| [FakeCall/FakeCalls](../malware/families/fakecalls.md) | Default call handler, fake UI, IVR | Korean banks | [Kaspersky](https://www.kaspersky.com/blog/fakecalls-banking-trojan/44072/), [Zimperium](https://zimperium.com/blog/mishing-in-motion-uncovering-the-evolving-functionality-of-fakecall-malware/) |
| Letscall | VoIP via WebRTC/ZEGOCLOUD, STUN/TURN relay | Korean users | [ThreatFabric](https://www.threatfabric.com/blogs/letscall-new-sophisticated-vishing-toolset) |
| [Cerberus](../malware/families/cerberus.md) | SMS/call interception, 2FA bypass | European banks | [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/apk.cerberus) |
| [SpyNote](../malware/families/spynote.md) | Call recording via foreground service | Global | [CYFIRMA](https://www.cyfirma.com/research/spynote-unmasking-a-sophisticated-android-malware/) |
| [Medusa](../malware/families/medusa.md) | Call/SMS interception, accessibility logging | Turkish/European banks | [ThreatFabric](https://www.threatfabric.com/blogs) |

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| Pre-6.0 | <23 | All permissions granted at install | Call interception trivial |
| 6.0 | 23 | Runtime permissions for `CALL_PHONE`, `READ_PHONE_STATE` | User must grant explicitly; [accessibility](accessibility-abuse.md) auto-grants |
| 9.0 | 28 | `VOICE_CALL` audio source restricted | Call recording moves to `MIC` source with speakerphone |
| 10 | 29 | `PROCESS_OUTGOING_CALLS` deprecated; [`CallRedirectionService`](https://developer.android.com/reference/android/telecom/CallRedirectionService) introduced | Malware adopts new API or uses default handler approach |
| 10 | 29 | Background microphone restrictions | Foreground service required for recording |
| 14 | 34 | [Foreground service type declaration required](https://developer.android.com/about/versions/14/changes/fgs-types-required) | Must declare `microphone` type in manifest |

## Detection During Analysis

??? example "Static Indicators"

    - `android.telecom.CallRedirectionService` in manifest
    - Request for `ROLE_CALL_REDIRECTION` via `RoleManager`
    - `TelecomManager` API usage (especially `getDefaultDialerPackage()`)
    - USSD code strings (`*21*`, `*67*`, `*61*`) in code or resources
    - Audio recording setup (`MediaRecorder`, `AudioRecord`) near telephony state listeners
    - `CALL_PHONE` + `READ_PHONE_STATE` + `READ_CALL_LOG` permission combination

??? example "Dynamic Indicators"

    - App requests default phone handler role
    - Outgoing calls to known bank numbers redirected to different destinations
    - USSD codes dialed programmatically
    - Audio recording service started during call state changes
    - Call log entries deleted after suspicious calls
    - WebRTC/VoIP library initialization without visible video/voice UI
