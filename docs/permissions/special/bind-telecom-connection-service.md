# BIND_TELECOM_CONNECTION_SERVICE

System permission that allows an app to register a `ConnectionService` with Android's telecom framework. When combined with the default dialer role, this grants full control over incoming and outgoing calls: the app can intercept, redirect, answer, and fabricate calls while displaying fake caller ID. [FakeCalls](../../malware/families/fakecalls.md) pioneered this attack surface for voice phishing (vishing), redirecting victims' bank calls to attacker-operated call centers.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_TELECOM_CONNECTION_SERVICE` |
| Protection Level | `signature` |
| Grant Method | App must register a `ConnectionService`; full call control requires becoming the default dialer via `RoleManager` or Settings |
| Introduced | API 23 (Android 6.0) |
| User Visibility | User must set the app as default phone app |
| Related | [`BIND_CALL_REDIRECTION_SERVICE`](bind-call-redirection-service.md) (Android 10+ call redirection), [`PROCESS_OUTGOING_CALLS`](../call-log/process-outgoing-calls.md) (deprecated) |

The `signature` protection level means only the system can bind to the service. Third-party apps declare the service and request the default dialer role. The critical distinction: `BIND_CALL_REDIRECTION_SERVICE` only intercepts outgoing calls, while a default dialer with `ConnectionService` controls the entire call lifecycle including incoming calls, call UI, and caller ID display.

## What It Enables

### ConnectionService Registration

```java
public class MaliciousConnectionService extends ConnectionService {

    @Override
    public Connection onCreateIncomingConnection(PhoneAccountHandle handle, ConnectionRequest request) {
        MaliciousConnection conn = new MaliciousConnection();
        conn.setAddress(request.getAddress(), TelecomManager.PRESENTATION_ALLOWED);
        conn.setRinging();
        return conn;
    }

    @Override
    public Connection onCreateOutgoingConnection(PhoneAccountHandle handle, ConnectionRequest request) {
        String dialed = request.getAddress().getSchemeSpecificPart();
        MaliciousConnection conn = new MaliciousConnection();

        if (isBankNumber(dialed)) {
            Uri attackerUri = Uri.fromParts("tel", ATTACKER_NUMBER, null);
            conn.setAddress(request.getAddress(), TelecomManager.PRESENTATION_ALLOWED);
            conn.setDialing();
            routeToAttacker(conn, attackerUri);
        } else {
            conn.setAddress(request.getAddress(), TelecomManager.PRESENTATION_ALLOWED);
            conn.setDialing();
        }
        return conn;
    }
}
```

### Default Dialer Role

```java
RoleManager roleManager = getSystemService(RoleManager.class);
Intent intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_DIALER);
startActivityForResult(intent, REQUEST_DEFAULT_DIALER);
```

Becoming the default dialer grants:

| Capability | Effect |
|-----------|--------|
| Outgoing call control | Intercept all outgoing calls, redirect to attacker numbers |
| Incoming call control | Answer, reject, or fabricate incoming calls |
| Call UI replacement | Display custom call screen showing spoofed caller ID |
| InCallService binding | Full control over the call UI and call state presentation |
| Call log access | Read and write call history |

## Abuse in Malware

### Voice Phishing (Vishing) via Default Dialer

The attack chain:

1. Malware social-engineers the user into setting it as the default phone app ("enhanced spam protection" or "call blocking" feature)
2. Victim later dials their bank's customer service number
3. Malware's `ConnectionService` intercepts the outgoing call
4. Call is silently redirected to an attacker-operated call center
5. The malware's custom `InCallService` displays the bank's real number on screen
6. The victim sees their bank's number, hears a professional IVR, and provides credentials
7. Attacker uses the credentials for account takeover

The victim has no visual indication the call was redirected. The phone screen shows the bank's name and number throughout the call.

### FakeCalls / Letscall

[FakeCalls](../../malware/families/fakecalls.md) is the defining malware family for this attack surface. First documented by [Kaspersky in April 2022](https://securelist.com/fakecalls-banking-trojan/), it has evolved through multiple generations:

| Generation | Year | Capabilities | Source |
|-----------|------|-------------|--------|
| v1 | 2022 | Outgoing call redirect to Korean banks, basic fake dialer UI | [Kaspersky](https://securelist.com/fakecalls-banking-trojan/) |
| v2 | 2023 | Incoming call spoofing, pre-recorded IVR audio, call recording | [Check Point](https://research.checkpoint.com/2023/fakecalls-android-trojan/) |
| v3 | 2024 | Bluetooth audio monitoring, screen state capture, Accessibility-based remote control, 13 apps identified | [Zimperium](https://zimperium.com/blog/mishing-in-motion-uncovering-the-evolving-functionality-of-fakecall-malware/) |

FakeCalls targets South Korean banking customers exclusively. The malware impersonates apps from Kookmin Bank, KakaoBank, and other major Korean financial institutions. The attacker call centers employ Korean-speaking operators who follow scripts mimicking real bank customer service.

### Bidirectional Call Control

Unlike `BIND_CALL_REDIRECTION_SERVICE` which only intercepts outgoing calls, the default dialer role enables bidirectional attacks:

| Direction | Attack |
|-----------|--------|
| Outgoing | Victim calls bank, redirected to attacker |
| Incoming | Attacker calls victim, caller ID shows bank's number |
| Fabricated | Malware generates a fake "incoming call" from the bank with no real call |

The fabricated incoming call is particularly dangerous. The malware can create a `Connection` object and present it through the `InCallService` as a real incoming call, complete with ringtone and the bank's caller ID. No actual phone call occurs; the audio is pre-recorded IVR played locally or streamed from C2.

## Comparison: Call Interception Methods

| Method | API | Direction | User Setup | Visibility |
|--------|-----|-----------|-----------|------------|
| `BIND_TELECOM_CONNECTION_SERVICE` + default dialer | 23+ | Both | Must become default phone app | Invisible (custom call UI) |
| [`BIND_CALL_REDIRECTION_SERVICE`](bind-call-redirection-service.md) | 29+ | Outgoing only | Must become default call redirect app | Invisible redirect |
| [`PROCESS_OUTGOING_CALLS`](../call-log/process-outgoing-calls.md) | 1-28 | Outgoing only | Runtime permission | Broadcast-based, deprecated |
| [`ANSWER_PHONE_CALLS`](../phone/answer-phone-calls.md) | 26+ | Incoming only | Runtime permission | Can auto-answer but not redirect |

The default dialer approach is the most powerful because it controls the entire call UI. The malware replaces the stock dialer, meaning it controls what the user sees during any call.

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 6.0 | 23 | `ConnectionService` and `InCallService` APIs introduced | Apps can manage calls and replace the dialer UI |
| 7.0 | 24 | Default dialer role formalized | Clearer path for apps to become the phone app |
| 10 | 29 | `RoleManager` introduced for default apps | `ROLE_DIALER` provides standardized default dialer request |
| 10 | 29 | `CallRedirectionService` added | Alternative for outgoing-only redirection without default dialer role |
| 12 | 31 | Role-based permissions tightened | `RoleManager` enforces stricter default app validation |
| 14 | 34 | Restricted settings expanded | Sideloaded apps face additional barriers to becoming default dialer |

## Detection Indicators

### Manifest Signals

```xml
<service
    android:name=".service.CallService"
    android:permission="android.permission.BIND_TELECOM_CONNECTION_SERVICE">
    <intent-filter>
        <action android:name="android.telecom.ConnectionService" />
    </intent-filter>
</service>

<service
    android:name=".service.InCallUI"
    android:permission="android.permission.BIND_INCALL_SERVICE">
    <intent-filter>
        <action android:name="android.telecom.InCallService" />
    </intent-filter>
</service>
```

A `ConnectionService` + `InCallService` combination in a non-dialer app is a strong indicator of FakeCalls-type malware.

### Behavioral Signals

- App requesting `ROLE_DIALER` without legitimate dialer functionality
- Call routing logic containing hardcoded bank phone numbers
- Pre-recorded audio files (`.mp3`, `.wav`) with IVR-style content
- `PhoneAccountHandle` registration followed by network communication to C2
- Custom call screen UI mimicking the stock Android dialer or a specific bank app

### Frida: Hook ConnectionService

```javascript
Java.perform(function() {
    var ConnectionService = Java.use("android.telecom.ConnectionService");
    ConnectionService.onCreateOutgoingConnection.implementation = function(handle, request) {
        var addr = request.getAddress();
        console.log("[*] Outgoing call via ConnectionService: " + addr);
        return this.onCreateOutgoingConnection(handle, request);
    };

    ConnectionService.onCreateIncomingConnection.implementation = function(handle, request) {
        var addr = request.getAddress();
        console.log("[*] Incoming call via ConnectionService: " + addr);
        return this.onCreateIncomingConnection(handle, request);
    };
});
```

## See Also

- [Call Interception](../../attacks/call-interception.md)
- [FakeCalls](../../malware/families/fakecalls.md)
- [BIND_CALL_REDIRECTION_SERVICE](bind-call-redirection-service.md)
- [PROCESS_OUTGOING_CALLS](../call-log/process-outgoing-calls.md)
- [ANSWER_PHONE_CALLS](../phone/answer-phone-calls.md)
