# BIND_CALL_REDIRECTION_SERVICE

System permission introduced in Android 10 (API 29) that allows an app to intercept and redirect outgoing phone calls before they connect. When a user dials a number, the system routes the call through the registered `CallRedirectionService`, which can modify the destination number, cancel the call, or allow it to proceed. Malware uses this to redirect calls to attacker-controlled numbers, enabling voice phishing (vishing) attacks where the victim believes they are speaking with their bank but are actually connected to a scammer.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_CALL_REDIRECTION_SERVICE` |
| Protection Level | `signature` |
| Grant Method | User selects the app as the default call redirection service in Settings > Apps > Default apps |
| Introduced | API 29 (Android 10) |
| Replaces | `PROCESS_OUTGOING_CALLS` broadcast (deprecated in API 29) |
| User Visibility | Must be set as default call redirection app in system settings |

The `signature` protection level means only the system can bind to the service. The app declares the service in its manifest, and the user must explicitly select it as the default call redirection handler. This is a higher bar than a simple runtime permission, but malware uses accessibility services or social engineering to navigate users through the setup.

## What It Enables

### Call Redirection Service

```java
public class MaliciousRedirector extends CallRedirectionService {
    @Override
    public void onPlaceCall(Uri handle, PhoneAccountHandle initial, boolean allowInteractiveResponse) {
        String dialed = handle.getSchemeSpecificPart();
        if (isBankNumber(dialed)) {
            Uri attackerNumber = Uri.fromParts("tel", "+1234567890", null);
            redirectCall(attackerNumber, initial, true);
        } else {
            placeCallUnmodified();
        }
    }
}
```

The service receives every outgoing call before it connects. It can:

| Action | Method | Effect |
|--------|--------|--------|
| Allow unchanged | `placeCallUnmodified()` | Call proceeds to original number |
| Redirect | `redirectCall(newUri, ...)` | Call connects to a different number |
| Cancel | `cancelCall()` | Call is silently dropped |

## Abuse in Malware

### Voice Phishing (Vishing)

The primary attack pattern. When the victim calls their bank, the malware intercepts the call and redirects it to an attacker-operated call center:

1. Victim dials their bank's customer service number
2. `CallRedirectionService` intercepts the outgoing call
3. Malware checks the number against a target list (bank numbers)
4. Call is silently redirected to the attacker's number
5. The victim's phone displays the original bank number (the redirect is invisible)
6. The attacker impersonates a bank representative
7. Victim provides credentials, OTPs, or authorizes transactions

### FakeCalls

[FakeCalls](../../malware/families/fakecalls.md) is the most documented family abusing call redirection. [ThreatFabric](https://www.threatfabric.com/blogs/fakecalls-a-new-android-banker) and [Kaspersky](https://securelist.com/fakecalls-banking-trojan/) documented its implementation targeting South Korean banking customers:

| Feature | Implementation |
|---------|---------------|
| Outgoing call interception | Redirects calls to Korean bank numbers to attacker call centers |
| Incoming call spoofing | Displays fake caller ID showing the bank's real number |
| Custom dialer UI | Shows a fake call screen mimicking the stock Android dialer |
| Selective targeting | Only redirects calls to specific bank numbers; all other calls proceed normally |
| Recording | Records the call for later use in social engineering |

### Combined with Other Techniques

| Technique | Combination |
|-----------|------------|
| [Overlay attacks](../../attacks/overlay-attacks.md) | Display fake banking UI alongside redirected calls |
| [SMS interception](../../attacks/sms-interception.md) | Capture OTPs sent during the fake bank interaction |
| [Accessibility abuse](../../attacks/accessibility-abuse.md) | Auto-enable the call redirection service as default |

## Comparison: BIND_CALL_REDIRECTION_SERVICE vs PROCESS_OUTGOING_CALLS

| Aspect | BIND_CALL_REDIRECTION_SERVICE | PROCESS_OUTGOING_CALLS |
|--------|-------------------------------|----------------------|
| API Level | 29+ (Android 10+) | 1-28 (deprecated API 29) |
| Grant Method | Default app selection in Settings | Runtime permission |
| Scope | Only one app can be the default redirector | Multiple apps receive the broadcast |
| Timing | Before call setup | During call setup |
| Can redirect | Yes, native API method | Yes, by modifying result data |
| Can cancel | Yes | Yes |
| User visibility | Must be set as default app | No special setup required |

`PROCESS_OUTGOING_CALLS` was deprecated because the broadcast model allowed multiple apps to interfere with calls simultaneously. The replacement service model ensures only one app handles call redirection, but the capability itself is more dangerous because the redirect is seamless and invisible to the user.

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 10 | 29 | `CallRedirectionService` introduced | Replaces deprecated `PROCESS_OUTGOING_CALLS` broadcast |
| 10 | 29 | Default app selection required | Only one app can redirect calls; must be explicitly set |
| 11 | 30 | Call screening improvements | `CallScreeningService` added alongside, but separate from redirection |
| 12 | 31 | Role-based default apps | `RoleManager` manages default call redirection role |

## Detection Indicators

### Manifest Signals

- `CallRedirectionService` declaration in manifest
- `BIND_CALL_REDIRECTION_SERVICE` combined with network permissions and overlay capabilities
- Service declaration targeting `android.telecom.CallRedirectionService` action

### Behavioral Signals

- App requesting to be set as default call redirection service without clear VoIP/calling functionality
- `redirectCall()` targeting known financial institution phone numbers
- Call redirection combined with call recording APIs
- Accessibility service navigating to default app settings to self-enable

## See Also

- [Call Interception](../../attacks/call-interception.md)
- [FakeCalls](../../malware/families/fakecalls.md)
- [PROCESS_OUTGOING_CALLS](../call-log/process-outgoing-calls.md)
