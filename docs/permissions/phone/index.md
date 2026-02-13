# Phone Permissions

Phone permissions expose telephony state, hardware identifiers, and call control. This group leaks IMEI, IMSI, carrier info, and phone number. It also enables initiating calls, answering inbound calls, and managing voicemail and SIP sessions without user interaction.

Before Android 10, `READ_PHONE_STATE` alone was enough to harvest persistent device identifiers. Combined with `CALL_PHONE`, malware can dial premium numbers or execute USSD codes that modify carrier settings, drain prepaid balance, or forward calls to attacker-controlled numbers.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [READ_PHONE_STATE](read-phone-state.md) | IMEI/IMSI harvesting, device fingerprinting, call state monitoring |
| [READ_PHONE_NUMBERS](read-phone-numbers.md) | Victim phone number extraction for account linking |
| [CALL_PHONE](call-phone.md) | Premium number dialing, USSD code execution, call fraud |
| [ANSWER_PHONE_CALLS](answer-phone-calls.md) | Intercept incoming calls, auto-answer for eavesdropping |
| [ADD_VOICEMAIL](add-voicemail.md) | Inject voicemail entries, social engineering via fake messages |
| [USE_SIP](use-sip.md) | SIP-based call interception, VoIP abuse |
| [ACCEPT_HANDOVER](accept-handover.md) | Hijack ongoing calls from one app to another |

## Play Store Policy

Google restricts phone and call log permissions under the same policy as SMS (January 2019). Apps must be declared as the default dialer or phone handler, or demonstrate an approved core use case. This restriction pushed identifier-harvesting malware toward sideloading and alternative distribution channels.

## Common Combinations

| Combo | Purpose |
|-------|---------|
| `READ_PHONE_STATE` + `INTERNET` | Device fingerprint exfiltration |
| `CALL_PHONE` + `READ_CONTACTS` | Automated calls to victim's contact list |
| `READ_PHONE_STATE` + `READ_SMS` + `RECEIVE_SMS` | Full telephony surveillance with OTP interception |
| `ANSWER_PHONE_CALLS` + `RECORD_AUDIO` | Call interception with recording |

## Families by Phone Permission Abuse

| Family | Primary Phone Permissions | Technique |
|--------|--------------------------|-----------|
| **Fakecalls** | `CALL_PHONE`, `ANSWER_PHONE_CALLS` | Banking trojan that intercepts outbound calls to bank customer service numbers. When the victim dials their bank, the malware drops the real call and connects to an attacker-operated call center instead. Also auto-answers inbound calls from the attacker to deliver vishing scripts. |
| **SpyNote** (CypherRat) | `READ_PHONE_STATE` | Device fingerprinting via IMEI, IMSI, and carrier info. Uses telephony identifiers to track victims across reinstalls and associate stolen data with specific devices. |
| **BRATA** | `CALL_PHONE`, `READ_PHONE_STATE` | Dials premium numbers for revenue, reads phone state to detect active calls and avoid interrupting ongoing conversations that might alert the victim. |
| **Cerberus** | `READ_PHONE_STATE`, `CALL_PHONE` | Harvests device identifiers for victim tracking, can initiate calls to premium numbers. |
| **Pegasus** | `READ_PHONE_STATE`, `ANSWER_PHONE_CALLS` | Full telephony surveillance -- harvests all identifiers, monitors call state, and can silently answer calls for ambient listening. |

## USSD Code Execution via CALL_PHONE

`CALL_PHONE` is not limited to voice calls. It can dial USSD (Unstructured Supplementary Service Data) codes that execute carrier-side commands without any user interaction beyond the initial permission grant:

| USSD Pattern | Effect |
|-------------|--------|
| `tel:*%2321%23` (`*#*#`) | Factory reset on some devices -- wipes all user data |
| `tel:**21*[number]%23` | Unconditional call forwarding -- redirects all incoming calls to attacker's number |
| `tel:**62*[number]%23` | Forward on not reachable -- catches calls when victim's phone is off or out of range |
| `tel:*%23*%23` prefixed codes | Various device/carrier diagnostic and configuration commands |

Call forwarding via USSD is particularly dangerous in financial fraud. The attacker forwards the victim's calls to their own number, then initiates a password reset on the victim's bank account. When the bank calls to verify, the attacker answers and confirms the reset. The victim never sees the incoming call.

## IMEI Harvesting Deprecation

Android 10 (API 29) was a turning point for device fingerprinting. `getDeviceId()`, `getImei()`, and `getSimSerialNumber()` now return `null` for apps targeting API 29+ unless the app holds `READ_PRIVILEGED_PHONE_STATE`, a signature-level permission reserved for system apps.

Malware families adapted with alternative identifiers:

| Identifier | Access Method | Persistence |
|-----------|--------------|-------------|
| `ANDROID_ID` | `Settings.Secure` -- no permission needed | Resets on factory reset, unique per app signing key |
| Google Advertising ID | Play Services API -- no permission needed | User-resettable, but most users never reset it |
| `Build.SERIAL` | Deprecated in API 26, requires `READ_PHONE_STATE` in 26-28, inaccessible in 29+ | Persistent across resets on some devices |
| Hardware MAC | Randomized since Android 10 for Wi-Fi scans | Unreliable for tracking |
| `MediaDrm` device ID | `MediaDrm` API -- no permission needed | Persistent, hard to reset, widely used by modern malware |

The `MediaDrm` Widevine device ID has become the preferred fingerprint for post-Android 10 malware. It requires no permissions, survives app reinstalls, and is consistent across apps on the same device.
