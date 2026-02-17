# Broadcast Theft

Intercepting broadcast intents meant for other apps. Android's broadcast system sends messages to all registered receivers. If a broadcast carries sensitive data and isn't properly protected, any app can register a receiver and read it.

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1624.001](https://attack.mitre.org/techniques/T1624/001/) | Event Triggered Execution: Broadcast Receivers | Persistence |

    T1624.001 covers registering for intents broadcasted by other applications, enabling interception of broadcasts not intended for the malicious app.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | Varies. Some broadcasts require permissions (e.g., `RECEIVE_SMS`). Others are unprotected. |
    | Condition | Target broadcast is not permission-protected or is ordered |

## How Broadcasts Work

An app sends a broadcast, and all registered `BroadcastReceiver` components matching the intent filter receive it. Two types:

**Normal broadcasts** (`sendBroadcast()`): delivered to all receivers simultaneously. No ordering, no priority, no ability to cancel.

**Ordered broadcasts** (`sendOrderedBroadcast()`): delivered sequentially by priority. Higher-priority receivers run first and can modify or cancel the broadcast before lower-priority receivers see it.

## Attack Patterns

### SMS Interception

The `SMS_RECEIVED` broadcast is ordered. Malware registers a receiver with maximum priority:

```xml
<receiver android:name=".SmsReceiver" android:exported="true">
    <intent-filter android:priority="999">
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

The malware receives the SMS first, extracts the OTP, and can call `abortBroadcast()` to prevent the default SMS app from showing it. The user never sees the message.

On Android 4.4+, only the default SMS app can abort SMS broadcasts, but malware can still read the content and forward it without aborting.

### Sticky Broadcast Leakage

Sticky broadcasts (deprecated in API 21) persist after being sent. Any app calling `registerReceiver()` with the matching filter receives the last sticky broadcast. This was used to leak battery status, charging state, and other system info.

`ACTION_BATTERY_CHANGED` is still a sticky broadcast and leaks detailed battery information without any permission.

### Custom Broadcast Interception

Apps that define custom broadcast actions without permission protection are vulnerable:

```java
sendBroadcast(new Intent("com.myapp.USER_LOGGED_IN")
    .putExtra("token", authToken));
```

Any app with a matching receiver sees this:

```xml
<receiver android:name=".TokenStealer" android:exported="true">
    <intent-filter>
        <action android:name="com.myapp.USER_LOGGED_IN" />
    </intent-filter>
</receiver>
```

### Boot Broadcast Race

Multiple apps receiving `BOOT_COMPLETED` race to start. Malware that starts first can interfere with security software that starts later.

## Security-Relevant System Broadcasts

| Broadcast | Data Exposed | Permission Required |
|-----------|-------------|-------------------|
| `SMS_RECEIVED` | SMS content, sender | `RECEIVE_SMS` |
| `WAP_PUSH_RECEIVED` | MMS push data | `RECEIVE_WAP_PUSH` |
| `NEW_OUTGOING_CALL` | Dialed number | `PROCESS_OUTGOING_CALLS` |
| `PHONE_STATE` | Call state, phone number | `READ_PHONE_STATE` |
| `BATTERY_CHANGED` | Battery level, charging, temperature | None |
| `CONNECTIVITY_CHANGE` | Network state changes | None (deprecated API 28) |
| `PACKAGE_ADDED/REMOVED` | Package name of installed/removed app | None |
| `BOOT_COMPLETED` | Device booted | `RECEIVE_BOOT_COMPLETED` |

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 1.0 | 1 | Broadcast system with ordered broadcasts | Any app can intercept any unprotected broadcast |
| 3.1 | 12 | Apps in stopped state don't receive broadcasts | Must be launched once; malware is typically already running |
| 4.4 | 19 | Only default SMS app can abort `SMS_RECEIVED` | Malware can still read SMS content without aborting |
| 5.0 | 21 | Sticky broadcasts deprecated | Legacy sticky broadcasts like `ACTION_BATTERY_CHANGED` still work |
| 8.0 | 26 | [Implicit broadcast restrictions](https://developer.android.com/about/versions/oreo/background#broadcasts) | Exempt broadcasts (`BOOT_COMPLETED`, `SMS_RECEIVED`) still delivered; dynamic registration still works |
| 14 | 34 | Context-registered receivers must declare [`RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED`](https://developer.android.com/about/versions/14/behavior-changes-14#runtime-receivers-exported) | Malware explicitly sets `RECEIVER_EXPORTED` |

## Families Using This Technique

SMS and broadcast interception is used by virtually every banking trojan for OTP theft. This table covers the primary use case for each family.

| Family | Broadcast Type | Purpose |
|--------|---------------|---------|
| [Cerberus](../malware/families/cerberus.md) | SMS_RECEIVED | 2FA OTP interception |
| [Anubis](../malware/families/anubis.md) | SMS_RECEIVED | OTP theft, SMS forwarding to C2 |
| [Hook](../malware/families/hook.md) | SMS_RECEIVED | OTP interception during ATS |
| [Ermac](../malware/families/ermac.md) | SMS_RECEIVED | 2FA bypass |
| [GodFather](../malware/families/godfather.md) | SMS_RECEIVED, PHONE_STATE | OTP theft, call state monitoring |
| [Hydra](../malware/families/hydra.md) | SMS_RECEIVED | OTP interception |
| [Octo](../malware/families/octo.md) | SMS_RECEIVED | OTP interception during remote access |
| [Medusa](../malware/families/medusa.md) | SMS_RECEIVED | 2FA bypass |
| [Xenomorph](../malware/families/xenomorph.md) | SMS_RECEIVED | OTP capture for ATS engine |
| [Anatsa](../malware/families/anatsa.md) | SMS_RECEIVED | OTP theft during automated transfers |
| [FluBot](../malware/families/flubot.md) | SMS_RECEIVED | OTP theft, SMS worm propagation |
| [Joker](../malware/families/joker.md) | SMS_RECEIVED | Premium subscription OTP confirmation |
| [GriftHorse](../malware/families/grifthorse.md) | SMS_RECEIVED | Premium SMS confirmation interception |
| [Harly](../malware/families/harly.md) | SMS_RECEIVED | Subscription confirmation codes |
| [SpyNote](../malware/families/spynote.md) | SMS_RECEIVED, PHONE_STATE | Full SMS/call surveillance |
| [Rafel RAT](../malware/families/rafelrat.md) | SMS_RECEIVED | SMS interception, ransomware unlock codes |
| [TrickMo](../malware/families/trickmo.md) | SMS_RECEIVED | OTP theft, originally TrickBot 2FA bypass |
| [Vultur](../malware/families/vultur.md) | SMS_RECEIVED | OTP interception |
| [SharkBot](../malware/families/sharkbot.md) | SMS_RECEIVED | OTP capture for ATS |
| [Chameleon](../malware/families/chameleon.md) | SMS_RECEIVED | 2FA bypass after biometric prompt disable |
| [Mamont](../malware/families/mamont.md) | SMS_RECEIVED | Notification and SMS interception |
| [TsarBot](../malware/families/tsarbot.md) | SMS_RECEIVED | OTP capture, 750+ target apps |
| [Antidot](../malware/families/antidot.md) | SMS_RECEIVED | 2FA interception |
| [Crocodilus](../malware/families/crocodilus.md) | SMS_RECEIVED | OTP theft during DTO |
| [Copybara](../malware/families/copybara.md) | SMS_RECEIVED | OTP interception |
| [Fakecalls](../malware/families/fakecalls.md) | NEW_OUTGOING_CALL | Call interception and redirection |
| [MoqHao](../malware/families/moqhao.md) | SMS_RECEIVED, PACKAGE_ADDED | SMS theft, app install monitoring |
| [Alien](../malware/families/alien.md) | SMS_RECEIVED | Notification sniffing for 2FA codes |
| [BRATA](../malware/families/brata.md) | SMS_RECEIVED | OTP theft before factory reset |
| [BankBot](../malware/families/bankbot.md) | SMS_RECEIVED | Early SMS-based OTP theft |
| [Albiriox](../malware/families/albiriox.md) | SMS_RECEIVED | OTP interception |
| [FireScam](../malware/families/firescam.md) | SMS_RECEIVED | Notification and SMS interception across all apps |
| [DeVixor](../malware/families/devixor.md) | SMS_RECEIVED | OTP interception for Iranian banking fraud |

[Fakecalls](../malware/families/fakecalls.md) is unique in using `NEW_OUTGOING_CALL` to intercept outgoing calls to bank numbers and redirect them to attacker-controlled lines with pre-recorded IVR audio.

## Detection During Analysis

??? example "Static Indicators"

    - `BroadcastReceiver` with high `android:priority` (especially for `SMS_RECEIVED`)
    - Receivers for system broadcasts containing sensitive data
    - Custom broadcasts sent with sensitive extras and no permission parameter
    - `sendBroadcast()` without `LocalBroadcastManager` for internal communication

??? example "Dynamic Indicators"

    - SMS content forwarded to C2 immediately after receipt
    - `abortBroadcast()` calls inside SMS receivers (suppressing notifications)
    - Broadcast receivers triggering network exfiltration on `BOOT_COMPLETED`
    - Multiple apps competing for the same ordered broadcast
