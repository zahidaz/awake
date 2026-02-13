# SMS Permissions

SMS permissions provide access to send, receive, and read text messages. Heavily regulated by Google Play policy since SMS is one of the most abused permission groups: OTP interception, premium SMS fraud, and worm-like spreading via phishing messages.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [READ_SMS](read-sms.md) | Read stored messages, harvest OTPs retroactively |
| [RECEIVE_SMS](receive-sms.md) | Intercept incoming messages in real-time, suppress notifications |
| [SEND_SMS](send-sms.md) | Send messages for premium fraud, phishing distribution, C2 communication |
| [RECEIVE_WAP_PUSH](receive-wap-push.md) | Intercept MMS push notifications |
| [RECEIVE_MMS](receive-mms.md) | Intercept incoming MMS messages |

## Play Store Policy

Since January 2019, Google restricts SMS and Call Log permissions to apps declared as the default SMS handler or that have an approved use case. Apps that cannot justify the need are rejected. This pushed malware distribution toward sideloading and alternative stores.

Malware works around this by:

- Using accessibility to read SMS notifications instead of the SMS permission
- Using notification listener service to intercept OTPs
- Distributing outside Play Store via smishing (SMS phishing) links

## Families by SMS Permission Abuse

| Family | Primary SMS Permissions | Technique |
|--------|------------------------|-----------|
| [**FluBot**](../../malware/families/flubot.md) | `SEND_SMS`, `READ_CONTACTS` | Worm behavior -- reads the contact list and sends SMS phishing messages to every entry, propagating itself across the victim's social graph |
| [**Joker**](../../malware/families/joker.md) (Bread) | `SEND_SMS`, `RECEIVE_SMS` | Premium SMS fraud -- subscribes victims to paid services by sending SMS to premium numbers and intercepting confirmation messages to complete the signup silently |
| [**Anubis**](../../malware/families/anubis.md) | `RECEIVE_SMS`, `READ_SMS` | Banking trojan -- intercepts OTP codes sent via SMS to bypass two-factor authentication on financial accounts |
| [**Cerberus**](../../malware/families/cerberus.md) | `RECEIVE_SMS`, `READ_SMS` | Banking trojan -- real-time OTP interception with automatic forwarding to C2, also reads stored SMS for account recovery codes |
| [**BRATA**](../../malware/families/brata.md) | `RECEIVE_SMS`, `READ_SMS`, `SEND_SMS` | Banking trojan -- intercepts OTPs, can send SMS to attacker-controlled numbers, performs factory reset via device admin after successful theft |
| [**Pegasus**](../../malware/families/pegasus.md) | `READ_SMS`, `RECEIVE_SMS` | State-sponsored -- full SMS database exfiltration for intelligence collection, not fraud |

## SMS as C2 Channel

Some families use SMS for command and control as a fallback when internet connectivity is unavailable or when network-level monitoring makes HTTP/HTTPS C2 too risky:

- The operator sends specially formatted SMS messages to the infected device containing encoded commands
- The implant parses incoming SMS, executes the command, and optionally replies via SMS with results
- SMS-based C2 is harder to block than domain-based C2 because it does not rely on DNS or IP infrastructure that defenders can sinkhole
- The tradeoff is visibility -- SMS messages appear in carrier logs and can be intercepted by lawful interception systems, making this channel less covert than encrypted HTTPS

This technique is most common in state-sponsored tooling (FinSpy, early Pegasus variants) where the operator controls or has access to carrier infrastructure, neutralizing the visibility risk.

## Evolution: Notification Listeners Replace SMS Permissions

Modern families increasingly avoid requesting SMS permissions entirely. Instead, they use `NotificationListenerService` to read OTP codes as they appear in the notification shade:

- **No runtime permission required** -- the user enables the notification listener through Settings > Apps > Special Access, which malware guides the user toward via overlay or social engineering
- **Broader coverage** -- notification listeners capture OTPs from SMS, WhatsApp, email, and authenticator apps through a single access grant
- **Evades Play Store policy** -- since the app never requests `READ_SMS` or `RECEIVE_SMS`, it does not trigger Google's restricted permission review
- **Families using this approach** include [Xenomorph](../../malware/families/xenomorph.md), [SharkBot](../../malware/families/sharkbot.md), and recent [Vultur](../../malware/families/vultur.md) variants, which have dropped SMS permissions entirely in favor of notification access combined with accessibility services
