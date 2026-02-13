# Notification Listener Abuse

Exploiting `NotificationListenerService` to silently read, exfiltrate, and dismiss notifications from every app on the device. As Android progressively restricted SMS permissions and Google Play banned their use in most apps, malware pivoted to notification listeners as the primary channel for OTP theft, message surveillance, and evidence suppression.

See also: [Notification Suppression](notification-suppression.md), [SMS Interception](sms-interception.md)

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`BIND_NOTIFICATION_LISTENER_SERVICE`](../permissions/special/bind-notification-listener-service.md) |
    | Grant Method | User must manually enable in Settings > Apps > Special access > Notification access |
    | Introduced | API 18 (Android 4.3) |

## Why Malware Moved to Notification Listeners

Google's January 2019 policy change restricted `READ_SMS` and `RECEIVE_SMS` to apps declared as the default SMS handler. Apps that could not justify the need were rejected from Play Store. This created a gap that notification listeners filled:

| Factor | SMS Interception | Notification Listener |
|--------|------------------|-----------------------|
| Play Store policy | Restricted since 2019 | No policy restriction |
| Runtime permission | `RECEIVE_SMS` runtime prompt | No runtime prompt -- Settings toggle |
| Coverage | SMS only | SMS, WhatsApp, Telegram, email, authenticator apps, push notifications |
| Real-time | Yes | Yes |
| Can suppress delivery | Yes (`abortBroadcast`, pre-4.4) | Yes (`cancelNotification`) |
| Works on Android 10+ | Heavily restricted | Fully functional |

## How It Works

### Service Declaration

The malware declares a `NotificationListenerService` in its manifest:

```xml
<service
    android:name=".NLService"
    android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
    <intent-filter>
        <action android:name="android.service.notification.NotificationListenerService" />
    </intent-filter>
</service>
```

Once the user enables notification access, the system binds to this service and delivers every notification event.

### StatusBarNotification Fields

Each callback receives a `StatusBarNotification` object. The fields malware targets:

| Field | Access Path | Data |
|-------|-------------|------|
| Source app | `sbn.getPackageName()` | Identifies which app posted the notification |
| Title | `notification.extras.getString(EXTRA_TITLE)` | Sender name, app name, or subject line |
| Text | `notification.extras.getString(EXTRA_TEXT)` | Message body, OTP code, transaction details |
| Big text | `notification.extras.getString(EXTRA_BIG_TEXT)` | Expanded notification content with full message |
| Subtext | `notification.extras.getString(EXTRA_SUB_TEXT)` | Account identifiers, secondary info |
| Post time | `sbn.getPostTime()` | When the notification was posted |
| Key | `sbn.getKey()` | Used to dismiss specific notifications |

### OTP Extraction

The core malware use case. Banking apps, email providers, and SMS all surface OTP codes in notification text. The extraction flow:

```java
public class NLService extends NotificationListenerService {
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        Bundle extras = sbn.getNotification().extras;
        String text = extras.getString(Notification.EXTRA_TEXT);
        String bigText = extras.getString(Notification.EXTRA_BIG_TEXT);
        String content = bigText != null ? bigText : text;

        if (content == null) return;

        String otp = extractOtp(content);
        if (otp != null) {
            exfiltrateToC2(sbn.getPackageName(), otp);
            cancelNotification(sbn.getKey());
        }
    }

    private String extractOtp(String text) {
        Matcher m = Pattern.compile("\\b(\\d{4,8})\\b").matcher(text);
        if (m.find()) return m.group(1);
        return null;
    }
}
```

Malware typically filters by package name to target specific banking or authentication apps, then uses regex to pull numeric codes from the notification body. After extraction, the notification is dismissed so the user never sees it.

### Message Surveillance

Messaging app notifications expose sender and preview text. WhatsApp, Telegram, Signal, and SMS all display message previews in the notification shade. The listener captures:

- **WhatsApp**: sender name in `EXTRA_TITLE`, message content in `EXTRA_TEXT`
- **Telegram**: channel/contact name in title, message preview in text
- **SMS/MMS**: phone number or contact name in title, message body in text
- **Email**: subject in title, preview text in body

For group chats, `EXTRA_TEXT` typically contains "Sender: message" format, giving the listener both the sender identity and content.

### Notification Dismissal

`cancelNotification(key)` removes a notification from the shade. Malware uses this to:

- Hide OTP notifications after extracting the code, preventing the user from noticing the 2FA attempt
- Suppress banking transaction alerts that would reveal unauthorized transfers
- Dismiss antivirus detection notifications
- Remove Google Play Protect warnings

The user sees nothing -- the notification appears and vanishes within milliseconds.

## Auto-Enabling via Accessibility

The notification listener requires manual user enablement in Settings. Malware with an active [accessibility service](accessibility-abuse.md) automates this:

1. Open `Settings` via intent: `android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS`
2. Use accessibility to find the malware's entry in the list
3. Tap the toggle to enable it
4. Navigate back, dismiss any confirmation dialogs

This requires no user interaction beyond the initial accessibility service grant. Several families chain the two: accessibility enables notification listener, and both work in tandem for full device surveillance.

## OTP Theft: Method Comparison

| Method | Permission | Coverage | Suppress | Android 10+ | Play Store | Stealth |
|--------|-----------|----------|----------|-------------|------------|---------|
| SMS broadcast receiver | `RECEIVE_SMS` | SMS only | Pre-4.4 only | Restricted | Banned | Low |
| ContentResolver SMS query | `READ_SMS` | Stored SMS | No | Restricted | Banned | Low |
| Notification listener | `BIND_NOTIFICATION_LISTENER_SERVICE` | All notifying apps | Yes | Works | Allowed | High |
| Accessibility screen reading | `BIND_ACCESSIBILITY_SERVICE` | Full screen content | No | Works | Scrutinized | High |
| SmsRetriever API | None | App-specific SMS | No | Works | Allowed | Very high |

Notification listeners hit the sweet spot: broad coverage, ability to suppress evidence, no runtime permission dialog, and less Play Store scrutiny than accessibility services.

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 4.3 (API 18) | `NotificationListenerService` introduced with manual user enablement | Social engineering or accessibility auto-enable |
| Android 5.0 (API 21) | `cancelNotification(key)` added for precise dismissal | Malware uses this offensively to suppress evidence |
| Android 8.0 (API 26) | Notification channels provide more context | Gives listeners more filtering capability, not less |
| Android 11 (API 30) | Notification history API (`getNotificationHistory()`) | Listeners retroactively access recent notifications even if not running when posted |
| Android 13 (API 33) | Restricted settings for sideloaded apps; cannot direct to notification access settings | Bypassed via session-based installers or store distribution |
| Android 14 (API 34) | Further tightening of restricted settings | Malware adapts installer package name to appear store-distributed |

## Families Using This Technique

| Family | Notification Abuse | Primary Purpose |
|--------|-------------------|-----------------|
| [Joker](../malware/families/joker.md) | Reads confirmation notifications to complete premium subscriptions silently | Subscription fraud |
| [Anatsa](../malware/families/anatsa.md) | Extracts OTPs from banking notifications during automated transfers | ATS-based bank fraud |
| [Cerberus](../malware/families/cerberus.md) | Notification-based 2FA theft as fallback when SMS interception fails | Banking credential theft |
| [GodFather](../malware/families/godfather.md) | Monitors push notifications for OTPs across 400+ banking targets | Banking fraud |
| [Mamont](../malware/families/mamont.md) | Push notification interception as primary OTP mechanism, avoids SMS permissions entirely | Russian banking fraud |
| [Fakecalls](../malware/families/fakecalls.md) | Hides call-related notifications to maintain the illusion of a legitimate bank call | VoIP call spoofing |
| [Xenomorph](../malware/families/xenomorph.md) | Notification listener for OTP capture plus message exfiltration from messaging apps | Banking ATS |
| [Hook](../malware/families/hook.md) | WhatsApp message exfiltration via notification interception | Surveillance, banking fraud |
| [Alien](../malware/families/alien.md) | First major family to use notification sniffing as a primary 2FA bypass | Banking credential theft |
| [Medusa](../malware/families/medusa.md) | v2 dropped SMS permissions, relies on notification listener for OTP theft | Banking fraud |
| [ToxicPanda](../malware/families/toxicpanda.md) | Notification interception for OTP codes during on-device fraud | Banking ATS |
| [Sturnus](../malware/families/sturnus.md) | Captures notifications from encrypted messaging apps | Banking fraud |
| [FireScam](../malware/families/firescam.md) | Intercepts notifications across all apps for broad surveillance | Spyware |
| [SpyNote](../malware/families/spynote.md) | Full notification monitoring as part of comprehensive device surveillance | RAT |

Joker deserves special mention: it reads incoming SMS confirmation codes from notifications to silently complete WAP billing subscriptions, never needing SMS permissions and never alerting the user.

## Detection During Analysis

??? example "Static Indicators"

    - `NotificationListenerService` in manifest with `BIND_NOTIFICATION_LISTENER_SERVICE` permission
    - References to `Notification.EXTRA_TEXT`, `EXTRA_TITLE`, `EXTRA_BIG_TEXT`
    - Regex patterns targeting numeric OTP codes (4-8 digit sequences)
    - `cancelNotification()` or `cancelAllNotifications()` calls
    - Intent action `ACTION_NOTIFICATION_LISTENER_SETTINGS` indicating automated enablement

??? example "Dynamic Indicators"

    - App requesting notification access during installation flow
    - Accessibility service navigating to notification listener settings
    - Network traffic containing notification content or extracted OTP codes shortly after notification events
    - Notifications disappearing from the shade faster than the user could read them
