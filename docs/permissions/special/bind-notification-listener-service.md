# BIND_NOTIFICATION_LISTENER_SERVICE

Allows reading the content of all notifications posted by any app. Increasingly used as an alternative to `READ_SMS` for OTP interception: banks send OTP codes that appear in notifications, and a notification listener captures them without needing SMS permissions.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE` |
| Protection Level | `signature` |
| Grant Method | Settings > Apps > Special access > Notification access |
| Introduced | API 18 (Android 4.3) |

Like accessibility services, only the system can bind to a notification listener. The user must manually enable it in settings.

## What It Enables

The service receives callbacks for every notification posted or removed on the device:

```java
public class NotifListener extends NotificationListenerService {
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        String packageName = sbn.getPackageName();
        String text = sbn.getNotification().extras.getString(Notification.EXTRA_TEXT);
        String title = sbn.getNotification().extras.getString(Notification.EXTRA_TITLE);
    }
}
```

Capabilities:

| Capability | Method |
|-----------|--------|
| Read notification content | `onNotificationPosted()` |
| Read notification history | `getActiveNotifications()` |
| Dismiss notifications | `cancelNotification()` |
| Snooze notifications | `snoozeNotification()` (API 26+) |

## Abuse in Malware

### OTP Interception (SMS Alternative)

Many banks and services include the OTP code directly in the notification text. A notification listener grabs it without needing `READ_SMS` or `RECEIVE_SMS`:

1. User triggers a login/transaction that requires 2FA
2. Bank sends SMS with OTP
3. Phone displays notification: "Your code is 123456"
4. Notification listener reads the notification text
5. Malware forwards the code to C2

This bypasses Google Play's SMS permission restrictions, since notification access is not subject to the same policy scrutiny.

### Message Exfiltration

Read messages from WhatsApp, Telegram, Signal, and other messaging apps via their notifications. Each notification contains sender name and message preview.

### Notification Dismissal

Malware can dismiss notifications to hide its activity:

- Dismiss banking app transaction alerts
- Dismiss security warnings
- Dismiss AV detection notifications

### Foreground App Detection

Notifications from apps reveal which apps are active, serving as an alternative to `UsageStatsManager` for timing overlay attacks.

### Notable Families

| Family | Notification Usage |
|--------|-------------------|
| [Cerberus](../../malware/families/cerberus.md) | Notification-based OTP theft as alternative to SMS |
| [Alien](../../malware/families/alien.md) | Notification sniffing for 2FA codes. First family to make this a primary feature. |
| [Xenomorph](../../malware/families/xenomorph.md) | Notification listener for OTP + message exfiltration |
| [Joker](../../malware/families/joker.md) | Read notifications to confirm premium subscriptions |
| [Hook](../../malware/families/hook.md) | Notification interception for WhatsApp message exfiltration |
| [Mamont](../../malware/families/mamont.md) | Notification interception as primary OTP theft mechanism |
| [GodFather](../../malware/families/godfather.md) | Notification-based push OTP capture |
| [Medusa](../../malware/families/medusa.md) v2 | Reduced to 5 permissions, uses notification listener instead of SMS |
| [ToxicPanda](../../malware/families/toxicpanda.md) | Notification interception for OTP codes |
| [Sturnus](../../malware/families/sturnus.md) | Notification capture from encrypted messaging apps |

## Android Version Changes

**Android 4.3 (API 18)**: notification listener service introduced.

**Android 13 (API 33)**: subject to restricted settings. Apps sideloaded from outside recognized stores cannot direct users to notification access settings.

**Android 13+**: `POST_NOTIFICATIONS` runtime permission required for apps to show their own notifications (separate concern, but affects the ecosystem).

## Detection

In the manifest:

```xml
<service
    android:name=".NotifListener"
    android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
    <intent-filter>
        <action android:name="android.service.notification.NotificationListenerService" />
    </intent-filter>
</service>
```

Any app declaring this that isn't a notification management utility warrants investigation.
