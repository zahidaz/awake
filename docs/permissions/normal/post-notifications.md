# POST_NOTIFICATIONS

Runtime permission introduced in Android 13 (API 33) that controls whether an app can display notifications. Before Android 13, any app could post notifications without asking. This permission directly impacts malware operations: foreground services require a visible notification on Android 8+, phishing attacks use fake notifications to lure users back into the app, and notification suppression techniques require the ability to post notifications first. Malware that cannot obtain this permission on Android 13+ loses a core persistence and social engineering channel.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.POST_NOTIFICATIONS` |
| Protection Level | `dangerous` |
| Permission Group | `NOTIFICATIONS` |
| Grant Method | Runtime permission dialog (Android 13+) |
| Introduced | API 33 (Android 13) |
| User Visibility | "Allow [app] to send you notifications?" dialog |
| Play Store Policy | Must justify notification usage in Data Safety section |

On Android 12 and below, no permission is needed to post notifications. On Android 13+, the runtime dialog appears when the app calls `requestPermissions()`. If denied, the app can still run but cannot display any notifications, including the foreground service notification required by the system.

## What It Enables

### Notification Display

```java
NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
    .setSmallIcon(R.drawable.icon)
    .setContentTitle("Update Available")
    .setContentText("Tap to install critical security update")
    .setPriority(NotificationCompat.PRIORITY_HIGH);
NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, builder.build());
```

### Foreground Service Notification

Android 8+ requires foreground services to display a persistent notification. Without `POST_NOTIFICATIONS` on Android 13+, the foreground service notification is hidden from the user, but the service still runs. This is actually advantageous for malware: the service persists without a visible indicator.

```java
startForeground(NOTIFICATION_ID, notification);
```

## Abuse in Malware

### Social Engineering via Fake Notifications

Malware uses notifications to impersonate system alerts, banking messages, and security warnings:

| Pattern | Technique | Example |
|---------|-----------|---------|
| Fake update | "Critical security update available" notification | Leads to overlay or dropper download |
| Fake banking alert | "Suspicious transaction detected" | Phishes credentials via overlay when tapped |
| Fake 2FA | "Verify your identity" | Triggers accessibility service enablement flow |
| Persistent reminder | Repeated "action required" notifications | Keeps user engaging with malicious app |

### Families Using Notification-Based Attacks

| Family | Notification Abuse | Details |
|--------|-------------------|---------|
| [Anatsa](../../malware/families/anatsa.md) | Fake PDF update notification | Dropper pushes "PDF Update" notification containing payload download |
| [FluBot](../../malware/families/flubot.md) | Fake delivery notification | "Your package is being delivered" with malicious link |
| [GodFather](../../malware/families/godfather.md) | Fake Play Protect alert | Impersonates Google Play Protect to trick users into granting accessibility |
| [Joker](../../malware/families/joker.md) | Fake subscription confirmation | Tricks users into interacting with premium SMS workflows |
| [MoqHao](../../malware/families/moqhao.md) | Chrome impersonation | Persistent notification mimicking Chrome update |
| [Hook](../../malware/families/hook.md) | Minimal foreground notification | Low-priority notification for persistent background service |
| [Cerberus](../../malware/families/cerberus.md) | Fake banking notification | Triggers overlay attack when user taps notification |

### Impact of Android 13+ Restriction

The runtime permission requirement created a split in malware behavior:

| Approach | How It Works |
|----------|-------------|
| Request early | Ask for notification permission immediately after install, before suspicious behavior. Many users grant it reflexively. |
| Skip notifications | Operate without notifications entirely. Foreground service still runs (notification hidden). Lose phishing/social engineering channel. |
| Target older Android | Focus on Android 12 and below where no permission is needed |
| [Accessibility bypass](../../attacks/runtime-permission-manipulation.md) | Use accessibility service to auto-grant the notification permission |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 4.1 | 16 | Notifications API expanded | Rich notification support |
| 8.0 | 26 | Notification channels required | Apps must create channels; users can disable per-channel |
| 8.0 | 26 | Foreground services require notification | Malware must show notification for persistent services |
| 13 | 33 | `POST_NOTIFICATIONS` runtime permission introduced | Apps must request permission; default state is denied for new installs |
| 13 | 33 | Temporary grant for existing apps | Apps installed before Android 13 upgrade retain notification access until user explicitly revokes |
| 14 | 34 | Foreground service type declarations | Services must declare type in manifest |

### Notification Channel Abuse

On Android 8+, apps create notification channels that users can individually control. Malware creates channels with misleading names:

- "System" or "Security" channels that users are reluctant to disable
- `IMPORTANCE_MIN` channels for foreground service notifications (minimized, barely visible)
- `IMPORTANCE_HIGH` channels for phishing notifications (heads-up display, sound)

## Detection Indicators

### Manifest Signals

- `POST_NOTIFICATIONS` requested alongside `BIND_ACCESSIBILITY_SERVICE` or `BIND_NOTIFICATION_LISTENER_SERVICE`
- Notification channel creation with system-impersonating names ("Google Play", "System Update", "Security Alert")
- `IMPORTANCE_HIGH` channels in apps that have no legitimate reason for urgent notifications

### Behavioral Signals

- Notification content containing URLs or deep links to WebView-based overlays
- Notifications posted immediately after app install requesting further permissions
- Rapid notification posting followed by notification cancellation (flash notifications)
