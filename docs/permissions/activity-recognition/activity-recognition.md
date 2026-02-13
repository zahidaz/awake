# ACTIVITY_RECOGNITION

Allows detecting the user's physical activity: walking, running, cycling, driving, tilting, or stationary. Uses accelerometer, gyroscope, and other motion sensors to classify movement.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACTIVITY_RECOGNITION` |
| Protection Level | `dangerous` |
| Permission Group | `ACTIVITY_RECOGNITION` |
| Grant Method | Runtime permission dialog |
| Introduced | API 29 (Android 10) |

Before Android 10, activity recognition data was available without any permission through the Google Activity Recognition API.

## What It Enables

Access to `ActivityRecognitionClient` (Google Play Services) or `SensorManager` for motion classification:

| Activity | Detection |
|----------|-----------|
| Still | Device stationary |
| Walking | Pedestrian movement |
| Running | Fast pedestrian movement |
| Cycling | Bicycle movement |
| In vehicle | Automotive movement |
| Tilting | Device orientation change |
| Unknown | Unclassified movement |

## Abuse in Malware

### Behavioral Profiling

Stalkerware uses activity data to track daily patterns:

- When the target leaves home (transitions from still to walking/driving)
- Commute patterns and timing
- Exercise routines
- Sleep schedule (extended still periods)

### Trigger-Based Actions

Malware can trigger specific actions based on activity state transitions. The `ActivityRecognitionClient` provides transition callbacks that are ideal for conditional surveillance:

```java
ActivityRecognitionClient client = ActivityRecognition.getClient(context);

List<ActivityTransition> transitions = new ArrayList<>();
transitions.add(new ActivityTransition.Builder()
    .setActivityType(DetectedActivity.IN_VEHICLE)
    .setActivityTransition(ActivityTransition.ACTIVITY_TRANSITION_ENTER)
    .build());
transitions.add(new ActivityTransition.Builder()
    .setActivityType(DetectedActivity.STILL)
    .setActivityTransition(ActivityTransition.ACTIVITY_TRANSITION_ENTER)
    .build());

ActivityTransitionRequest request = new ActivityTransitionRequest(transitions);
Intent intent = new Intent(context, ActivityReceiver.class);
PendingIntent pendingIntent = PendingIntent.getBroadcast(
    context, 0, intent, PendingIntent.FLAG_MUTABLE
);
client.requestActivityTransitionUpdates(request, pendingIntent);
```

The `BroadcastReceiver` then triggers surveillance actions based on the detected transition:

```java
public class ActivityReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        ActivityTransitionResult result = ActivityTransitionResult.extractResult(intent);
        for (ActivityTransitionEvent event : result.getTransitionEvents()) {
            if (event.getActivityType() == DetectedActivity.STILL) {
                startAudioRecording(context);
            }
            if (event.getActivityType() == DetectedActivity.IN_VEHICLE) {
                startLocationTracking(context);
                scheduleDataExfiltration(context);
            }
        }
    }
}
```

This allows malware to:

- Start location tracking when the user begins driving
- Activate microphone recording when the user is stationary (in a meeting)
- Defer data exfiltration until the user is in a vehicle (likely not looking at phone)
- Adjust polling frequency based on movement state to conserve battery

### Context Enhancement

Activity data combined with location creates richer surveillance: not just where someone is, but what they're doing there.

### Anti-Analysis and Sandbox Evasion

Activity recognition can serve as an environment fingerprint. Emulators and sandboxes produce no real activity transitions. Malware can delay payload activation until it detects genuine activity state changes, confirming execution on a real device:

```java
client.requestActivityUpdates(5000, pendingIntent);
```

If the callback never fires or always returns `DetectedActivity.UNKNOWN`, the app can assume it is running in a sandbox and suppress malicious behavior.

### Notable Families

No major malware families have been publicly documented abusing `ACTIVITY_RECOGNITION` as a primary capability. However, the permission was only introduced in Android 10, and before that, activity recognition data was freely available without any permission through the Google Activity Recognition API. This means pre-2019 stalkerware and surveillance tools could collect activity data silently.

Commercial spyware platforms like [Pegasus](../../malware/families/pegasus.md) and [Hermit](../../malware/families/hermit.md) collect comprehensive device state including motion data, but they do so through root-level access or exploitation rather than the `ACTIVITY_RECOGNITION` permission. Stalkerware families like [SpyNote](../../malware/families/spynote.md) focus on higher-value data (GPS, camera, microphone) and have not been documented adding activity recognition to their collection modules.

## Android Version Changes

**Pre-Android 10**: activity recognition data was available without any permission through the Google Activity Recognition API (part of Google Play Services). Any app could silently monitor user activity.

**Android 10 (API 29)**: `ACTIVITY_RECOGNITION` introduced as a runtime permission. Apps targeting API 29+ must request this permission before using `ActivityRecognitionClient` or the `SensorManager` step detector/counter. Apps targeting lower API levels can still access the data without the permission, even on Android 10 devices.

**Android 12 (API 31)**: apps targeting API 31+ must request the permission regardless of what API level they target. The backward-compatibility exemption was removed.

**Android 14 (API 34)**: no significant changes to the permission itself, but Google Play policies increasingly require justification for activity recognition access in app review.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.ACTIVITY_RECOGNITION" />
```

Expected in fitness, navigation, and transportation apps. Suspicious in apps with no movement-related functionality.

### Static Analysis Indicators

- `ActivityRecognition.getClient()` or `ActivityRecognitionClient` usage
- `ActivityTransitionRequest` construction with specific transition types
- `PendingIntent` registered for activity transition callbacks
- `DetectedActivity` constants used in conditional logic (especially `IN_VEHICLE`, `STILL`, `ON_FOOT`)
- `BroadcastReceiver` implementations that trigger other permissions (audio recording, location) based on activity state

### Dynamic Analysis Indicators

- App registers for activity transition updates immediately after installation
- Activity state data appearing in network traffic payloads
- Other surveillance actions (recording, location tracking) triggered only after specific activity transitions
- App behavior changes between emulator (no transitions) and real device (active transitions)

### Permission Combination Red Flags

`ACTIVITY_RECOGNITION` combined with [ACCESS_FINE_LOCATION](../location/access-fine-location.md) and [RECORD_AUDIO](../microphone/record-audio.md) suggests context-aware surveillance. Combined with [RECEIVE_BOOT_COMPLETED](../normal/receive-boot-completed.md), the app restarts activity monitoring after every reboot. The most suspicious combination is `ACTIVITY_RECOGNITION` + `INTERNET` + `RECEIVE_BOOT_COMPLETED` in an app with no fitness, navigation, or transportation UI.
