# BODY_SENSORS_BACKGROUND

Allows accessing body sensor data while the app is in the background. Extends `BODY_SENSORS` to continuous monitoring without requiring the app to be visible.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BODY_SENSORS_BACKGROUND` |
| Protection Level | `dangerous` |
| Grant Method | Runtime permission dialog (separate from foreground sensor access) |
| Introduced | API 33 (Android 13) |

## What It Enables

Continuous sensor data collection without user interaction. The app does not need to be in the foreground or show a notification (unlike foreground services for location).

```java
SensorManager sensorManager = (SensorManager) getSystemService(SENSOR_SERVICE);
Sensor heartRate = sensorManager.getDefaultSensor(Sensor.TYPE_HEART_RATE);

sensorManager.registerListener(new SensorEventListener() {
    @Override
    public void onSensorChanged(SensorEvent event) {
        float bpm = event.values[0];
        storeLocally(bpm, event.timestamp);
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }
}, heartRate, SensorManager.SENSOR_DELAY_NORMAL);
```

With `BODY_SENSORS_BACKGROUND` granted, this listener continues receiving events even when the app is not visible. Without the background permission, the listener is suspended when the app leaves the foreground.

## Abuse in Malware

No known malware families currently request `BODY_SENSORS_BACKGROUND`. The permission was introduced in Android 13 and has an extremely narrow legitimate use case, making it both rare in the wild and conspicuous when present.

### Stalkerware: The Primary Threat

`BODY_SENSORS_BACKGROUND` is purpose-built for the stalkerware threat model. A surveillance app installed by an abusive partner could continuously monitor the victim's heart rate and step count without any visible indicator. The data reveals:

- **Sleep patterns**: extended periods of low heart rate and zero steps
- **Exercise and movement**: elevated heart rate combined with step activity
- **Emotional state**: resting heart rate spikes can correlate with stress, anxiety, or fear
- **Daily routine**: step count patterns reveal commute timing, work schedule, and deviations from routine

Unlike [ACCESS_BACKGROUND_LOCATION](../location/access-background-location.md), which requires a persistent notification on Android 12+, background body sensor access has no mandatory user-visible indicator, making it harder for the victim to detect.

### Continuous Biometric Exfiltration

A surveillance app could batch-collect sensor data in a local database and periodically exfiltrate during scheduled sync windows:

```java
public class SensorCollector extends Service {
    private SensorManager sensorManager;
    private SQLiteDatabase db;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        sensorManager = (SensorManager) getSystemService(SENSOR_SERVICE);
        db = new SensorDatabase(this).getWritableDatabase();

        Sensor heartRate = sensorManager.getDefaultSensor(Sensor.TYPE_HEART_RATE);
        Sensor stepCounter = sensorManager.getDefaultSensor(Sensor.TYPE_STEP_COUNTER);

        SensorEventListener listener = new SensorEventListener() {
            @Override
            public void onSensorChanged(SensorEvent event) {
                ContentValues values = new ContentValues();
                values.put("sensor_type", event.sensor.getType());
                values.put("value", event.values[0]);
                values.put("timestamp", System.currentTimeMillis());
                db.insert("sensor_data", null, values);
            }

            @Override
            public void onAccuracyChanged(Sensor sensor, int accuracy) {
            }
        };

        sensorManager.registerListener(listener, heartRate, SensorManager.SENSOR_DELAY_NORMAL);
        sensorManager.registerListener(listener, stepCounter, SensorManager.SENSOR_DELAY_NORMAL);

        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
```

## Android Version Changes

**Android 13 (API 33)**: `BODY_SENSORS_BACKGROUND` introduced. This mirrors the pattern established with `ACCESS_BACKGROUND_LOCATION` in Android 10 -- splitting foreground and background access into separate runtime permissions that must be granted independently. Users see a separate permission dialog specifically for background sensor access.

**Android 14 (API 34)**: Health Connect API encouraged as the preferred mechanism for health data access. Apps using Health Connect rather than direct sensor access follow a different permission model.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.BODY_SENSORS_BACKGROUND" />
```

Very few legitimate apps need background body sensor access outside of dedicated health monitoring apps.

### Static Analysis Indicators

- Manifest declares both `BODY_SENSORS` and `BODY_SENSORS_BACKGROUND`
- `SensorEventListener` registration inside a `Service` rather than an `Activity`
- `START_STICKY` return from `onStartCommand()` combined with sensor registration (indicates persistent collection)
- Local database writes in `onSensorChanged()` callbacks (batch collection for later exfiltration)

### Dynamic Analysis Indicators

- Sensor event listeners remain active after the app is swiped away from recents
- Background service continuously consuming sensor data without any foreground UI
- Periodic network bursts containing timestamped biometric data
- Battery usage attributed to sensor wake locks without corresponding user activity

### Permission Combination Red Flags

`BODY_SENSORS_BACKGROUND` is suspicious in almost any app that is not a dedicated health monitoring platform. Combined with `INTERNET` and [RECEIVE_BOOT_COMPLETED](../normal/receive-boot-completed.md), it indicates an app designed to persistently collect and exfiltrate biometric data across device reboots. Combined with [ACCESS_BACKGROUND_LOCATION](../location/access-background-location.md) and [RECORD_AUDIO](../microphone/record-audio.md), it forms a comprehensive background surveillance stack.
