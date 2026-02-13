# Sensors Permissions

Access to body sensors like heart rate monitors and step counters. Niche abuse potential: biometric data theft from wearables, health data exfiltration. Primarily relevant to fitness app analysis and targeted surveillance rather than commodity malware.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [BODY_SENSORS](body-sensors.md) | Read heart rate, step count, and other biometric data from paired sensors |
| [BODY_SENSORS_BACKGROUND](body-sensors-background.md) | Continuous background biometric monitoring |

## Health Data as Intelligence

Body sensor data carries disproportionate value in targeted surveillance. Heart rate variability reveals stress responses during specific meetings or conversations. Sleep pattern disruption indicates anxiety. Sudden changes in step counts or activity levels can signal illness, injury, or changes in routine that are operationally relevant.

For high-value targets -- executives, diplomats, journalists -- this data provides a physiological layer of surveillance that the target cannot consciously mask. A person can control what they say on a phone call, but they cannot control their resting heart rate spiking during a conversation about a sensitive topic.

## Wearable Bridge Attack

The most practical sensor exploitation path is through the companion phone app for a wearable device. When a target pairs a smartwatch or fitness tracker with their phone, the companion app (Fitbit, Samsung Health, Garmin Connect) syncs all health data to the phone. A compromised phone app with `BODY_SENSORS` can then read this synced data, effectively turning the wearable into a remote biometric sensor without ever compromising the wearable itself.

This is particularly effective because:

- Wearable companion apps request `BODY_SENSORS` legitimately, so the permission grant does not look anomalous
- The wearable collects data continuously, including during sleep
- Historical data is often cached on the phone, providing weeks or months of biometric history in a single exfiltration

## Stalkerware Context

Stalkerware apps abuse `BODY_SENSORS_BACKGROUND` for continuous heart rate monitoring as a proxy for behavior detection. Elevated heart rate at unexpected times, changes in sleep patterns, or sudden increases in physical activity can trigger alerts to the stalker. This transforms health tracking into behavioral surveillance -- the stalker does not need to know where the target is if they can infer what the target is doing from biometric signals alone.

## Relevant Families

**Pegasus** (NSO Group) has documented sensor access capabilities, reading data from paired wearables as part of its full-device compromise. Given Pegasus operates at the OS level with root or equivalent access, it can bypass the permission model entirely, but the `BODY_SENSORS` permission remains relevant for understanding what data categories are accessible through legitimate API surfaces that less sophisticated implants must use.
