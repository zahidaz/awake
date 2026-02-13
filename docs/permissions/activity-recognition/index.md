# Activity Recognition Permissions

Access to physical activity data: whether the user is walking, running, cycling, driving, or stationary. Used in targeted surveillance to build behavioral profiles. Low priority for commodity malware.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [ACTIVITY_RECOGNITION](activity-recognition.md) | Track user's physical activity state for behavior profiling |

## Exposed Data

The Activity Recognition API returns `DetectedActivity` objects, each with a type and confidence score:

| Activity Type | Intelligence Value |
|--------------|-------------------|
| `IN_VEHICLE` | Target is driving or riding in a vehicle -- reveals commute patterns |
| `ON_BICYCLE` | Cycling activity -- narrows transport mode for physical surveillance |
| `ON_FOOT` | Walking -- baseline movement, often paired with location for route mapping |
| `RUNNING` | Exercise pattern -- reveals routine and predictable locations (gym, park) |
| `STILL` | Stationary -- indicates the target is at a fixed location (home, office, meeting) |
| `TILTING` | Device angle changed -- can infer phone pickup, pocket/table transitions |
| `WALKING` | Subset of ON_FOOT -- more granular movement classification |

When combined with location data, activity recognition builds comprehensive movement profiles. A surveillance operator can determine not just where a target went, but how they got there, when they stopped, and how long they stayed. This is the difference between a series of GPS dots and an actionable pattern-of-life analysis.

## Spyware Families

Several state-sponsored and commercial spyware families request this permission:

- **Pegasus** (NSO Group) -- full activity monitoring as part of its comprehensive device surveillance suite
- **Hermit** (RCS Lab) -- collects activity data alongside location for target profiling
- **PlainGnome** -- Russian-linked spyware that harvests activity states for behavioral analysis

Commodity malware rarely bothers with this permission. The intelligence it provides is only valuable when an operator is building a sustained profile of a specific target, making it a strong indicator of targeted surveillance rather than bulk data theft.

## Android Version History

Prior to Android 10 (API 29), activity recognition data was available to any app using the Google Play Services Activity Recognition API without a dedicated permission. API 29 introduced `ACTIVITY_RECOGNITION` as a runtime permission, requiring explicit user consent. This change was part of a broader push to gate sensor-derived behavioral data behind granular permissions rather than bundling it under broad grants.
