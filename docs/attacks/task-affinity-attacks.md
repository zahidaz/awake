# Task Affinity Attacks

Manipulating Android's activity back stack to place a malicious activity inside a target app's task. The user believes they're interacting with the legitimate app because the malicious activity appears in its task and recent apps entry. Also known as "StrandHogg" after the vulnerability disclosure that popularized it.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | None |
    | Condition | Manifest configuration only |

## How Task Affinity Works

Every activity has a `taskAffinity` property (defaults to the app's package name). Activities with the same affinity are grouped into the same task. The task appears as a single entry in the Recent Apps screen.

By default, all activities in an app share the same affinity and appear in one task. But an attacker's activity can declare affinity matching the target app:

```xml
<activity
    android:name=".PhishingActivity"
    android:taskAffinity="com.target.banking.app"
    android:allowTaskReparenting="true"
    android:excludeFromRecents="true" />
```

## Attack Patterns

### StrandHogg (v1)

Disclosed in 2019 by Promon. Affects all Android versions.

1. Malicious app launches with `taskAffinity` matching the target app
2. Malicious activity is placed into the target's task stack
3. When user opens the target app from recent apps or launcher, the malicious activity appears instead
4. The malicious activity presents a phishing UI

The attack uses `allowTaskReparenting="true"`: the malicious activity starts in its own task but migrates to the target's task when the target is launched.

### StrandHogg 2.0 (CVE-2020-0096)

Disclosed in 2020. Affected Android 8.0-9.0 (patched in May 2020 security update).

An elevation of privilege vulnerability where a malicious app could take over any activity of any app. Unlike v1, the victim app doesn't need to be running. The malicious app could start any exported activity and intercept it, without the user noticing.

### Task Hijacking for Phishing

Practical phishing scenario:

1. Malware sets `taskAffinity="com.chase.sig.android"`
2. User opens Chase banking app from launcher
3. Instead of Chase, the malware's phishing activity appears
4. User enters credentials
5. Malware stores credentials and launches the real Chase activity
6. User sees the real app and doesn't realize they were phished

The Recent Apps screen shows the Chase icon and label, further selling the illusion.

## Relevant Manifest Attributes

| Attribute | Effect |
|-----------|--------|
| `taskAffinity` | Controls which task the activity belongs to |
| `allowTaskReparenting` | Activity can move between tasks |
| `launchMode="singleTask"` | Creates new task if none with matching affinity exists |
| `excludeFromRecents` | Hides malicious activity from recent apps |
| `documentLaunchMode` | Controls document-based task creation |

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 10 (API 29) | Restricted task affinity behavior for background-launched activities (StrandHogg v1 patch) | Variations remain possible with certain launch mode configurations |
| May 2020 Security Patch | Patched StrandHogg 2.0 (CVE-2020-0096) | Only applies to devices receiving the patch |
| Android 12+ | Additional restrictions on background activity starts | The underlying task model hasn't fundamentally changed; residual risk remains on unpatched devices |

## Detection During Analysis

??? example "Static Indicators"

    - Activities with `taskAffinity` set to another app's package name
    - `allowTaskReparenting="true"` combined with non-default affinity
    - `launchMode="singleTask"` or `"singleInstance"` on suspicious activities
    - `excludeFromRecents="true"` (hiding the malicious activity)

??? example "Dynamic Indicators"

    - Malicious activity appearing in target app's task in Recent Apps
    - Task reparenting observed when target app is launched
    - Phishing UI displayed inside another app's task context

## Families Using This Technique

| Family | Usage | Era |
|--------|-------|-----|
| [BankBot](../malware/families/bankbot.md) | Early adopter. Used `taskAffinity` + `allowTaskReparenting` to inject phishing activities into banking app tasks. | 2016-2017 |
| [Anubis](../malware/families/anubis.md) | Combined task affinity with overlay attacks for layered credential theft. | 2018 |
| [Gustuff](../malware/families/gustuff.md) | Used task manipulation alongside accessibility-driven ATS for automated fund transfers. | 2019 |
| [Cerberus](../malware/families/cerberus.md) | Included task affinity phishing as one of multiple credential theft vectors. | 2019-2020 |

Task affinity attacks were the dominant phishing technique from 2014-2017. They were largely superseded by [overlay attacks](overlay-attacks.md) (which don't require task manipulation) and [accessibility abuse](accessibility-abuse.md) (which provides broader device control). However, the underlying Android task model remains unchanged, and StrandHogg-style attacks still work on unpatched devices.

### Relationship to Overlay Attacks

Both task affinity attacks and [overlay attacks](overlay-attacks.md) achieve the same goal: presenting a fake UI over a legitimate app. The key difference:

| Aspect | Task Affinity | Overlay |
|--------|--------------|---------|
| Permission needed | None | `SYSTEM_ALERT_WINDOW` or Accessibility |
| Android version | All (with mitigations from 10+) | All (with restrictions from 12+) |
| Visibility | Appears inside target app's task | Floats above all apps |
| Trigger | User opens target app | Malware detects target app launch |
| Modern usage | Rare | Standard |

The shift happened because overlays are more flexible (can trigger on any app launch, don't require prior task setup) and accessibility abuse provides far more capabilities beyond just phishing.
