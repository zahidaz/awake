# Overlay Attacks

Drawing a fake UI on top of a legitimate app to steal credentials. The defining technique of Android banking malware since ~2016. The attacker creates a window that looks identical to a banking app's login screen, and the user types their credentials into the attacker's view.

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1417.002](https://attack.mitre.org/techniques/T1417/002/) | Input Capture: GUI Input Capture | Credential Access, Collection |
    | [T1453](https://attack.mitre.org/techniques/T1453/) | Abuse Accessibility Features | Collection, Credential Access |

    T1417.002 explicitly covers overlay attacks using `SYSTEM_ALERT_WINDOW` and fake login screens. T1453 applies when accessibility services trigger the overlay based on foreground app detection.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`SYSTEM_ALERT_WINDOW`](../permissions/special/system-alert-window.md) or [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) |
    | Trigger | Foreground app detection (knowing when to show the overlay) |
    | Payload | HTML/WebView template matching the target app's UI |

## How It Works

### Foreground Detection

The malware needs to know when the user opens a target app. Methods used:

| Method | Android Version | Details |
|--------|----------------|---------|
| `getRunningTasks()` | Pre-5.0 | Deprecated, returns only caller's tasks on 5.0+ |
| `UsageStatsManager` | 5.0+ | Requires [`PACKAGE_USAGE_STATS`](../permissions/special/package-usage-stats.md), polls every ~1 second |
| Accessibility events | 4.1+ | `TYPE_WINDOW_STATE_CHANGED` fires when any activity starts, most reliable |
| `ActivityLifecycleCallbacks` | Only for own process | Not useful for monitoring other apps |

!!! tip "Analyst Note"

    Accessibility is the preferred method: it's real-time, requires no polling, and the malware likely needs accessibility for other purposes anyway. If a sample requests `BIND_ACCESSIBILITY_SERVICE`, treat it as the likely overlay trigger mechanism.

### Injection Display

When the target app is detected, the malware displays its overlay:

**WebView approach** (most common): a `WebView` loads an HTML page styled to match the target app. These HTML templates ("injects" or "webfakes") are downloaded from C2 per target app. Major malware operations maintain inject kits covering hundreds of banking apps across multiple countries.

**Native View approach**: Android `View` objects constructed programmatically. Less common because it's harder to maintain across app UI updates.

**Full Activity approach**: some families launch a full `Activity` with `FLAG_ACTIVITY_NEW_TASK` themed to look like the target. This doesn't require `SYSTEM_ALERT_WINDOW` but is less precise in timing.

### Credential Capture

The injected form submits entered data to C2 via HTTPS POST. Captured fields typically include:

- Login credentials (username, password)
- Card numbers (PAN, CVV, expiry)
- PINs
- Security questions

### Inject Kits

Malware-as-a-service (MaaS) operations sell or rent inject kits. An inject kit is a collection of HTML/CSS/JS files, one per target app, that mimic the target's login UI. These are versioned and updated when banks change their UI.

The C2 server maps package names to inject URLs:

```
com.chase.sig.android -> https://c2.example/injects/chase.html
com.bankofamerica.cashpromobile -> https://c2.example/injects/boa.html
```

The malware downloads only injects for apps found on the device (see [`QUERY_ALL_PACKAGES`](../permissions/normal/query-all-packages.md)).

## Evolution

| Era | Technique | Example Families |
|-----|-----------|-----------------|
| 2014-2016 | Simple overlays using `TYPE_SYSTEM_ALERT` | GM Bot, [BankBot](../malware/families/bankbot.md) |
| 2016-2018 | WebView-based injects, C2-managed templates | [Marcher](../malware/families/marcher.md), Red Alert |
| 2018-2020 | Accessibility-triggered overlays, large inject kits | [Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md), [Hydra](../malware/families/hydra.md) |
| 2020-2022 | ATS (Automated Transfer System), overlay + accessibility combo | [Anatsa](../malware/families/anatsa.md), [SharkBot](../malware/families/sharkbot.md), [Xenomorph](../malware/families/xenomorph.md) |
| 2022-2024 | Overlays declining as primary technique, replaced by full device control via accessibility | [Hook](../malware/families/hook.md), [Octo](../malware/families/octo.md)/ExobotCompact |
| 2025 | On-device virtualization: real banking apps run inside malware-controlled sandbox | [GodFather](../malware/families/godfather.md) v3 |
| 2025 | NFC payment overlays: fake tap-to-pay screens capturing card data | [Hook](../malware/families/hook.md) v3 |

The trend is away from pure overlay attacks toward on-device fraud using accessibility to operate the real banking app directly. Overlays are still used for initial credential capture, but the real value is in accessibility-based ATS. The most recent evolution ([GodFather v3](../malware/families/godfather.md)) bypasses overlays entirely by running the real banking app inside a virtual environment and intercepting all interactions at runtime.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 4.0 | 14 | `TYPE_SYSTEM_ALERT` window type | Original overlay mechanism, draws over all apps |
| 5.0 | 21 | `UsageStatsManager` for foreground detection | Polling-based overlay trigger without accessibility |
| 6.0 | 23 | `SYSTEM_ALERT_WINDOW` becomes a runtime permission | Auto-granted from Play Store installs until API 26 |
| 8.0 | 26 | `TYPE_APPLICATION_OVERLAY` replaces `TYPE_SYSTEM_ALERT` | Renders below permission dialogs, but attacker doesn't need to overlay those |
| 8.0 | 26 | `SYSTEM_ALERT_WINDOW` no longer auto-granted from Play Store | Malware pivots to accessibility-triggered overlays |
| 10 | 29 | Overlays cannot appear over focused app activities | [Accessibility](accessibility-abuse.md) gestures bypass this entirely |
| 12 | 31 | [`FLAG_WINDOW_IS_PARTIALLY_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_PARTIALLY_OBSCURED) warns apps of overlays | Most apps don't check this flag |
| 12 | 31 | Overlays untouchable over system dialogs | Accessibility service performs the touches instead |
| 12 | 31 | [Untrusted touch events blocked](https://developer.android.com/about/versions/12/behavior-changes-all#untrusted-touch-events) when overlay obscures the target | Malware uses `FLAG_NOT_TOUCHABLE` with `alpha < 0.8` |
| 15 | 35 | Further restrictions on overlay interaction patterns | Drives adoption of [app virtualization](app-virtualization.md) as alternative |

!!! info "Every overlay restriction pushed malware toward heavier reliance on [accessibility services](accessibility-abuse.md)"

## Families Using This Technique

| Family | Overlay Approach | Inject Kit Size | Also Uses ATS |
|--------|-----------------|-----------------|---------------|
| [Cerberus](../malware/families/cerberus.md) | WebView | 300+ targets | No |
| [Anubis](../malware/families/anubis.md) | WebView | 250+ targets | No |
| [BankBot](../malware/families/bankbot.md) | Activity | 50+ targets | No |
| [Hydra](../malware/families/hydra.md) | WebView | 400+ targets | No |
| [Hook](../malware/families/hook.md) | WebView | 400+ targets | Yes |
| [GodFather](../malware/families/godfather.md) | WebView | 400+ targets | No |
| [Ermac](../malware/families/ermac.md) | WebView | 400+ targets | No |
| [Xenomorph](../malware/families/xenomorph.md) | WebView | 400+ targets | Yes |
| [Octo](../malware/families/octo.md) | WebView | 200+ targets | Yes |
| [Alien](../malware/families/alien.md) | WebView | 200+ targets | No |
| [Medusa](../malware/families/medusa.md) | WebView | 100+ targets | No |
| [SharkBot](../malware/families/sharkbot.md) | Native | 20+ targets | Yes |
| [Zanubis](../malware/families/zanubis.md) | WebView | 40+ targets | Yes |
| [Fakecalls](../malware/families/fakecalls.md) | WebView | Korean banks | No |
| [Mamont](../malware/families/mamont.md) | WebView | Russian banks | No |
| [Copybara](../malware/families/copybara.md) | WebView | Italian banks | Yes |
| [Crocodilus](../malware/families/crocodilus.md) | WebView | 8 countries | Yes |
| [BingoMod](../malware/families/bingomod.md) | WebView | European banks | Yes |
| [Brokewell](../malware/families/brokewell.md) | WebView | European banks | Yes |
| [Klopatra](../malware/families/klopatra.md) | WebView | Turkish banks | Yes |
| [Albiriox](../malware/families/albiriox.md) | WebView | 400+ targets | Yes |
| [Herodotus](../malware/families/herodotus.md) | WebView | Southern/Central EU | Yes |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | WebView | Thai/Vietnamese banks | No |
| [Sturnus](../malware/families/sturnus.md) | WebView | Southern/Central EU | Yes |
| [Antidot](../malware/families/antidot.md) | WebView | Multi-language | Yes |
| [TrickMo](../malware/families/trickmo.md) | WebView | European banks | No |
| [TsarBot](../malware/families/tsarbot.md) | WebView | 750+ targets | Yes |
| [BlankBot](../malware/families/blankbot.md) | WebView | Turkish banks | Yes |
| [Vultur](../malware/families/vultur.md) | Native | European banks | Yes |
| [Chameleon](../malware/families/chameleon.md) | WebView | AU/EU banks | No |
| [ToxicPanda](../malware/families/toxicpanda.md) | WebView | EU/LATAM banks | Yes |
| [Frogblight](../malware/families/frogblight.md) | WebView | Turkish banks | Yes |
| [BTMOB RAT](../malware/families/btmob.md) | WebView injection (`brows` command) | Crypto/banking | Yes |
| [Rafel RAT](../malware/families/rafelrat.md) | Activity-based | Multi-region | No |
| [RatOn](../malware/families/raton.md) | WebView | Czech banks | Yes |
| [DeVixor](../malware/families/devixor.md) | WebView | Iranian banks | No |

Notable exceptions: [Gigabud](../malware/families/gigabud.md) and [Vultur](../malware/families/vultur.md) v1 deliberately avoid overlay attacks, using screen recording instead to capture credentials as the victim interacts with their real banking app. [NGate](../malware/families/ngate.md) uses a phishing WebView for card PIN entry rather than traditional banking overlays.

## Detection During Analysis

??? example "Static Indicators"

    - `SYSTEM_ALERT_WINDOW` in manifest
    - `TYPE_APPLICATION_OVERLAY` in code
    - `UsageStatsManager` calls for foreground detection
    - WebView loading local HTML or C2-hosted URLs
    - Accessibility service monitoring `TYPE_WINDOW_STATE_CHANGED`

??? example "Dynamic Indicators"

    - Window created with overlay type when a banking app is foregrounded
    - Network request to C2 matching pattern of inject download
    - HTML files stored in app's internal storage matching banking app names
