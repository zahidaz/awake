# App Virtualization Attacks

Android app-level virtualization frameworks (VirtualApp, DroidPlugin, VirtualXposed) allow one app to run other apps inside a virtual container without installation. Malware abuses this to run real banking apps inside a hostile sandbox, intercepting all user input and network traffic without modifying the target APK. This eliminates the need for overlays, bypasses repackaging detection, and defeats most runtime integrity checks because the target app is unmodified.

See also: [Overlay Attacks](overlay-attacks.md), [Accessibility Abuse](accessibility-abuse.md), [Play Store Evasion](play-store-evasion.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1670](https://attack.mitre.org/techniques/T1670/) | Virtualization Solution | Defense Evasion |

## Why It Matters

Traditional banking trojans use [overlay attacks](overlay-attacks.md) to display a fake login screen on top of the real app. This has known weaknesses: Google restricts overlay permissions since Android 10, and banking apps increasingly detect overlays.

Virtualization-based attacks eliminate overlays entirely:

1. The victim interacts with the **real, unmodified banking app**. Every UI element, certificate check, and server response is genuine. Nothing visually fake to detect.
2. The app runs inside a **virtual container controlled by the malware**. The virtualization engine interposes a proxy layer between the app and the Android framework.
3. **All user input passes through the malware's hooks.** Xposed or similar frameworks inject into the virtualized app's process, capturing taps, text input, credentials, PINs, and OTPs.
4. **Network traffic is intercepted and modified.** Hooks into HTTP libraries (OkHttpClient, etc.) let the malware read and alter API calls between the app and its backend.
5. **Security checks are neutralized.** Root detection, integrity checks, and accessibility service detection all query the Android system, but the virtualization proxy feeds fake responses. The app "sees" a clean, unrooted device.

This is fundamentally harder to detect from both the user's perspective (everything looks real) and the app's perspective (standard security checks pass).

## Preconditions

| Requirement | Detail |
|------------|--------|
| Installation | Victim installs the malicious app (social engineering, phishing, trojanized app) |
| No root required | Virtualization operates at the application layer, not the kernel |
| Target APK | Malware downloads the target banking app's APK or copies it from the device |
| Permissions | Varies by family. Accessibility service grants additional control but is not strictly required for basic virtualization |

## How It Works

### Virtual Container Architecture

The host malware app embeds a virtualization engine (typically based on VirtualApp or DroidPlugin). This engine creates a virtual Android runtime inside the host app's process space:

```
┌─────────────────────────────────────────┐
│  Host Malware APK                       │
│  ┌───────────────────────────────────┐  │
│  │  Virtualization Engine            │  │
│  │  (VirtualApp / DroidPlugin)       │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Virtual Container          │  │  │
│  │  │  ┌───────────────────────┐  │  │  │
│  │  │  │  Real Banking App     │  │  │  │
│  │  │  │  (unmodified APK)     │  │  │  │
│  │  │  └───────────────────────┘  │  │  │
│  │  │  + Xposed Hooking Module    │  │  │
│  │  │  + Credential Logger        │  │  │
│  │  │  + Network Interceptor      │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
        │
        ▼ Android Framework (proxied)
```

The virtualization engine provides:

- **Virtual filesystem**: Isolated `/data/data/` for the guest app
- **Virtual Process IDs**: The guest app believes it has its own PID
- **StubActivity**: A blank activity declared in the host's manifest that Android launches. The virtualization engine renders the guest app's UI inside it.
- **Intent interception**: System intents directed at the guest app are intercepted and routed through the virtual container

### Intent Redirection

When the victim launches the real banking app, the malware's accessibility service intercepts the intent and redirects it to the StubActivity, which boots a virtual instance of the banking app inside the container. The user sees the real banking app UI but inside the malware's sandbox.

### Credential Capture via Hooking

Inside the virtual container, a hooking framework (Xposed, Frida, or custom hooks) injects into the guest app's process:

- **UI hooks**: Capture text entered into login fields
- **Network hooks**: Intercept OkHttpClient, HttpURLConnection, and WebView network calls to read credentials in transit
- **Crypto hooks**: Log encryption keys and plaintext before encryption

### Why Standard Defenses Fail

| Defense | Why It Fails |
|---------|-------------|
| Root detection | Virtualization doesn't require root. Device appears unrooted. |
| SafetyNet / Play Integrity | Checks run in the host app's context or are proxied with clean responses |
| APK signature verification | The banking app's APK is unmodified. Signature is valid. |
| Accessibility service detection | The hooking happens inside the virtual container, not via Android's accessibility framework |
| Repackaging detection | No repackaging occurred. The original APK runs as-is. |
| SSL certificate pinning | Can be bypassed by hooks inside the container, or the proxy layer terminates TLS |

## Frameworks Abused

| Framework | Type | Origin | Malware Usage |
|-----------|------|--------|---------------|
| [VirtualApp](https://github.com/nicknash/VirtualApp) | Open-source app-level virtualization | Originally lody/VirtualApp on GitHub | [GodFather](../malware/families/godfather.md) (2025), [FjordPhantom](#fjordphantom) (2023), adware (2017+) |
| VirtualXposed | VirtualApp + Xposed integration | GitHub | [GodFather](../malware/families/godfather.md) (2025) |
| DroidPlugin | Open-source plugin framework | 360 Mobile Security | [PluginPhantom](#pluginphantom) (2016), adware (2017+) |
| Parallel Space / DualSpace | Commercial dual-instance apps | Google Play (100M+ downloads) | Account cloning, 2FA bypass |

## Malware Families

### FjordPhantom

First banking trojan to weaponize full app-level virtualization. [Discovered by Promon](https://promon.io/security-news/fjordphantom-android-malware) in November 2023, first observed spreading in Southeast Asia in September 2023.

| Attribute | Detail |
|-----------|--------|
| First seen | September 2023 |
| Targets | Banking apps in Indonesia, Thailand, Vietnam, Singapore, Malaysia |
| Virtualization base | VirtualApp (modified open-source) |
| Hooking | Java hooking framework injected into container |
| Distribution | Email, SMS, messaging apps with social engineering |
| Impact | [$280,000 stolen from a single victim](https://www.bleepingcomputer.com/news/security/fjordphantom-android-malware-uses-virtualization-to-evade-detection/) |

Promon [tested 113 top global banking apps](https://promon.io/security-news/fjordphantom-android-malware) and found 80% were vulnerable to this attack vector. FjordPhantom hooks Accessibility services, GooglePlayServices, and UI functions inside the virtual container. Because the original app is unmodified, repackaging detection is bypassed entirely.

### GodFather (Virtualization Variant)

[GodFather](../malware/families/godfather.md) added on-device virtualization in June 2025, replacing its previous overlay-based approach. [Disclosed by Zimperium zLabs](https://zimperium.com/blog/your-mobile-app-their-playground-the-dark-side-of-the-virtualization).

| Attribute | Detail |
|-----------|--------|
| Virtualization added | June 2025 |
| Targets | ~12 Turkish financial institutions (Akbank, Garanti BBVA, Halkbank, ING, Ziraat), scans ~500 apps globally |
| Virtualization base | VirtualApp engine |
| Hooking | Xposed framework for Java-layer API hooking |
| Anti-analysis | ZIP manipulation, `$JADXBLOCK` fields in manifest to defeat jadx |

GodFather's StubActivity acts as an intermediary: Android believes it is launching the legitimate app, but the malware controls what renders on screen. When the victim launches the real banking app, GodFather's accessibility service intercepts the Intent and redirects it to the StubActivity. Xposed hooks inject into network libraries (OkHttpClient) to intercept API calls, recording credentials, passwords, PINs, and touch events.

### PluginPhantom

First known Android trojan to abuse a plugin/virtualization framework. [Discovered by Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/unit42-pluginphantom-new-android-trojan-abuses-droidplugin-framework/) in November 2016.

Used the DroidPlugin framework to load malicious functionality as plugin APKs without installation. Each plugin implemented a separate capability (file theft, location tracking, keylogging, SMS interception, audio recording, screenshot capture, camera access). Plugins could be updated dynamically without reinstalling the host app.

### GoldFactory (Modified Banking Apps)

Chinese-speaking threat group active since June 2023. Rather than running apps inside a virtual container, GoldFactory takes original banking APKs and [injects malicious code while preserving normal functionality](https://thehackernews.com/2025/12/goldfactory-hits-southeast-asia-with.html). Uses three different runtime hooking frameworks: FriHook, SkyHook, and PineHook.

Over 300 unique modified banking app samples identified, leading to [11,000+ infections](https://thehackernews.com/2025/12/goldfactory-hits-southeast-asia-with.html) across Thailand, Vietnam, and Indonesia. Their [GoldPickaxe](../malware/families/goldpickaxe.md) variant harvests facial biometric data for [deepfake-based bank fraud](https://www.group-ib.com/media-center/press-releases/goldfactory-ios-trojan/).

## Adware and Plugin Framework Abuse

Before banking trojans adopted virtualization, adware campaigns abused these frameworks at scale. [Unit 42 documented](https://unit42.paloaltonetworks.com/unit42-new-trend-android-adware-abusing-android-plugin-frameworks/) 32 apps abusing DroidPlugin and 21 abusing VirtualApp on Google Play in early 2017. At [Black Hat Asia 2017](https://blackhat.com/docs/asia-17/materials/asia-17-Luo-Anti-Plugin-Don't-Let-Your-App-Play-As-An-Android-Plugin-wp.pdf), Palo Alto Networks researchers presented "Anti-Plugin," identifying 64,058 samples using plugin technology, of which 61,172 were malicious or gray.

## Academic Research

| Paper | Venue | Year | Key Finding |
|-------|-------|------|-------------|
| [App in the Middle](https://dl.acm.org/doi/10.1145/3322205.3311088) | ACM SIGMETRICS | 2019 | 7 attack vectors in 32 virtualization frameworks; 164 credential-stealing repackaged apps found |
| [Parallel Space Traveling](https://www.cs.ucr.edu/~heng/pubs/sacmat2020.pdf) | ACM SACMAT | 2020 | 160+ virtualization apps analyzed; apps in virtual environments not isolated from each other |
| [Mascara](https://arxiv.org/abs/2010.10639) | arXiv | 2020 | Automated attack framework building virtual environments for credential theft; proposed ArtMethod-based detection |
| [VAHunt](https://dl.acm.org/doi/10.1145/3372297.3423341) | ACM CCS | 2020 | Detected 139,000+ virtualization-based malware samples with 0.7% false negatives, zero false positives |
| [Virtualization Pen Testing](https://arxiv.org/abs/2601.21258) | arXiv | 2026 | Tested FjordPhantom-style attacks against 83 banking apps (405M+ downloads) in East/Southeast Asia |

## Timeline

| Date | Event |
|------|-------|
| 2015-2016 | VirtualApp and DroidPlugin open-sourced; Parallel Space hits 100M downloads |
| November 2016 | [PluginPhantom discovered](https://unit42.paloaltonetworks.com/unit42-pluginphantom-new-android-trojan-abuses-droidplugin-framework/) -- first trojan abusing DroidPlugin |
| January 2017 | [Adware campaigns on Google Play](https://unit42.paloaltonetworks.com/unit42-new-trend-android-adware-abusing-android-plugin-frameworks/) abusing VirtualApp and DroidPlugin (53 apps found) |
| April 2017 | [Black Hat Asia 2017](https://blackhat.com/docs/asia-17/materials/asia-17-Luo-Anti-Plugin-Don't-Let-Your-App-Play-As-An-Android-Plugin-wp.pdf) -- 64K malicious plugin samples identified |
| November 2020 | VAHunt detects 139K+ virtualization-based malware samples |
| September 2023 | FjordPhantom first observed in Southeast Asia |
| November 2023 | [Promon discloses FjordPhantom](https://promon.io/security-news/fjordphantom-android-malware) -- first banking trojan using full app virtualization |
| June 2025 | [GodFather virtualization variant disclosed by Zimperium](https://zimperium.com/blog/your-mobile-app-their-playground-the-dark-side-of-the-virtualization) |
| December 2025 | [GoldFactory campaign hits Southeast Asia](https://thehackernews.com/2025/12/goldfactory-hits-southeast-asia-with.html) with modified banking apps, 11K+ infections |

## Detection

??? example "Indicators of Virtualization"

    - Presence of VirtualApp, DroidPlugin, or VirtualXposed libraries in APK
    - `StubActivity` or similarly named proxy activities in the manifest
    - Multiple app processes running under a single UID
    - Abnormal file paths (`/data/data/<host_package>/virtual/...`)
    - Xposed framework indicators inside app memory
    - Network traffic from unexpected process contexts

??? example "App-Side Detection"

    - Check if the app is running inside a virtual environment by inspecting the calling package
    - Verify `Application.getProcessName()` matches expected package name
    - Check for VirtualApp-specific system properties
    - Inspect `/proc/self/maps` for injected libraries from known virtualization frameworks
    - Detect Xposed by checking for `de.robv.android.xposed` class loading

    [Appdome documents](https://www.appdome.com/how-to/mobile-fraud-prevention-detection/know-your-customer-checks/block-secondary-space-in-android-apps/) "Second Space" and "Parallel App" attacks as a fraud vector. [Licelus (DexProtector)](https://licelus.com/resources/guide-to-mobile-application-protection/threats/emulators-and-virtualization-apps) notes that the virtualization app is a more privileged process than any target app, giving it unrestricted interaction capabilities.
