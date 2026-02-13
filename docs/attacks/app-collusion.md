# App Collusion

Application collusion is a threat where two or more Android apps cooperate to perform a malicious action that neither could achieve independently. Each app requests only a minimal set of permissions, appearing benign in isolation. When combined on the same device, the apps aggregate permissions and share data through inter-app communication channels to achieve their goal. The real-world threat is dominated by SDK-mediated collusion, where a data broker distributes an SDK to many independent developers who unknowingly enable cross-app surveillance.

See also: [Intent Hijacking](intent-hijacking.md), [Content Provider Attacks](content-provider-attacks.md), [Broadcast Theft](broadcast-theft.md), [Dynamic Code Loading](dynamic-code-loading.md)

## Why It Matters

Android's security model is built around per-app sandboxing and permission grants. Every security check, store review, and malware scanner evaluates apps individually. Collusion exploits this blind spot: when malicious behavior is distributed across multiple apps, no single app triggers detection. Current app store review and malware scanning remain [overwhelmingly single-app focused](https://people.cs.vt.edu/danfeng/papers/AsiaCCS-17-Yao.pdf); combinatorial analysis of app pairs is computationally expensive and not performed at scale by any store.

## Communication Channels

### Overt Channels (Designed for Legitimate IPC)

| Channel | Mechanism | Detection Difficulty |
|---------|-----------|---------------------|
| Broadcast Intents | Explicit or implicit intents between apps | Low (visible in manifest and at runtime) |
| Content Providers | One app exports a provider, the other queries it | Low (declared in manifest) |
| Bound Services | One app exports a Service, the other binds to it | Low (declared in manifest) |
| External storage | Shared filesystem (`/sdcard/`) for data exchange | Medium (scoped storage limits this on Android 10+) |
| SharedPreferences | Key-value XML files if world-readable | Medium (deprecated mode but still works) |
| Local network sockets | Local HTTP server on localhost | High (no manifest declaration required) |

### Covert Channels (Abuse of System Resources)

| Channel | Mechanism | Detection Difficulty |
|---------|-----------|---------------------|
| System settings | Volume, vibration, brightness as signaling | Very high |
| `/proc` filesystem | CPU usage statistics, thread counts | Very high |
| Sensor data | Accelerometer/vibration engine to encode data | Very high |
| UNIX socket enumeration | Checking socket availability as a signal | Very high |
| External storage hidden files | Identifiers written to shared filesystem | High |

Sources: [Towards a threat assessment framework for apps collusion](https://pmc.ncbi.nlm.nih.gov/articles/PMC6961490/), [Android Inter-App Communication: Threats, Solutions, and Challenges](https://arxiv.org/pdf/1803.05039)

## Two Collusion Models

### 1. Intentional Multi-App Collusion

A malware author deliberately splits functionality across multiple apps. Each app is purpose-built to collaborate. This is the model most studied in academic literature but less common in the wild.

**Canonical example**: App A has `CAMERA` permission but no `INTERNET`. App B has `INTERNET` but no `CAMERA`. App A captures photos and passes them to App B via a shared Content Provider or external storage. App B exfiltrates them. Neither app individually appears malicious.

### 2. SDK-Mediated Collusion

A data broker or ad-tech company distributes an SDK to many independent developers. The developers may be unaware of the SDK's full behavior. The SDK operator aggregates data from all embedding apps, achieving cross-app surveillance that no individual app could perform. **This is the dominant real-world collusion model.**

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Prayer   │  │ QR       │  │ Speed    │  │ Weather  │
│ App      │  │ Scanner  │  │ Trap App │  │ App      │
│ +SDK     │  │ +SDK     │  │ +SDK     │  │ +SDK     │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │              │
     └─────────────┴──────┬──────┴──────────────┘
                          │
                   ┌──────▼──────┐
                   │ SDK Backend │
                   │ (aggregates │
                   │  all data)  │
                   └─────────────┘
```

## Real-World Cases

### MoPlus SDK Collusion (First Confirmed Wild Collusion)

Discovered in a dataset of 50,000 apps provided by Intel Security. [Presented at Virus Bulletin 2016](https://www.virusbulletin.com/virusbulletin/2018/03/vb2016-paper-wild-android-collusions/) as the first confirmed case of malicious app collusion in the wild.

The [MoPlus SDK](https://www.researchgate.net/profile/Jorge-Blasco/publication/308926966_WILD_ANDROID_COLLUSIONS/links/57f7c76f08ae280dd0bcc6c3/WILD-ANDROID-COLLUSIONS.pdf) (by Baidu) was embedded in over 1,000 applications. The SDK opened a local HTTP server on the device, enabling a C2 operator to send arbitrary intents, obtain sensitive information, and silently install apps on rooted devices. Apps colluded by checking which one had the highest privileges via SharedPreferences, then the most-privileged app would execute commands. [McAfee detected 21 apps](https://news.softpedia.com/news/21-android-apps-spotted-using-app-collusion-attacks-505252.shtml) using this collusion technique.

### PixPirate Two-App Architecture

[PixPirate](../malware/families/pixpirate.md) uses a genuine two-app collusion architecture. [First documented by Cleafy](https://www.cleafy.com/cleafy-labs/pixpirate-a-new-brazilian-banking-trojan) in February 2023; the two-app technique was [documented by IBM Trusteer](https://www.ibm.com/think/insights/pixpirate-brazilian-financial-malware) in March 2024.

| Component | Role |
|-----------|------|
| Downloader | Visible app that the user installs. Has a launcher icon. |
| Droppee (payload) | No launcher icon, no `MAIN`/`LAUNCHER` intent-filter, invisible on home screen |

The droppee exports a service `com.companian.date.sepherd` with intent-filter action `com.ticket.stage.Service`. The downloader uses `BindService` with `BIND_AUTO_CREATE` to launch it. Even if the downloader is deleted, the droppee persists via broadcast receivers listening for `BOOT_COMPLETED`, connectivity changes, and other system events. This is not just a dropper/payload relationship: the downloader remains an active participant in the malicious operation.

### Measurement Systems SDK (US Defense Contractor Link)

[Wall Street Journal investigation](https://www.foxbusiness.com/technology/apps-with-hidden-data-harvesting-software-banned-by-google) and [Bleeping Computer coverage](https://www.bleepingcomputer.com/news/security/android-apps-with-45-million-installs-used-data-harvesting-sdk/) in April 2022 revealed that Measurement Systems S. de R.L. (Panama) paid developers to embed its SDK in their apps, present in apps with at least 60 million installs including Muslim prayer apps (10M+ downloads), speed-trap detectors, and QR-code readers.

The SDK collected precise GPS location, email addresses, phone numbers, clipboard content, and nearby device MAC addresses. Corporate records linked Measurement Systems to Vostrom Holdings and Packet Forensics, a Virginia-based defense contractor doing cyber intelligence work for US national security agencies. Discovered by researchers Joel Reardon and Serge Egelman (same researchers behind the "50 Ways to Leak Your Data" USENIX paper).

### X-Mode Social / Predicio (Location Data Brokers)

[X-Mode Social SDK](https://techcrunch.com/2021/01/28/x-mode-location-google-apple-ban/) collected granular location data from apps including Muslim Pro (98M+ downloads), selling data to US military contractors. Apple and Google both ordered developers to remove the SDK in December 2020.

[Predicio](https://www.vice.com/en/article/dy8eba/google-predicio-ban-muslim-prayer-app) (France-based) was part of a supply chain funneling data: individual apps -> SDK providers -> middlemen -> Gravy Analytics -> Venntel (US government contractor selling to ICE and CBP). This represents SDK-mediated collusion at its most extreme: the SDK operator aggregates data from many independently-developed apps to build a surveillance product. [EFF covered the broader implications](https://www.eff.org/deeplinks/2021/03/apple-and-google-kicked-two-location-data-brokers-out-their-app-stores-good-now).

### SpinOk SDK (Trojan Module in 100+ Apps)

[Dr.Web discovered](https://news.drweb.com/show?i=14705&lng=en) SpinOk in May 2023, a trojan SDK disguised as an advertising module found in [193 apps with over 451 million cumulative downloads](https://www.bleepingcomputer.com/news/security/spinok-android-malware-found-in-more-apps-with-30-million-installs/). Collected device sensor data, file listings, clipboard content, and could execute arbitrary JavaScript. Used anti-emulation techniques (gyroscope, magnetometer data) to avoid sandbox detection. Notable affected apps: Noizz (100M), Zapya (100M), vFly (50M), MVBit (50M). Developers embedded it unknowingly.

### Salmonads SDK (IMEI Sharing via Filesystem)

[Documented in "50 Ways to Leak Your Data"](https://www.usenix.org/conference/usenixsecurity19/presentation/reardon) at USENIX Security 2019. Chinese developers' assistant platform that wrote the device IMEI to `/sdcard/.googlex9/.xamdeco0962`. Other apps using the same SDK but without `READ_PHONE_STATE` permission could read the IMEI from that file. Lower bound of affected installs: ~17.6 million.

### Cross-Library Data Harvesting (XLDH)

[Documented at USENIX Security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/wang-jice). 42 malicious libraries inside apps detected the presence of Facebook/Twitter/Google SDKs in the same app, then invoked their API functions to steal access tokens, user profiles, and favorites. Affected more than 19,000 apps with a total of 9 billion downloads. Malicious libraries hid data in crash reports and used C2 servers to schedule exfiltration.

### CVE-2019-2234: Google/Samsung Camera Confused Deputy

[Checkmarx discovered](https://checkmarx.com/blog/how-attackers-could-hijack-your-android-camera/) that a rogue app with zero camera/storage permissions could force the Google Camera app to take photos and record video (even with screen off or phone locked). Classic confused deputy: the Camera app held permissions but exposed unprotected components that any app could invoke via intents. Patched via Play Store update.

## Academic Research

| Paper | Venue | Year | Key Finding |
|-------|-------|------|-------------|
| [Analyzing Inter-Application Communication](https://people.eecs.berkeley.edu/~daw/papers/intents-mobisys11.pdf) | ACM MobiSys | 2011 | Foundational paper on intent-based security risks |
| [Towards Taming Privilege-Escalation](https://download.hrz.tu-darmstadt.de/media/FB20/Dekanat/Publikationen/TRUST/NDSS_2012_Towards_Taming_Privilege-Escalation_Attacks_on_Android.pdf) | NDSS | 2012 | Early work on ICC-enabled privilege escalation through colluding apps |
| [DIALDroid](https://people.cs.vt.edu/danfeng/papers/AsiaCCS-17-Yao.pdf) | ACM AsiaCCS | 2017 | Analyzed 110,150 apps, found 23,000+ colluding app pairs in 82 minutes. [Open-sourced](https://github.com/dialdroid-android/DIALDroid) |
| [50 Ways to Leak Your Data](https://www.usenix.org/conference/usenixsecurity19/presentation/reardon) | USENIX Security | 2019 | Real-world SDK-based side channels and covert channels; Salmonads IMEI leak |
| [XLDH](https://www.usenix.org/conference/usenixsecurity21/presentation/wang-jice) | USENIX Security | 2021 | 42 malicious libraries harvesting data from Facebook/Twitter/Google SDKs in 19K+ apps |
| [A Tale of Four Gates](https://research.birmingham.ac.uk/en/publications/a-tale-of-four-gates-privilege-escalation-and-permission-bypasses/) | 2022 | 2022 | 52,982 instances of fourth-order privilege escalation missed by first-order analysis |
| [Covert Third-party Identifiers](https://www.usenix.org/conference/usenixsecurity24/presentation/dong-zikan) | USENIX Security | 2024 | 17 tracking SDKs storing persistent identifiers on external storage, defeating scoped storage |

## Android Platform Defenses

| Defense | Android Version | What It Mitigates |
|---------|----------------|-------------------|
| Scoped Storage | Android 10 (enforced Android 11) | Apps get isolated storage; prevents reading other apps' files on external storage |
| Package Visibility Filtering | Android 11 | Apps cannot enumerate all installed apps; limits ability to discover colluding partners |
| Restricted implicit intents | Android 14 | Implicit intents only delivered to exported components; tighter broadcast receiver controls |
| Background execution limits | Android 8.0+ | Limits on background services and implicit broadcasts reduce ability to trigger colluding apps |

!!! warning "Key Limitation"
    All of these defenses mitigate specific channels but do not address the fundamental problem. [USENIX Security 2024 research](https://www.usenix.org/conference/usenixsecurity24/presentation/dong-zikan) demonstrated that 17 tracking SDKs can breach Android's scoped storage defense using hidden files and media file attachment techniques. Platform defenses reduce the attack surface but cannot eliminate collusion as long as apps can communicate through any shared channel.
