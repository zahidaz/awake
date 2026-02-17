# Supply Chain Attacks

Compromising the software or hardware supply chain to distribute malware through trusted channels: poisoned SDKs that developers unknowingly embed, hijacked build dependencies, purchased developer accounts, and firmware backdoors inserted during manufacturing. Supply chain attacks bypass the user's trust decision entirely. The victim installs a legitimate app from a trusted source, or buys a new phone, and the malware is already there.

See also: [Play Store Evasion](play-store-evasion.md), [Dynamic Code Loading](dynamic-code-loading.md), [Firmware Grayware](../grayware/firmware-grayware.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1474](https://attack.mitre.org/techniques/T1474/) | Supply Chain Compromise | Initial Access |
    | [T1474.001](https://attack.mitre.org/techniques/T1474/001/) | Compromise Software Dependencies and Development Tools | Initial Access |
    | [T1474.002](https://attack.mitre.org/techniques/T1474/002/) | Compromise Hardware Supply Chain | Initial Access |
    | [T1474.003](https://attack.mitre.org/techniques/T1474/003/) | Compromise Software Supply Chain | Initial Access |

    T1474.001 covers Gradle/Maven dependency attacks (MavenGate, typosquatting, dependency confusion). T1474.002 covers firmware pre-installs during manufacturing (BADBOX, Triada firmware). T1474.003 covers SDK poisoning (SpinOk, Necro, Goldoson) and app acquisition attacks.

!!! warning "Scale"

    | Vector | Largest Documented Case | Devices Affected |
    |--------|------------------------|-----------------|
    | SDK poisoning | [SpinOk](https://news.drweb.com/show?i=14705&lng=en) (2023) | 421M+ downloads |
    | OEM pre-installed SDKs | [IMDEA study](https://networks.imdea.org/a-study-analyzes-pre-installed-software-on-android-devices-and-its-privacy-risks-for-users/) (2019) | 11,000+ SDKs across 214 brands |
    | Firmware pre-install | [BADBOX 2.0](https://www.humansecurity.com/learn/blog/badbox-peachpit-and-the-fraudulent-device-in-your-delivery-box/) (2023-2025) | 10M+ devices |
    | Build dependency | [MavenGate](https://blog.oversecured.com/Introducing-MavenGate-a-supply-chain-attack-method-for-Java-and-Android-applications/) (2024) | 18% of Maven domains vulnerable |
    | App acquisition | Barcode Scanner (2021) | 10M+ installs |

## SDK Supply Chain Poisoning

The most effective Android supply chain vector. A malicious SDK presents itself as a legitimate advertising, analytics, or monetization component. App developers integrate it through standard Gradle dependencies or direct SDK drops. The SDK activates its malicious functionality after integration, reaching the developer's entire user base.

### Why It Works

- Developers rarely audit third-party SDK source code
- SDKs run with the host app's full permission set
- A single compromised SDK can infect hundreds of apps simultaneously
- Google Play review focuses on the app, not on individual SDK components
- SDK updates can introduce malicious code after initial review

### Major Cases

**SpinOk** (2023): A malicious SDK distributed as a minigame/engagement component. [Discovered by Dr.Web](https://news.drweb.com/show?i=14705&lng=en) in May 2023, then [expanded by CloudSEK](https://www.cloudsek.com/threatintelligence/supply-chain-attack-infiltrates-android-apps-with-malicious-sdk) to 193 affected apps. The SDK collected files, images, clipboard content, and could hijack cryptocurrency payments. Over 421 million combined downloads across 101+ apps. 43 apps were still active on the Play Store at time of discovery.

**[Goldoson](../malware/families/goldoson.md)** (2023): Malicious third-party library in 60+ legitimate South Korean apps. [Discovered by McAfee](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/) in April 2023. Collected installed app data, WiFi/Bluetooth device info, GPS locations, and performed background ad click fraud. Over 100 million combined downloads.

**[Necro](../malware/families/necro.md) / Coral SDK** (2024): Malicious advertising SDK using [image steganography](play-store-evasion.md#steganographic-payloads) to hide payloads in PNG files. [Kaspersky found it](https://securelist.com/necro-trojan-is-back-on-google-play/113881/) in Wuta Camera (10M+) and Max Browser (1M+) on Google Play. Native library obfuscated with OLLVM, modular plugin architecture for ad fraud and proxy tunneling. 11M+ total infections. The original 2019 Necro variant hit CamScanner (100M+ installs) through a different SDK ("AdHub").

**[SparkCat](../malware/families/sparkcat.md)** (2024-2025): SDK in Android and iOS apps using Google ML Kit OCR to scan photo galleries for cryptocurrency wallet recovery phrases. [Discovered by Kaspersky](https://securelist.com/sparkcat-stealer-in-app-store-and-google-play/115385/), oldest build dated March 2024. 242,000+ downloads. First cross-platform SDK supply chain attack hitting both Google Play and Apple App Store simultaneously.

**ExpensiveWall** (2017): Malicious code hidden inside an SDK called "gtk" that developers embedded in their apps. The SDK was packed to evade Play Protect. [Check Point discovered](https://research.checkpoint.com/2017/expensivewall-dangerous-packed-malware-google-play-will-hit-wallet/) it sending premium SMS and signing users up for paid services. 5.9M to 21.1M downloads across 100+ apps.

**SWAnalytics / Operation Sheep** (2019): Analytics SDK integrated into apps on major Chinese third-party stores (Tencent MyApp, Wandoujia, Huawei App Store, Xiaomi App Store). [Check Point documented](https://research.checkpoint.com/2019/operation-sheep-pilfer-analytics-sdk-in-action/) that the SDK silently exfiltrated users' entire contact lists to servers controlled by Hangzhou Shun Wang Technologies. 250 million combined downloads.

For data harvesting SDKs (X-Mode, Measurement Systems, Patternz), see [Data Broker SDKs](../grayware/data-broker-sdks.md).

## OEM Pre-installed Software

A distinct vector from firmware backdoors: OEMs integrate third-party SDKs into their own system apps for monetization, analytics, or device management, without fully auditing what those SDKs collect or do. These apps ship as system packages, cannot be uninstalled, run with elevated privileges, and bypass Play Store review entirely.

### The Structural Problem

The most comprehensive study of this ecosystem is from [IMDEA Networks (IEEE S&P 2020)](https://dspace.networks.imdea.org/bitstream/handle/20.500.12761/684/An_Analysis_of_Pre-installed_Android_Software_2019_EN.pdf): researchers analyzed 82,000+ pre-installed apps across 1,700+ devices from 214 brands and found 11,000+ third-party SDKs embedded in system apps, 4,845+ custom permissions defined by supply chain participants, and data flowing to advertising/tracking companies including Baidu, Tencent, Alibaba, Facebook, and Verizon/Yahoo/AOL. 806 apps embedded Facebook's Graph SDK across 748 devices, with 293 signed by the device vendor rather than Facebook. OEMs, carriers, and chipset vendors all define custom permissions that circumvent Android's standard permission model. The study won awards from both AEPD (Spanish Data Protection Agency) and CNIL (French Data Protection Authority).

The layered supply chain creates blind spots at every level: chipset vendor provides a platform package, OEM integrates it with carrier-required components, regional distributor adds monetization SDKs, and no single entity audits the full stack.

### Monetization SDKs on System Partition

OEMs and carriers pre-install app recommendation engines that silently install apps without user consent, operating as system-level services that cannot be removed.

**Digital Turbine / DT Ignite**: Pre-installed as a system app by 30+ carriers (AT&T, Verizon, T-Mobile, Vodafone, Deutsche Telekom, Singtel) and OEMs including Samsung and LG. [First reported by Android Police in 2014](https://www.androidpolice.com/2014/12/01/t-mobile-and-verizon-and-possibly-others-are-using-a-new-system-app-to-silently-install-bloatware-onto-phones/), DT Ignite silently installs "recommended" apps in the background based on carrier/advertiser deals (up to $1.19/user per app install). Cannot be uninstalled, continues pushing apps throughout the device lifecycle. Hundreds of millions of devices globally.

**ironSource AppCloud on Samsung**: Since 2022, Samsung embedded ironSource's AppCloud (now Unity-owned) on Galaxy A and M series phones in the West Asia/North Africa region. [SMEX documented](https://smex.org/invasive-israeli-software-is-harvesting-data-from-samsung-users-in-wana/) that the app is unremovable, harvests user data, and installs apps without consent. [Malwarebytes confirmed the findings](https://www.malwarebytes.com/blog/news/2025/11/budget-samsung-phones-shipped-with-unremovable-spyware-say-researchers) in November 2025.

### Analytics SDKs in Chinese OEM Firmware

[Researchers from the University of Edinburgh and Trinity College Dublin (ACM WiSec 2023)](https://www.scss.tcd.ie/Doug.Leith/pubs/wisecfp034-liu.pdf) analyzed data transmitted by pre-installed system apps on Xiaomi, OnePlus, and Oppo Realme devices. Chinese-region firmware transmitted persistent device identifiers (IMEI, MAC address), geolocation, phone numbers, app usage patterns, and call history to third-party analytics endpoints, even when users opted out of analytics and personalization. Global firmware versions of the same devices did not exhibit this behavior. The third-party SDKs receiving data included Baidu, Alibaba, and Tencent analytics components that OEMs integrated as replacements for Google services unavailable in China.

**Baidu Push SDK**: [Palo Alto Networks Unit 42 found](https://unit42.paloaltonetworks.com/android-apps-data-leakage/) that Baidu's Android Push SDK collected MAC addresses, IMSI numbers, carrier info, and device data. The SDK was embedded in pre-installed apps across OEMs representing over 66% of global Android market share. IMSI numbers enable lifetime user tracking even across device changes.

### Insecure OEM SDK Integration

**Samsung SwiftKey Keyboard** (2015): Samsung pre-installed a customized SwiftKey keyboard with a language pack update mechanism that transmitted over unencrypted HTTP. [NowSecure discovered](https://www.nowsecure.com/blog/2017/06/16/remote-code-execution-as-system-user-on-samsung-phones/) (CVE-2015-2865, CVE-2015-4640, CVE-2015-4641) that an attacker could intercept the request, inject a malicious ZIP with directory traversal, and achieve remote code execution as a system user. The keyboard could not be disabled, and even when not set as default, still ran the vulnerable update check. 600+ million Samsung devices affected including Galaxy S6, S5, S4.

### Adware SDKs in Budget OEM Firmware

**GMobi SDK** (2016): Adware SDK [discovered by Dr.Web](https://vms.drweb.com/virus/?i=7999629) pre-installed on ~40 mobile device models including Micromax AQ5001. Also found in apps from ASUS (WebStorage) and Trend Micro (Dr. Safety, Dr. Booster). The SDK collected emails, device info, GPS/network coordinates, displayed ad notifications, and made mobile payments. OEMs and even Trend Micro unknowingly integrated it as a legitimate monetization component.

**UMX Lifeline Program Phones** (2020): The UMX U686CL, a $35 phone distributed through the US government's Lifeline Assistance program for low-income Americans, [shipped with two pre-installed malware components](https://www.malwarebytes.com/blog/news/2020/01/united-states-government-funded-phones-come-pre-installed-with-unremovable-malware): a Wireless Update app (Adups variant silently installing HiddenAds trojan) and the Settings app itself functioning as a heavily-obfuscated trojan dropper. Since Settings is essential to device operation, removing it bricked the phone. [Malwarebytes later found the same pattern](https://www.malwarebytes.com/blog/android/2020/07/we-found-yet-another-phone-with-pre-installed-malware-via-the-lifeline-assistance-program) on the ANS UL40, another Lifeline phone. Both brands traced back to TeleEpoch Ltd.

**Tecno / Transsion** (2020): Triada and xHelper found pre-installed on Transsion's Tecno W2 smartphones, primarily sold in Africa. [Secure-D recorded](https://www.upstreamsystems.com/press/press-releases/xhelper-triada-malware-pre-installed-on-thousands-of-low-cost-chinese-android-devices-in-emerging-markets/) 19.2 million suspicious transactions from over 200,000 unique devices across Ethiopia, Cameroon, Egypt, Ghana, and South Africa. The malware silently signed users up for premium subscriptions. Google attributed the insertion to "a malicious supplier somewhere within the supply chain." Transsion is the top-selling phone manufacturer in Africa (40.6% of the African smartphone market, 69.5% of feature phones in Q4 2019).

### Kryptowire Systematic Audits (2016-2022)

[Kryptowire](https://www.quokka.io/) (now Quokka), funded by the US Department of Homeland Security, conducted the most systematic ongoing audit of pre-installed OEM software. Key findings:

| Year | Scope | Findings |
|------|-------|----------|
| 2016 | BLU Products (Adups FOTA) | Full SMS, contacts, IMEI, location exfiltrated to Chinese servers every 72 hours |
| [2018](https://www.kryptowire.com/android-firmware-defcon-2018/) | 25 device models, 11 sold by US carriers | 38 vulnerabilities: pre-installed apps could force-install apps, record audio, modify system settings |
| [2019](https://www.kryptowire.com/android-firmware-2019/) | 29 OEMs including Samsung (33 vulnerable apps), Xiaomi (15) | 146 vulnerabilities including dynamic code loading, command execution, audio recording |
| 2021 | 70,000 applications, 3B+ lines of code | 500+ vulnerabilities affecting ~2 billion devices |

## Build Pipeline & Dependency Attacks

Attacks targeting the Android development toolchain: Gradle dependencies, Maven repositories, build scripts, and signing infrastructure.

### MavenGate (2024)

[Oversecured discovered](https://blog.oversecured.com/Introducing-MavenGate-a-supply-chain-attack-method-for-Java-and-Android-applications/) that attackers could hijack abandoned Java/Android library dependencies by purchasing expired domain names associated with library maintainers, then asserting control over their `groupId` via DNS TXT records on Maven Central. This allowed publishing malicious versions of those libraries that Gradle would resolve during builds. 6,170 of 33,938 analyzed domains (18.18%) were vulnerable. Reports sent to 200+ companies including Google, Facebook, Signal, Amazon. Sonatype disabled accounts associated with expired domains in response.

### JCenter Sunset Risk (2021-2024)

JFrog announced JCenter shutdown in February 2021 (final sunset August 2024). Since Android Studio historically included `jcenter()` by default in `build.gradle`, every pre-AGP 4.2 Android project referenced it. The transition period created dependency resolution gaps: libraries never migrated to Maven Central could potentially be claimed by attackers on other repositories. [Google moved the default](https://blog.gradle.org/jcenter-shutdown) to `mavenCentral()` in AGP 7.0.

### Maven Central Typosquatting (2024)

A malicious package impersonating the Jackson JSON library was published to Maven Central using `org.fasterxml.jackson.core` instead of the legitimate `com.fasterxml.jackson.core`. [Sonatype and Aikido reported](https://www.aikido.dev/blog/maven-central-jackson-typosquatting-malware) the package contained a multi-stage payload delivering a Cobalt Strike beacon. Downloaded 846 times in 10 days. First sophisticated malware detected on Maven Central.

### Dependency Confusion

Security researcher Alex Birsan [demonstrated in February 2021](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) that publishing malicious packages to public registries with the same names as private internal packages could trick build systems into pulling the malicious public version. Successfully breached 35+ companies including Microsoft, Apple, PayPal, Tesla, Uber. The technique applies directly to Maven/Gradle builds where `repositories {}` block ordering determines resolution priority. [Academic research (arXiv, July 2024)](https://arxiv.org/html/2407.18760v4) confirmed that Gradle repository declaration order (Maven Central vs. JitPack) determines which artifact wins.

### Gradle Wrapper Tampering

A supply chain attack in the Minecraft modding community involved tampered Gradle Wrapper JAR files that granted admin-level access. Gradle responded by releasing a [GitHub Action for Wrapper validation](https://blog.gradle.org/project-integrity) using known checksums and adding [dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html) features.

### npm Dependency Attacks (React Native)

The npm ecosystem, which React Native apps depend on, has seen repeated supply chain attacks. The **event-stream incident** (November 2018) was the most significant: an attacker socially engineered maintainership of the event-stream package (~2M weekly downloads), added a dependency containing an AES-encrypted payload targeting the Copay cryptocurrency wallet. Copay versions 5.0.2-5.1.0 shipped with the backdoor. More recently, [Sonatype reported](https://www.sonatype.com/press-releases/18000-new-malicious-packages-discovered-in-q1) 778,500+ malicious npm packages identified by end of 2024.

## Platform Signing Key Compromise

In December 2022, [Google's APVI disclosed](https://www.bleepingcomputer.com/news/security/samsung-lg-mediatek-certificates-compromised-to-sign-android-malware/) that platform signing certificates from Samsung, MediaTek, LG, and Revoview had leaked and were being used to sign malware. An APK signed with a platform certificate gets `android.uid.system`, granting system-level privileges with all permissions auto-granted. Malware samples signed with Samsung's certificate dated back to 2016. See [Privilege Escalation](privilege-escalation.md#leaked-platform-signing-certificates) for technical details.

## App Acquisition & Update Hijacking

Threat actors purchase legitimate apps or developer accounts, then push malicious updates to the existing user base. This bypasses all initial trust barriers: the app already has installs, reviews, and history.

### Developer Account Market

According to [Kaspersky research (2023)](https://www.infosecurity-magazine.com/news/malicious-android-apps-sold/), Google Play developer accounts sell on dark web marketplaces for $60-$200 each. Existing apps with established user bases sell for $20,000+ depending on install count. The buyer retains the original developer's signing keys and account access, allowing them to push updates indistinguishable from legitimate ones.

### Barcode Scanner / Lavabird (2021)

A barcode scanning app with 10M+ installs received a malicious update on December 4, 2020. [Malwarebytes discovered](https://www.malwarebytes.com/blog/news/2021/02/barcode-scanner-app-on-google-play-infects-10-million-users-with-one-update) that Lavabird Ltd. had sold the app to a third party who injected heavily obfuscated adware. The buyer retained all original certificates and account access. The update introduced no new permissions, just malicious code hidden in the existing codebase.

### PhantomLance / APT32 (2015-2020)

Vietnamese state-linked threat group APT32 published clean apps on Google Play, created fake GitHub developer profiles for legitimacy, then delivered malware via subsequent updates. [Kaspersky documented](https://www.kaspersky.com/blog/phantomlance-android-backdoor-trojan/35234/) spyware collecting geolocation, call logs, contacts, SMS, and device information. Active for five years before discovery. Targeted users across India, Bangladesh, Vietnam, Indonesia, and other Southeast Asian countries.

### Konfety "Evil Twin" (2024)

[HUMAN Security discovered](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-konfety-spreads-evil-twin-apps-for-multiple-fraud-schemes/) threat actors creating "decoy twin" apps on Google Play (clean, no malicious code) and corresponding "evil twin" apps distributed via malvertising. Evil twins spoofed the decoy apps' package names and publisher IDs, conducting ad fraud and sideloading code. 250+ decoy apps on Google Play, generating 10 billion programmatic ad requests per day at peak.

## Firmware Supply Chain

Malware embedded in device firmware during manufacturing. Affects budget Android devices where OEMs outsource firmware to third-party suppliers who monetize through bundled malware. See [Firmware Grayware](../grayware/firmware-grayware.md) for detailed coverage of ADUPS, Cosiloon, [Triada](../malware/families/triada.md), Gionee, Lemon Group, BADBOX, and RottenSys.

The firmware vector is the most severe supply chain compromise: infections survive factory resets, operate with system privileges, and cannot be removed without reflashing a clean ROM.

## Framework-Specific Vectors

### Xamalicious (2023)

Malware built using the Xamarin framework, hiding malicious behavior in Xamarin DLLs that standard Android analysis tools cannot inspect. [McAfee documented](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/stealth-backdoor-android-xamalicious-actively-infecting-devices/) it contacting C2 to download a second-stage assembly DLL injected at runtime. 25 apps on Google Play, 327,000+ compromised devices. The cross-platform framework itself became the evasion mechanism.

## Families Using This Technique

| Family | Supply Chain Vector | Scale |
|--------|-------------------|-------|
| [Triada](../malware/families/triada.md) | Firmware pre-install via compromised OEM vendor; Tecno W2 supply chain insertion | 40+ device models, 4,500+ infections (2025 wave) |
| [Necro](../malware/families/necro.md) | Coral SDK embedded in legitimate apps | 11M+ downloads |
| [Goldoson](../malware/families/goldoson.md) | Malicious third-party library in Korean apps | 100M+ downloads |
| [SparkCat](../malware/families/sparkcat.md) | OCR SDK targeting crypto wallets | 242K+ downloads |
| [Joker](../malware/families/joker.md) | Various SDK wrappers, versioning attacks | Millions across hundreds of apps |
| SpinOk | Malicious engagement/minigame SDK | 421M+ downloads |
| ExpensiveWall | Packed "gtk" SDK | 5.9M-21.1M downloads |
| Chamois | Firmware pre-install + SDK distribution | 199M installs at peak |
| GMobi | Adware SDK pre-installed on ~40 OEM device models | ~40 device models + ASUS/Trend Micro apps |
| Measurement Systems | Data-harvesting SDK linked to US defense contractor | 60M+ downloads |
| DT Ignite | OEM/carrier pre-installed silent app installer | Hundreds of millions via 30+ carriers |

## Detection During Analysis

??? example "Static Indicators"

    - Third-party SDKs with obfuscated native libraries (`libcoral.so`, `libsvm.so`) using OLLVM
    - SDK package names not matching known legitimate advertising SDKs
    - Gradle dependencies resolving from uncommon or recently created Maven repositories
    - `build.gradle` referencing `jcenter()` alongside `mavenCentral()` (dependency confusion risk)
    - APK signed with a platform certificate not matching the expected OEM for the declared device target
    - SDK initialization code in `Application.onCreate()` that loads native libraries before any app UI

??? example "Dynamic Indicators"

    - SDK components making encrypted POST requests on first launch before any user interaction
    - PNG/JPEG downloads followed by class loading (steganographic payload delivery)
    - SDK network traffic to domains unrelated to the declared SDK vendor
    - `DexClassLoader` invocations from within SDK code paths
    - Data exfiltration (contacts, location, device IDs) from code paths outside the app's core functionality
    - Random activation thresholds (SDK generates random number, only activates on certain values)

??? example "OEM Pre-installed Indicators"

    - System apps (installed on `/system/app` or `/system/priv-app`) containing third-party SDK package names
    - Pre-installed apps with `QUERY_ALL_PACKAGES` or `ACCESS_FINE_LOCATION` unrelated to stated functionality
    - Custom permissions defined by supply chain participants (not standard Android permissions)
    - System services making periodic HTTP POST requests to analytics/advertising domains
    - Silent APK installation activity from system-privileged apps (DT Ignite pattern)
    - FOTA update components contacting non-OEM servers (`bigdata.adups.com`, `rebootv5.adsunflower.com`)
