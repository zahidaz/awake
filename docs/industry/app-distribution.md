# App Distribution

Alternative distribution channels outside Google Play, the APK modding ecosystem, and evolving platform policies. Malware distribution increasingly uses third-party stores, sideloading, and modded APK sites.

## Official & Major Stores

| Store | Region | Users/Scale | Notes |
|-------|--------|-------------|-------|
| [Google Play](https://play.google.com/) | Global | 2.5B+ devices | Official store. Play Protect scanning blocks 1.75M harmful apps annually. Droppers still get through regularly. |
| [Huawei AppGallery](https://consumer.huawei.com/en/mobileservices/appgallery/) | Global | 580M+ MAU | Third-largest app store globally (behind Google Play and Apple App Store). Own review process. [Joker trojans](https://news.drweb.com/show/?i=14182) found in 2020 (538K installs), [Cynos trojan](https://www.bleepingcomputer.com/news/security/over-nine-million-android-devices-infected-by-info-stealing-trojan/) in 190+ apps (9.3M installs) in 2021. |
| [Samsung Galaxy Store](https://galaxystore.samsung.com/) | Global | Pre-installed on Samsung devices | [Showbox clones with malware](https://www.androidpolice.com/samsung-galaxy-store-malware-movie-piracy-showbox/) found in 2021. Two vulnerabilities disclosed in 2023: [CVE-2023-21433](https://www.nccgroup.com/research-blog/technical-advisory-multiple-vulnerabilities-in-the-galaxy-app-store-cve-2023-21433-cve-2023-21434/) allowed silent arbitrary app installation, CVE-2023-21434 enabled URL filter bypass. |
| [Amazon Appstore](https://www.amazon.com/gp/mas/get/amazonapp) | Global | ~597K apps at shutdown | Discontinued on Android devices August 20, 2025 after 14 years. [Continues only on Fire TV and Fire Tablet](https://techcrunch.com/2025/02/20/amazon-is-shutting-down-its-app-store-on-android/). |

## Chinese Stores

Google Play is unavailable in China. Users install apps from OEM and third-party stores, making these primary distribution channels for both legitimate apps and malware targeting Chinese users. OEM stores have overtaken independent third-party stores in market share.

| Store | Operator | Notes |
|-------|----------|-------|
| [Tencent MyApp (Yingyongbao)](https://sj.qq.com/) | Tencent | China's largest independent third-party Android store. ~270M MAU. Deeply integrated with WeChat and QQ. |
| [Xiaomi GetApps](https://global.app.mi.com/) | Xiaomi | 260M MAU across 100+ markets. 30M daily installs. Being [replaced by Indus Appstore on Indian devices](https://x.com/SavageAryan007/status/1857381097283174748) from January 2025. |
| [OPPO App Market](https://developers.oppomobile.com/) | OPPO | Pre-installed on OPPO/OnePlus devices. Also known as HeyTap App Market. |
| Vivo App Store | Vivo | Pre-installed on Vivo/iQOO devices. 400M+ global device base. |
| [360 Mobile Assistant](https://zhushou.360.cn/) | Qihoo 360 | Once a top independent store, now declining as OEM stores dominate. |
| Baidu Mobile Assistant | Baidu | Significantly diminished. Baidu's [91 Assistant shut down September 2025](https://www.digitalphablet.com/business/baidu-ends-91-assistant-amid-costly-outdated-investment/). |

## Regional & Alternative Stores

| Store | Region | Notes |
|-------|--------|-------|
| [CafeBazaar](https://cafebazaar.ir/) | Iran | Dominant Iranian store, ~97% market share. 50M+ users, 29M MAU. [Sold to Tapsell](https://www.intellinews.com/iran-s-hezardastan-sells-android-app-store-caf-bazaar-to-local-tapsell-362903/) in January 2025. [200+ credential-harvesting apps](https://thehackernews.com/2023/11/200-malicious-apps-on-iranian-android.html) targeting Iranian banks found in 2023. |
| [RuStore](https://rustore.ru/) | Russia | State-backed, launched May 2022 by VK. 50M+ MAU. [Mandatory pre-installation](https://en.wikipedia.org/wiki/RuStore) on all devices sold in Russia since September 2025. Expanding to 70 countries. |
| [Indus Appstore](https://www.indusappstore.com/) | India | Launched February 2024 by PhonePe (Walmart-backed). Supports 12 Indian languages, 200K+ apps. Zero listing fees, zero commission on third-party payment gateways. Xiaomi replacing GetApps with Indus on Indian devices. |
| [Epic Games Store](https://store.epicgames.com/) | Global | Launched on Android August 2024. [29M users by end of 2024](https://techcrunch.com/2024/08/16/epic-games-store-debuts-on-mobile-fortnite-returns-to-ios-in-eu/). US court ordered Google to allow third-party stores within Play Store, creating "Registered App Stores" effective November 2024. |

## Open-Source Distribution

| Platform | Type | Notes |
|----------|------|-------|
| [F-Droid](https://f-droid.org/) | FOSS app store | Free and open-source software only. 4,000+ apps. Builds apps from source code (reproducible builds). Flags anti-features (ads, tracking) transparently. Under existential threat from [Google's Developer Verification Decree](https://f-droid.org/en/2025/09/29/google-developer-registration-decree.html) requiring all Android developers to register with Google. |
| [Aurora Store](https://auroraoss.com/) | Google Play client | Open-source, unofficial Google Play frontend. Not a separate catalog. Allows anonymous access to Google Play apps. Google [aggressively blocking](https://gitlab.com/AuroraOSS/AuroraStore) anonymous dispenser accounts. |

## APK Hosting & Mirrors

These are not app stores. They host APK files for download without providing a storefront or app discovery experience.

| Platform | Type | Notes |
|----------|------|-------|
| [APKMirror](https://www.apkmirror.com/) | Curated APK archive | Founded 2014, independently owned. Manually reviews every upload. Verifies cryptographic signatures against known developer certificates. No piracy. One of the most trusted APK sources. |
| [APKPure](https://apkpure.com/) | APK download site | [Compromised in April 2021](https://securelist.com/apkpure-android-app-store-infected/101845/): official client app v3.17.18 was trojanized with Triada dropper via an unverified ad SDK. Kaspersky blocked it on 9,380+ devices. Fixed in v3.17.19. |
| [Uptodown](https://en.uptodown.com/) | APK distribution | Founded 2002, based in Spain. 100M active users. [450M+ monthly downloads](https://en.uptodown.com/about-us/stats). 260K+ apps. Hosts legitimate APKs on own servers. |
| [Aptoide](https://en.aptoide.com/) | Decentralized marketplace | Open-source, community-driven. Users create their own "stores." [Breached April 2020](https://www.androidpolice.com/2020/04/21/aptoide-database-breach-exposes-20-million-user-accounts-possibly-more-to-come/): 39M accounts copied, 20M records leaked. Emails, SHA-1 hashed passwords (unsalted), names, IPs exposed. |

## B2B Distribution Platforms

| Platform | Type | Notes |
|----------|------|-------|
| [Appland](https://www.appland.se/) | White-label pre-loaded app store | Swedish company (founded 2011), [acquired by OnMobile Global in 2018](https://pitchbook.com/profiles/company/56488-06) for ~$15M. B2B infrastructure for mobile operators and OEMs. App stores are pre-installed as system apps on smartphones before shipping, granting `INSTALL_PACKAGES` for silent APK installation. Installed on 10M+ devices across 200+ countries. [TIMWE partnership](https://www.businesswire.com/news/home/20140826005959/en/Appland-Announces-Global-Reseller-Agreement-with-TIMWE-to-Offer-Localized-App-Stores-to-Emerging-Markets-via-Mobile-Network-Operators) rolled out across mobile operators in Latin America, Southeast Asia, and CIS/Russia. Revenue via carrier billing (charged to phone bill). Pre-loaded stores have been observed bundling carrier billing SDKs ([Fortumo](https://fortumo.com/), now part of [Boku](https://www.boku.com/)) and server-pushed install lists that silently install apps without user interaction. The line between "alternative store" and malware distribution platform depends on what gets silently installed. |

## APK Modding & Cracking

Modified APKs (mods) distributed through forums and dedicated sites. Modded APKs are a primary malware distribution vector: trojans, adware, and spyware are injected into popular cracked apps, then the victim installs a "premium" version and gets malware bundled in.

| Platform | Type | Notes |
|----------|------|-------|
| ACMarket | Modded app store | Distributes cracked and modded APKs. Multiple mirror domains (acmarket.net, .icu, .app). Known malware distribution vector. No reliable vetting. |
| An1.com | Modded games | Modded Android game distribution. Claims file scanning but no independent verification. |
| HappyMod | Modded app store | Community-uploaded modded APKs. Claims VirusTotal scanning but mods are user-submitted with no professional vetting. |
| [Lucky Patcher](https://www.luckypatchers.com/) | Modification tool | Not a store. Device-level APK patching tool for ad removal, license bypass, in-app purchase bypass, and permission modification. Most features require root. Frequently flagged by AV. |
| [Mobilism](https://forum.mobilism.me/) | Piracy forum | Forum-based piracy platform. Users share cracked/modded APKs via threads and direct downloads. No automated scanning or vetting. |

## Platform Policy Changes

### Google Play Sideloading Restrictions (2024-2025)

Google has progressively tightened controls over sideloaded apps:

| Change | Year | Impact |
|--------|------|--------|
| [Enhanced Fraud Protection](https://9to5google.com/2024/10/03/google-blocking-sideloaded-apps-india/) | 2024 | Automatically blocks sideloaded apps requesting sensitive permissions (SMS, accessibility, notification listener). Piloted in Singapore, expanded to Brazil, India, Kenya, Nigeria, Philippines, South Africa, Thailand, Vietnam. Shielded 10M devices from 36M risky installs. |
| [Play Integrity API tightening](https://developer.android.com/google/play/integrity) | 2025 | Stricter verdicts require apps to be installed via Google Play for strong integrity ratings. Devices need security updates within 12 months. Penalizes sideloaded apps. |
| [Developer Verification Decree](https://android-developers.googleblog.com/2025/08/elevating-android-security.html) | 2025 | All Android developers, including those distributing outside Play Store, must register with Google. Unregistered apps blocked on certified devices. Enforcement begins March 2026, mandatory in Brazil/Indonesia/Singapore/Thailand from September 2026, global 2027+. |
| Play Protect scanning expansion | 2025 | Daily scans increased from 200B to 350B, covering both Play Store and sideloaded apps. Blocked 1.75M harmful apps. |

### EU Digital Markets Act

Google is designated as a [DMA gatekeeper](https://digital-markets-act.ec.europa.eu/index_en) for Android and Google Play. In March 2025, the European Commission [informed Alphabet of DMA breaches](https://epthinktank.eu/2025/04/24/digital-markets-act-enforcement-state-of-play/) regarding Google Play's restrictions on developers steering users to alternative distribution channels and payment methods. US federal courts separately ordered Google to allow third-party stores within Google Play effective November 2024.

### Android Source Code Delays

In March 2025, Google stopped releasing Android source code immediately after device launches, instead delaying releases by weeks or months. This hinders FOSS developers, alternative distributions like F-Droid, and custom ROM projects that depend on timely AOSP access.
