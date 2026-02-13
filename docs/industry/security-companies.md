# Mobile Security Industry

The mobile security industry has distinct segments. Understanding who operates where helps when reading reports, evaluating tools, and recognizing whose perspective shapes the research.

## Threat Intelligence / Malware Research

Companies that discover, analyze, and name mobile malware families. Their reports are primary sources.

| Company | Focus | Notable For |
|---------|-------|-------------|
| Avast Threat Labs | Consumer + research | [Avast Decoded blog](https://decoded.avast.io/). Android adware, Play Store threats, [Cerberus](../malware/families/cerberus.md) analysis. |
| CheckPoint Research | Broad security research | CPR publishes Android malware campaigns, Play Store threat analysis. [Rafel RAT](../malware/families/rafelrat.md) discovery (120+ campaigns). [FluHorse](../malware/families/fluhorse.md) (Flutter-based stealer). |
| Cisco Talos | Broad threat intelligence | [Gustuff](../malware/families/gustuff.md) analysis. [Predator](../malware/families/predator.md) deep-dive (Python implant architecture). |
| Citizen Lab | Digital surveillance research | University of Toronto. [Pegasus](../malware/families/pegasus.md), [Predator](../malware/families/predator.md), [FinSpy](../malware/families/finspy.md) tracking. |
| Cleafy | Financial fraud, mobile banking | Detailed banking trojan reports. [Copybara](../malware/families/copybara.md), [Anatsa](../malware/families/anatsa.md), [BRATA](../malware/families/brata.md), [ToxicPanda](../malware/families/toxicpanda.md), [SharkBot](../malware/families/sharkbot.md), [PixPirate](../malware/families/pixpirate.md), [BingoMod](../malware/families/bingomod.md), [Klopatra](../malware/families/klopatra.md), [Albiriox](../malware/families/albiriox.md). |
| CYFIRMA | External threat landscape management | [FireScam](../malware/families/firescam.md) discovery (fake RuStore/Telegram Premium info-stealer). |
| Cyble | Dark web intelligence + mobile | CRIL (Cyble Research and Intelligence Labs). [Chameleon](../malware/families/chameleon.md), [GodFather](../malware/families/godfather.md) v2, [TsarBot](../malware/families/tsarbot.md), [Antidot](../malware/families/antidot.md), [TrickMo](../malware/families/trickmo.md), [Gigabud](../malware/families/gigabud.md), [BTMOB RAT](../malware/families/btmob.md), [DeVixor](../malware/families/devixor.md). |
| ESET | Broad antivirus + research | Regular Android publications. [FinSpy](../malware/families/finspy.md) devirtualization. [NGate](../malware/families/ngate.md) NFC relay discovery. FurBall, SpyAgent. |
| Fortinet FortiGuard Labs | Broad threat intelligence | Android malware write-ups, [BankBot](../malware/families/bankbot.md) analysis. |
| Google TAG | State-sponsored threat tracking | Tracks commercial spyware. [Predator](../malware/families/predator.md) exploit chains, [Hermit](../malware/families/hermit.md) analysis. |
| Group-IB | Threat intelligence, fraud prevention | [GodFather](../malware/families/godfather.md), [Gustuff](../malware/families/gustuff.md) discovery. APT-level mobile tracking. |
| HUMAN Security (Satori) | Bot/fraud intelligence | [Harly](../malware/families/harly.md) analysis. Mobile fraud research. |
| IBM Security Trusteer | Financial fraud | [PixPirate](../malware/families/pixpirate.md) analysis. Banking fraud intelligence. |
| Kaspersky | Broad threat intelligence | Long Android malware history. [Triada](../malware/families/triada.md), [Harly](../malware/families/harly.md), [BRATA](../malware/families/brata.md), Roaming Mantis, [LightSpy](../malware/families/lightspy.md) (initial iOS disclosure). |
| Lookout | Mobile-focused threat intel | [Pegasus](../malware/families/pegasus.md) (Chrysaor), [Hermit](../malware/families/hermit.md) discovery. [KoSpy](../malware/families/kospy.md) DPRK spyware, [GuardZoo](../malware/families/guardzoo.md) Houthi surveillance. [BoneSpy](../malware/families/bonespy.md)/[PlainGnome](../malware/families/plaingnome.md) Sandcat spyware. [EagleMsgSpy](../malware/families/eaglemsgspy.md) Chinese lawful intercept. [LightSpy](../malware/families/lightspy.md) (DragonEgg attribution). [DCHSpy](../malware/families/dchspy.md) MuddyWater Iranian surveillanceware. |
| McAfee Mobile Research | Mobile malware, adware, PUPs | Part of McAfee Labs. Primary tracker of [MoqHao](../malware/families/moqhao.md)/Roaming Mantis. Original discovery of [SpyAgent](../malware/families/spyagent.md) OCR crypto theft, [Goldoson](../malware/families/goldoson.md) SDK supply chain, [Xamalicious](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/stealth-backdoor-android-xamalicious-actively-infecting-devices/) Xamarin backdoor, [.NET MAUI evasion](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/). Deep Korean and Indian market coverage. HiddenAds, Clicker, and Invisible Adware at-scale ad fraud discovery. [SpyLoan](../malware/families/spyloan.md) global tracking. [Sun Team](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/malware-on-google-play-targets-north-korean-defectors/) DPRK attribution. |
| NCC Group / Fox-IT | Offensive security + research | [SharkBot](../malware/families/sharkbot.md), [Ermac](../malware/families/ermac.md)/[Hook](../malware/families/hook.md) lineage analysis. [FluBot](../malware/families/flubot.md) DGA research. |
| PRODAFT | Threat intelligence | [FluBot](../malware/families/flubot.md) infrastructure analysis. Underground forum monitoring. |
| Proofpoint | Email/messaging threats | TangleBot ([Medusa](../malware/families/medusa.md)) naming. Mobile phishing campaigns. |
| Sophos | Cross-platform threats | X-Ops team publishes Android malware analysis. [FluBot](../malware/families/flubot.md), [PJobRAT](../malware/families/pjobrat.md) Taiwan campaign. |
| ThreatFabric | Android banking trojans | Most prolific Android malware research. Named [Cerberus](../malware/families/cerberus.md), [Anatsa](../malware/families/anatsa.md), [Hook](../malware/families/hook.md), [Ermac](../malware/families/ermac.md), [Xenomorph](../malware/families/xenomorph.md), [Medusa](../malware/families/medusa.md), [Vultur](../malware/families/vultur.md), [Octo](../malware/families/octo.md), [Alien](../malware/families/alien.md), [Brokewell](../malware/families/brokewell.md), [Crocodilus](../malware/families/crocodilus.md), [Herodotus](../malware/families/herodotus.md), [Sturnus](../malware/families/sturnus.md), [RatOn](../malware/families/raton.md). [LightSpy](../malware/families/lightspy.md) DragonEgg-to-LightSpy link. |
| Trend Micro | Enterprise threats | [TgToxic](../malware/families/toxicpanda.md) discovery. Mobile ransomware, spyware. |
| Zimperium | Mobile threat defense | [GriftHorse](../malware/families/grifthorse.md) discovery. [Hook](../malware/families/hook.md) v3, [GodFather](../malware/families/godfather.md) v3 analysis. [Gigabud](../malware/families/gigabud.md)+[SpyNote](../malware/families/spynote.md) infrastructure mapping. zLabs research. |
| Zscaler ThreatLabz | Cloud security + research | [Copybara](../malware/families/copybara.md) MQTT analysis, [Anatsa](../malware/families/anatsa.md) Play Store campaigns. |

## Threat Intel Vendor Comparison

Which vendor to reference depends on what you need. This matrix ranks the major Android malware research publishers.

| Vendor | Named Families | Blog Frequency | Primary Focus | Free Intel |
|--------|---------------|----------------|---------------|------------|
| ThreatFabric | 30+ | Weekly | Banking trojans, MaaS | Blog posts, IOCs |
| Cleafy | 15+ | Bi-weekly | Banking fraud, ATS | Blog posts |
| Kaspersky | 20+ | Weekly | Broad (banking, spyware, adware) | Securelist blog, quarterly stats |
| ESET | 15+ | Bi-weekly | Broad (regional focus) | WeLiveSecurity blog |
| Cyble | 15+ | Weekly | Dark web + mobile | CRIL blog |
| Lookout | 10+ | Monthly | Spyware, state-sponsored | Blog posts |
| Zimperium | 10+ | Monthly | Banking trojans, enterprise | zLabs blog, annual report |
| Check Point | 10+ | Bi-weekly | Broad campaigns | CPR blog |
| Google TAG | 5+ | Quarterly | State-sponsored, 0-days | Blog posts |

ThreatFabric is the most prolific for Android banking trojans specifically. Cleafy provides the deepest technical analysis of ATS/on-device fraud. Kaspersky has the broadest coverage. Lookout leads in commercial spyware tracking.

## Mobile Endpoint Security

Detection and prevention products running on devices or managing device fleets.

| Company | Product Type | Notes |
|---------|-------------|-------|
| CrowdStrike | EDR with mobile | Falcon for Mobile. Extends endpoint detection to Android/iOS. |
| Lookout | Mobile endpoint security | Enterprise MDM + threat detection. Acquired by F5. |
| Microsoft Defender | Cross-platform | Defender for Endpoint includes Android device management. |
| Pradeo | Mobile fleet security | App analysis and device protection. |
| Samsung Knox | Platform security | Hardware-backed isolation. Enterprise security platform. |
| Zimperium | Mobile threat defense (MTD) | On-device ML detection. zIPS for enterprise. z9 engine. |

## App Security Testing (SAST/DAST)

Finding vulnerabilities in Android apps.

| Company | Focus | Notes |
|---------|-------|-------|
| Guardsquare | Protection (DexGuard) + testing (AppSweep) | Both sides: packer vendor and security testing. Contributes to ProGuard/R8. Acquired [Verimatrix XTD](../packers/verimatrix.md) in Feb 2026 for $8.5M -- now controls DexGuard, ProGuard, and Verimatrix XTD. |
| NowSecure | Mobile app security testing | Automated SAST/DAST. OWASP MASVS testing. Blog covers practical mobile security. |
| Oversecured | Automated Android/iOS vuln scanning | Founded by Sergey Toshin. 225+ Google app vulnerabilities. Top blog in the space. |
| Promon | App shielding (RASP) | Runtime protection. Discovered StrandHogg (task affinity attack). |
| Quixxi | App security | Mobile app security platform, vulnerability scanning. |

## AV Engines (Android Detection)

Their detection names appear in [VirusTotal](https://www.virustotal.com/). For detailed detection name formats and cross-vendor mapping, see [Naming Conventions](../malware/naming-conventions.md).

### Primary Engines (Best Android Coverage)

| Engine | Detection Name Format | Notes |
|--------|----------------------|-------|
| Avast/AVG | `Android:Family-X [Trj]` | Same engine (Avast acquired AVG). Strong mobile. |
| Bitdefender | `Android.Trojan.Banker.XX` | Licensed by eScan, GData, Emsisoft, VIPRE, Arcabit. |
| DrWeb | `Android.BankBot.NNNNN` | Numeric IDs. Popular in CIS countries. Good mobile coverage. |
| ESET-NOD32 | `Android/Spy.Banker.XXX` | Consistent naming. Research-backed signatures. |
| Fortinet | `Android/Family.A!tr` | Good mobile coverage, suffix indicates type. |
| Kaspersky | `HEUR:Trojan-Banker.AndroidOS.Family.x` | Best Android heuristic detection. Prefixes: HEUR, UDS, PDM. |
| McAfee | `Android/Family.X` or `Artemis!HASH` | "Artemis" = generic cloud ML detection. |
| Microsoft | `Trojan:AndroidOS/Family.A!MTB` | Growing Android coverage. |
| Sophos | `Andr/Family-X` | Consistent `Andr/` prefix. |
| Symantec/Broadcom | `Trojan.Gen.MBT` | Often generic, poor family attribution. |
| Trend Micro | `AndroidOS_Family.VARIANT` | Enterprise-focused. |

### Mobile-Specific Engines

| Engine | Notes |
|--------|-------|
| AhnLab-V3 | Korean. `Trojan/Android.Banker.NNNNNN`. Strong on Asian malware. |
| Avast-Mobile | Mobile-dedicated scanner. |
| BitDefenderFalx | Bitdefender's mobile engine. |
| Symantec Mobile Insight | Broadcom's mobile engine. Often generic verdicts. |
| Trustlook | Mobile-focused behavioral detection. |

### EDR / Next-Gen (Limited Family Attribution)

| Engine | Notes |
|--------|-------|
| CrowdStrike Falcon | Behavioral, often no family name. |
| DeepInstinct | Binary ML verdict only. |
| Palo Alto Networks | ML-based, usually no family name. |
| SentinelOne (Static ML) | Binary verdict: "Static AI - Malicious APK". |
| Elastic | Community rules. |

### Regional Engines

| Engine | Region | Notes |
|--------|--------|-------|
| Alibaba / AliCloud | China | `TrojanBanker:Android/Family.HASH` |
| Antiy-AVL | China | `Trojan/Android.Banker.family` |
| Baidu | China | `Android.Trojan.Bank.XX` |
| Huorong | China | Endpoint security. |
| Jiangmin | China | `TrojanBanker.AndroidOS.xx` |
| Kingsoft | China | `Android.Troj.Family.x` |
| Rising | China | `Trojan.Banker/Android!version` |
| Tencent | China | `A.privacy.family.x` |
| ALYac | Korea | Uses Bitdefender engine. |
| TACHYON | Korea | `Trojan-Android/Family` |
| ViRobot | Korea | `Android.Family.X` |
| Bkav Pro | Vietnam | Limited mobile coverage. |
| K7AntiVirus / K7GW | India | Numeric hash-based names. |
| QuickHeal | India | `Android.Family.GEN` |
| Ikarus | Austria | `Trojan-Banker.AndroidOS.Family`. |
| Zillya | Ukraine | `Trojan.Banker.Android.NNNNN` |
| Yandex | Russia | `Trojan.AndroidOS.Family` |

## Offensive Security / Research

Organizations doing Android security research from an offensive or research perspective.

| Company | Focus | Notes |
|---------|-------|-------|
| 8kSec | Mobile security training + research | Battlegrounds CTF platform. Blog covers app and kernel Android security. |
| Google Android Red Team | Internal offensive security | androidoffsec.withgoogle.com. Kernel exploitation, fuzzing. |
| Google Project Zero | 0-day research | Top-tier exploit chain research. Android kernel, Binder, codecs. |
| Trellix (formerly FireEye Mobile) | Advanced threat research | Mobile APT tracking, nation-state campaigns. |
| WithSecure (F-Secure) | Pentesting tools | Maintains Drozer (Android assessment tool). |

## Digital Forensics

Mobile forensics tools used by law enforcement, incident response, and intelligence.

| Company | Product | Notes |
|---------|---------|-------|
| Cellebrite | UFED, Physical Analyzer | Market leader in mobile forensics. Physical extraction, app data parsing. |
| Grayshift | GrayKey | iPhone and Android device unlocking. Law enforcement focused. |
| Magnet Forensics | AXIOM | Cross-platform digital forensics including mobile. Acquired by Thoma Bravo. |
| MOBILedit | Forensic Express | Mobile phone examination and data extraction. |
| MSAB | XRY | Swedish mobile forensics. Logical and physical extraction. |
| Oxygen Forensics | Detective | Cloud data extraction, mobile device forensics. |

## Packer / Protection Vendors

Companies selling Android app protection. Documented in [Packers](../packers/index.md).

| Company | Product | Origin |
|---------|---------|--------|
| Baidu | Baidu Reinforcement | China |
| Bangcle | SecNeo | China |
| Digital.ai (formerly Arxan) | App Protection | USA |
| Guardsquare | DexGuard | Belgium |
| iJiami | iJiami | China |
| Licel | DexProtector | Netherlands |
| Nagain / APKProtect | APKProtect | China |
| NetEase | NeteaseYiDun | China |
| Promon | Promon SHIELD | Norway |
| Qihoo 360 | 360 Jiagu | China |
| SenseShield | [Virbox Protector](../packers/virbox.md) | China |
| Tencent | Legu | China |
| INKA Entworks | [AppSealing](../packers/appsealing.md) | South Korea |
| Lockin Company | [LIAPP](../packers/liapp.md) | South Korea |
| Appdome Inc | [Appdome](../packers/appdome.md) | USA/Israel |
| Zimperium | [zShield](../packers/zshield.md) | USA |
| Verimatrix (now Guardsquare) | [Verimatrix XTD](../packers/verimatrix.md) | France |

## App Distribution / Third-Party Stores

Alternative distribution channels outside Google Play. Relevant because malware distribution increasingly uses these channels and sideloading.

| Store/Platform | Region | Notes |
|----------------|--------|-------|
| 360 Mobile Assistant | China | Qihoo 360's store. |
| Amazon Appstore | Global | Ships with Fire devices. Available on standard Android. |
| APKMirror | Global | APK hosting. More curated than APKPure. Focused on original developer uploads. |
| Apkada | Russia/CIS | Russian-language store. |
| APKPure | Global | APK download site. Users sideload from here. Itself was compromised with malware in 2021. |
| Aptoide | Global | Third-party marketplace. Community-driven. Used by legitimate apps and malware alike. |
| Baidu Mobile Assistant | China | Baidu's app store. |
| CafeBazaar | Iran | Dominant Iranian Android store. 40M+ users. |
| Google Play | Global | Official store. Play Protect scanning. Droppers still get through regularly. |
| Huawei AppGallery | Global (Huawei devices) | Second-largest Android store. Own review process. Used for regional malware distribution. |
| OPPO App Market | China/Global | Pre-installed on OPPO/OnePlus. |
| Samsung Galaxy Store | Global (Samsung devices) | Samsung's store. Less strict review than Play Store historically. |
| Tencent MyApp (Yingyongbao) | China | Major Chinese Android store. |
| Vivo App Store | China/Global | Pre-installed on Vivo devices. |
| Xiaomi GetApps | China/Global | Pre-installed on Xiaomi devices. |

In China, Google Play is unavailable. Users install apps from OEM stores (Tencent, Baidu, Xiaomi, etc.), making these stores primary distribution channels for both legitimate apps and malware targeting Chinese users.

## APK Modding / Cracking Scene

Modified APKs (mods) distributed through forums and dedicated sites. Relevant because modded APKs are a malware distribution vector: trojans are injected into popular cracked apps.

| Platform | Type | Notes |
|----------|------|-------|
| ACMarket | Modded app store | Distributes modified APKs. Known malware distribution vector. |
| An1.com | Modded games | Modded Android game distribution. |
| HappyMod | Modded app store | Modded game APKs. Community uploads. |
| Lucky Patcher | Modification tool | In-app purchase bypass, ad removal, permission modification. Widely used. |
| Mobilism | Forum + APK sharing | Cracked/modded APK distribution. Active community. |

Modded APKs are frequently repackaged with additional payloads (adware, spyware, banking trojans). The user installs a "cracked" version of a game or premium app and gets malware bundled in.

## Bug Bounty Programs

Vulnerability disclosure programs specifically relevant to Android security.

| Program | Scope | Max Payout | Notes |
|---------|-------|------------|-------|
| [Google VRP](https://bughunters.google.com/) | Android OS, Pixel devices, Google apps | $1,000,000 (full exploit chain) | Largest mobile bounty. Covers kernel, framework, and app-level bugs. Paid [$11.8M total in 2024](https://security.googleblog.com/2025/03/vulnerability-reward-program-2024-in.html). |
| [Google Mobile VRP](https://bughunters.google.com/) | First-party Android apps | $30,000 (RCE) | Separate program for Google-developed Android apps (Maps, YouTube, etc.) |
| [Samsung Mobile Security Rewards](https://security.samsungmobile.com/) | Samsung devices, Knox, Galaxy Store | $1,000,000 | Covers One UI, Knox, Samsung-specific drivers and firmware |
| [Qualcomm Bug Bounty](https://www.qualcomm.com/company/product-security/) | Snapdragon chipsets, modem, TEE | Varies | Baseband and TrustZone vulnerabilities. Critical for Android exploit chains. |
| [MediaTek PSIRT](https://www.mediatek.com/security) | MediaTek chipsets | Varies | Second-largest Android chipset vendor |

## Standards Bodies and Regulators

Organizations setting mobile security standards and regulations.

| Organization | Standard/Regulation | Relevance |
|-------------|-------------------|-----------|
| [NIST](https://www.nist.gov/) | SP 800-163 (Vetting Mobile Apps), SP 800-124 (Managing Mobile Devices) | US government mobile security guidelines |
| [ENISA](https://www.enisa.europa.eu/) | Smartphone Secure Development Guidelines | EU mobile security guidance for developers and enterprises |
| [EMVCo](https://www.emvco.com/) | SBMP (Software-Based Mobile Payments) | Certification for mobile payment app security. [DexProtector](../packers/dexprotector.md) and [Verimatrix](../packers/verimatrix.md) are EMVCo-certified. |
| [PCI SSC](https://www.pcisecuritystandards.org/) | PCI MPoC (Mobile Payments on COTS) | Standard for accepting payments on commercial off-the-shelf mobile devices |
| [OWASP](https://owasp.org/) | [MASVS](https://mas.owasp.org/MASVS/) / [MASTG](https://mas.owasp.org/MASTG/) | Mobile Application Security Verification Standard and Testing Guide. Industry-standard testing framework. |
| [GSMA](https://www.gsma.com/) | FS.05, FS.31 | Mobile device security guidelines, SIM security standards |
| EU Parliament | [Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) | Mandatory cybersecurity requirements for products with digital elements, including mobile apps. Effective 2027. |
