# Resources

External resources for Android security research. Blogs, tools, frameworks, and link collections.

## Blogs & Research

### Malware Research

| Source | Focus |
|--------|-------|
| [CheckPoint Research](https://research.checkpoint.com/) | Android malware campaigns, Play Store threats, mobile APT tracking. |
| [Cleafy Labs](https://www.cleafy.com/labs) | Banking malware, financial fraud, mobile threat intelligence. |
| [Cyble CRIL](https://cyble.com/blog/) | Dark web intelligence, mobile malware sold on underground forums. |
| [Fortinet FortiGuard](https://www.fortinet.com/blog/threat-research) | Android malware write-ups, mobile threat landscape. |
| [IBM Security Trusteer](https://securityintelligence.com/) | Mobile banking fraud, overlay attack research, financial malware analysis. |
| [Sophos X-Ops](https://news.sophos.com/en-us/category/threat-research/) | Cross-platform threat research including Android malware families. |
| [ThreatFabric](https://www.threatfabric.com/blogs) | Android banking trojans. Most prolific mobile malware research team. |
| [Trellix (FireEye)](https://www.trellix.com/blogs/research/) | Advanced mobile threats, nation-state campaigns. |

### Vulnerability Research

| Source | Focus |
|--------|-------|
| [8kSec](https://8ksec.io/blog/) | App and kernel-level Android security. Battlegrounds CTF. |
| [Google Android Offensive Security](https://androidoffsec.withgoogle.com/) | Kernel exploitation, Binder fuzzing, driver analysis from Google's red team. |
| [Google Project Zero](https://projectzero.google/) | 0-day research. Android exploit chains, Pixel vulnerabilities. |
| [NowSecure Blog](https://www.nowsecure.com/blog/) | Mobile app security testing, practical vulnerability analysis. |
| [Oversecured Blog](https://blog.oversecured.com/) | Android app vulnerabilities. Systematic disclosure in Google, Samsung, TikTok apps. Top resource. |

### Vendor Security Blogs

| Source | Focus |
|--------|-------|
| [Avast Decoded](https://decoded.avast.io/) | Android malware, adware campaign analysis. |
| [ESET WeLiveSecurity](https://www.welivesecurity.com/) | Android malware publications, regional threat analysis. |
| [Group-IB Blog](https://www.group-ib.com/blog/) | Threat intelligence, fraud prevention, APT campaigns. |
| [Intel 471 Blog](https://intel471.com/blog) | Underground marketplace monitoring, MaaS tracking. |
| [Kaspersky Securelist](https://securelist.com/) | Mobile malware analysis, APT campaigns targeting Android. |
| [Lookout Threat Intelligence](https://www.lookout.com/threat-intelligence) | Mobile endpoint threats, surveillance software, state-sponsored spyware. |
| [McAfee Mobile Research](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/) | Mobile malware, adware, PUPs. Part of McAfee Labs. |
| [NCC Group Research](https://research.nccgroup.com/) | Offensive security research, Android malware lineage analysis. |
| [PRODAFT Blog](https://www.prodaft.com/blog) | Threat intelligence, underground infrastructure analysis. |
| [Trend Micro Blog](https://www.trendmicro.com/en_us/research.html) | Mobile ransomware, enterprise mobile threats. |
| [Zimperium Blog](https://www.zimperium.com/blog/) | Mobile threat defense research, zero-day discoveries. |

### Platform / Ecosystem

| Source | Focus |
|--------|-------|
| [Android Developers Blog](https://android-developers.googleblog.com/) | New API changes, security feature announcements. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly CVE patches for Android. |
| [Google Security Blog](https://security.googleblog.com/) | Play Protect updates, platform security changes. |

## Frameworks & Standards

| Resource | What It Is |
|----------|-----------|
| [bazaar.abuse.ch](https://bazaar.abuse.ch/) | Malware sample database with multi-vendor tagging and YARA rule matching. |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) | Malware reference database. Cross-vendor name mapping. |
| [MISP Galaxy](https://www.misp-galaxy.org/) | Open threat intelligence knowledge base. Threat actors, malware families, tools, and ATT&CK clusters. |
| [MITRE ATT&CK Mobile](https://attack.mitre.org/matrices/mobile/) | Adversary technique taxonomy. High-level classification, not operational detail. |
| [OWASP MAS](https://mas.owasp.org/) | Mobile application security testing guide. Compliance-oriented. |
| [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | Top 10 mobile security risks. |

## Tools

### Analysis & Detection

| Tool | Purpose |
|------|---------|
| [Androguard](https://github.com/androguard/androguard) | Python framework for Android app analysis |
| [APKiD](https://github.com/rednaga/APKiD) | Packer, protector, obfuscator identification |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | Extract URLs, endpoints, and secrets from APK files |
| [dex2jar](https://github.com/pxb1988/dex2jar) | DEX to JAR conversion |
| [Droidlysis](https://github.com/cryptax/droidlysis) | Automated Android malware property extraction (permissions, receivers, services) |
| [Drozer](https://github.com/WithSecureLabs/drozer) | Android security assessment framework. IPC probing, provider testing. |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated mobile security analysis |
| [Quark Engine](https://github.com/quark-engine/quark-engine) | Android malware scoring and behavior analysis |
| [SUPER](https://github.com/SUPERAndroidAnalyzer/super) | Secure, Unified, Powerful and Extensible Rust Android Analyzer |
| [VirusTotal](https://www.virustotal.com/) | Multi-engine malware scanning. 70+ AV engines. See [Naming Conventions](../malware/naming-conventions.md) for detection name formats. |

### Device

| Tool | Purpose |
|------|---------|
| [LSPosed](https://github.com/LSPosed/LSPosed) | Xposed framework for modern Android |
| [Magisk](https://github.com/topjohnwu/Magisk) | Root management with detection bypass |

### Network

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS proxy and traffic interception |
| [mitmproxy](https://mitmproxy.org/) | Scriptable HTTPS proxy |

### Reverse Engineering

| Tool | Purpose |
|------|---------|
| [apktool](https://github.com/iBotPeaches/Apktool) | APK disassembly and reassembly |
| [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) | Multi-decompiler view (Procyon, CFR, FernFlower, jadx side-by-side) |
| [Frida](https://frida.re/) | Dynamic instrumentation: hooking, tracing, modifying runtime behavior |
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Dump DEX files from packed apps at runtime |
| [Ghidra](https://ghidra-sre.org/) | Native code reverse engineering (NSA, free) |
| [jadx](https://github.com/skylot/jadx) | DEX to Java decompiler |
| [medusa](https://github.com/Ch0pin/medusa) | Extensible framework combining Frida scripts for Android dynamic analysis |
| [Objection](https://github.com/sensepost/objection) | Frida-powered runtime exploration |
| [reFrida](https://github.com/zahidaz/refrida) | Browser-based Frida IDE with Monaco editor, disassembler, memory search, Stalker tracing, and visual interceptor builder |
| [r2frida](https://github.com/nowsecure/r2frida) | Radare2 + Frida integration |
| [radare2](https://rada.re/) | Open-source reverse engineering framework |

### Emulation & Sandboxing

| Tool | Purpose |
|------|---------|
| [Android Emulator](https://developer.android.com/studio/run/emulator) | Official Android emulator with AVD manager |
| [Genymotion](https://www.genymotion.com/) | High-performance Android emulator for testing |
| [rootAVD](https://github.com/newbit1/rootAVD) | Root Android Virtual Devices for Frida and dynamic analysis |
| [Cuckoo Droid](https://github.com/idanr1986/cuckoo-droid) | Automated Android malware sandbox |
| [Joe Sandbox Mobile](https://www.joesecurity.org/) | Commercial automated malware analysis sandbox |

## Link Collections

| Resource | What It Is |
|----------|-----------|
| [android-security-awesome](https://github.com/ashishb/android-security-awesome) | Curated list of Android security tools and resources |
| [awesome-android-security](https://github.com/saeidshirazi/awesome-android-security) | Pentester and bug bounty focused links |
| [Awesome Android Reverse Engineering](https://github.com/user1342/Awesome-Android-Reverse-Engineering) | RE tools and techniques |
| [Awesome-Android-Vulnerability-Research](https://github.com/IamAlch3mist/Awesome-Android-Vulnerability-Research) | Vulnerability research focused |

## Periodic Reports

| Report | Publisher | Cadence |
|--------|-----------|---------|
| [Financial Threat Report](https://securelist.com/financial-threat-report-2024/115966/) | Kaspersky Securelist | Annual |
| [Mobile Threat Landscape 2024](https://securelist.com/mobile-threat-report-2024/115494/) | Kaspersky Securelist | Annual |
| [Consumer Mobile Threat Report 2023](https://www.mcafee.com/blogs/internet-security/mcafee-2023-consumer-mobile-threat-report/) | McAfee Labs | Annual |
| [Mobile Threat Statistics Q1 2025](https://securelist.com/malware-report-q1-2025-mobile-statistics/116676/) | Kaspersky Securelist | Quarterly |
| [Mobile Threat Statistics Q2 2025](https://securelist.com/malware-report-q2-2025-mobile-statistics/117349/) | Kaspersky Securelist | Quarterly |
| [Mobile Threat Statistics Q3 2025](https://securelist.com/malware-report-q3-2025-mobile-statistics/118013/) | Kaspersky Securelist | Quarterly |
| [ESET Threat Report H1 2024](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h1-2024/) | ESET | Semi-annual |
| [ESET Threat Report H2 2025](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h2-2025/) | ESET | Semi-annual |
| [Year in Review: 0-days](https://projectzero.google/2022/04/the-more-you-know-more-you-know-you.html) | Google Project Zero | Annual |
| [Global Mobile Threat Report](https://www.zimperium.com/global-mobile-threat-report/) | Zimperium | Annual |
| [Mobile Banking Heists Report](https://www.zimperium.com/mobile-banking-heists-report/) | Zimperium | Annual |
| [Mobile Threat Intelligence Report](https://www.lookout.com/threat-intelligence/report) | Lookout | Annual |
| [Global Threat Landscape Report](https://www.fortinet.com/resources/reports/threat-landscape-report) | Fortinet | Semi-annual |

## Notable Research

Key technical research publications from security teams. For vendor-specific malware analysis, see individual [malware family pages](../malware/families/index.md).

| Research | Publisher | Topic |
|----------|-----------|-------|
| [A 0-click exploit chain for the Pixel 9 (3-part series)](https://projectzero.google/2026/01/pixel-0-click-part-1.html) | Google Project Zero | Dolby decoder integer overflow + kernel driver sandbox escape. 139-day patch gap. |
| [Bad Binder: Android In-The-Wild Exploit](https://projectzero.google/2019/11/bad-binder-android-in-wild-exploit.html) | Google Project Zero | CVE-2019-2215 Binder use-after-free. Linked to NSO Group's [Pegasus](../malware/families/pegasus.md). |
| [In-the-Wild Series: Android Exploits](https://projectzero.google/2021/01/in-wild-series-android-exploits.html) | Google Project Zero | Chrome RCE + Android n-day privilege escalation from watering hole. |
| [Multiple Internet-to-Baseband RCE in Exynos Modems](https://projectzero.google/2023/03/multiple-internet-to-baseband-remote-rce.html) | Google Project Zero | 18 zero-days in Samsung Exynos modems. 4 allow RCE with just a phone number. |
| [Samsung In-the-Wild Exploit Chain](https://projectzero.google/2022/11/a-very-powerful-clipboard-samsung-in-the-wild-exploit-chain.html) | Google Project Zero | Logic bugs exploited against Samsung devices. CVE-2021-25337, CVE-2021-25369, CVE-2021-25370. |
| [Analyzing a Modern In-the-Wild Android Exploit](https://projectzero.google/2023/09/analyzing-modern-in-wild-android-exploit.html) | Google Project Zero | CVE-2023-0266 (ALSA 0-day) + CVE-2023-26083 (Mali GPU 0-day). Commercial spyware. |
| [.NET MAUI Evasion](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-malware-campaigns-evading-detection-using-cross-platform-framework-net-maui/) | McAfee Labs | Malware using C#/.NET MAUI framework to bypass DEX-based analysis. |
| [Xamalicious Backdoor](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/stealth-backdoor-android-xamalicious-actively-infecting-devices/) | McAfee Labs | Xamarin-based backdoor in 25 Google Play apps (327K downloads). Xamarin build process acts as packer hiding malicious code. |
| [SpyAgent OCR Crypto Theft](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-android-spyagent-campaign-steals-crypto-credentials-via-image-recognition/) | McAfee Labs | 280+ fake apps using image recognition to steal crypto wallet seed phrases from device photos. |
| [Invisible Adware](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/invisible-adware-unveiling-ad-fraud-targeting-android-users/) | McAfee Labs | 43 Play Store apps (2.5M downloads) loading ads only when screen is off, weeks-long activation delay. |
| [India MaaS Phishing](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-phishing-scam-using-malware-as-a-service-on-the-rise-in-india/) | McAfee Labs | MaaS platform with 800+ apps targeting Indian banking users, 3,700+ infected devices. |
| [Disclosure of 7 Android and Pixel Vulnerabilities](https://blog.oversecured.com/Disclosure-of-7-Android-and-Google-Pixel-Vulnerabilities/) | Oversecured | WebView file theft, Bluetooth permission bypass, VPN bypass, system component access. |
| [Two Weeks of Securing Samsung Devices](https://blog.oversecured.com/Two-weeks-of-securing-Samsung-devices-Part-1/) | Oversecured | 60+ Samsung vulnerabilities. Path traversal via `Uri.getLastPathSegment()`, SMS database access. |
| [20 Security Issues in Xiaomi Devices](https://blog.oversecured.com/20-Security-Issues-Found-in-Xiaomi-Devices/) | Oversecured | Intent redirection, content provider, and privilege escalation in Xiaomi system apps. |
| [Exploiting Memory Corruption on Android](https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/) | Oversecured | Native memory corruption via VirtualRefBasePtr. PayPal vulnerability example. |
| [Play Core Library Code Execution](https://blog.oversecured.com/Oversecured-automatically-discovers-persistent-code-execution-in-the-Google-Play-Core-Library/) | Oversecured | Persistent code execution through dynamic module loading. Automated discovery. |
| [NGate: NFC Relay Attacks](https://www.welivesecurity.com/en/eset-research/ngate-android-malware-relays-nfc-traffic-to-steal-cash/) | ESET | First Android NFC relay malware. Clones payment cards via NFCGate for ATM cash withdrawal. |
| [EvilVideo: Telegram Zero-Day](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/) | ESET | Zero-day exploit for Telegram for Android. APKs disguised as video previews. Sold on underground forums. |
| [525,600 Assessments: Top Mobile App Risks](https://www.nowsecure.com/blog/2025/04/30/525600-assessments-later-top-mobile-app-risks-since-2022/) | NowSecure | 75% of apps have misconfigured crypto, 85% have SDK vulnerabilities, 1 in 5 has hardcoded keys. |
| [Dangerous Mobile App Permissions](https://www.nowsecure.com/blog/2025/06/04/how-dangerous-mobile-app-permissions-threaten-enterprise-security/) | NowSecure | Analysis of 378,000+ Android apps: 62% request dangerous permissions. |
| [AI-Assisted Decompilation](https://www.nowsecure.com/blog/2025/01/29/decompiling-apps-with-ai-language-models/) | NowSecure | Using language models to optimize decompiled Android app code. |

## Conference Talks

Notable Android security presentations from major conferences.

### Black Hat / DEF CON

| Talk | Speaker | Event | Topic |
|------|---------|-------|-------|
| [Android Packers: Separating from the Pack](https://www.blackhat.com/us-20/briefings/schedule/index.html#android-packers-separating-from-the-pack-20359) | Maddie Stone | Black Hat USA 2020 | Packer identification, unpacking methodology, APKiD development |
| [Strandhogg: Attacking Android Through Task Affinity](https://promon.co/strandhogg-2-0/) | Promon Research | DEF CON 27 | Task affinity hijacking (CVE-2020-0096), UI spoofing |
| [Breaking Secure Messaging on Android](https://www.blackhat.com/us-23/briefings/schedule/) | Various | Black Hat USA 2023 | Accessibility-based message exfiltration from E2E encrypted apps |
| [The Art of Android Malware Analysis](https://www.blackhat.com/us-24/) | Various | Black Hat USA 2024 | Modern banking trojan analysis, ATS reverse engineering |
| [Pixel 0-Click Exploit Chain](https://projectzero.google/2026/01/pixel-0-click-part-1.html) | Google Project Zero | Associated research | Dolby decoder overflow + kernel sandbox escape on Pixel 9 |

### HITB / OffensiveCon / Other

| Talk | Speaker | Event | Topic |
|------|---------|-------|-------|
| [Breaking Android's Verified Boot](https://www.hitb.org/) | Various | HITB | AVB bypass, bootloader exploitation, firmware persistence |
| [Frida for Android Malware Analysis](https://www.youtube.com/watch?v=iMNs8YAy6pk) | Eduardo Novella | Various | Dynamic instrumentation for banking trojan analysis |
| [DexProtector Internals](https://www.romainthomas.fr/post/26-01-dexprotector/) | Romain Thomas | Associated research | vtable hooking, asset encryption, native bridge analysis |

## YouTube Channels

| Channel | Focus | Notable Content |
|---------|-------|-----------------|
| [LaurieWired](https://www.youtube.com/@lauriewired) | Android malware analysis, reverse engineering | Malware deep-dives, assembly analysis, practical RE walkthroughs |
| [8kSec](https://www.youtube.com/@8ksec) | Mobile security research | Android kernel exploitation, app security testing |
| [Maddie Stone](https://www.youtube.com/@maddiestone) | 0-day research, Android exploitation | Google Project Zero research presentations |
| [stacksmashing](https://www.youtube.com/@stacksmashing) | Hardware hacking, reverse engineering | Hardware-adjacent Android security, Flipper Zero integration |
| [John Hammond](https://www.youtube.com/@_JohnHammond) | General security, CTF walkthroughs | Occasional mobile security and malware analysis content |
| [IppSec](https://www.youtube.com/@ippsec) | HTB walkthroughs | Android challenge walkthroughs and mobile exploitation |
| [Corellium](https://www.youtube.com/@corellium) | Mobile security platform | Android reverse engineering tutorials, virtualization-based analysis |

## Training Platforms

| Platform | Description |
|----------|-------------|
| [8kSec Battlegrounds](https://8ksec.io/battle/) | Free mobile security challenges (CTF-style). Android challenges include deep link exploitation, client-side bypass, malicious app creation. Community writeups available. |
| [OWASP MASTG Test Apps](https://mas.owasp.org/) | Standardized vulnerable Android and iOS apps for practicing MASVS testing. |
| [OVAA](https://github.com/AresS31/ovaa) | Oversecured Vulnerable Android App. Practice exploiting common Android vulnerabilities. |
| [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | Vulnerable banking app for practicing common Android app vulnerabilities. |
| [DIVA](https://github.com/payatu/diva-android) | Damn Insecure and Vulnerable App. Covers 13 common Android vulnerability categories. |
| [AndroGoat](https://github.com/satishpatnayak/AndroGoat) | Open-source vulnerable Android app for practicing OWASP Top 10 Mobile risks. |
| [hpAndro](https://github.com/AyoubSas/hpandro) | Kotlin-based vulnerable app with multiple challenge categories. |

### Courses

| Course | Provider | Notes |
|--------|----------|-------|
| [SEC575: Mobile Device Security and Ethical Hacking](https://www.sans.org/cyber-security-courses/mobile-device-security-ethical-hacking/) | SANS | Comprehensive mobile security course covering Android and iOS. GMOB certification. |
| [Android App Security with Frida](https://8ksec.io/training/) | 8kSec | Focused on dynamic instrumentation for Android app testing and malware analysis. |
| [Mobile Application Penetration Testing](https://www.elearnsecurity.com/course/mobile_application_penetration_testing/) | INE/eLearnSecurity | Covers Android and iOS pentesting methodology. eMAPT certification. |
| [Android Security Internals](https://www.udemy.com/course/android-reverse-engineering-from-scratch/) | Various (Udemy) | Budget-friendly courses on Android RE fundamentals. |

## CTF Resources

### Android-Specific CTFs

| Platform | Description |
|----------|-------------|
| [8kSec Battlegrounds](https://8ksec.io/battle/) | Dedicated mobile security CTF with Android challenges |
| [MOBISEC](https://mobisec.reyammer.io/) | University of California course with Android security challenges (public materials) |
| [Android CTF by BSides](https://github.com/AnirudhSK/Android-CTF) | Open-source Android security challenges |
| [Injured Android](https://github.com/AnirudhSK/android-security-assessment) | CTF-style vulnerable Android app with progressive difficulty |

### CTF Writeup Collections

| Resource | Content |
|----------|---------|
| [CTFtime Mobile Challenges](https://ctftime.org/) | Filter by "mobile" tag for Android-specific writeups from global CTF events |
| [HackTricks Android](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting) | Android pentesting methodology used in CTF contexts |

## Community

### Forums and Chat

| Platform | Description |
|----------|-------------|
| [Android Security subreddit](https://www.reddit.com/r/AndroidSecurity/) | Discussion of Android vulnerabilities, patches, and research |
| [Mobile Hacking Discord](https://discord.gg/mobilehacking) | Community server for mobile security researchers |
| [Frida Discord](https://discord.gg/frida) | Official Frida community for dynamic instrumentation help |
| [OWASP Slack #mobile-security](https://owasp.org/slack/invite) | OWASP community channel for mobile security discussion |

### Bug Bounty Programs

| Program | Scope | Max Payout |
|---------|-------|------------|
| [Google VRP](https://bughunters.google.com/about/rules/google-friends/google-and-alphabet-vulnerability-reward-program-vrp-rules) | Android OS, Pixel devices, Google apps | [$1,000,000 for full exploit chains](https://security.googleblog.com/2025/03/vulnerability-reward-program-2024-in.html). Up to $15,000 for critical single bugs. |
| [Google Mobile VRP](https://bughunters.google.com/) | First-party Android apps (Google, Fitbit, Waymo, Waze) | [$30,000 for RCE without interaction](https://securityweek.com/google-launches-bug-bounty-program-for-mobile-applications/). $7,500 for sensitive data theft. |
| [Samsung Mobile Security Rewards](https://security.samsungmobile.com/rewardsProgram.smsb) | Samsung mobile devices, Knox, Galaxy Store | Up to $1,000,000 for critical chain on flagship devices |
| [Qualcomm Bug Bounty](https://www.qualcomm.com/company/product-security/reporting-security-concern) | Snapdragon chipsets, modem firmware | Varies; covers baseband and TEE vulnerabilities |
| [HackerOne Mobile Programs](https://hackerone.com/) | Various mobile app vendors | Varies by program; filter by "mobile" scope |

### Researchers to Follow

| Researcher | Affiliation | Focus |
|------------|-------------|-------|
| Maddie Stone | Google Project Zero | Android 0-days, exploit chains, packer analysis |
| Sergey Toshin | Oversecured | Android app vulnerabilities, systematic vuln discovery |
| Lukas Stefanko | ESET | Android malware tracking, Play Store threats |
| Federico Valentini / Alessandro Strino | Cleafy | Banking trojan analysis, ATS research |
| Cengiz Han Sahin | ThreatFabric | Android banking malware naming and tracking |
