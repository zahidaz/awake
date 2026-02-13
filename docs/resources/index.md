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
| [SUPER](https://github.com/nicksdevice/super) | Secure, Unified, Powerful and Extensible Rust Android Analyzer |
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
| [frida-dexdump](https://github.com/nicksdevice/frida-dexdump) | Dump DEX files from packed apps at runtime |
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
| [rootAVD](https://gitlab.com/nicksdevice/rootAVD) | Root Android Virtual Devices for Frida and dynamic analysis |
| [Cuckoo Droid](https://github.com/nicksdevice/cuckoodroid) | Automated Android malware sandbox |
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
| [Mobile Threat Report](https://www.mcafee.com/blogs/) | McAfee Labs | Annual |
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

## Training Platforms

| Platform | Description |
|----------|-------------|
| [8kSec Battlegrounds](https://8ksec.io/battle/) | Free mobile security challenges (CTF-style). Android challenges include deep link exploitation, client-side bypass, malicious app creation. Community writeups available. |
| [OWASP MASTG Test Apps](https://mas.owasp.org/) | Standardized vulnerable Android and iOS apps for practicing MASVS testing. |
| [OVAA](https://github.com/AresS31/ovaa) | Oversecured Vulnerable Android App. Practice exploiting common Android vulnerabilities. |
