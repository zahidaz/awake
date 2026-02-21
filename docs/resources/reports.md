# Reports & Research

Periodic threat reports and notable technical research publications on Android security.

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
