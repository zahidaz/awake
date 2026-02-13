# AWAKE

**Android Wiki of Attacks, Knowledge & Exploits**

Structured reference for Android security research. How malware works, how attacks exploit the platform, and how to reverse engineer protected applications. Built for practitioners -- offense-focused, cross-referenced, and maintained.

---

## Start Here

=== "Malware Analyst"

    Start with the family catalog and timeline for historical context. Use naming conventions to map between vendor detection names. For analysis methodology, follow static analysis then dynamic analysis. If the sample is packed, identify the packer first -- the analysis decision tree walks through identification by native library, asset structure, and APKiD signature.

    Key topics: C2 techniques, persistence mechanisms, dynamic code loading, threat actor attribution, grayware and data harvesting

=== "Reverse Engineer"

    Start with packer identification. The comparison matrix ranks all documented protectors across DEX encryption, virtualization, anti-Frida, RASP, and unpacking difficulty. For runtime work, hooking and patching cover Frida, Xposed, and smali modification. The development frameworks page covers React Native, Flutter, Xamarin, Unity, and 8 others with framework-specific tooling and RE strategies.

    Key topics: dynamic analysis environment setup, network interception, SSL pinning bypass, anti-analysis check catalog

=== "Pentester"

    Start with the attack techniques catalog -- 21 techniques organized by attack surface with a 9-stage kill chain and technique combination matrix. The permissions section documents what each Android permission unlocks and how it can be abused, with escalation patterns showing how malware moves from auto-granted normal permissions to full device control.

    Key topics: deep link exploitation, WebView exploitation, content provider attacks, intent hijacking, overlay attacks, tapjacking

=== "Threat Intelligence"

    Start with threat actors for MaaS operator attribution and pricing models. The timeline tracks evolution from 2010 to present. The grayware section covers data broker SDKs, predatory lending, and the gray area between aggressive monetization and malware. The industry section maps security companies, AV engines, naming conventions, and distribution channels.

    Key topics: naming conventions, periodic reports, notable research, geographic hotspots

---

## Malware Lineage

Android malware families share code through source leaks, MaaS rebranding, and direct evolution. Knowing the lineage predicts capabilities.

```
Cerberus (2019) ──leak──> Alien (2020) ──fork──> Ermac (2021) ──evolve──> Hook (2023)

BankBot (2016) ──influence──> Anubis (2018) ──leak──> GodFather (2022)

Exobot (2016) ──> ExobotCompact ──> Coper ──> Octo (2022) ──> Octo2 (2024)

BRATA (2019) ──evolve──> Copybara (2021) ──> ToxicPanda (2024)

CraxRAT ──> SpySolr ──> BTMOB RAT (2025)
```

The Cerberus source leak (September 2020) was the single most impactful event in Android malware history. It seeded three successor families and lowered the barrier for new operators across the ecosystem. GodFather inherited Anubis's overlay architecture but added dynamic injection from C2. Octo traces back to Exobot (2016) through four generations of refinement.

## 2024-2025 Trends

| Trend | What Changed |
|-------|-------------|
| NFC relay attacks | Contactless payment cards cloned via NFC relay for ATM cash withdrawal. Bypasses traditional banking security entirely. |
| OCR-based crypto theft | Photos on device scanned for cryptocurrency seed phrases. First seen on both Play Store and App Store simultaneously. |
| On-device virtualization | Real banking apps installed inside VirtualApp sandbox on the infected device, intercepting all interactions transparently. |
| Reduced permission footprints | Full banking trojan functionality maintained with as few as 5 permissions by routing everything through accessibility services. |
| Fake lockscreen PIN capture | Fake lockscreens displayed over the real one to steal device unlock PINs. Used alongside VNC for complete device takeover. |
| Human behavior mimicry | Automated transfers typed with natural delays and randomized touch coordinates to evade behavioral biometric fraud detection. |
| Commercial packer adoption | Malware authors increasingly use commercial packers (Virbox, DexGuard) rather than custom solutions. Reduces development cost at the expense of identifiable signatures. |
| Firebase as C2 | Firebase Cloud Messaging, Firestore, and Remote Config abused for C2 configuration delivery and data exfiltration. Traffic indistinguishable from legitimate app telemetry. |
| MaaS pricing escalation | Premium MaaS operations charging $5-10k/month for full-featured RATs. Budget alternatives emerging at $650/month with reduced feature sets. |

## Attack Kill Chain

How attacks chain together in a typical Android banking trojan operation. Each stage builds on the previous.

| Stage | Objective | How |
|-------|-----------|-----|
| 1. Delivery | Get on device | Phishing, sideloading, Play Store dropper |
| 2. Dropper | Install payload | Dynamic code loading, staged download from C2 |
| 3. Persistence | Survive reboots | Boot receivers, foreground services, scheduled jobs |
| 4. Privilege escalation | Gain control | Accessibility service grant via social engineering, device admin activation |
| 5. Credential theft | Steal logins | Overlay injection, keylogging, screen capture, clipboard monitoring |
| 6. 2FA bypass | Intercept OTPs | SMS broadcast interception, notification listener for push-based codes |
| 7. On-device fraud | Move money | ATS fills transfer fields via accessibility, confirms transactions, hides confirmations |
| 8. Exfiltration | Send to C2 | HTTP, WebSocket, Telegram Bot API, Firebase, SFTP |
| 9. Anti-analysis | Avoid detection | Emulator checks, Frida detection, device admin anti-uninstall, post-fraud device wipe |

The attack techniques section documents all 21 techniques with technique combinations showing which pairs are most commonly observed together, and a defense priority ranking by prevalence in active campaigns.

## Packer Landscape

!!! tip "Workflow"

    Run APKiD on the sample. Check the analysis decision tree for the next step based on the result. The comparison matrix ranks all documented protectors head-to-head. For universal unpacking, hook `DexClassLoader` or `InMemoryDexClassLoader` at runtime, or use frida-dexdump to scan process memory for DEX magic bytes.

| Difficulty | What Makes It Hard |
|------------|-------------------|
| Easy-Medium | Whole-DEX encryption with known structure. Generic memory dump recovers the payload. Chinese packers, AppSealing. |
| Medium-Hard | Class-level encryption, native anti-Frida, integrity checks. Requires targeted bypass before dumping. DexGuard, DexProtector, Appdome, zShield, Verimatrix. |
| Hard | Aggressive anti-hooking, Magisk-aware root detection, server-side verification. Manual native RE required. LIAPP, Arxan, Promon SHIELD. |
| Expert | DEX virtualization -- bytecode translated to proprietary VM instructions. No static recovery possible, must trace the VM interpreter. Virbox. |

## State-Sponsored Spyware

Commercial and government spyware operates on a separate track from financially-motivated malware, with different distribution (targeted, often zero-click), capabilities (full device compromise), and targets (journalists, activists, political figures).

| Operator | Tool | Distribution | Key Capability |
|----------|------|-------------|----------------|
| NSO Group (Israel) | Pegasus | Zero-click exploits | Full device compromise, cross-platform |
| Cytrox/Intellexa (EU) | Predator | Exploit chains | Alien loader + Predator implant, sanctioned 2024 |
| FinFisher (Germany) | FinSpy | Targeted delivery | Lawful intercept, bankrupt 2022 |
| RCS Lab (Italy) | Hermit | ISP network injection | Modular architecture, carrier-level delivery |
| APT41 (China) | LightSpy | Watering hole | 14+ plugins, WeChat Pay theft, cross-platform |
| ScarCruft/APT37 (DPRK) | KoSpy | Trojanized apps | Firebase Firestore C2, Play Store presence |

The spyware timeline tracks the full chronology from FinSpy (2012) through KoSpy (2025). The threat actors page covers attribution, operational patterns, and the intersection between commercial spyware vendors and state intelligence agencies.

## Geographic Hotspots

| Region | Dominant Threats | Distribution |
|--------|-----------------|-------------|
| Western Europe | Anatsa, Octo, Medusa, Vultur | Play Store droppers |
| Southern Europe | Copybara, Sturnus, Herodotus | Vishing (TOAD), smishing |
| Turkey | Frogblight, BlankBot, Klopatra | Smishing, phishing pages |
| Russia/CIS | Mamont, FireScam | Fake parcel tracking, fake app stores |
| Iran | DeVixor, DCHSpy | Fake VPN apps, automotive phishing |
| South Korea | Fakecalls, SoumniBot, SpyAgent | Smishing, fake banking apps |
| East Asia | MoqHao, FluHorse | Smishing (Roaming Mantis), trojanized apps |
| Southeast Asia | Gigabud, GoldPickaxe | Fake government/banking apps |
| Latin America | PixPirate, ToxicPanda, Zanubis | WhatsApp lures, social engineering |
| Middle East | GuardZoo, AridSpy | Trojanized messaging apps |
