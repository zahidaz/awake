# Mobile Security Industry

The companies and organizations involved in Android security, from threat intelligence firms naming malware families to forensics companies extracting device data to the modding scene distributing repackaged APKs.

| Page | Content |
|------|---------|
| [App Distribution](app-distribution.md) | Third-party stores, APK modding, and cracking scene |
| [AV Engines](av-engines.md) | VirusTotal detection engines: primary, mobile-specific, EDR, regional |
| [Digital Forensics](digital-forensics.md) | Mobile forensics tools for device extraction and analysis |
| [Packer Vendors](packer-vendors.md) | Companies selling Android app protection and obfuscation |
| [Security Products](security-products.md) | Endpoint security, app security testing (SAST/DAST), offensive research |
| [Standards & Bug Bounties](standards-bounties.md) | Security standards, regulators, and vulnerability disclosure programs |
| [Threat Intelligence](threat-intelligence.md) | Research labs that discover and name malware families, vendor comparison matrix |

## Industry Structure

The mobile threat landscape is split across several roles that rarely overlap.

**Discovery.** The initial sample surfaces through one of a few paths: a honeypot or crawler at a threat intel firm (ThreatFabric, Cleafy, Cyble), a Play Store audit by a vendor with scanner partnerships (Dr.Web, Kaspersky, ESET), a VirusTotal retrohunt, or a user complaint escalated through an AV vendor's telemetry pipeline. Academic groups and CERTs occasionally contribute first sightings, but rarely for banking trojans.

**Naming.** Whoever publishes first picks the name. ThreatFabric named [Cerberus](../malware/families/cerberus.md), [Alien](../malware/families/alien.md), [Ermac](../malware/families/ermac.md), [Hook](../malware/families/hook.md), and [Octo](../malware/families/octo.md). Cleafy named [Copybara](../malware/families/copybara.md), [BingoMod](../malware/families/bingomod.md), and [ToxicPanda](../malware/families/toxicpanda.md). Kaspersky and ESET tend to publish under their own internal naming schemes, creating parallel nomenclatures. There is no central naming authority. The result is alias sprawl: [Octo](../malware/families/octo.md) is also known as ExobotCompact, Coper is the same lineage as [Octo](../malware/families/octo.md) v1, and [Anatsa](../malware/families/anatsa.md) overlaps with TeaBot.

**Detection.** AV engines on VirusTotal each assign their own signature strings. Google Play Protect runs its own classifier. None of these align with the research-community names. An analyst looking at a sample may see `Trojan-Banker.AndroidOS.Ermac` from Kaspersky, `Android/Spy.Cerberus` from ESET, and `Artemis!{hash}` from McAfee, all for the same APK.

**Response.** Takedowns are rare for Android malware. Law enforcement has only intervened in a handful of cases (see key events below). Most "response" is Google pulling apps from the Play Store after a vendor publishes, sometimes weeks or months after initial discovery.

## How Malware Gets Named

The naming lifecycle works roughly as follows:

1. **Sample acquisition.** A researcher obtains an APK through a dropper on Play Store, a phishing SMS campaign, a C2 panel crawl, or VirusTotal hunting rules (YARA/VT Intelligence).
2. **Triage and clustering.** The sample is decompiled, and its code structure, C2 protocol, overlay injection pattern, and string artifacts are compared against known families. If it does not match, it is a candidate for a new family name.
3. **Naming and publication.** The discovering firm publishes a blog post with the chosen name, IOCs (hashes, C2 domains), and a technical breakdown. This becomes the de facto name.
4. **VirusTotal propagation.** Other engines gradually pick up the sample. Each assigns its own detection label. There is no standard mapping.
5. **Cross-vendor drift.** Over time, forks and rebrands compound the confusion. [Cerberus](../malware/families/cerberus.md) source leaked and spawned [Alien](../malware/families/alien.md), which spawned [Ermac](../malware/families/ermac.md), which spawned [Hook](../malware/families/hook.md). Each got a separate name despite sharing large portions of code. Malpedia and ThreatFabric's threat tracker are the closest things to a canonical mapping, but neither is exhaustive.

## MaaS Economy

Most active Android banking trojans operate as Malware-as-a-Service. The operator (threat actor deploying the malware against victims) rents access from the developer (threat actor who wrote and maintains the bot). This is a subscription business.

### What's Sold

A standard MaaS package includes:

- **Admin panel.** Web-based C2 dashboard for managing bots, pushing commands, configuring inject targets, and viewing stolen credentials.
- **Inject kit.** A library of HTML overlay pages that mimic banking apps. Sold per-region or as a full global set. Some sellers offer custom inject creation as an upsell.
- **Builder / APK generator.** Allows the operator to produce new APK variants with unique signing keys, package names, and obfuscation profiles.
- **Support channel.** Private Telegram group or forum thread where the developer provides updates, troubleshooting, and feature announcements.
- **Updates.** Ongoing patches for detection evasion, new Android version compatibility, and feature additions (VNC, keylogging, SMS forwarding, push notification interception).

### Pricing

Prices are quoted from underground advertisements and open-source reporting. Monthly rental is the standard model, though some offer lifetime or per-build pricing.

| Family | Price | Notes |
|--------|-------|-------|
| [Cerberus](../malware/families/cerberus.md) | $4,000/month | Sold 2019-2020, source code auctioned then leaked free in Sept 2020 |
| [Hook](../malware/families/hook.md) | $7,000/month | Premium tier, VNC and RAT capabilities, advertised by DukeEugene |
| [Ermac](../malware/families/ermac.md) | $3,000/month | Same developer lineage as Cerberus/Alien, sold on darknet forums |
| [Octo](../malware/families/octo.md) | $2,000/month | Also sold as Octo2 with upgraded C2 encryption, DGA |
| [BTMOB](../malware/families/btmob.md) | $5,000-$10,000 | Higher price point, newer entrant |
| [Albiriox](../malware/families/albiriox.md) | $650-$720/month | Budget tier, lower feature set |

Price correlates loosely with feature maturity, evasion quality, and the developer's reputation. Leaks and law enforcement actions crash prices overnight. After the [Cerberus](../malware/families/cerberus.md) source leak, the entire market adjusted downward temporarily because operators could fork Cerberus for free.

### Distribution Channels

MaaS listings and operator coordination happen on:

- **Telegram channels.** Primary distribution vector since 2020. Developers run private channels for customer support and public channels for advertisements. Some families ([Hook](../malware/families/hook.md), [Ermac](../malware/families/ermac.md)) were advertised almost exclusively through Telegram.
- **XSS Forum.** Russian-language cybercrime forum. Long-running threads for [Cerberus](../malware/families/cerberus.md), [Ermac](../malware/families/ermac.md), and [Octo](../malware/families/octo.md) sales. Requires vetting for membership.
- **Exploit.in.** Another Russian-language forum with active Android malware vendor sections.
- **Breached.to (formerly RaidForums successor).** English-language forum where leaked source code and cracked panels surface. Lower operational security, more likely to attract less sophisticated operators.

Inject kits circulate separately from the bot itself. A thriving secondary market exists for regional overlay packs targeting specific banks, crypto exchanges, and payment apps.

## Key Industry Events

A short list of events that materially changed the Android threat landscape.

**Cerberus source leak (September 2020).** After failing to auction the Cerberus source code, the developer released it for free on underground forums. This single event seeded multiple successor families: [Alien](../malware/families/alien.md), [Ermac](../malware/families/ermac.md), and eventually [Hook](../malware/families/hook.md). It lowered the barrier to entry for new operators and flooded the ecosystem with Cerberus-derived variants that persist today.

**FluBot takedown by Europol (June 2022).** Europol's Dutch-led operation seized [FluBot](../malware/families/flubot.md)'s infrastructure across 11 countries. One of the few successful law enforcement actions against a mobile malware operation. [FluBot](../malware/families/flubot.md) had been one of the most aggressive SMS-worm-style Android threats in Europe. The takedown was effective: [FluBot](../malware/families/flubot.md) did not resurface.

**FinFisher bankruptcy (2022).** FinFisher GmbH, developer of the [FinSpy](../malware/families/finspy.md) commercial spyware suite, filed for insolvency after years of legal pressure and investigations into sales to authoritarian regimes. Signaled that commercial spyware vendors face real legal risk, at least in EU jurisdictions.

**Intellexa sanctions (March 2024).** The US Treasury sanctioned Intellexa Consortium entities and individuals behind the [Predator](../malware/families/predator.md) spyware. First financial sanctions specifically targeting a commercial spyware vendor. Intellexa's operations fragmented but did not fully cease, with infrastructure rotating through new hosting providers.
