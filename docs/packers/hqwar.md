# Hqwar

Android malware packer/dropper sold as a service to malware operators. Kaspersky's collection contains 200,000+ Hqwar-packed trojans, approximately 80% of which are financial threats. Hqwar wraps a payload's DEX file in an RC4-encrypted shell and uses `DexClassLoader` to load the decrypted payload at runtime, evading static AV signatures. Peak activity in Q3 2018 (141,000 packages). The packer was a major driver of the 2018 record in mobile banking trojan attacks.

## Overview

| Property | Value |
|----------|-------|
| **First Seen** | Early 2016 |
| **Type** | Malware packer / Dropper-as-a-Service |
| **Attribution** | Unknown single author (infrequent updates led to decline) |
| **Detection** | Trojan-Dropper.AndroidOS.Hqwar (Kaspersky) |

## Protection Mechanism

| Step | Description |
|------|-------------|
| 1 | Original payload DEX is extracted from the malware APK |
| 2 | DEX is encrypted using RC4 with a hardwired key |
| 3 | Encrypted payload is embedded in the Hqwar wrapper APK |
| 4 | At runtime, Hqwar decrypts the payload and loads it via `DexClassLoader` |
| 5 | Payload executes in memory without being written as a separate APK |

The in-memory-only approach avoids triggering installation prompts but sacrifices persistence across reboots.

## Payload Statistics

Kaspersky analysis of 200,000+ Hqwar-packed samples:

| Payload Family | Percentage |
|---------------|-----------|
| Faketoken | 28.81% |
| Boogr (ML-detected) | 14.53% |
| Asacub | 10.10% |
| [Marcher](../malware/families/marcher.md) | 8.44% |
| Grapereh | 7.67% |
| SmsThief | 7.20% |
| Gugi | 6.18% |
| [Svpeng](../malware/families/svpeng.md) | 5.38% |
| Agent | 5.24% |
| Palp | 1.97% |

22 distinct trojan families used Hqwar as their packer. One-third of all payloads were Faketoken banking trojans.

## Activity Timeline

| Period | Packed Samples | Notes |
|--------|---------------|-------|
| 2016 | Initial | Gained popularity by end of 2016 |
| Q3 2018 | 141,000 | Peak activity, drove record banking trojan detections |
| 2019 | 22,000 | Sharp decline due to infrequent author updates |

The decline was attributed to the single author's infrequent updates. As AV signatures caught up with the wrapper, operators migrated to other packers.

## Regional Focus

Hqwar-packed banking trojan droppers were especially prevalent in Turkey, where they carried both international families ([Marcher](../malware/families/marcher.md), [Svpeng](../malware/families/svpeng.md)) and regional threats.

## Identification

| Indicator | Value |
|-----------|-------|
| Kaspersky detection | `Trojan-Dropper.AndroidOS.Hqwar.*` |
| Runtime behavior | `DexClassLoader` invocation loading decrypted DEX from memory |
| Encryption | RC4 with hardwired key |
| File artifacts | Encrypted blob in APK assets, no visible DEX payload in static analysis |

## References

- [Securelist: HQWar - the higher it flies, the harder it drops](https://securelist.com/hqwar-the-higher-it-flies-the-harder-it-drops/93689/)
- [Securelist: Mobile Malware Evolution 2018](https://securelist.com/mobile-malware-evolution-2018/89689/)
