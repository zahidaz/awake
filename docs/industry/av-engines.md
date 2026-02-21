# AV Engines

Detection names from these engines appear on [VirusTotal](https://www.virustotal.com/). For detailed detection name formats and cross-vendor mapping, see [Naming Conventions](../malware/naming-conventions.md).

## Primary Engines

Best Android coverage across the major vendors.

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

## Mobile-Specific Engines

| Engine | Notes |
|--------|-------|
| AhnLab-V3 | Korean. `Trojan/Android.Banker.NNNNNN`. Strong on Asian malware. |
| Avast-Mobile | Mobile-dedicated scanner. |
| BitDefenderFalx | Bitdefender's mobile engine. |
| Symantec Mobile Insight | Broadcom's mobile engine. Often generic verdicts. |
| Trustlook | Mobile-focused behavioral detection. |

## EDR / Next-Gen

Limited family attribution. These engines detect malicious behavior but rarely assign specific family names.

| Engine | Notes |
|--------|-------|
| CrowdStrike Falcon | Behavioral, often no family name. |
| DeepInstinct | Binary ML verdict only. |
| Palo Alto Networks | ML-based, usually no family name. |
| SentinelOne (Static ML) | Binary verdict: "Static AI - Malicious APK". |
| Elastic | Community rules. |

## Regional Engines

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
