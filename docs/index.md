# AWAKE

**Android Wiki of Attacks, Knowledge & Exploits**

A structured knowledge base for Android security research. How malware works, how attacks exploit the platform, how protections are broken, and where the industry stands. Built for analysts, reversers, pentesters, and threat intelligence researchers.

Everything is offense-first: understanding how things break, not how to defend them.

---

## What's Inside

<div class="grid cards" markdown>

-   **[Attack Techniques](attacks/index.md)**

    ---

    How Android malware and exploits actually work. 30+ techniques organized by attack surface, with a kill chain showing how they combine in real operations and a matrix of the most common technique pairings.

-   **[Malware Families](malware/families/index.md)**

    ---

    80+ individual family write-ups covering capabilities, C2 infrastructure, campaign history, and code lineage. A [timeline](malware/timeline.md) from 2010 to present and a [naming guide](malware/naming-conventions.md) for mapping between vendor detection names.

-   **[Packers & Protectors](packers/index.md)**

    ---

    Every major Android packer documented: how to identify it, how it protects, and how to unpack it. Head-to-head comparison matrix, identification decision tree, and universal unpacking toolkit.

-   **[Permissions](permissions/index.md)**

    ---

    50+ Android permissions documented from an abuse perspective. What each unlocks, how malware uses it, and how permissions escalate from auto-granted to full device control.

-   **[Reversing](reversing/index.md)**

    ---

    Static analysis, dynamic analysis, hooking, patching, and network interception. Plus [28 development frameworks](reversing/frameworks/index.md) -- Flutter, React Native, Unity, Xamarin, and more -- each with its own reversing workflow.

-   **[Grayware](grayware/index.md)**

    ---

    The gray area between legitimate software and malware. Data broker SDKs, ad fraud, stalkerware, predatory lending apps, firmware grayware, commercial surveillance, and the data trade that funds it all.

-   **[Platform Security](platform-abuse/index.md)**

    ---

    Android's security mechanisms from the offense side. App sandbox, SELinux, verified boot, keystore, Play Integrity, and biometric authentication -- what they protect and where they fall short.

-   **[Industry](industry/index.md)**

    ---

    The mobile security landscape: AV vendors, MDM providers, app security companies, and threat intelligence firms. Who does what, and how they fit together.

</div>

---

## Where to Start

=== "Malware Analyst"

    Start with the [family catalog](malware/families/index.md) for the full list of documented families. The [timeline](malware/timeline.md) gives historical context, and [naming conventions](malware/naming-conventions.md) helps when different vendors use different names for the same thing. When a sample is packed, identify the packer first using the [decision tree](packers/index.md#analysis-decision-tree).

    Frequently referenced: [attack techniques](attacks/index.md), [persistence](attacks/persistence-techniques.md), [dynamic code loading](attacks/dynamic-code-loading.md), [grayware](grayware/index.md)

=== "Reverse Engineer"

    Start with [packer identification](packers/index.md). The comparison matrix ranks all documented protectors and the decision tree tells you where to begin. For runtime work, [hooking](reversing/hooking.md) and [patching](reversing/patching.md) cover the major approaches. The [frameworks section](reversing/frameworks/index.md) covers 28 development frameworks, each with its own analysis workflow.

    Frequently referenced: [dynamic analysis](reversing/dynamic-analysis.md), [network interception](reversing/network-analysis.md), [anti-analysis techniques](attacks/anti-analysis-techniques.md)

=== "Pentester"

    Start with [attack techniques](attacks/index.md) -- organized by attack surface with a combination matrix showing how techniques pair in real campaigns. The [permissions section](permissions/index.md) documents what each permission unlocks and how escalation works in practice.

    Frequently referenced: [deep links](attacks/deep-link-exploitation.md), [WebViews](attacks/webview-exploitation.md), [content providers](attacks/content-provider-attacks.md), [intent hijacking](attacks/intent-hijacking.md), [overlays](attacks/overlay-attacks.md)

=== "Threat Intelligence"

    Start with [threat actors](malware/threat-actors.md) for MaaS operator attribution and pricing. The [timeline](malware/timeline.md) tracks evolution from 2010 to present. [Grayware](grayware/index.md) covers the ecosystem between aggressive monetization and outright malware. The [industry section](industry/index.md) maps the security vendor landscape.

    Frequently referenced: [naming conventions](malware/naming-conventions.md), [supply chain attacks](attacks/supply-chain-attacks.md), [Play Store evasion](attacks/play-store-evasion.md)

---

## Recent Trends

| Trend | What's Happening |
|-------|-----------------|
| NFC relay attacks | Contactless payment cards cloned via NFC relay for ATM cash withdrawal. Bypasses traditional banking security entirely. |
| OCR-based crypto theft | Photos scanned for cryptocurrency seed phrases via on-device OCR. First seen on both [Play Store and App Store](malware/families/sparkcat.md) simultaneously. |
| On-device fraud automation | Real banking apps run inside virtualized sandboxes on infected devices, with automated transfers mimicking human behavior to evade fraud detection. |
| Minimal permission malware | Full banking trojan functionality with as few as 5 permissions by routing everything through [accessibility services](attacks/accessibility-abuse.md). |
| Commercial packer adoption | Malware authors buying commercial protectors ([Virbox](packers/virbox.md), [DexGuard](packers/dexguard.md)) instead of building custom solutions. |
| Legitimate services as C2 | Firebase, Telegram Bot API, and cloud storage used for command-and-control. Traffic blends with normal app behavior. |
| Cross-platform framework evasion | Malware built with .NET MAUI and Xamarin hides logic in C# assemblies that standard Android scanners never inspect. |
| India threat surge | Rapid growth in phishing-as-a-service and [predatory lending apps](malware/families/spyloan.md) targeting Indian mobile banking. |
