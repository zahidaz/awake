# Standards & Bug Bounties

Security standards governing mobile apps and vulnerability disclosure programs relevant to Android.

## Bug Bounty Programs

| Program | Scope | Max Payout | Notes |
|---------|-------|------------|-------|
| [Google VRP](https://bughunters.google.com/) | Android OS, Pixel devices, Google apps | $1,000,000 (full exploit chain) | Largest mobile bounty. Covers kernel, framework, and app-level bugs. Paid [$11.8M total in 2024](https://security.googleblog.com/2025/03/vulnerability-reward-program-2024-in.html). |
| [Google Mobile VRP](https://bughunters.google.com/) | First-party Android apps | $30,000 (RCE) | Separate program for Google-developed Android apps (Maps, YouTube, etc.) |
| [Samsung Mobile Security Rewards](https://security.samsungmobile.com/) | Samsung devices, Knox, Galaxy Store | $1,000,000 | Covers One UI, Knox, Samsung-specific drivers and firmware |
| [Qualcomm Bug Bounty](https://www.qualcomm.com/company/product-security/) | Snapdragon chipsets, modem, TEE | Varies | Baseband and TrustZone vulnerabilities. Critical for Android exploit chains. |
| [MediaTek PSIRT](https://www.mediatek.com/security) | MediaTek chipsets | Varies | Second-largest Android chipset vendor |

## Standards Bodies & Regulators

| Organization | Standard/Regulation | Relevance |
|-------------|-------------------|-----------|
| [NIST](https://www.nist.gov/) | SP 800-163 (Vetting Mobile Apps), SP 800-124 (Managing Mobile Devices) | US government mobile security guidelines |
| [ENISA](https://www.enisa.europa.eu/) | Smartphone Secure Development Guidelines | EU mobile security guidance for developers and enterprises |
| [EMVCo](https://www.emvco.com/) | SBMP (Software-Based Mobile Payments) | Certification for mobile payment app security. [DexProtector](../packers/dexprotector.md) and [Verimatrix](../packers/verimatrix.md) are EMVCo-certified. |
| [PCI SSC](https://www.pcisecuritystandards.org/) | PCI MPoC (Mobile Payments on COTS) | Standard for accepting payments on commercial off-the-shelf mobile devices |
| [OWASP](https://owasp.org/) | [MASVS](https://mas.owasp.org/MASVS/) / [MASTG](https://mas.owasp.org/MASTG/) | Mobile Application Security Verification Standard and Testing Guide. Industry-standard testing framework. |
| [GSMA](https://www.gsma.com/) | FS.05, FS.31 | Mobile device security guidelines, SIM security standards |
| EU Parliament | [Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) | Mandatory cybersecurity requirements for products with digital elements, including mobile apps. Effective 2027. |
