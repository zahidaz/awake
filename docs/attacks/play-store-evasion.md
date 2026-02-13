# Play Store Evasion

Techniques malware uses to bypass Google Play Protect and store review to distribute through the official Play Store. The dropper-based distribution model is the dominant strategy for Android banking malware since 2020 -- a clean app passes all checks at upload, then downloads or activates its malicious payload post-installation. Understanding these techniques is essential for analyzing how malware reaches millions of devices through a trusted distribution channel.

See also: [Dynamic Code Loading](dynamic-code-loading.md), [Persistence Techniques](persistence-techniques.md), [Anti-Analysis Techniques](anti-analysis-techniques.md), [Mass Malware Generation](mass-malware-generation.md)

!!! warning "Scale of the Problem"

    Google removed over 2.3 million apps from the Play Store in 2024 for policy violations. Despite automated scanning (Play Protect) and manual review, sophisticated droppers consistently bypass all layers. [ThreatFabric](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions) and [Cleafy](https://www.cleafy.com/) regularly document families that survive on the store for months before detection.

## Dropper Chains

The standard architecture separates benign-looking dropper apps from actual malicious payloads across multiple stages.

### Stage 1: The Clean App

A functional utility (PDF reader, QR scanner, file manager, phone cleaner) published to the Play Store. Contains zero malicious code at upload time. Often accumulates thousands of legitimate downloads and positive reviews before activation.

```java
public class CleanApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        if (shouldActivate()) {
            fetchPayload();
        }
    }

    private boolean shouldActivate() {
        long installTime = getPackageManager()
            .getPackageInfo(getPackageName(), 0).firstInstallTime;
        long daysSinceInstall = (System.currentTimeMillis() - installTime)
            / (1000 * 60 * 60 * 24);
        return daysSinceInstall > 14 && !isEmulator() && checkGeo();
    }
}
```

### Stage 2: Payload Delivery

Once activation conditions are met, the dropper downloads an encrypted DEX or APK from C2:

| Delivery Method | Stealth Level | Families Using It |
|----------------|---------------|-------------------|
| Direct APK download + install prompt | Low | Early [SharkBot](../malware/families/sharkbot.md) |
| Encrypted DEX loaded via `DexClassLoader` | High | [Anatsa](../malware/families/anatsa.md), [Joker](../malware/families/joker.md) |
| Steganographic PNG with embedded payload | Very High | [Necro](../malware/families/necro.md) |
| Native library decrypts embedded DEX | High | [Mandrake](../malware/families/mandrake.md) |
| Base64 in SharedPreferences | Medium | [Joker](../malware/families/joker.md) variants |

### Stage 3: Modular C2 Plugins

Advanced families download individual capability modules as separate DEX files from C2, activating only what the operator needs for a specific target. This minimizes the attack surface exposed to any single analysis.

## Versioning Attacks

The dropper publishes as a legitimate app and accumulates installs and reviews. After weeks or months, a malicious update is pushed. [Google's Threat Analysis Group](https://thehackernews.com/2023/08/malicious-apps-use-sneaky-versioning.html) documented this as "versioning" in 2023 -- initial versions pass review, later versions introduce dynamic code loading that fetches the actual malware.

[Anatsa](../malware/families/anatsa.md) demonstrated this in 2024: a phone cleaner app was published to the Play Store, and approximately six weeks later, a malicious update activated the dropper functionality. By that point it had already accumulated enough installs and reviews to appear trustworthy. In July 2025, [Zscaler reported](https://www.zscaler.com/blogs/security-research/technical-analysis-anatsa-campaigns-android-banking-malware-active-google) an Anatsa dropper disguised as a PDF reader reached 90,000 downloads and the #4 spot in "Top Free - Tools" before detection.

## Geographic Targeting

Malware activates only in target countries to reduce exposure and evade analysis environments that typically run in US/EU cloud infrastructure.

| Check Method | Reliability | Bypass Difficulty |
|-------------|-------------|-------------------|
| SIM country code (`TelephonyManager.getSimCountryIso()`) | High | Requires physical SIM from target country |
| Network country code (`getNetworkCountryIso()`) | Medium | VPN does not change this |
| IP geolocation (server-side) | Medium | Detectable via VPN/proxy |
| System locale / language | Low | Easily spoofed |
| Timezone | Low | Easily spoofed |

```java
private boolean isTargetCountry() {
    TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
    String simCountry = tm.getSimCountryIso().toUpperCase();
    String[] targets = {"DE", "GB", "IT", "ES", "AU", "TR"};
    return Arrays.asList(targets).contains(simCountry);
}
```

[MITRE ATT&CK documents this as T1627.001 (Geofencing)](https://attack.mitre.org/techniques/T1627/001/). [Anatsa](../malware/families/anatsa.md) campaigns in 2024 specifically targeted the UK, Germany, Spain, Slovakia, Slovenia, and Czech Republic while avoiding Eastern European and Chinese IP ranges. Analysis environments in non-target geolocations never trigger payload delivery, resulting in clean verdicts.

## Delayed Activation

Malware waits hours, days, or weeks before contacting C2 or enabling malicious functionality. Google Play Protect's automated analysis sandbox runs apps for a limited time window -- sleeping through it guarantees a clean scan.

Common delay strategies:

| Strategy | Implementation | Detection Risk |
|----------|---------------|----------------|
| Time bomb | Check `firstInstallTime`, activate after N days | Low if delay > 72 hours |
| C2 kill switch | Server returns "inactive" until operator decides | Very low -- no local trigger |
| Interaction count | Activate after N app opens by user | Low -- sandbox interaction is minimal |
| Update trigger | First version clean, malicious update activates dropper | Low -- review focuses on diff |

The C2 kill switch is the most effective: the dropper app calls home, and the server decides whether this device should receive the payload. During review periods or when analysis is detected, the server simply never delivers. [Mandrake](../malware/families/mandrake.md) survived on Google Play for over two years (2022-2024) using this approach, with [Kaspersky reporting](https://securelist.com/mandrake-apps-return-to-google-play/113147/) that five apps sat on the store undetected.

## Code Hiding Techniques

### Obfuscated Native Loaders

[Mandrake](../malware/families/mandrake.md) hides its initial stage in a native library (`libopencv_dnn.so`) heavily obfuscated using OLLVM. This library exports functions to decrypt a second-stage DEX loader from the APK's assets folder. Native code is significantly harder for Play Protect to analyze compared to Dalvik bytecode.

### Steganographic Payloads

[Necro](../malware/families/necro.md) (2024) used steganography to hide payloads inside PNG images. The [Coral SDK](https://securelist.com/necro-trojan-is-back-on-google-play/113881/) embedded in the dropper sends an encrypted POST request to C2, which responds with a link to a PNG file. The payload is encoded in the least significant bits of the image's blue channel as Base64. This technique infected 11 million devices across apps including Wuta Camera (10M+ downloads) and Max Browser (1M+ downloads).

### Runtime String Decryption

[Anatsa](../malware/families/anatsa.md) decrypts each string at runtime using a dynamically generated DES key, preventing static extraction of C2 URLs, package names, or other indicators. Combined with emulation checks and device model verification, this defeats both static and dynamic analysis in automated sandboxes.

### Manifest Corruption

[SoumniBot](../malware/families/soumnibot.md) and some [Anatsa](../malware/families/anatsa.md) variants inject malformed data into the APK's `AndroidManifest.xml`, intentionally corrupting compression parameters. The Android runtime tolerates these malformations and parses the manifest correctly, but analysis tools (apktool, aapt) crash or produce incomplete output.

## Families and Play Store Campaigns

| Family | Store Disguise | Evasion Techniques | Downloads Before Removal |
|--------|---------------|-------------------|------------------------|
| [Anatsa](../malware/families/anatsa.md) | PDF readers, QR scanners, file managers | Versioning, geo-targeting, DES string encryption, manifest corruption | 90,000+ per campaign |
| [SharkBot](../malware/families/sharkbot.md) | Antivirus apps, file managers | Reduced APK functionality, payload via C2 update | 50,000+ |
| [Joker](../malware/families/joker.md) | Messaging, wallpapers, cameras | Base64 DEX in strings, DCL from C2 | Millions across hundreds of apps |
| [Harly](../malware/families/harly.md) | Games, utilities | Encrypted payload in APK assets | Millions |
| [Necro](../malware/families/necro.md) | Camera apps, browsers | Steganographic PNG, Coral SDK loader | 11,000,000+ |
| [Mandrake](../malware/families/mandrake.md) | Wi-Fi tools, astronomy, file sharing | OLLVM native loader, multi-year dormancy, C2 kill switch | 32,000+ |
| [Xenomorph](../malware/families/xenomorph.md) | Fast Cleaner | Dropper downloads payload APK | 50,000+ |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | Government services, utility apps | Social engineering for TestFlight/Enterprise certs | Targeted campaigns |
| Grabos | Music players, utilities | [Commercial obfuscator](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-grabos-exposed-millions-to-pay-per-install-scam-on-google-play/) hiding PPI fraud code | 4,200,000-17,500,000 across 144 apps |
| [Goldoson](../malware/families/goldoson.md) | Popular Korean utility/game apps | [Malicious SDK embedded in legitimate apps](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/) | 100,000,000+ across 60+ apps |
| Xamalicious | Health, games, horoscope, productivity | [Xamarin framework as packer](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/stealth-backdoor-android-xamalicious-actively-infecting-devices/), dynamic second-stage DLL loading | 327,000+ across 25 apps |

## Developer Account & App Acquisition

Threat actors purchase legitimate apps or developer accounts to push malicious updates to existing user bases, bypassing all initial trust barriers.

### Account Market

According to [Kaspersky research (2023)](https://www.infosecurity-magazine.com/news/malicious-android-apps-sold/), Google Play developer accounts sell on dark web marketplaces for $60-$200 each. Existing apps with established user bases command $20,000+ depending on install count. The buyer retains original signing keys and account access.

### Barcode Scanner (2021)

A barcode scanning app with 10M+ installs received a malicious update on December 4, 2020. [Malwarebytes discovered](https://www.malwarebytes.com/blog/news/2021/02/barcode-scanner-app-on-google-play-infects-10-million-users-with-one-update) that Lavabird Ltd. had sold the app to a third party who injected heavily obfuscated adware. No new permissions requested, just malicious code hidden in the existing codebase.

### Konfety "Evil Twin" (2024)

[HUMAN Security discovered](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-konfety-spreads-evil-twin-apps-for-multiple-fraud-schemes/) "decoy twin" apps on Google Play (clean) paired with "evil twin" apps distributed via malvertising that spoofed the decoy apps' package names and publisher IDs. 250+ decoy apps, generating 10 billion programmatic ad requests per day at peak.

### PhantomLance / APT32 (2015-2020)

Vietnamese state-linked APT32 published clean apps, created fake GitHub developer profiles, then delivered spyware via updates. [Kaspersky documented](https://www.kaspersky.com/blog/phantomlance-android-backdoor-trojan/35234/) the campaign active for five years before discovery. Targeted users across Southeast Asia.

## Session-Based Installer Bypass

Android 13 introduced [Restricted Settings](https://www.bleepingcomputer.com/news/security/malware-devs-already-bypassed-android-13s-new-security-feature/) to block sideloaded apps from accessing Accessibility Services and Notification Listener. Apps installed via a session-based `PackageInstaller` API (the method used by Play Store and legitimate app marketplaces) are exempt from this restriction.

[SecuriDropper](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions) (dropper-as-a-service) exploits this by using the session-based installer to install its malicious payload, making Android unable to distinguish it from a marketplace-installed app. The payload then freely requests Accessibility Service access. This bypass works on Android 13 and 14.

```java
PackageInstaller installer = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
    PackageInstaller.SessionParams.MODE_FULL_INSTALL);

int sessionId = installer.createSession(params);
PackageInstaller.Session session = installer.openSession(sessionId);

OutputStream out = session.openWrite("payload.apk", 0, apkBytes.length);
out.write(apkBytes);
out.close();

session.commit(PendingIntent.getBroadcast(
    this, sessionId, new Intent("INSTALL_COMPLETE"),
    PendingIntent.FLAG_MUTABLE).getIntentSender());
```

[SpyNote](../malware/families/spynote.md) and [Anatsa](../malware/families/anatsa.md) droppers adopted this technique within weeks of Restricted Settings launching, as [documented by cryptax](https://cryptax.medium.com/android-spynote-bypasses-restricted-settings-breaks-many-re-tools-8791b3e6bf38).

## Android Version Changes

| Version | Change | Impact on Evasion |
|---------|--------|-------------------|
| Android 11 | Package visibility restrictions | Malware must declare `QUERY_ALL_PACKAGES` or use targeted `<queries>` |
| Android 13 | Restricted Settings for sideloaded apps | Bypassed via session-based installer within weeks |
| Android 14 | Restricted Settings still bypassable | SecuriDropper technique persists |
| Android 14 | Dynamic code loading warnings for writable paths | Malware switches to `InMemoryDexClassLoader` or read-only files |
| Android 15 | Enhanced Play Protect live threat detection | Real-time behavioral analysis catches some delayed activation |
| Android 15 | Stricter DCL enforcement for API 35+ | Loaded DEX must be in read-only paths |

## Detection During Analysis

??? example "Static Indicators"

    - `DexClassLoader` or `InMemoryDexClassLoader` usage
    - `PackageInstaller.Session` API calls (session-based installer abuse)
    - Encrypted blobs in `assets/` with high Shannon entropy
    - `TelephonyManager` calls for SIM/network country checks
    - Native libraries with OLLVM obfuscation indicators
    - Manifest parsing errors in apktool/aapt

??? example "Dynamic Indicators"

    - Long delay (hours/days) before first C2 contact
    - Payload DEX files appearing in app-private directories after delay
    - Network requests conditional on device locale, SIM, or IP geolocation
    - PNG/JPEG downloads followed by class loading (steganographic delivery)
    - `PackageInstaller` session creation for secondary APK installation

??? example "Sandbox Evasion Checks to Watch For"

    - `Build.FINGERPRINT` containing "generic" or "sdk"
    - `Build.MODEL` matching known emulator models
    - `/dev/socket/qemud`, `/dev/qemu_pipe` file existence checks
    - SIM operator/country returning empty or default values
    - Battery temperature/level anomalies (emulators report static values)
    - `Settings.Secure.ANDROID_ID` set to known emulator defaults
