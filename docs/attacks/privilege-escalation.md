# Privilege Escalation

Gaining elevated privileges on an Android device beyond what the app sandbox permits -- from kernel root exploits and SELinux bypasses to abusing leaked platform signing keys and chaining runtime permissions into full device control. Privilege escalation is the dividing line between commodity malware (which operates within the permission model) and commercial spyware (which breaks out of it entirely).

See also: [Accessibility Abuse](accessibility-abuse.md), [Device Admin Abuse](device-admin-abuse.md), [SELinux](../platform-abuse/selinux.md)

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Root exploits | Unpatched kernel or driver vulnerability on target device |
    | SELinux bypass | Root access or kernel write primitive to modify policy/hooks |
    | Platform cert abuse | Leaked or stolen OEM platform signing certificate |
    | Permission chains | Social engineering + [accessibility service](accessibility-abuse.md) enablement |
    | Zero-click | No user interaction; exploits in baseband, Bluetooth, or RCS processing |

## Root Exploits (Historical)

Privilege escalation on Android historically meant getting root. Before modern SELinux enforcement and verified boot, a single kernel vulnerability could give an attacker uid 0 and full device control. These exploits remain relevant: millions of unpatched devices still run in the wild, and commercial spyware vendors maintain private exploit chains targeting current kernels.

### Framaroot (2013--2014)

One-click root tool exploiting Samsung Exynos kernel flaws and misconfigured `setuid` binaries. Named its exploits after Lord of the Rings characters (Gandalf, Boromir, Pippin), each targeting a different kernel vulnerability. Originally distributed as a legitimate rooting utility, Framaroot's exploit binaries were later embedded directly into malware. The [Pegasus](../malware/families/pegasus.md) Android variant (Chrysaor) reused Framaroot exploits for initial privilege escalation on older Samsung devices, as [documented by Lookout in 2017](https://www.lookout.com/threat-intelligence/article/pegasus-for-android).

### Towelroot -- CVE-2014-3153

Race condition in the Linux kernel `futex` subsystem discovered by [George Hotz (GeoHot)](https://towelroot.com/). The vulnerability allowed an unprivileged process to escalate to root through a `futex_requeue` race. Affected every Android device running kernel versions before 3.14.5. The [Pegasus](../malware/families/pegasus.md) Android variant used Towelroot as one of several exploits in its escalation chain. Google's [analysis of Chrysaor](https://security.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html) confirmed Towelroot was the primary root vector on devices where Framaroot failed.

### DirtyCow -- CVE-2016-5195

Copy-on-write race condition in the Linux kernel's memory subsystem, present since kernel 2.6.22 (2007). The bug allowed a local attacker to gain write access to read-only memory mappings by racing `madvise(MADV_DONTNEED)` against page fault handling. On Android, this translated to overwriting `setuid` binaries or directly patching the running kernel in memory. DirtyCow was [widely exploited in the wild](https://dirtycow.ninja/) and became one of the most reliable Android root exploits ever discovered. ZNIU malware was the [first family observed exploiting DirtyCow on Android at scale](https://blog.trendmicro.com/trendlabs-security-intelligence/zniu-first-android-malware-exploit-dirty-cow-vulnerability/), targeting over 40 countries in 2017.

### MediaTek-SU -- CVE-2020-0069

Command injection in MediaTek's `CMDQ` driver that allowed any app to execute commands as root. Affected millions of devices across dozens of OEMs using MediaTek chipsets (including Amazon Fire tablets). The vulnerability was [publicly disclosed by XDA Developers](https://www.xda-developers.com/mediatek-su-root-exploit/) after being used in the rooting community for months, and was exploited by multiple malware campaigns targeting budget MediaTek phones in Southeast Asia and Africa. MediaTek patched it in March 2020, but OEM patch distribution for low-end devices was slow to nonexistent.

### DirtyPipe -- CVE-2022-0847

Flaw in the Linux kernel pipe buffer implementation that allowed overwriting data in arbitrary read-only files by manipulating page cache references through the `splice()` system call. Affected kernel versions 5.8 through 5.16.11. On Android, this impacted devices running Android 12 with kernel 5.10, including Pixel 6 and Samsung Galaxy S22. [Google patched it in the Android Security Bulletin for March 2022](https://source.android.com/docs/security/bulletin/2022-03-01). Some spyware vendors reportedly integrated DirtyPipe into their exploit chains during the window between public disclosure and patch deployment.

### KingRoot and KingoRoot

Commercial one-click rooting tools that bundled dozens of kernel exploits covering hundreds of device/kernel combinations. Both tools ship as closed-source APKs that phone home to Chinese servers, download device-specific exploit payloads, and attempt multiple root strategies sequentially. Malware authors repurpose the exploit binaries extracted from these tools rather than developing their own. [Lookout research](https://www.lookout.com/threat-intelligence/article/lookout-discovers-new-trojanized-adware) documented adware campaigns using KingRoot's exploit modules to silently root devices and install system-level adware that survives factory resets.

## Kernel Exploits by Commercial Spyware

Commercial spyware operates at a different tier than commodity malware. These vendors maintain dedicated exploit development teams that target zero-day vulnerabilities in the Android kernel, GPU drivers, and baseband processors. The exploits are chained together -- typically a sandbox escape, a kernel privilege escalation, and a SELinux bypass -- to achieve persistent, undetectable implant installation.

### Pegasus -- NSO Group

The most documented commercial spyware on Android. The Android variant, codenamed Chrysaor by Google, was [first analyzed by Lookout and Google in April 2017](https://security.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html). Early versions used known exploits (Framaroot, Towelroot) as a fallback when zero-days failed. Later versions shifted entirely to zero-day chains. Pegasus's Android capabilities include live call recording, camera/microphone access, message extraction from encrypted apps, and GPS tracking -- all requiring kernel-level access to bypass Android's sandbox. The [Amnesty International Pegasus Project (2021)](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/) documented its deployment against journalists and activists globally.

### Predator -- Cytrox/Intellexa

Google TAG and Cisco Talos jointly documented a [5-exploit chain used by Predator in 2022-2023](https://blog.google/threat-analysis-group/protecting-android-users-from-0-day-attacks/). The chain targeted Chrome, the Android kernel, and specific Qualcomm/ARM GPU drivers. Predator was delivered via one-click links sent through messaging apps. Once initial code execution was achieved through a Chrome renderer bug, the chain escalated through a sandbox escape, then a kernel exploit for full device compromise. [Cisco Talos's deep technical analysis](https://blog.talosintelligence.com/mercenary-intellexa-predator/) revealed Predator's modular loader architecture and its use of Python-based implant modules running with root privileges.

### Hermit -- RCS Lab

Italian spyware documented by [Lookout in June 2022](https://www.lookout.com/threat-intelligence/article/lookout-discovers-hermit-spyware) and [confirmed by Google TAG](https://blog.google/threat-analysis-group/italian-spyware-vendor-targets-users-in-italy-and-kazakhstan/). Hermit's delivery was notable: ISP-level cooperation was used to disable the target's mobile data, then an SMS was sent impersonating the carrier and directing the victim to install a "connectivity fix" app. The app contained exploit chains targeting the Android kernel. Google identified victims in Italy and Kazakhstan.

### NoviSpy

Serbian police spyware [documented by Amnesty International in December 2024](https://www.amnesty.org/en/documents/eur70/8813/2024/en/). NoviSpy was installed on journalists' and activists' devices during police custody using Cellebrite UFED for initial device unlock, then deployed a spyware implant that exploited Qualcomm zero-day vulnerabilities including CVE-2024-43047 (a use-after-free in Qualcomm's DSP driver). The implant gained kernel access, bypassed SELinux, and established persistent surveillance. This case is significant because it documented the intersection of lawful access tools (Cellebrite) and spyware deployment in a single attack chain.

### QuaDream REIGN

Parallel competitor to NSO Group, [documented by Citizen Lab and Microsoft in April 2023](https://citizenlab.ca/2023/04/spyware-vendor-quadream-exploits-victims-customers/). Primarily known for iOS zero-click exploits, but the company marketed Android capabilities to government clients. QuaDream shut down in 2023, reportedly due to business difficulties after public exposure. The Android component's technical details remain less documented than the iOS variant.

## Zero-Click Exploits on Android

Zero-click exploits require no user interaction. The attacker sends a specially crafted message, network packet, or Bluetooth signal that triggers code execution in a background process. These are the highest-value exploits because they leave no social engineering trail.

### Samsung Exynos Baseband RCE (2023)

Google Project Zero's [Natalie Silvanovich disclosed 18 vulnerabilities](https://googleprojectzero.blogspot.com/2023/03/multiple-internet-to-baseband-remote-rce.html) in Samsung's Exynos modem firmware in March 2023. Four of these (CVE-2023-24033, CVE-2023-26496, CVE-2023-26497, CVE-2023-26498) allowed remote code execution in the baseband processor with only the victim's phone number. The attacker could send a specially crafted SIP INVITE or other VoLTE/VoWiFi packet that triggered a buffer overflow in the baseband's protocol parsing code. Affected chipsets included Exynos 980, 1080, 1280, 2200, and Exynos Modem 5123/5300 -- present in Samsung Galaxy S22, A53, Pixel 6, Pixel 7, and various Vivo devices. Baseband RCE is particularly dangerous because the baseband processor operates outside Android's security model entirely: no SELinux, no app sandbox, direct access to cellular communications.

### CVE-2023-40088 -- Bluetooth Zero-Click RCE

Memory corruption in Android's Bluetooth stack (`com_android_bluetooth_btservice_AdapterService.cpp`) [patched in December 2023](https://source.android.com/docs/security/bulletin/2023-12-01). Exploitation required Bluetooth to be enabled and the attacker to be within Bluetooth range. No pairing or user interaction needed. The bug allowed remote code execution in the Bluetooth service process, which runs with elevated privileges. Combined with a second-stage kernel exploit, this could achieve full device compromise from physical proximity alone.

### LANDFALL (2024)

Samsung-specific zero-click exploit chain [reported by Google TAG in 2024](https://blog.google/threat-analysis-group/state-backed-attackers-and-commercial-surveillance-vendors-repeatedly-use-the-same-exploits/). Details remain partially restricted due to ongoing patching, but the chain targeted Samsung's RCS message processing and achieved code execution without any user interaction. Attributed to a commercial spyware vendor. The exploit leveraged vulnerabilities in Samsung's Messages app (the default RCS client on Galaxy devices), which processes rich media content automatically upon receipt.

### Rich Communication Services (RCS) Attack Surface

RCS replaces SMS with a richer protocol supporting read receipts, group chats, and media. The expanded functionality introduces a larger attack surface. RCS clients automatically process incoming messages including media previews, vCards, and location data. Vulnerabilities in media parsing (image codecs, video decoders, PDF renderers) within the RCS client can be triggered by sending a crafted message. Google Messages and Samsung Messages both handle RCS processing in the background, making them prime zero-click targets.

## SELinux Bypass

Modern Android devices run SELinux in enforcing mode. Even with a kernel exploit granting uid 0, the attacker's process remains confined by SELinux policy. Commercial spyware must bypass or disable SELinux to operate freely. See the dedicated [SELinux](../platform-abuse/selinux.md) page for the platform's design and enforcement details.

### Nulling selinux_enforcing

The most direct approach. The attacker uses a kernel write primitive to set the `selinux_enforcing` global variable to 0, switching SELinux from enforcing to permissive mode. On older kernels (pre-4.17), this variable was a simple integer in kernel memory. The exploit locates it via `/proc/kallsyms` (if readable) or through known offsets for the target kernel build, then overwrites it.

```c
unsigned long enforcing_addr = find_symbol("selinux_enforcing");
*(int *)enforcing_addr = 0;
```

Modern kernels compile with `CONFIG_KALLSYMS_ALL=n` and restrict `/proc/kallsyms` access, making symbol resolution harder but not impossible -- the attacker can scan kernel memory for known patterns.

### Removing Security Hook Heads

A more surgical approach that disables specific SELinux hooks without changing the enforcing flag (which is monitored by some integrity checking systems). The Linux Security Module (LSM) framework uses a linked list of `security_hook_heads`. The attacker patches the function pointers in the hook list to point to no-op functions, effectively neutering individual permission checks (file access, process creation, socket operations) while leaving SELinux nominally in enforcing mode.

### SELinux Policy Injection

On rooted devices, the attacker can load custom SELinux policies using `semodule` or by directly writing to `/sys/fs/selinux/load`. This adds `allow` rules for the attacker's process domain without disabling enforcement for other domains. Tools like `sepolicy-inject` and `magiskpolicy` (from the [Magisk](https://github.com/topjohnwu/Magisk) project) automate this process.

```bash
magiskpolicy --live "allow untrusted_app system_data_file file { read write open create }"
```

### Pegasus SELinux Bypass

Pegasus (Chrysaor) [used a multi-stage SELinux bypass](https://security.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html). After gaining root via kernel exploit, it checked the SELinux status. If enforcing, it exploited a known vulnerability in the kernel's SELinux implementation or used the kernel write primitive to patch the enforcement flag. It then relabeled its own process context to a privileged domain (`init` or `system_server`) to operate with full access to all protected resources. Later versions used more sophisticated techniques including runtime policy modification to add targeted allow rules rather than disabling enforcement entirely.

## System App Impersonation

### Leaked Platform Signing Certificates

In December 2022, Google security researcher Lukasz Siewierski [disclosed that platform signing certificates](https://bugs.chromium.org/p/apvi/issues/detail?id=100) from Samsung, LG, MediaTek, and other OEMs had been leaked and were being used to sign malware. An APK signed with a platform certificate gets the `android.uid.system` shared UID, granting it the same privileges as the core system -- access to all protected APIs, all permissions auto-granted, ability to interact with system services without restriction.

The leaked certificates affected:

| OEM | Certificate Serial | Impact |
|-----|-------------------|--------|
| Samsung | Various platform certs | Malware could run as system on Samsung devices |
| LG | Platform signing key leaked | System-level access on LG devices |
| MediaTek | Platform cert included in SDK leaks | Widely used in budget device malware |
| Revoview | Platform cert | Limited device impact |

### SharedUserId Exploitation

An APK declaring `android:sharedUserId="android.uid.system"` in its manifest and signed with the platform certificate runs in the system process's UID. This gives it:

- All signature-level permissions without declaration
- Write access to `/data/system/` and other protected directories
- Ability to bind to system services as a privileged caller
- Access to `Settings.Secure` and `Settings.Global` for direct modification

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:sharedUserId="android.uid.system">
```

### Triada Supply-Chain Abuse

[Triada](../malware/families/triada.md) represents the most sophisticated system app impersonation observed in the wild. Rather than exploiting leaked certificates post-manufacture, Triada was [pre-installed at the firmware level](https://securelist.com/android-triada-trojan/78481/) during the manufacturing process of budget Android devices. The malware was injected into the system image itself, running as a system app with full platform privileges from first boot. Google's investigation revealed that a supply-chain compromise at an ODM (original design manufacturer) allowed the malware to be embedded into the firmware of multiple device brands. Over 40 device models were confirmed affected.

## Permission Escalation Chains

Not all privilege escalation requires exploiting vulnerabilities. On Android, a single permission can be chained into progressively greater control through the framework's own APIs. These chains exploit the trust model: once the user grants one sensitive permission, the malware uses it to acquire others without further user consent.

### The Overlay-to-Accessibility Chain

The most common escalation path used by banking trojans:

1. App requests [`SYSTEM_ALERT_WINDOW`](../permissions/special/system-alert-window.md) (auto-granted for Play Store installs on Android 6-9, or via Settings toggle)
2. Overlay covers the screen with a fake dialog or tutorial
3. Overlay guides/tricks the user into enabling [accessibility service](accessibility-abuse.md)
4. Accessibility service auto-grants all remaining runtime permissions by navigating Settings
5. Full device control achieved: keylogging, screen reading, gesture injection, notification interception

This chain converts a single, relatively easy-to-obtain permission into total device control through social engineering and UI manipulation.

### Accessibility as the Master Permission

Once an accessibility service is active, it can programmatically grant every other permission the malware needs:

| Permission | How Accessibility Grants It |
|-----------|---------------------------|
| Runtime permissions (camera, mic, location, SMS, etc.) | Navigates to Settings > Apps > Permissions, clicks "Allow" |
| [Device admin](device-admin-abuse.md) | Clicks "Activate" on the device admin prompt |
| [Notification listener](notification-listener-abuse.md) | Toggles the switch in Settings > Notification access |
| Default SMS app | Navigates Settings > Default apps > SMS, selects the malware |
| Install unknown apps | Enables "Allow from this source" in Settings |
| Battery optimization exemption | Navigates to battery settings, disables optimization |

This is why accessibility is the single most dangerous permission on Android. Every other permission becomes obtainable once accessibility is compromised.

### Device Admin Escalation

From [device admin](device-admin-abuse.md) activation:

1. `lockNow()` locks the screen, forcing PIN/pattern entry
2. Overlay or accessibility captures the PIN during unlock
3. `resetPassword()` (pre-Android 7) changes the lock credential
4. `wipeData()` used as ransomware or anti-forensics threat
5. Camera disable and other policies used as leverage

### Notification Listener to Account Takeover

From [notification listener](notification-listener-abuse.md) access:

1. Intercept incoming SMS/push notifications containing OTPs
2. Suppress the notification so the user never sees it
3. Forward the OTP to C2 for real-time use
4. Attacker uses stolen credentials + OTP to take over banking/email accounts
5. Account takeover enables further attacks (SIM swap, credential resets)

## Android Version Timeline

| Version | Year | Escalation-Relevant Changes |
|---------|------|-----------------------------|
| Android 4.3 | 2013 | SELinux introduced in permissive mode |
| Android 4.4 | 2013 | SELinux enforcing for core domains; `su` binary restricted |
| Android 5.0 | 2014 | Full SELinux enforcement; 64-bit ABI; verified boot (warning only) |
| Android 6.0 | 2015 | Runtime permissions model; `SYSTEM_ALERT_WINDOW` auto-granted from Play Store |
| Android 7.0 | 2016 | Verified boot strictly enforced; file-based encryption; `resetPassword()` restricted |
| Android 8.0 | 2017 | Project Treble (HAL isolation); `SYSTEM_ALERT_WINDOW` type restrictions; seccomp filter for zygote |
| Android 9.0 | 2018 | Biometric API; device admin deprecated for third-party apps; kernel CFI on Pixel |
| Android 10 | 2019 | Scoped storage; background activity launch restrictions; BoundsSanitizer in media codecs |
| Android 11 | 2020 | One-time permissions; scoped storage enforced; `MANAGE_EXTERNAL_STORAGE` gated; async `binder` calls restricted |
| Android 12 | 2021 | Approximate location option; `SameSite` cookies in WebView; ART module updatable via Play |
| Android 13 | 2022 | Restricted settings for sideloaded apps (blocks accessibility/notification listener); notification permission required; intent filter matching stricter |
| Android 14 | 2023 | Minimum target SDK enforced (blocks installing very old APKs); credential manager API; background activity launch further restricted |
| Android 15 | 2024 | Expanded restricted settings; improved integrity checking; 16KB page size support reducing exploit reliability |

## Families Using This Technique

| Family | Escalation Method | Details |
|--------|-------------------|---------|
| [Pegasus](../malware/families/pegasus.md) | Zero-day kernel exploits, SELinux bypass | Full exploit chain: sandbox escape + kernel root + SELinux disable. Framaroot/Towelroot as fallback |
| [Predator](../malware/families/predator.md) | 5-exploit chain (Chrome + kernel + GPU driver) | Delivered via one-click links, exploits Chrome renderer then escalates |
| [Hermit](../malware/families/hermit.md) | Kernel exploits with ISP-level delivery | ISP cooperation for delivery, exploit chain for root |
| [Triada](../malware/families/triada.md) | Supply-chain firmware injection | Pre-installed as system app, runs with platform certificate |
| [FinSpy](../malware/families/finspy.md) | DirtyCow and other kernel exploits | Government spyware, maintained private exploit library |
| ZNIU | DirtyCow (CVE-2016-5195) | First malware to exploit DirtyCow on Android at scale |
| [Anatsa](../malware/families/anatsa.md) | Overlay -> accessibility -> permission auto-grant | Classic permission chain for banking fraud |
| [Hook](../malware/families/hook.md) | Accessibility -> full device control + VNC | Permission chain with remote access |
| [Octo](../malware/families/octo.md) | Accessibility -> screen streaming -> ATS | Permission chain for on-device fraud |
| [Cerberus](../malware/families/cerberus.md) | Overlay + accessibility + device admin | Triple escalation for persistence and fraud |
| [GodFather](../malware/families/godfather.md) | Overlay -> accessibility -> auto-grant | Permission chain targeting banking apps |
| [Xenomorph](../malware/families/xenomorph.md) | Accessibility -> ATS with auto-permission grant | Automated permission escalation for on-device fraud |
| [Chameleon](../malware/families/chameleon.md) | Accessibility -> runtime permission manipulation | Bypasses Android 13 restricted settings |
| NoviSpy | Qualcomm zero-day (CVE-2024-43047) | Physical access deployment with Cellebrite + kernel exploit |

## Detection During Analysis

??? example "Static Indicators"

    - Native libraries (`.so` files) containing known exploit strings (`towelroot`, `dirtycow`, `dirty_pipe`, `CMDQ`)
    - ELF binaries in `assets/` or `lib/` directories not matching expected app functionality
    - `sharedUserId="android.uid.system"` in AndroidManifest.xml
    - APK signed with known leaked platform certificates (compare against [Google's APVI database](https://bugs.chromium.org/p/apvi/issues/list))
    - References to `/proc/kallsyms`, `/dev/kmem`, `selinux_enforcing`, or `/sys/fs/selinux/enforce` in native code
    - `DexClassLoader` or `Runtime.exec()` loading binaries from writable directories
    - Requests for `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE` + `BIND_DEVICE_ADMIN` in the same manifest (permission chain setup)

??? example "Dynamic Indicators"

    - Process UID changing from app UID to 0 (root) during execution
    - SELinux mode switching from enforcing to permissive (`getenforce` returns `Permissive`)
    - New files appearing in `/system/`, `/data/local/tmp/`, or `/data/data/<pkg>/` with root ownership
    - `su` binary being written or executed
    - Kernel log (`dmesg`) showing SELinux denials followed by sudden silence (enforcement disabled)
    - Accessibility service enabling itself through UI automation sequences visible in `dumpsys accessibility`
    - Sequential Settings navigation captured in accessibility event logs (permission auto-granting behavior)
    - Process context labels changing in `/proc/<pid>/attr/current` (SELinux domain transition)

??? example "Frida: Detect Root Escalation Attempts"

    ```javascript
    Java.perform(function() {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmd) {
            var cmdStr = cmd.join(" ");
            if (cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("/system/") !== -1) {
                console.log("[*] Suspicious exec: " + cmdStr);
                console.log(Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Exception").$new()
                ));
            }
            return this.exec(cmd);
        };

        var System = Java.use("java.lang.System");
        System.load.implementation = function(lib) {
            console.log("[*] System.load: " + lib);
            return this.load(lib);
        };

        System.loadLibrary.implementation = function(lib) {
            console.log("[*] System.loadLibrary: " + lib);
            return this.loadLibrary(lib);
        };
    });
    ```
