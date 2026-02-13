# SELinux

Security-Enhanced Linux on Android provides mandatory access control (MAC) that confines every process -- including root -- to a defined policy. Since Android 5.0, SELinux runs in enforcing mode on all production devices. For attackers, SELinux is the primary obstacle between a kernel or system exploit and full device control. Understanding its structure, its weaknesses, and the ways it has been bypassed is essential for Android offensive research.

## Policy Architecture

SELinux on Android uses a combination of type enforcement (TE), role-based access control (RBAC), and multi-level security (MLS) to define what every process can access.

### Type Enforcement

Every process and object on the system receives a security label (context) in the format `user:role:type:mls_level`. Type enforcement rules define allowed interactions between types:

```
allow untrusted_app app_data_file:file { read write open getattr };
allow untrusted_app activity_service:service_manager find;
```

The kernel denies any access not explicitly granted by an `allow` rule. There is no implicit permission -- even root running as `u:r:su:s0` is subject to whatever rules exist for the `su` type.

### Domain Transitions

When a process executes a binary, SELinux can force a domain transition to a new security context. The Android init process starts as `u:r:init:s0` and transitions child processes into their assigned domains. The Zygote process (`u:r:zygote:s0`) forks app processes and transitions them into the appropriate app domain based on the app's signing certificate and `seinfo` tag.

### Multi-Level Security (MLS)

Android uses MLS categories to isolate apps from each other. Each app receives a unique category pair (e.g., `s0:c149,c256,c512,c768`), preventing one untrusted app from accessing another's files even though both run in the `untrusted_app` domain. The category assignment is derived from the app's UID.

## App Process Contexts

The [seapp_contexts](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/seapp_contexts) file maps apps to their SELinux domains based on signing certificate, `seinfo` tag, and user type.

| Domain | Assigned To | Capabilities |
|--------|------------|--------------|
| `untrusted_app` | Third-party apps from Play Store or sideloaded | Standard app sandbox, no access to system internals |
| `untrusted_app_32` | 32-bit third-party apps on 64-bit devices | Same as `untrusted_app` with 32-bit ABI |
| `platform_app` | Apps signed with the platform certificate | Access to platform-level services and some system APIs |
| `system_app` | Apps in `/system/app` or `/system/priv-app` signed with platform cert | Broader system access, can interact with system services |
| `priv_app` | Privileged apps in `/system/priv-app` | Extended permissions beyond standard apps |
| `isolated_app` | Isolated service processes (`isolatedProcess=true`) | Extremely restricted, no network, no filesystem access |
| `ephemeral_app` | Instant apps | Reduced permissions compared to `untrusted_app` |

The `seinfo` tag is assigned by the [mac_permissions.xml](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/mac_permissions.xml) file based on the app's signing certificate. Apps signed with the platform key receive `seinfo=platform`, which maps to the `platform_app` domain. All other apps default to `untrusted_app`.

## Policy Files and Analysis Tools

### Policy Locations

| Path | Contents |
|------|----------|
| `/sys/fs/selinux/policy` | Compiled binary policy currently loaded in kernel |
| `/vendor/etc/selinux/` | Vendor-specific policy fragments |
| `/system/etc/selinux/` | System policy fragments |
| `/sepolicy` | Legacy monolithic policy (pre-Android 8.0 Treble) |
| `boot.img` ramdisk | Contains `sepolicy` on some device configurations |

### Analysis Tools

| Tool | Purpose |
|------|---------|
| `seinfo` | Display SELinux policy info, list types and attributes |
| `sesearch` | Search policy rules (allow, neverallow, type_transition) |
| `sepolicy-analyze` | AOSP tool for analyzing compiled policy |
| `audit2allow` | Convert SELinux denial logs into allow rules |
| `setenforce` | Toggle between enforcing (1) and permissive (0) -- requires root |
| `getenforce` | Query current SELinux mode |
| `chcon` | Change security context of a file |
| `restorecon` | Restore file context to policy default |

Extracting and decompiling the running policy from a device:

```bash
adb pull /sys/fs/selinux/policy /tmp/sepolicy
sesearch --allow -s untrusted_app /tmp/sepolicy
sesearch --allow -t app_data_file /tmp/sepolicy
seinfo -t /tmp/sepolicy | grep app
```

## Known Bypasses and Weaknesses

### Neverallow Violations

The AOSP policy includes `neverallow` rules that define security invariants -- transitions and accesses that must never be permitted. These are checked at policy compile time. However, vendor policy additions (particularly on OEM devices shipping custom SELinux rules) have historically introduced rules that violate these invariants.

Google's [CTS tests](https://source.android.com/docs/security/features/selinux/validate) verify that neverallow rules are respected, but devices that ship outside the CTS program or with incomplete testing have been caught with policy violations. Research from [8kSec on Android SELinux internals](https://8ksec.io/android-selinux-internals-part-i-8ksec-blogs/) documents how vendor policy fragments can inadvertently weaken the security posture.

### Permissive Domains in Production

During development, new SELinux domains are initially set to permissive mode to avoid breaking functionality while the correct rules are authored. The AOSP documentation explicitly states that permissive mode is not supported on production devices. CTS tests check that the global SELinux mode is enforcing.

However, individual domains can be set to permissive even when the global mode is enforcing. OEM vendors have shipped devices with permissive vendor-specific domains, allowing processes in those domains to bypass all MAC restrictions while the rest of the system remains enforcing. This was common on budget devices from smaller manufacturers who lacked the resources for complete policy development.

### CVEs Involving SELinux Bypass

| CVE | Year | Description |
|-----|------|-------------|
| [CVE-2022-20421](https://github.com/0xkol/badspin) | 2022 | Android Binder use-after-free achieving full kernel R/W, leading to root and complete SELinux bypass on Pixel 6 |
| [CVE-2024-53197](https://source.android.com/docs/security/bulletin) | 2024 | Privilege escalation exploited as part of a zero-day chain reportedly used by Cellebrite against Serbian activists |
| [CVE-2025-27363](https://source.android.com/docs/security/bulletin) | 2025 | Malformed binder transactions overwriting kernel structures, bypassing SELinux protections |
| [CVE-2025-38352](https://www.lookout.com/threat-intelligence/article/cve-2025-38352-cve-2025-48543) | 2025 | Local privilege escalation via race condition in POSIX CPU timers, enabling sandbox escape |

The [klecko blog on SELinux bypasses](https://klecko.github.io/posts/selinux-bypasses/) documents historical techniques for defeating SELinux after obtaining kernel code execution, including patching the in-kernel policy, disabling the enforcement flag, and manipulating process credentials.

### Kernel Exploit to SELinux Disable

Once an attacker achieves kernel code execution (through a kernel vulnerability), SELinux can be neutralized by:

1. **Patching the enforcement flag**: Writing `0` to the kernel's `selinux_enforcing` variable switches the entire system to permissive mode
2. **Modifying process credentials**: Overwriting the `security` field in the task's `cred` structure to assign an unrestricted SELinux context
3. **Disabling LSM hooks**: Zeroing out the SELinux hook functions in the Linux Security Module framework

Samsung devices with RKP (Real-time Kernel Protection) implement hypervisor-level protection of these structures, but [research has shown](https://cloudfuzz.github.io/android-kernel-exploitation/chapters/linux-privilege-escalation.html) that even RKP can be bypassed by targeting the hypervisor itself or finding gaps in its coverage.

## Magisk and SELinux

[Magisk](https://github.com/topjohnwu/Magisk) provides root access on Android while attempting to maintain a functional SELinux enforcing mode. Understanding how Magisk interacts with SELinux is critical for both root detection and offensive research.

### MagiskSU Context

All processes spawned from the Magisk daemon, including root shells and their child processes, run in the context `u:r:magisk:s0`. This is a custom domain that Magisk injects into the SELinux policy during boot. The `magisk` domain is granted broad permissions through injected policy rules, giving root shells access equivalent to the `init` or `kernel` domain while maintaining the enforcing state for all other processes.

### Sepolicy Injection

The `magiskinit` binary replaces the stock `/init` as the first userspace process (PID 1). Before executing the real init, it:

1. Loads the stock SELinux policy from the boot image or vendor partition
2. Patches the policy in memory to inject the `magisk` domain and associated rules
3. Writes the modified policy for the kernel to load

This happens before any other process starts, so the injected rules are active from the earliest point of the boot sequence. Magisk modules can provide additional policy patches via `sepolicy.rule` files, though [compatibility varies across devices](https://topjohnwu.github.io/Magisk/guides.html).

### Zygisk

Zygisk loads Magisk code directly into the Zygote process, allowing module developers to execute code in every app process before specialization. From a SELinux perspective, the Zygisk code runs within the `zygote` domain during injection, then transitions to the app's assigned domain when the process specializes. This is relevant for tools that need to run with elevated context before the app sandbox takes effect.

### Detection Implications

Because Magisk keeps SELinux in enforcing mode, simple `getenforce` checks return "Enforcing" on rooted Magisk devices. This means enforcement mode alone is not a reliable indicator of an unmodified device. More sophisticated detection checks for the presence of the `magisk` type in the loaded policy:

```bash
cat /sys/fs/selinux/policy | strings | grep magisk
```

## Permissive Mode Detection

### How Malware Uses Permissive Mode

When SELinux is in permissive mode, critical security restrictions are disabled. As [documented by Magisk's developer](https://www.xda-developers.com/permissive-selinux-dangers-exploits/), any arbitrary app can permanently root a device without user consent by exploiting known vulnerabilities that are normally blocked by SELinux policy. When SELinux is permissive during boot, Zygote also disables seccomp syscall filters, further unrestricting third-party processes.

Malware targeting rooted or compromised devices checks for permissive mode to determine if advanced exploitation techniques are available. A permissive device is effectively unprotected -- the app sandbox, inter-app isolation, and system service restrictions all become advisory rather than enforced.

### Detection by Banking Apps and Security Software

Banking apps and root detection libraries check SELinux status through multiple methods:

| Method | Detail |
|--------|--------|
| `getenforce` command | Runs the binary and parses stdout for "Enforcing" or "Permissive" |
| `/sys/fs/selinux/enforce` | Reads the kernel's enforcement flag directly (0 = permissive, 1 = enforcing) |
| `android.os.SELinux` | Hidden system API with `isSELinuxEnforced()` method |
| Process context check | Reads `/proc/self/attr/current` to verify the expected SELinux label |
| Policy analysis | Checks for overly permissive rules or custom domains like `magisk` |

### How Root Hiders Counter Detection

Root management solutions (Magisk, KernelSU, APatch) maintain enforcing mode specifically to pass these checks. The SELinux status reported through all standard interfaces shows "Enforcing" because the system genuinely is enforcing -- Magisk achieves its goals through injected policy rules rather than disabling enforcement.

Tools like [Shamiko](https://github.com/LSPosed/LSPosed.github.io) and [PlayIntegrityFix](https://github.com/chiteroman/PlayIntegrityFix) go further by hiding the `magisk` domain from policy inspection and spoofing device properties that root detection examines.

## Offensive Relevance

### For Exploit Development

SELinux policy analysis reveals what a compromised process can and cannot do. Before developing a post-exploitation payload, an attacker must know what the target domain's policy allows:

```bash
sesearch --allow -s untrusted_app /tmp/sepolicy | wc -l
sesearch --allow -s untrusted_app -t binder_device /tmp/sepolicy
sesearch --allow -s platform_app -c service_manager /tmp/sepolicy
```

The gap between what `untrusted_app` can do and what `platform_app` or `system_app` can do defines the value of privilege escalation from one domain to another.

### For Malware Analysis

When analyzing a sample that requires root or system-level access, understanding the SELinux context it expects to run in reveals its operational requirements. Malware that checks for permissive mode likely relies on exploitation techniques blocked by enforcing policy. Malware that functions within `untrusted_app` constraints is more sophisticated -- it operates within the sandbox using permitted APIs like [accessibility services](../attacks/accessibility-abuse.md).

### For Forensics

SELinux audit logs (`/data/misc/audit/audit.log` and `dmesg`) record all policy denials. On a compromised device, these logs reveal what the attacker attempted that was blocked by policy, providing a trace of exploitation activity even when the attack itself left no other artifacts.

## Cross-References

- [Accessibility Abuse](../attacks/accessibility-abuse.md) operates entirely within the `untrusted_app` SELinux domain, requiring no policy bypass
- [Persistence Techniques](../attacks/persistence-techniques.md) must work within SELinux constraints on non-rooted devices
- [Verified Boot](verified-boot.md) protects the SELinux policy files from modification on locked bootloader devices
- [Play Integrity](play-integrity.md) checks enforcing mode as one signal in device integrity attestation
