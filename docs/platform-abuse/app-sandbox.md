# App Sandbox

Android's primary isolation mechanism. Every app runs in its own process under a unique Linux UID, confined by SELinux mandatory access control. The sandbox is the foundation of Android's security model, and breaking it is the highest-value target for exploit chains.

## Process Isolation Model

### UID-Per-App

At install time, the package manager assigns each app a unique Linux UID (typically in the range 10000-19999, formatted as `u0_a0` through `u0_a9999`). This UID determines file access, IPC permissions, and network socket ownership.

| Property | Value |
|----------|-------|
| UID range | 10000 -- 19999 (per user profile) |
| GID | Same as UID by default |
| Supplementary GIDs | Added for specific permissions (e.g., `inet` for network access) |
| Process name | App package name |
| Home directory | `/data/data/<package>/` (owned by app UID) |

Each app's data directory is created with permissions `0700` and owned by the app's UID. No other app (except root and system) can read or write to it.

### Zygote Fork Model

All app processes are forked from the Zygote process, which pre-loads the Android framework classes. This means every app starts with the same base framework state, and isolation is enforced post-fork through UID assignment and SELinux context transition.

The fork-based model means all apps initially share the same memory pages (copy-on-write). This has historically enabled side-channel attacks where one app can infer another app's behavior from memory access patterns.

## SELinux Enforcement

### App Security Contexts

Android assigns SELinux security contexts to app processes based on their trust level:

| Context | Assignment | Capabilities |
|---------|-----------|-------------|
| `untrusted_app` | Third-party apps from Play Store or sideloaded | Most restricted; standard app sandbox |
| `untrusted_app_25` | Apps targeting API 25 or below | Slightly more permissive (legacy compatibility) |
| `untrusted_app_27` | Apps targeting API 27 or below | Legacy compatibility for Oreo-era apps |
| `untrusted_app_29` | Apps targeting API 29 or below | Scoped storage exemptions |
| `untrusted_app_32` | Apps targeting API 32 or below | Bluetooth permission compatibility |
| `platform_app` | Apps signed with the platform key | Access to platform-protected APIs |
| `system_app` | Apps in `/system/app/` or `/system/priv-app/` | System-level access |
| `isolated_app` | Isolated processes (e.g., WebView renderers) | Most restricted context, no network |
| `priv_app` | Privileged system apps | `signatureOrSystem` permissions |

The context `u:r:untrusted_app:s0:c512,c768` breaks down as:

| Field | Value | Meaning |
|-------|-------|---------|
| User | `u` | SELinux user (always `u` on Android) |
| Role | `r` | SELinux role (always `r` for processes) |
| Type | `untrusted_app` | Process type determining allowed operations |
| Sensitivity | `s0` | MLS sensitivity level |
| Categories | `c512,c768` | Per-app categories for app-to-app isolation |

### Neverallow Rules

Android's SELinux policy includes `neverallow` rules that are enforced at compile time and verified by CTS (Compatibility Test Suite). These rules guarantee certain access patterns are impossible regardless of any `allow` rules:

```
neverallow untrusted_app system_data_file:file { create write };
neverallow untrusted_app kernel:security { load_policy setenforce };
neverallow untrusted_app self:capability { sys_admin sys_boot };
```

OEM policy customizations must not violate these rules. [8kSec's research on Android SELinux internals](https://8ksec.io/android-selinux-internals-part-i-8ksec-blogs/) documents how vendor policy additions sometimes inadvertently weaken these guarantees.

## IPC Boundaries

Inter-process communication is how apps interact with each other and with system services. Each IPC mechanism represents a potential sandbox escape vector.

### Binder

The primary IPC mechanism in Android. All system service calls (`ActivityManager`, `PackageManager`, `WindowManager`, etc.) go through Binder. The kernel Binder driver (`/dev/binder`) mediates all transactions and enforces UID-based access control.

Binder is the most security-critical component in the Android kernel because it mediates every cross-process interaction. A vulnerability in the Binder driver means sandbox escape.

### Intents

Higher-level IPC built on top of Binder. Intents can carry data (`extras`, `URIs`) and trigger components in other apps. Poorly exported components are a major attack surface -- see [Intent Hijacking](../attacks/intent-hijacking.md) and [Content Provider Attacks](../attacks/content-provider-attacks.md).

### Content Providers

SQL-backed or file-backed data stores that other apps can query. Exported content providers with insufficient permission checks allow data theft. [Oversecured's research](https://blog.oversecured.com/Content-Providers-and-the-potential-weak-spots-they-can-have/) found that more than 80% of apps contain content provider vulnerabilities, including path traversal, SQL injection, and URI grant abuse.

Content provider path traversal allows an attacker to read arbitrary files from the target app's sandbox by manipulating the URI path:

```
content://com.vulnerable.app.provider/../../../shared_prefs/secrets.xml
```

[Oversecured documented](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/) how intent redirection vulnerabilities allow access to non-exported content providers by exploiting intermediate activities that pass attacker-controlled intents.

## Sandbox Escape History

### CVE-2019-2215: Binder Use-After-Free

The most significant Android sandbox escape in the wild. [Discovered by Project Zero](https://projectzero.google/2019/11/bad-binder-android-in-wild-exploit.html) in October 2019, this vulnerability was a use-after-free in the Binder kernel driver exploited by [NSO Group's Pegasus](../malware/families/pegasus.md) spyware.

| Detail | Value |
|--------|-------|
| CVE | CVE-2019-2215 |
| Component | Binder driver (`binder.c`) |
| Type | Use-after-free |
| Impact | Kernel privilege escalation from app sandbox |
| Exploited by | NSO Group (Pegasus) |
| Affected devices | Pixel 1/2, Samsung S7/S8/S9, Huawei P20, Xiaomi devices, LG, Oppo |
| Root cause | `binder_thread` struct freed via `BINDER_THREAD_EXIT` while epoll still holds a reference to its `wait_queue_head_t` |

The exploit chain: Chrome renderer exploit (for remote code execution) chained with CVE-2019-2215 (for kernel privilege escalation) to achieve full device compromise from a malicious webpage. The bug existed in the upstream Linux kernel and [remained unpatched in Android for nearly two years](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-2215.html) despite being fixed upstream.

### CVE-2024-49415: Samsung Zero-Click

[Discovered by Project Zero researcher Natalie Silvanovich](https://thehackernews.com/2025/01/google-project-zero-researcher-uncovers.html), this vulnerability (CVSS 8.1) in Samsung's Monkey's Audio codec allowed code execution without user interaction on Samsung devices running Android 12-14. When Google Messages was configured for RCS, the transcription service decoded incoming audio locally before user interaction, providing a zero-click attack surface.

### Modern In-the-Wild Android Exploit (2023)

[Project Zero analyzed a full exploit chain](https://projectzero.google/2023/09/analyzing-modern-in-wild-android-exploit.html) targeting Samsung devices, combining multiple vulnerabilities:

| Stage | CVE | Component | Purpose |
|-------|-----|-----------|---------|
| Initial access | Multiple | Chrome/Samsung Internet | Remote code execution in renderer |
| Sandbox escape | Multiple | GPU driver | Escape browser sandbox |
| Kernel | CVE-2023-0266 | ALSA driver | Kernel privilege escalation |
| Persistence | N/A | SELinux policy modification | Maintain access across reboot |

### CVE-2024-43093: Android Framework Escalation

[Actively exploited in the wild](https://thehackernews.com/2024/11/google-warns-of-actively-exploited-cve.html), this vulnerability in the Android Framework's System component allowed privilege escalation on Android 11-14. Google confirmed limited, targeted exploitation.

### Historical CVE Timeline

| CVE | Year | Component | Impact |
|-----|------|-----------|--------|
| CVE-2014-3153 | 2014 | futex (kernel) | Privilege escalation (TowelRoot) |
| CVE-2015-1805 | 2015 | pipe_read/pipe_write (kernel) | Root from app (used in-the-wild) |
| CVE-2016-5195 | 2016 | Copy-on-write (kernel) | Dirty COW, root from any process |
| CVE-2019-2215 | 2019 | Binder driver | Sandbox escape (Pegasus) |
| CVE-2021-0920 | 2021 | Unix socket garbage collection | Privilege escalation (in-the-wild) |
| CVE-2021-1048 | 2021 | epoll (kernel) | Use-after-free (in-the-wild) |
| CVE-2023-0266 | 2023 | ALSA sound driver | Samsung exploit chain |
| CVE-2024-43093 | 2024 | Android Framework | System privilege escalation |

## Shared UID Attack Surface

The deprecated `android:sharedUserId` manifest attribute allows apps signed with the same certificate to run under the same UID, sharing data directories and process space.

| Risk | Detail |
|------|--------|
| Certificate compromise | If a developer's signing key is compromised, any app signed with it can access all shared UID apps' data |
| Legacy OEM bundles | Pre-installed OEM apps sharing `android.uid.system` gain system-level access |
| Privilege inheritance | A vulnerable app sharing a UID with a privileged app inherits its capabilities |

[Maddie Stone's Black Hat 2019 research](https://i.blackhat.com/USA-19/Thursday/us-19-Stone-Securing-The-System-A-Deep-Dive-Into-Reversing-Android-Preinstalled-Apps.pdf) on pre-installed Android apps showed how shared UIDs among OEM apps created attack chains where a vulnerability in one low-privilege pre-installed app could escalate to system-level access through a shared UID partner.

`sharedUserId` was deprecated in API 29 (Android 10). Starting in Android 15, non-system platform-signed apps must be [explicitly allowlisted](https://source.android.com/docs/core/permissions/platform-signed-shared-uid-allowlist) to join shared UIDs.

## /proc Filesystem Information Leaks

The `/proc` filesystem exposes kernel and process information. Despite progressive restrictions across Android versions, side-channel attacks remain possible.

| Path | Information Leaked | Restricted Since |
|------|-------------------|-----------------|
| `/proc/<pid>/stat` | Stack pointer (ESP), CPU time | Partial in Android 7 |
| `/proc/<pid>/status` | UID, memory maps | Android 7 (other app PIDs) |
| `/proc/interrupts` | Global interrupt statistics | Android 8 |
| `/proc/stat` | Aggregate CPU usage | Android 8 |
| `/proc/meminfo` | System memory state | Still accessible |
| `/proc/net/tcp` | Open TCP connections | Android 10 (per-app network namespace) |

[ProcHarvester research](https://gruss.cc/files/procharvester.pdf) demonstrated that accessible `/proc` data allowed inferring app launches from a set of 100 apps with 96% accuracy on Android 7, and side-channel timing from `/proc/<pid>/stat` could recover soft keyboard input.

A zero-permission app can still determine system memory pressure, CPU usage patterns, and (on older versions) network connections. Combined with timing analysis, this enables activity fingerprinting without any permissions.

## Detection During Analysis

??? example "Sandbox Integrity Checks"

    - Verify SELinux is enforcing: `getenforce` should return `Enforcing`
    - Check app SELinux context: `ps -Z | grep <package>`
    - Verify file permissions on data directories: `ls -la /data/data/<package>/`
    - Check for shared UIDs in manifest: `android:sharedUserId`
    - Monitor Binder transactions: `adb shell dumpsys binder_logs`

??? example "Sandbox Escape Indicators"

    - App process running as UID 0 (root)
    - SELinux context changed from `untrusted_app` to another domain
    - App accessing files outside its `/data/data/` directory
    - Kernel exploit artifacts (modified `/proc/version`, unusual kernel modules)
    - Binder transactions to `su` daemon or Magisk

## Cross-References

- [Content Provider Attacks](../attacks/content-provider-attacks.md) -- sandbox boundary crossing via IPC
- [Intent Hijacking](../attacks/intent-hijacking.md) -- exploiting exported components to access sandboxed data
- [Dynamic Code Loading](../attacks/dynamic-code-loading.md) -- loading code that operates within or escapes the sandbox
- [Pegasus](../malware/families/pegasus.md) -- state-sponsored malware using sandbox escape exploits
- [Play Integrity](play-integrity.md) -- device integrity verification from within the sandbox
