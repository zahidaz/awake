# Dynamic Analysis

Running the app and observing its behavior at runtime. Bypasses packing and obfuscation since the code must decrypt itself to execute. Captures network traffic, API calls, file operations, and runtime behavior that static analysis cannot reveal.

## Setup

### Environment Options

| Environment | Pros | Cons |
|-------------|------|------|
| Physical device (rooted) | No emulator detection, real hardware | Risk to personal data, device may get locked by ransomware |
| Android emulator (stock) | Easy to snapshot/restore, free | Detected by most malware |
| Genymotion | Better hardware simulation | Still detectable, commercial |
| Custom AOSP build | Can disable detection checks at framework level | Complex setup |

For malware analysis, a rooted physical device with a clean image is ideal. Use a dedicated device with no personal data.

### Root Access

Root is needed for:

- Frida server execution
- Network traffic interception (iptables, cert injection)
- File system access to app private directories
- Process tracing (strace, ltrace)

Options: Magisk (recommended, supports MagiskHide/Zygisk for detection bypass), KernelSU, or engineering builds. For emulator-based analysis, [8kSec's emulator rooting guide](https://8ksec.io/rooting-an-android-emulator-for-mobile-security-testing/) provides a step-by-step walkthrough using rootAVD to enable root access on Android Virtual Devices for Frida server and dynamic analysis without a physical device.

### Network Interception

Configure proxy for HTTP/HTTPS traffic:

```bash
adb shell settings put global http_proxy <proxy_ip>:<port>
```

For HTTPS, install the proxy CA certificate as a system cert (requires root on Android 7+):

```bash
# Convert cert to Android format
openssl x509 -inform PEM -subject_hash_old -in burp-ca.pem | head -1
# Result: 9a5ba575
cp burp-ca.pem 9a5ba575.0
adb push 9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

On Android 14+, system cert injection requires mounting the cert store differently due to read-only system partition changes.

For apps with certificate pinning, see [Hooking](hooking.md) for Frida-based bypass.

## Runtime Observation

### Logcat

Android's system log captures app output, exceptions, and system events:

```bash
adb logcat --pid=$(adb shell pidof com.target.app)
```

Filter for useful information:

```bash
adb logcat | grep -E "(http|url|key|token|password|error|exception)" -i
```

Malware authors often leave debug logging in release builds.

### Process and File Monitoring

```bash
# Watch file system changes
adb shell inotifywait -m /data/data/com.target.app/

# Monitor network connections
adb shell netstat -anp | grep <pid>

# Trace system calls
adb shell strace -p <pid> -e trace=network,file
```

### Dumping Decrypted DEX

For packed apps, the real DEX is decrypted in memory at runtime. Capture it:

**Using Frida** (see [Hooking](hooking.md)):

Hook `DexFile` or `InMemoryDexClassLoader` to dump DEX bytes when they're loaded.

**Using /proc/maps**:

```bash
adb shell su -c "cat /proc/<pid>/maps" | grep dex
adb shell su -c "dd if=/proc/<pid>/mem bs=1 skip=<offset> count=<size> of=/sdcard/dumped.dex"
```

**Using [fridump](https://github.com/Nightbringer21/fridump)** or similar memory dumping tools.

Once dumped, the DEX can be analyzed with jadx like an unpacked app.

### Traffic Analysis

Beyond proxy interception:

- Wireshark/tcpdump for non-HTTP protocols
- mitmproxy for programmatic traffic manipulation
- If the app uses certificate pinning, bypass it first via Frida (see [Hooking](hooking.md))
- Check for non-standard ports, raw socket communication, DNS-based C2

## Anti-Analysis Detection

Malware commonly checks for analysis environments:

| Check | What It Detects |
|-------|----------------|
| `Build.FINGERPRINT` contains "generic" | Emulator |
| `/system/bin/su` exists | Root |
| Magisk package present | Root (Magisk) |
| Frida port 27042 open | Frida server |
| `/proc/self/maps` contains "frida" | Frida injection |
| `Settings.Global.ADB_ENABLED` | USB debugging |
| Low sensor count | Emulator |
| Battery always charging | Emulator |
| No SIM / IMEI all zeros | Emulator |

Bypassing these checks is covered in [Hooking](hooking.md) (return fake values) and [Patching](patching.md) (remove checks from code).

### Sandbox Evasion

Beyond simple environment fingerprinting, malware employs behavioral evasion that specifically targets automated sandbox analysis:

| Technique | How It Works | Examples |
|-----------|-------------|----------|
| Time-based delays | Payload activates only after N days post-install, or sleeps for extended periods before executing malicious code | [Anatsa](../malware/families/anatsa.md) delays payload delivery until user activity is detected |
| Interaction gating | Requires real user gestures (taps, scrolls, swipes) before triggering malicious behavior; sandbox bots rarely generate realistic touch events | Overlay injection only activates after detecting scroll events on a target banking app |
| Network environment checks | Validates presence of real cellular data (MCC/MNC codes), rejects Wi-Fi-only or VPN connections typical of sandboxes | Checks `TelephonyManager.getNetworkOperator()` for valid carrier codes |
| Locale and SIM validation | Verifies device locale, timezone, SIM operator, and country code match a target region before activating | [MoqHao](../malware/families/moqhao.md) targets specific country codes; deactivates outside target regions |
| Installed app enumeration | Checks for specific banking or financial apps before deploying overlays; sandboxes rarely have these installed | Calls `PackageManager.getInstalledPackages()` looking for target apps from its overlay list |
| Sensor validation | Reads accelerometer, gyroscope, or GPS data to confirm a real device with physical movement | Checks `SensorManager` for realistic sensor event streams that emulators cannot produce |

Countering sandbox evasion during analysis: use a physical device with a real SIM card in the target region, install target banking apps (empty accounts), interact naturally with the device, and set the system clock forward if time-based delays are suspected.

### API Monitoring

Key Android APIs to monitor during dynamic analysis, grouped by the capability they indicate:

| API | Capability | What to Watch For |
|-----|-----------|-------------------|
| `ContentResolver.query()` on contacts/SMS/call log URIs | Data theft | Bulk reads of `content://sms`, `content://contacts`, `content://call_log` |
| `MediaRecorder` / `MediaProjection` | Screen recording | `createVirtualDisplay()` calls, screen capture buffer access |
| `Camera` / `AudioRecord` | Surveillance | Camera preview callbacks, audio buffer reads without visible UI |
| `PackageManager.getInstalledPackages()` | Target app enumeration | Iterating installed packages to match against overlay target lists |
| `AccessibilityService` callbacks | Device control | `onAccessibilityEvent()` handling, `performAction()` calls for automated clicks/input |
| `Socket` / `HttpURLConnection` / `OkHttpClient` | C2 communication | Outbound connections, request/response bodies, custom headers |
| `TelephonyManager` methods | Device fingerprinting | IMEI, phone number, SIM operator, network operator reads |
| `KeyStore` / `Cipher` | Cryptographic operations | Key generation, encryption/decryption of C2 payloads or stolen data |
| `Runtime.exec()` / `ProcessBuilder` | Command execution | Shell commands for root checks, data exfiltration, or persistence |
| `DexClassLoader` / `InMemoryDexClassLoader` | Dynamic code loading | Loading decrypted DEX payloads at runtime; dump the bytes passed to these constructors |

Hook these APIs with Frida (see [Hooking](hooking.md)) to build a behavioral profile of the sample without relying on network traffic alone.

### Instruction-Level Tracing

For heavily obfuscated native code (e.g., [Mandrake](../malware/families/mandrake.md)'s OLLVM-protected libraries), function-level hooking may not be sufficient. [Frida's Stalker API](https://8ksec.io/advanced-frida-usage-part-10-instruction-tracing-using-frida-stalker/) enables instruction-level tracing, observing every instruction as it executes in real time. This is the most powerful dynamic analysis technique for understanding native control flow in obfuscated samples.

### AI-Assisted Decompilation

[NowSecure's research on AI-assisted decompilation](https://www.nowsecure.com/blog/2025/01/29/decompiling-apps-with-ai-language-models/) explores using language models to recover and optimize decompiled code, transforming jadx output into more readable and analyzable form. This is particularly useful for large-scale analysis where manual code review is impractical.

## Family-Specific Analysis Notes

Certain malware families require specific dynamic analysis approaches due to their anti-analysis techniques:

| Family | Challenge | Approach |
|--------|-----------|----------|
| [Mandrake](../malware/families/mandrake.md) | OLLVM-obfuscated native libs | Frida Stalker instruction tracing on libapp.so |
| [SoumniBot](../malware/families/soumnibot.md) | Malformed manifest crashes tools | Use aapt2 dump instead of apktool, or pull manifest from running process |
| [GodFather](../malware/families/godfather.md) v3 | $JADXBLOCK anti-decompilation + virtualization | Must use dynamic analysis exclusively; hook VirtualApp framework APIs |
| [Necro](../malware/families/necro.md) | Steganographic payload in PNG | Monitor network for image downloads, hook BitmapFactory to capture pixel extraction |
| [Klopatra](../malware/families/klopatra.md) | Virbox packer | Dump DEX from memory after Virbox unpacker runs; hook DexClassLoader |
| [Chameleon](../malware/families/chameleon.md) | Disables biometric auth | Monitor BiometricPrompt API calls, observe settings changes |
| [FluBot](../malware/families/flubot.md) | DGA-based C2 | Capture DNS requests to observe domain generation; hook network resolution |
| [Hook](../malware/families/hook.md) | VNC-like screen streaming | Capture MediaProjection API usage, observe screen buffer access |
| [Octo](../malware/families/octo.md) | DGA + remote access | Observe AccessibilityService events, capture screen streaming buffers |
| [NGate](../malware/families/ngate.md) | NFC relay | Monitor NFC adapter API calls, capture relayed card data in transit |
| [Cerberus](../malware/families/cerberus.md) lineage | AES-encrypted C2 traffic | Hook `Cipher.doFinal` to capture plaintext request/response bodies before encryption |
| [Anatsa](../malware/families/anatsa.md) | Multi-stage dropper with delayed payload delivery | Payload triggers only after user activity (scrolls, gestures); automate interaction or patch delay checks |
| [SharkBot](../malware/families/sharkbot.md) | DGA for C2 resolution | Extract the domain generation algorithm and predict domains; hook DNS resolution to capture generated names |
| [Vultur](../malware/families/vultur.md) | AlphaVNC-based screen streaming | Monitor VNC initialization and `MediaProjection` setup; capture VNC handshake traffic |
| [SpyNote](../malware/families/spynote.md) | Raw TCP socket protocol for C2 | Capture with `tcpdump` since proxy tools miss non-HTTP traffic; decode custom binary protocol |
| [Gigabud](../malware/families/gigabud.md) | Virbox-packed, core logic in native `libstrategy.so` | Hook native JNI calls from `libstrategy.so`; trace command dispatch after Virbox unpacking |
| [MoqHao](../malware/families/moqhao.md) | Auto-execution on install, no user interaction needed | Malware activates immediately via broadcast receivers; capture initial C2 beacon within seconds of install |

### C2 Protocol Identification

During traffic analysis, identify the C2 protocol to classify the family:

| Protocol | Families |
|----------|----------|
| HTTP/HTTPS REST | Most banking trojans ([Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md), [GodFather](../malware/families/godfather.md)) |
| WebSocket | [TsarBot](../malware/families/tsarbot.md), [PJobRAT](../malware/families/pjobrat.md) |
| MQTT | [Copybara](../malware/families/copybara.md) |
| Raw TCP | [Albiriox](../malware/families/albiriox.md) (unencrypted) |
| Firebase Cloud Messaging | [Vultur](../malware/families/vultur.md) v2, [KoSpy](../malware/families/kospy.md) |
| Firebase Firestore | [KoSpy](../malware/families/kospy.md) (config delivery) |
| Telegram Bot API | Various (dead drop resolver) |
| TOR | [Hydra](../malware/families/hydra.md) |

## Tools

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS proxy, traffic interception |
| [mitmproxy](https://mitmproxy.org/) | Scriptable HTTPS proxy |
| [Wireshark](https://www.wireshark.org/) | Packet capture and analysis |
| [Frida](https://frida.re/) | Runtime instrumentation (see [Hooking](hooking.md)) |
| [strace](https://strace.io/) | System call tracing |
| [Magisk](https://github.com/topjohnwu/Magisk) | Root management with detection bypass |
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Dump DEX files from memory |
| [medusa](https://github.com/Ch0pin/medusa) | Extensible Frida-powered framework for dynamic analysis |
| [house](https://github.com/nccgroup/house) | Runtime mobile application analysis toolkit |
