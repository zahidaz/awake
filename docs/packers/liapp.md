# LIAPP

LIAPP is a commercial RASP and packer solution developed by **Lockin Company** (Seoul, South Korea). It combines DEX encryption, native library protection, and aggressive runtime self-protection into a hybrid product that functions as both a packer and a RASP framework. Recognized by Gartner for application shielding, LIAPP reports over 150 million device installations across 45,000+ applications. Among Korean-origin protectors, LIAPP is consistently described as one of the hardest to bypass on modding and reverse engineering forums.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Lockin Company |
| Origin | Seoul, South Korea |
| Type | Commercial Packer + RASP |
| Platforms | Android, iOS |
| Products | LIAPP (mobile apps), LIAPP for Game (Unity engine), LIAPP Enterprise |
| Scale | 150M+ device installations, 45K+ protected apps |
| Recognition | Gartner-recognized for application shielding |
| Website | [liapp.lockincomp.com](https://liapp.lockincomp.com) |

## Identification

### APKiD Detection

APKiD detection for LIAPP is not yet implemented. This is tracked as [APKiD issue #339](https://github.com/rednaga/APKiD/issues/339). Manual identification is required.

### File Artifacts

| Artifact | Description |
|----------|-------------|
| `com.lockincomp.*` | Package references in manifest or DEX (when not fully encrypted) |
| Native libraries | Names not well-documented publicly; XOR-encrypted strings within `.so` files make signature matching difficult |
| Encrypted assets | Encrypted DEX payloads stored in assets directory |
| XOR-encrypted strings | All meaningful strings in native libraries are XOR-encrypted, requiring decryption before static analysis yields useful results |

### Static Identification Challenges

LIAPP is harder to fingerprint statically than most commercial packers. The combination of encrypted strings in native libraries, non-distinctive library naming, and absence of APKiD signatures means identification often relies on:

- Behavioral observation during dynamic analysis (detection dialogs, specific crash patterns)
- Presence of `com.lockincomp` references in non-encrypted portions of the APK
- Server-side communication patterns to LIAPP licensing endpoints
- Comparison with known LIAPP-protected apps from the Korean market

## Protection Mechanisms

### DEX Encryption

Application DEX files are encrypted and loaded through a native decryption routine at runtime. The encryption covers the full DEX payload rather than selective class-level encryption, requiring the entire DEX to be decrypted into memory before class loading proceeds.

### Source Code Obfuscation

Beyond encryption, LIAPP applies obfuscation transforms to the DEX bytecode including name mangling, control flow alteration, and dead code insertion. This ensures that even after DEX recovery, the code resists straightforward decompilation.

### String Encryption

Strings are encrypted using XOR-based schemes implemented in the native layer. String decryption happens through JNI calls from Java code into the native library, which decrypts and returns the plaintext. The XOR keys are embedded in the native binary with their own layer of obfuscation, requiring IDA Pro or Ghidra analysis to extract.

### JNI Library Protection

Native `.so` files shipped with the application are encrypted within the APK. LIAPP decrypts them at load time before `dlopen`. This protects both the developer's own JNI code and LIAPP's runtime security libraries from static extraction.

### Anti-Debugging

- ptrace-based debugger detection
- JDWP connection monitoring
- TracerPid checks via `/proc/self/status`
- Timing-based detection (execution speed anomalies indicating single-stepping)

### Anti-Tampering

- APK signature verification against expected certificate
- DEX file integrity checks (checksum validation)
- Native library hash verification
- Detects modification of any protected component

### Anti-Hooking

- Detects Frida through multiple vectors (port scanning, `/proc/maps` inspection, named pipe checks)
- Xposed framework detection (class presence, stack trace analysis)
- Substrate/Cydia detection on older devices
- Inline hook detection on native functions

### Root Detection

LIAPP's root detection is notably aggressive:

- Standard `su` binary and root management app checks
- **Magisk root-masking detection** -- specifically targets MagiskHide and Shamiko, detecting root even when hidden
- SELinux status verification
- System partition integrity checks
- Zygisk module detection

This makes LIAPP one of the few protectors that reliably detects Magisk-hidden root, placing it alongside [Promon SHIELD](promon.md) and [Arxan](arxan.md) in detection sophistication.

### VM/Emulator Detection

- Build property analysis (hardware, manufacturer, model, fingerprint)
- Sensor availability and behavior checks
- Telephony state inspection
- File system artifacts specific to emulators
- Timing-based checks that detect virtualization overhead

### Repackaging Prevention

Certificate pinning against the original signing key combined with integrity verification of the APK structure. Repackaging with a different key triggers detection at startup.

### Memory Integrity Monitoring

Continuous runtime monitoring of memory regions containing protected code. Detects:

- Memory patching (writing to `.text` segments)
- Breakpoint insertion (INT3/BRK instruction detection)
- Memory dumping attempts via `/proc/self/mem` access monitoring

### Process Scanning

Scans the process list and `/proc` filesystem for known analysis tools, debuggers, and hooking frameworks. This includes detection of:

- frida-server process names (including renamed binaries)
- IDA remote debugger server
- GDB server
- Memory dumping utilities

### Server-Side Token Verification

LIAPP implements server-side authentication token verification as a defense-in-depth layer. Even after bypassing all client-side checks (root detection, anti-hooking, memory integrity), the app communicates with LIAPP's backend to validate an integrity token. If the server determines the client environment is compromised, the app functionality is restricted server-side.

This architecture means that a fully patched local bypass may still fail at the application level because the server rejects requests from tampered clients. Defeating this requires either:

- Replaying valid tokens captured from a clean device
- Reversing the token generation algorithm and forging valid tokens
- Intercepting and modifying the server response to always return "valid"

### Unity Engine Protection (LIAPP for Game)

LIAPP for Game is a dedicated product targeting Unity-based games:

- `libil2cpp.so` encryption and integrity verification
- IL2CPP metadata protection
- Memory value modification detection (anti-GameGuardian)
- Speed hack detection
- Game asset integrity checks

## Unpacking Methodology

LIAPP is described on modding forums as "one of the toughest anti-cheat systems" encountered in Android reverse engineering. The difficulty stems from the layered defense architecture:

```
Layer 1: Root/emulator detection (blocks execution on hostile environment)
Layer 2: Anti-hooking/anti-debugging (prevents dynamic analysis tools)
Layer 3: Memory integrity monitoring (detects runtime patching)
Layer 4: Process scanning (detects analysis tools)
Layer 5: DEX/SO encryption (prevents static analysis)
Layer 6: XOR string encryption in native (requires IDA/Ghidra RE)
Layer 7: Server-side token verification (blocks tampered clients remotely)
```

Bypassing layers 1-4 requires IDA Pro and C++ reverse engineering expertise to understand and patch the native security library. Layer 6 requires manual XOR key extraction from the native binary. Layer 7 introduces a server-side component that cannot be defeated through local patching alone.

### No Comprehensive Public Bypass

Unlike [AppSealing](appsealing.md) which has dedicated tools like AppPealing, no comprehensive public bypass tool exists for LIAPP. The XDA Forums contain threads discussing LIAPP and AppSealing unpacking, but no complete automated solution has been published. Each bypass attempt documented publicly addresses only a subset of LIAPP's protection layers.

This absence of public tooling means analysts must approach LIAPP-protected targets with manual native reverse engineering:

```
1. Extract the native security library from the APK
2. Load in IDA Pro or Ghidra
3. Identify XOR-encrypted string blobs and decrypt them
4. Map out the detection check functions from the decrypted strings
5. Patch or hook each detection function individually
6. Handle server-side token verification separately
```

### frida-dexdump Limitations

Standard frida-dexdump can recover decrypted DEX if the analyst first bypasses the anti-Frida and anti-root checks. However, reaching that point requires neutralizing multiple native-level detection mechanisms that specifically target Frida. ZygiskFrida injection (to avoid ptrace-based detection) combined with process name spoofing improves the chances of surviving long enough to dump.

## Comparison with Other Protectors

| Feature | LIAPP | [DexGuard](dexguard.md) | [DexProtector](dexprotector.md) | [Promon SHIELD](promon.md) | [AppSealing](appsealing.md) |
|---------|-------|----------|--------------|-------------|------------|
| DEX encryption | Yes (full) | Yes (class-level) | Yes | No | Yes (selective) |
| String encryption | XOR in native | AES/XOR polymorphic | White-box dynamic keys | Externalized to native | Weak |
| Anti-hooking | Aggressive | Comprehensive | Comprehensive | Comprehensive | Basic |
| Root detection | Magisk-aware | Comprehensive | Comprehensive | Magisk-aware | Moderate |
| Server-side verification | Yes | No | No | No | No |
| Memory monitoring | Yes | No | Partial | Yes | No |
| Unity game support | Yes (dedicated product) | No | Limited | No | Yes |
| Public bypass tools | None | Limited | Limited | Limited | Yes (AppPealing) |
| Unpacking difficulty | Hard | Medium-Hard | Medium-Hard | Medium (bypass) | Low-Medium |

LIAPP functions as a hybrid packer+RASP, comparable to [DexProtector](dexprotector.md)'s full protection suite in scope. In the Korean market, it serves as the equivalent of [Promon SHIELD](promon.md) for European banking. The server-side token verification layer is unique among the documented packers and adds a dimension that purely client-side protectors lack.

## Industry Usage

LIAPP is primarily deployed in:

- **Korean banking** -- KBPay (KB Financial Group), NH Bank (NongHyup), and other major Korean financial institutions
- **Telecommunications** -- U+ Customer Center (LG U+) and carrier-affiliated apps
- **Gaming** -- Korean game publishers using LIAPP for Game to protect Unity titles
- **Government and enterprise** -- Korean public sector and corporate applications requiring certified protection

The Korean financial regulatory environment drives adoption, as banks must demonstrate application-level security controls. LIAPP's Gartner recognition and domestic presence make it the default choice for Korean financial institutions, similar to how [Promon SHIELD](promon.md) dominates European banking.

## Analyst Workflow

```
1. Attempt APKiD -> no LIAPP signature (issue #339 pending)
2. Manual inspection: look for com.lockincomp references, XOR-encrypted native strings
3. If server-side verification present -> capture valid tokens from clean device first
4. Use ZygiskFrida for stealth injection (avoid ptrace detection)
5. Hook anti-root and anti-hooking checks in native library (requires prior IDA analysis)
6. Once checks bypassed -> frida-dexdump for DEX recovery
7. Decrypt XOR strings from native library using extracted keys
8. For Unity games -> extract and analyze decrypted libil2cpp.so
9. Handle server-side token replay/forgery if app functionality depends on it
```

Physical device with Magisk + Zygisk + ZygiskFrida is strongly recommended. Emulators are likely to be detected and blocked. Even with hidden root (Shamiko), LIAPP's Magisk-masking detection may trigger, requiring native-level patches to the detection routine itself.

## References

- [LIAPP Official](https://liapp.lockincomp.com)
- [Lockin Company](https://www.lockincomp.com)
- [APKiD -- Issue #339 (LIAPP Detection)](https://github.com/rednaga/APKiD/issues/339)
- [APKiD -- Packer Detection](https://github.com/rednaga/APKiD)
- [Gartner -- Application Shielding Market](https://www.gartner.com)
- [frida-dexdump -- Automated DEX Dumping](https://github.com/hluwa/frida-dexdump)
- [ZygiskFrida -- Stealth Frida Injection](https://github.com/lico-n/ZygiskFrida)
- [XDA Forums -- LIAPP and AppSealing Discussion](https://xdaforums.com)
- [IDA Pro -- Native Analysis](https://hex-rays.com/)
