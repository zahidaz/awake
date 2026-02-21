# Android Packers & Obfuscators

Packers (protectors, armoring tools) transform APKs to resist reverse engineering, tampering, and automated analysis. Legitimate developers use them to protect IP. Malware authors use them to evade detection and slow down analysts.

Obfuscators are a lighter category: they transform code to make it harder to read but don't encrypt or pack DEX files. Many protection products combine both.

[APKiD](https://github.com/rednaga/APKiD) can identify most commercial packers and obfuscators automatically.

## Packers / Protectors

| Packer | Vendor | Origin | Status |
|--------|--------|--------|--------|
| [360 Jiagu](qihoo-360-jiagu.md) | Qihoo 360 | China | Documented |
| [APKProtect](apkprotect.md) | Nagain | China | Documented |
| [Arxan (Digital.ai)](arxan.md) | Digital.ai | USA | Documented |
| [Baidu Reinforcement](tencent-legu.md) | Baidu | China | Documented |
| [Bangcle (SecNeo)](bangcle.md) | Bangcle | China | Documented |
| [DexGuard](dexguard.md) | Guardsquare | Belgium | Documented |
| [DexProtector](dexprotector.md) | Licel | Netherlands | Documented |
| [iJiami](tencent-legu.md) | iJiami | China | Documented |
| [NeteaseYiDun](tencent-legu.md) | NetEase | China | Documented |
| [Promon SHIELD](promon.md) | Promon | Norway | Documented |
| [Tencent Legu](tencent-legu.md) | Tencent | China | Documented |
| [Virbox](virbox.md) | SenseShield Technology | China | Documented |
| [AppSealing](appsealing.md) | INKA Entworks | South Korea | Documented |
| [LIAPP](liapp.md) | Lockin Company | South Korea | Documented |
| [Appdome](appdome.md) | Appdome Inc | USA/Israel | Documented |
| [Zimperium zShield](zshield.md) | Zimperium | USA | Documented |
| [Verimatrix XTD](verimatrix.md) | Verimatrix (now Guardsquare) | France | Documented |

## Obfuscators

| Obfuscator | Type | Notes |
|-----------|------|-------|
| [R8 / ProGuard](r8-proguard.md) | Free (Google/open source) | Default Android build tools. Name obfuscation, dead code removal, optimization. R8 replaced ProGuard. |
| Allatori | Commercial | Java/Android obfuscator. String encryption, flow obfuscation, watermarking. |
| DashO | Commercial | PreEmptive Solutions. Obfuscation + tamper detection + analytics. |
| Zelix KlassMaster | Commercial | Aggressive flow obfuscation, string encryption, stack trace obfuscation. |
| OLLVM | Open source | Obfuscator-LLVM. Control flow flattening, bogus control flow, string encryption for native code. Used by [Mandrake](../malware/families/mandrake.md). |

## Protection Capabilities Comparison

| Feature | Packers | Obfuscators | RASP |
|---------|---------|-------------|------|
| Name obfuscation | Yes | Yes | No |
| String encryption | Yes | Some | No |
| DEX encryption | Yes | No | No |
| Native code wrapping | Yes | No | No |
| Anti-debugging | Yes | No | Yes |
| Anti-tampering | Yes | No | Yes |
| Root detection | Some | No | Yes |
| Emulator detection | Some | No | Yes |
| Runtime self-protection | Some | No | Yes |

**RASP** (Runtime Application Self-Protection) products like Promon SHIELD focus on runtime checks rather than code transformation. They detect hostile environments (root, hooking, debugging) and respond at runtime, often combined with a packer or obfuscator.

## Malware Families by Packer

Commercial packers are increasingly adopted by malware authors. The packer provides anti-analysis protection without the developer needing to build their own.

| Packer | Families | Notes |
|--------|----------|-------|
| [Virbox](virbox.md) | [Gigabud](../malware/families/gigabud.md), [Klopatra](../malware/families/klopatra.md), GoldDigger/GoldPickaxe | GoldFactory group standardized on Virbox. `libvdog.so` marker. |
| [DexGuard](dexguard.md) | [Anatsa](../malware/families/anatsa.md), [Xenomorph](../malware/families/xenomorph.md) | Higher-tier MaaS families use DexGuard's commercial protection. |
| [Tencent Legu](tencent-legu.md) | [Triada](../malware/families/triada.md), various Chinese malware | Common in Chinese market. `libshella.so` / `libshellx.so` marker. |
| [360 Jiagu](qihoo-360-jiagu.md) | Chinese banking trojans, stalkerware | `libjiagu.so` marker. Multi-DEX support. |
| [Bangcle](bangcle.md) | Regional malware, adware | `libsecexe.so` / `libSecShell.so` marker. |
| Custom packers | [Mandrake](../malware/families/mandrake.md), [SoumniBot](../malware/families/soumnibot.md) | OLLVM-obfuscated native loaders ([Mandrake](../malware/families/mandrake.md)), manifest parsing exploits ([SoumniBot](../malware/families/soumnibot.md)) |
| [AppSealing](appsealing.md) | Korean banking apps, Unity games | `libcovault-appsec.so` marker. Bypass: AppPealing Xposed module. |
| [LIAPP](liapp.md) | Korean banking apps (KBPay, NH Bank) | Hardest Korean protector. Server-side token verification. No public bypass tool. |
| No packer (obfuscation only) | [Cerberus](../malware/families/cerberus.md) lineage, [SpyNote](../malware/families/spynote.md) | Rely on string encryption, class renaming, and custom obfuscation instead of commercial packers |

## Universal Unpacking Toolkit

Tools for approaching any packed sample regardless of the specific packer.

### DEX Recovery

| Tool | Purpose | Packer Coverage |
|------|---------|-----------------|
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Scans process memory for DEX magic bytes and dumps all loaded DEX files | All packers that decrypt DEX into memory (Chinese packers, DexGuard, DexProtector, AppSealing, LIAPP, Appdome, zShield) |
| [FART](https://github.com/hanbinglengyue/FART) | ART-level DEX dumper. Patches `dex2oat` to dump DEX at compilation time | Effective against packers that use `InMemoryDexClassLoader` |
| [DexDump (smartdone)](https://github.com/smartdone/dexdump) | Xposed module for dumping DEX at class loading | Older Chinese packers, some DexGuard builds |
| [reFrida](https://github.com/zahidaz/refrida) | Pre-built Frida scripts including DEX interception and string decryption | Broad coverage with configurable hooks |
| [AppPealing](https://codeberg.org/pufferffish/apppealing) | Xposed module that disables AppSealing checks and dumps decrypted DEX | AppSealing only |

### RASP Bypass

| Tool | Purpose | Notes |
|------|---------|-------|
| [Objection](https://github.com/sensepost/objection) | Runtime mobile exploration. Built-in root, SSL, and debug bypasses | Good starting point, handles common detection patterns |
| [Shamiko](https://github.com/LSPosed/LSPosed.github.io) | Zygisk module that hides Magisk root from detection | Preferred for Promon SHIELD, Arxan, and LIAPP |
| [ZygiskFrida](https://github.com/lico-n/ZygiskFrida) | Injects Frida gadget via Zygisk at process spawn | Avoids ptrace-based detection. Critical for Arxan, DexProtector, and LIAPP |
| [MagiskHide Props Config](https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf) | Modifies device fingerprint properties to defeat emulator detection | Useful when running on physical rooted device |

### Native Analysis

| Tool | Purpose | When to Use |
|------|---------|-------------|
| [Ghidra](https://ghidra-sre.org/) + [D-810](https://github.com/joydo/d810) | Native decompiler with OLLVM deobfuscation plugin | Arxan guard network, Mandrake native loaders, Promon SHIELD library, zShield post-XXTEA |
| [IDA Pro](https://hex-rays.com/) + Keypatch | Native disassembler with inline patching | Virbox VM interpreter, DexProtector native bridge, LIAPP native library |
| [Frida Stalker](https://frida.re/docs/stalker/) | Instruction-level tracing at runtime | Tracing Virbox VM dispatch loop, mapping guard execution in Arxan |
| XXTEA ELF Unpacker (DavidBuchanan314) | Decrypts XXTEA-encrypted ELF bodies from zShield native libraries | zShield only. Removes outermost protection layer, OLLVM flattening remains |

### Recommended Lab Setup

```
Physical device (Pixel 5+, rooted with Magisk + Zygisk)
  ├─ Shamiko (hide root from target app)
  ├─ ZygiskFrida (stealth Frida injection)
  ├─ Objection (runtime exploration)
  └─ mitmproxy (network interception)

Alternative: Android emulator (API 30-33)
  ├─ frida-server on non-default port (rename binary)
  ├─ Burp Suite / mitmproxy with custom CA
  └─ Note: many commercial packers detect emulators
```

Physical devices are strongly preferred for DexProtector, Promon SHIELD, Arxan, LIAPP, and Appdome analysis. These products aggressively detect emulators and virtual environments. Chinese packers, AppSealing, and DexGuard are generally workable in emulators with basic evasion.

## Unpacking Strategy

```
1. Identify packer (APKiD, manual inspection of native libs)
2. Choose approach:
   - Memory dump: hook DexClassLoader/InMemoryDexClassLoader to capture DEX at load time
   - Process dump: dump /proc/self/maps regions containing DEX magic bytes
   - Framework hook: intercept ClassLoader to extract loaded classes
3. Reconstruct DEX from dump
4. Decompile unpacked DEX normally (JADX, Ghidra)
```

For packer-specific unpacking procedures, see the individual packer pages. [Frida DEX dumping scripts](../reversing/hooking.md#dex-loading-interception) cover the universal hooking approach.

## Custom Packers

Some malware authors build their own packing solutions rather than using commercial products. These require per-sample analysis but follow predictable patterns.

| Technique | Examples | Analysis Approach |
|-----------|----------|-------------------|
| XOR-encrypted DEX in assets | Budget banking trojans, SMS stealers | Extract asset, brute-force single-byte XOR key (typically visible in native loader) |
| AES-encrypted second stage | Multi-stage droppers | Hook `javax.crypto.Cipher` to intercept key and IV, or extract from native loader |
| Steganographic DEX in images | [Necro](../malware/families/necro.md) | Reverse the pixel-to-byte extraction algorithm from the loader class |
| Manifest manipulation | [SoumniBot](../malware/families/soumnibot.md) | Install on device and dump via `adb shell dumpsys package`, bypassing parser bugs |
| OLLVM-obfuscated native loader | [Mandrake](../malware/families/mandrake.md) | D-810 for OLLVM deobfuscation, Frida Stalker for runtime tracing |
| Encrypted shared preferences payload | Dropper-style malware | Hook `SharedPreferences.getString()` to capture decrypted payload before loading |
| Split APK abuse | Play Store droppers | Reassemble all splits into a single APK using `bundletool`, then analyze normally |

Custom packers are generally easier to break than commercial ones because they lack the engineering investment in anti-tampering and anti-hooking. The main challenge is identifying the specific decryption mechanism, which is usually straightforward once the native loader or Java-based decryptor is located.

## Packer Comparison Matrix

Head-to-head comparison across all documented packers on the features that matter for analysis.

| Feature | [Virbox](virbox.md) | [DexGuard](dexguard.md) | [DexProtector](dexprotector.md) | [Arxan](arxan.md) | [Promon](promon.md) | [Chinese](tencent-legu.md) | [AppSealing](appsealing.md) | [LIAPP](liapp.md) | [Appdome](appdome.md) | [zShield](zshield.md) | [Verimatrix](verimatrix.md) |
|---------|--------|----------|--------------|-------|--------|--------|-----------|------|---------|---------|-----------|
| DEX encryption | Yes | Yes (class-level) | Yes | Partial | No | Yes (whole DEX) | Yes (selective) | Yes (full) | Yes | Yes (.szip) | Yes |
| DEX virtualization | Yes (core) | Optional | No | No | No | No | No | No | No | No | No |
| String encryption | VM-based | Method calls | White-box keys | Yes | No | Basic XOR | Weak | XOR (native) | Native | 32-bit key | Inlined per-site |
| Native protection | Yes | Yes | Yes | Guard network | No (RASP) | No | SO encryption | SO encryption | SO encryption | XXTEA + OLLVM | C/C++ obfuscation |
| Anti-Frida | Yes | Yes | Yes | Yes | Yes | Basic | Basic (port) | Aggressive | Multi-vector | Syscall-based | Yes |
| Anti-root | Yes | Yes | Yes | Yes | Yes | Basic | Moderate | Magisk-aware | Comprehensive | Yes | Yes |
| Anti-emulator | Yes | Yes | Yes | Yes | Yes | Basic | Yes | Aggressive | Yes | Yes | Yes |
| White-box crypto | No | No | vTEE CryptoModule | Yes | No | No | No | No | No | zKeyBox (separate) | EMVCo certified |
| RASP | Partial | Partial | Core feature | Yes | Primary | No | Basic | Core feature | OneShield | Integrity checks | Full suite |
| Code virtualization | DEX + native | Optional | Hide Access | Guard-level | No | No | No | No | No | No | No |
| Server-side verification | No | No | No | No | No | No | No | Yes | No | No | OTA updates |
| Unpacking difficulty | Expert | Medium-Hard | Medium-Hard | Hard | Medium | Easy-Medium | Low-Medium | Hard | Medium-Hard | Medium-Hard | Medium |
| Public bypass tools | None | Limited | Limited | None | Limited | Generic DEX dump | AppPealing | None | None | XXTEA unpacker | None |

## Analysis Decision Tree

When encountering a protected sample, use this sequence to minimize wasted effort:

```
Start
  |
  ├─ Run APKiD
  │   ├─ packer : appsealing → AppSealing (use AppPealing or Frida kill/signal/alarm hooks)
  │   ├─ packer : Zimperium (zShield) → zShield (XXTEA unpacker + OLLVM deflattening)
  │   ├─ protector : InsideSecure → Verimatrix XTD (verify: check for libencryption_*.so)
  │   ├─ protector : Appdome → Appdome (layered bypass: anti-debug → anti-root → anti-Frida → SSL)
  │   ├─ Other packer identified → Go to packer-specific page
  │   ├─ Obfuscator only → Proceed with jadx, use deobfuscation scripts
  │   └─ Unknown protection → Manual inspection below
  |
  ├─ Check native libraries
  │   ├─ libvirbox_*.so → Virbox (virtualized, needs dynamic analysis)
  │   ├─ libshell*.so → Tencent Legu
  │   ├─ libjiagu*.so → Qihoo 360
  │   ├─ libdexguard.so → DexGuard
  │   ├─ libdexprotector.*.so / libdpboot.so → DexProtector
  │   ├─ libsecexe.so → Bangcle
  │   ├─ libcovault-appsec.so → AppSealing
  │   ├─ libloader.so + Appdome DEX → Appdome
  │   ├─ libencryption_*.so → Verimatrix XTD
  │   ├─ lib<random12chars>.so (~3MB, packed ELF) → zShield
  │   ├─ com.lockincomp.* references → LIAPP (no APKiD signature yet)
  │   └─ Unknown .so → Check strings, imports for packer signatures
  |
  ├─ Check obfuscation level
  │   ├─ a/b/c class names, no string encryption → R8/ProGuard only
  │   ├─ Single-char classes + byte[]->String methods → DexGuard string encryption
  │   ├─ All strings readable, class names intact → No obfuscation
  │   └─ Native JNI stubs replacing Java methods → Virtualization (Virbox or DexGuard advanced)
  |
  ├─ Check assets
  │   ├─ assets/AppSealing/ directory → AppSealing
  │   ├─ *.szip files (~8MB) + truncated .odex → zShield
  │   └─ Encrypted blobs → Generic packer or custom encryption
  |
  └─ Choose approach
      ├─ Obfuscation only → Static analysis with jadx deobfuscation
      ├─ DEX encryption → frida-dexdump or DexClassLoader hook
      ├─ Virtualization → Dynamic analysis only (hook VM interpreter)
      ├─ RASP only → Frida with detection bypass hooks
      ├─ Server-side verification (LIAPP) → Token replay from clean device
      └─ White-box crypto (Verimatrix, zKeyBox) → Code lifting, not key extraction
```

## Packer Trends in Malware (2024-2025)

| Trend | Details |
|-------|---------|
| Commercial packer adoption | Malware authors increasingly use commercial packers (Virbox, DexGuard) rather than custom solutions. Reduces development cost at the expense of identifiable signatures. |
| Multi-layer protection | Modern samples combine a commercial packer with custom obfuscation layers. [Klopatra](../malware/families/klopatra.md) uses Virbox + custom string encryption. |
| Packer-as-a-Service | Underground forums offer packing services where customers submit APKs and receive protected versions. No need to license the packer directly. |
| Custom packers declining | Only sophisticated groups like [Mandrake](../malware/families/mandrake.md) developers invest in custom OLLVM-based protection. Most operators use off-the-shelf solutions. |
| RASP integration | Banking trojans increasingly encounter RASP-protected target apps ([Promon](promon.md), [Arxan](arxan.md), [LIAPP](liapp.md), [Appdome](appdome.md)), requiring malware to bypass runtime checks to perform overlay injection or accessibility manipulation. |
| Guardsquare consolidation | Guardsquare's acquisition of Verimatrix XTD (Feb 2026) means one vendor now controls [DexGuard](dexguard.md), [R8/ProGuard](r8-proguard.md), and [Verimatrix XTD](verimatrix.md). Expect product consolidation and white-box crypto integration into DexGuard. |
| Korean market protectors | [LIAPP](liapp.md) and [AppSealing](appsealing.md) dominate the Korean banking and gaming markets. LIAPP's server-side token verification introduces a new dimension that purely client-side protectors lack. |
| No-code SaaS protection | [Appdome](appdome.md) and [AppSealing](appsealing.md) offer cloud-based protection without build pipeline changes. Appeals to organizations without mobile security engineering teams. |
| Manifest-level evasion | [SoumniBot](../malware/families/soumnibot.md) demonstrated that packing the code is not the only option. Malforming the APK structure itself can defeat analysis tools without any packer. |

## Detection Evasion Effectiveness

How much each protection layer reduces detection rates across multi-engine scanning:

| Protection | Approximate Detection Rate Reduction | Why |
|-----------|--------------------------------------|-----|
| No protection | Baseline | All engines can scan the raw DEX |
| R8/ProGuard only | 5-10% | Engines pattern-match on behavior, not names |
| Chinese packer (basic) | 30-50% | Engines scan the stub, not the encrypted payload |
| AppSealing | 30-50% | Similar to Chinese packers; DEX encrypted but weak string protection |
| DexGuard | 50-70% | String encryption hides IoCs; class encryption hides behavior patterns |
| LIAPP | 50-70% | Full DEX encryption + native string encryption + server-side layer |
| Appdome | 50-70% | DEX encryption + native library encryption + multi-vector RASP |
| zShield | 60-80% | XXTEA ELF encryption + .szip DEX + randomized library names |
| Verimatrix XTD | 50-70% | Code encryption + multi-language obfuscation + inlined string decryption |
| Virbox (virtualized) | 70-90% | Proprietary VM instructions are opaque to all static scanners |
| Custom packer + obfuscation | 60-80% | Varies by implementation quality |
| RASP only (no packing) | 0-10% | Code is still scannable; RASP operates at runtime |

These figures are approximate and based on observed VirusTotal detection ratios for packed vs unpacked samples of the same families. The main takeaway: DEX virtualization ([Virbox](virbox.md)) provides the highest static analysis resistance, while basic Chinese packers offer adequate protection against automated scanning but fall quickly to manual Frida-based analysis.
