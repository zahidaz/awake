# Chinese Packers

Chinese packing services dominate Android malware protection. Since Google Play is unavailable in China, apps distribute through OEM stores (Tencent, Baidu, Xiaomi) that don't enforce the same restrictions. Chinese packers are free or cheap, widely available, and frequently abused by malware authors.

## Overview

| Packer | Vendor | Free Tier | APKiD Signature |
|--------|--------|-----------|-----------------|
| Tencent Legu | Tencent | Yes | `packer : Tencent Legu` |
| 360 Jiagu | Qihoo 360 | Yes | `packer : Qihoo 360` |
| Bangcle (SecNeo) | Bangcle | Yes | `packer : Bangcle` |
| Baidu Reinforcement | Baidu | Yes | `packer : Baidu` |
| iJiami | iJiami | Limited | `packer : iJiami` |
| NeteaseYiDun | NetEase | Limited | `packer : NetEase` |
| APKProtect | Nagain | Yes | `packer : APKProtect` |

## Tencent Legu

The most widely used Chinese packer. Free protection service integrated with Tencent's app distribution ecosystem.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libshell-super.2019.so`, `libshella-*.so`, or `libtxoprot.so` |
| DEX stub | Minimal `classes.dex` with shell loader class |
| Asset files | Encrypted DEX in `assets/` (e.g., `classes.dex.dat`) |
| Metadata | `tencent_stub` in APK metadata |

### Protection

- DEX encryption with AES
- Native library anti-debugging (ptrace self-attach)
- Emulator detection via hardware properties
- Anti-Frida checks (port scanning, /proc/maps inspection)
- String encryption in native layer
- Code segment checksumming

### Unpacking

1. Hook `DexClassLoader` or `InMemoryDexClassLoader` to intercept DEX loading
2. Dump DEX bytes from memory after native loader decrypts
3. Alternative: use `frida-dexdump` which scans process memory for DEX headers

## Qihoo 360 Jiagu

Free protection from Qihoo 360, one of China's largest security companies. Frequently seen in both legitimate Chinese apps and malware.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so` |
| DEX stub | Stub application class loading encrypted payload |
| Asset files | `classes.dat`, `classes0.dex` in `assets/` |
| Package prefix | Loader classes in `com.qihoo.util` or `com.stub` |

### Protection

- Multi-layer DEX encryption
- Native anti-debugging with signal handlers
- VM detection via `/proc/cpuinfo` and hardware serial
- Function-level encryption (selected methods encrypted individually)
- Anti-memory-dump techniques (mprotect manipulation)

### Unpacking

Hook `dvmLoadNativeCode` or `JNI_OnLoad` in the jiagu library. The decrypted DEX is written to a temporary file before loading; monitoring file creation in the app's data directory can capture it.

## Bangcle (SecNeo)

One of the earliest Chinese packers. Still encountered in older malware samples.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libsecexe.so`, `libsecmain.so`, `libSecShell.so` |
| DEX stub | Minimal loader calling native initialization |
| Asset files | `classes.jar` or encrypted DEX in `assets/` |

### Protection

- DEX encryption and dynamic loading
- Anti-debugging via ptrace
- Root detection
- Basic emulator detection

### Unpacking

Older Bangcle versions use straightforward DEX-in-assets encryption. The native library decrypts and writes a temporary DEX file. Hook file operations or dump from `/proc/<pid>/maps`.

## Common Unpacking Strategy

All Chinese packers follow a similar pattern:

1. Stub `Application` class loads native library
2. Native library decrypts the real DEX from assets
3. Decrypted DEX loaded via `DexClassLoader` or `InMemoryDexClassLoader`
4. Real `Application` class instantiated and lifecycle delegated

The universal approach:

```javascript
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libraryPath, parent) {
        console.log("[DexClassLoader] Loading: " + dexPath);
        this.$init(dexPath, optimizedDir, libraryPath, parent);
    };

    var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buf, parent) {
        console.log("[InMemoryDexClassLoader] Size: " + buf.remaining());
        this.$init(buf, parent);
    };
});
```

For automated dumping, `frida-dexdump` handles most Chinese packers without family-specific scripts.

## Malware Usage

Chinese packers are the most common protection found on malware samples:

| Packer | Notable Malware Usage |
|--------|----------------------|
| Tencent Legu | [Triada](../malware/families/triada.md) firmware variants, Chinese adware |
| Qihoo 360 Jiagu | Banking trojans, Chinese-origin malware |
| Bangcle | Older banking trojans, [BankBot](../malware/families/bankbot.md) variants |
| Baidu | Adware, Chinese-targeted malware |

These packers are freely available, making them the default choice for budget-conscious malware operators. The protection is adequate against automated AV scanning but yields to manual analysis with Frida-based unpacking.

## Baidu Reinforcement

Baidu's free app protection service. Less sophisticated than Tencent Legu or Qihoo 360 but still encountered in malware samples, particularly Chinese-targeted adware and data-harvesting families.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libbaiduprotect.so`, `libprotectClass.so` |
| DEX stub | Application class delegating to Baidu loader |
| Asset files | Encrypted payload in `assets/baiduprotect/` |

### Protection

- DEX encryption with custom algorithm
- Basic anti-debugging (ptrace)
- Emulator detection via Build properties
- No function-level encryption (entire DEX encrypted as blob)

### Unpacking

Straightforward DEX dump. The native library decrypts the entire DEX payload in one pass and loads via standard class loader. Hook `DexClassLoader` or dump from memory after load.

## iJiami

Commercial packing service offering both free and paid tiers. The free tier provides basic encryption; paid tiers add anti-tampering, root detection, and code virtualization.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libexecmain.so`, `libexec.so` |
| DEX stub | Shell class invoking native decryption |
| Asset files | `ijiami.dat` or encrypted DEX in `assets/ijiami/` |
| Metadata | `ijiami` references in APK resources |

### Protection

- Multi-layer DEX encryption
- Anti-debugging with signal handling
- Root detection (su, Magisk, system partition checks)
- Paid tier: method-level encryption, code virtualization

### Unpacking

Free tier: standard DEX dump via `frida-dexdump` or class loader hook. Paid tier with method-level encryption requires hooking individual method decryption calls, similar to [DexGuard](dexguard.md) string decryption approach.

## NeteaseYiDun

NetEase's application security service, integrated with their gaming ecosystem. Most commonly seen in Chinese mobile games but occasionally in malware targeting Chinese users.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libnesec.so`, `libNetHTProtect.so` |
| Package | `com.netease.nis.wrapper` package in DEX stub |
| Asset files | Encrypted payload in `assets/nis/` |

### Protection

- DEX encryption with multi-key scheme
- Anti-debugging and anti-hooking
- Integrity verification of native libraries
- Memory protection (mprotect on decrypted regions)

### Unpacking

Hook before mprotect calls revoke read access. The decrypted DEX resides in memory briefly before protection flags are set. Timing the dump is critical. `frida-dexdump` works if executed during the loading window.

## APKProtect

Nagain's free protection service. Less common than the major packers but still appears in budget malware operations.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libAPKProtect.so` |
| Asset files | Encrypted DEX in `assets/apk_protect/` |

### Protection

- DEX encryption
- Basic anti-debugging
- Minimal obfuscation compared to competitors

### Unpacking

Simple DEX dump. `frida-dexdump` handles APKProtect without special configuration.

## Detection and Triage

### Rapid Packer Identification

```bash
apkid sample.apk
```

If APKiD is unavailable, check for known native library markers:

| Library Name | Packer |
|-------------|--------|
| `libshella*.so`, `libshell-super*.so` | Tencent Legu |
| `libjiagu*.so` | Qihoo 360 |
| `libsecexe.so`, `libSecShell.so` | Bangcle |
| `libbaiduprotect.so` | Baidu |
| `libexecmain.so` | iJiami |
| `libnesec.so` | NeteaseYiDun |
| `libAPKProtect.so` | APKProtect |
| `libvdog.so` | [Virbox](virbox.md) |
| `libdexguard.so` | [DexGuard](dexguard.md) |

### Packer Complexity Ranking

From easiest to hardest to unpack:

| Tier | Packers | Approach |
|------|---------|----------|
| Easy | APKProtect, Baidu, Bangcle (old) | `frida-dexdump` works immediately |
| Medium | Tencent Legu, Qihoo 360, iJiami (free) | `frida-dexdump` + class loader hooks |
| Hard | NeteaseYiDun, iJiami (paid), [DexGuard](dexguard.md) | Timed dumps, string decryption hooks needed |
| Expert | [Virbox](virbox.md) (virtualized), DexGuard (virtualized) | VM analysis required, [see Virbox page](virbox.md) |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [frida-dexdump](https://github.com/nicksdevice/frida-dexdump)
