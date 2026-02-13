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

## Advanced Unpacking Techniques

### Tencent Legu Anti-Frida Bypass

Tencent Legu checks for Frida by scanning `/proc/self/maps` for `frida-agent` strings and probing port 27042. A combined bypass hooks these checks at the native level:

```javascript
var openPtr = Module.findExportByName("libc.so", "open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc") !== -1 &&
            this.path.indexOf("/maps") !== -1) {
            this.isMaps = true;
        }
    }
});

var readPtr = Module.findExportByName("libc.so", "read");
Interceptor.attach(readPtr, {
    onLeave: function(retval) {
        if (this.isMaps) {
            var buf = this.context.x1;
            var content = buf.readUtf8String();
            if (content && content.indexOf("frida") !== -1) {
                buf.writeUtf8String(content.replace(/frida/g, "aaaaa"));
            }
        }
    }
});

var connectPtr = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        if (port === 27042) {
            args[1] = ptr(0);
        }
    }
});
```

For Legu versions after 2023, the packer also scans for `frida-gadget` in loaded modules and checks named pipes in `/proc/self/fd/`. The [Frida naming convention](https://frida.re/docs/gadget/) for renamed gadgets can bypass the string-based check. Using `frida-server` with `--listen 0.0.0.0:1337` on a non-standard port avoids port scanning detection.

### NeteaseYiDun Memory Protection Bypass

NeteaseYiDun uses `mprotect` to remove read permissions from memory pages containing the decrypted DEX after loading. Hooking `mprotect` prevents this:

```javascript
var mprotect = Module.findExportByName("libc.so", "mprotect");
Interceptor.attach(mprotect, {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.prot = args[2].toInt32();
        if (this.prot === 0) {
            console.log("[mprotect] Blocking PROT_NONE at " +
                this.addr + " size=" + this.size);
            args[2] = ptr(1);
        }
    }
});
```

After bypassing, `frida-dexdump` can scan the readable memory for DEX headers.

### Qihoo 360 Function-Level Decryption

360 Jiagu's advanced mode encrypts individual methods rather than the entire DEX. Each method body is encrypted and only decrypted when called. To recover all methods, force class initialization:

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith("com.target.")) {
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        try {
                            method.setAccessible(true);
                        } catch(e) {}
                    });
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("Class enumeration complete, dumping DEX...");
        }
    });
});
```

After forcing all classes to load (which triggers method decryption), dump the DEX from memory. The decrypted method bodies are now in place.

## Automated Unpacking Pipeline

For batch processing multiple Chinese-packed samples, a repeatable pipeline:

```
1. APKiD identification -> route to packer-specific bypass script
2. Install on rooted device with Magisk + Shamiko (hides root)
3. Spawn with Frida using combined anti-analysis bypass
4. Wait for app initialization (3-5 seconds)
5. Run frida-dexdump -> collect all DEX files
6. Filter dumped DEX by size (> 50KB, skip framework DEX)
7. Decompile with jadx -> verify recovered code
8. Extract IOCs (strings, URLs, package names)
```

The [frida-dexdump](https://github.com/hluwa/frida-dexdump) tool handles steps 4-6 in a single command:

```bash
frida-dexdump -FU -o /output/dir/
```

For samples with aggressive anti-Frida, use [Hluwa's FART (Frida ART Runtime)](https://github.com/AnyThinker/FART) which dumps DEX at the ART runtime level, bypassing userspace detection entirely. FART modifies the ART interpreter to dump DEX bytecode during method execution, operating below the level where packers can detect instrumentation.

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
- [frida-dexdump](https://github.com/hluwa/frida-dexdump)
