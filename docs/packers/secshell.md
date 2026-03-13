# SecShell (Bangcle)

SecShell is [Bangcle/SecNeo's](bangcle.md) (梆梆安全) second-generation APK packer, significantly more sophisticated than the original Bangcle protection. The Bangcle heritage is confirmed by the anti-tamper marker string `__b_a_n_g_c_l_e__check1234567_` still embedded in the native library. [Fortinet documented](https://www.fortinet.com/blog/threat-research/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-i-debugging-in-the-scope-of-native-layer) SecShell in their analysis of the Rootnik malware family.

SecShell replaces an app's real DEX with a ~20KB stub. The real code is encrypted inside `assets/meta-data/manifest.mf` and decrypted into memory at runtime. The native unpacker (`libSecShell.so`) itself contains a second layer: its own code segment is aPLib-compressed, so even the decryption logic isn't directly visible to disassemblers.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | Bangcle / SecNeo (梆梆安全) |
| Origin | China |
| Type | Commercial Packer/Protector |
| Lineage | Second-generation [Bangcle](bangcle.md) packer |
| APKiD Signature | `bangcle_secshell` |

## Identification

### File Artifacts

| Artifact | Description |
|----------|-------------|
| `libSecShell.so` | Native unpacker (ARM), self-packed via aPLib |
| `libSecShell-x86.so` | x86 variant |
| `libemulator_check.so` | Emulator detection library |
| `assets/meta-data/manifest.mf` | Base64-encoded encrypted DEX payload |
| `assets/meta-data/rsa.pub` | RSA-1024 public key (integrity check) |
| `assets/meta-data/rsa.sig` | RSA-1024 signature over `manifest.mf` |
| `com.SecShell.SecShell.AW` | Application class in manifest |
| `classes.dex` (~20KB) | Stub loader, not real app code |

The stub DEX contains a small set of SecShell control classes:

| Class | Purpose |
|-------|---------|
| `AW` (extends `Application`) | Entry point, loads `libSecShell.so`, calls `H.attach()` |
| `H` | Native method declarations (`attach`, `b`, `bb`, `c`, `d`, etc.) + stores `PKGNAME`, `APPNAME`, `ACFNAME` |
| `a` | ClassLoader patching via reflection (version-aware, SDK 4-28+) |
| `b` | `ServiceConnection` for multi-process DEX sharing |
| `c` | Custom `PathClassLoader` routing SecShell classes to stub, app classes to unpacked DEX |
| `AP` | `AppComponentFactory` (SDK 28+) intercepts Activity/Service/Provider/Receiver instantiation |
| `CP` | `ContentProvider` triggering early DEX load via static initializer |

## Protection Mechanisms

### Self-Packed Native Library

`libSecShell.so` ships with its main code section compressed. The ELF's `DT_INIT` entry point triggers multi-stage self-decompression before any DEX work:

1. **aPLib decompression** -- LZ77 variant with bit-level control stream, variable-length gamma-coded back-references
2. **XOR decryption** -- 4-byte key from a config struct, applied in 4-byte chunks (key may be `0x00000000` for no XOR)
3. **ELF relocation** -- patches absolute addresses in the decompressed code
4. **Bangcle anti-tamper** -- checks for `__b_a_n_g_c_l_e__check1234567_` markers

The config struct is located via `DT_INIT`: `config_addr = LOAD4_vaddr + *(uint32*)(LOAD4_start)`.

| Config Offset | Purpose |
|---------------|---------|
| `+0x08` | Compressed data end offset |
| `+0x0c` | Base address adjustment |
| `+0x1c` | Decompressed code size (bytes) |
| `+0x20` | XOR key (4 bytes; 0 = no XOR) |
| `+0x28` | Input size for decompressor |

After decompression, the code is ~590KB of ARM Thumb with aggressive obfuscation applied to all 660+ functions.

### DEX Payload Encryption

The encrypted DEX is stored in `assets/meta-data/manifest.mf` as concatenated Base64 segments with `=`/`==` padding as delimiters. The first segments contain SHA-1 digests of protected entries; the final large segment is the encrypted DEX.

**RSA-1024** is used for integrity verification only (not key transport). `rsa.pub` contains the public key; `rsa.sig` contains a 128-byte signature over `manifest.mf`. The private key is held by the packer vendor, preventing payload tampering without their cooperation.

**Dual-mode cipher**: a runtime mode flag selects between two decryption algorithms:

| Mode | Algorithm | Details |
|------|-----------|---------|
| 0 | RC4 | Standard KSA with 256-byte S-box, standard PRGA |
| 1 | SM4-ECB | Standard big-endian block loading, 32 rounds, standard S-box/CK/FK constants |

Both modes use the same 16-byte key pointer and cap decryption at 128KB (`0x20000` bytes) per call.

**Key derivation** is protected by aggressive control-flow flattening. The key is likely derived from runtime data (signing certificate, package name, or other app metadata) via JNI callbacks. String references `string_key`, `file_hash`, `mthfilekey`, `nthfilekey` suggest key material is associated with specific files. All JNI class/method name strings are obfuscated as MD5 hashes (prefixed with `p`), preventing identification of which Android APIs are called.

A second independent SM4-only code path exists with its own key derivation chain using MD5 + S-box transform.

### Version-Aware DEX Injection

| SDK Range | Technique |
|-----------|-----------|
| < 14 | Directly patches `PathClassLoader` internals (`mPaths`, `mFiles`, `mZips`, `mDexs`) |
| 14-18 | Reflects into `DexPathList.makeDexElements()`, prepends DEX elements array |
| 19-27 | Same + `makePathElements()` fallback + `dexElementsSuppressedExceptions` handling |
| 28+ | Native JNI method for in-memory DEX load (DEX never touches disk) |

On SDK 28+, the decrypted DEX exists only in memory, defeating filesystem-based extraction entirely.

### AppComponentFactory Hijack (SDK 28+)

The `AP` class extends `AppComponentFactory` to intercept all Activity, Service, BroadcastReceiver, and ContentProvider instantiation, routing them through the unpacked classloader. This ensures all dynamically loaded classes are properly resolved even when the system framework creates components before the app's own code runs.

## Anti-Analysis Techniques

| Technique | Details |
|-----------|---------|
| Self-packed native code | `.so` decompresses its own code segment at runtime; static disassembly shows only the decompression stub |
| Stripped ELF sections | Section headers corrupted (code section marked NOBITS), only program headers usable |
| Mixed ARM/Thumb execution | Constant mode switching defeats linear disassemblers |
| Instruction overlap | One instruction starts mid-way through another |
| Opaque predicates | Impossible branch conditions create dead code paths |
| Control flow flattening | All 660+ functions use TBH/TBB switch-based state machines; Ghidra fails to recover jump tables for ~67% of them |
| MD5-hashed C++ symbols | Function names like `p7761422212597DBD84E86431350E0961`; the hash is NOT standard MD5 of the name string, likely HMAC or salted |
| MD5-hashed JNI strings | 250+ JNI class/method name strings stored as `p`-prefixed MD5 hashes, decoded at runtime via XOR string decoder |
| JNI dynamic registration | Native methods registered via `JNI_OnLoad`, not discoverable through `Java_com_*` symbol names |
| In-memory DEX (SDK 28+) | Decrypted code never written to disk |
| RSA-1024 integrity check | Prevents payload tampering without the packer vendor's private key |
| Emulator detection | `libemulator_check.so` shipped alongside |
| Root/Magisk detection | `root_kill()`, `check_root()`, `is_magisk_check_process()`, `is_miuiinstaller_process()` in native code |
| Inotify monitoring | File access monitoring to detect dump attempts |
| ART verification bypass | `--compiler-filter=verify-none` disables dex2oat verification; hooks `Runtime::IsVerificationEnabled()` |
| Indirect cipher dispatch | SM4 function called through GOT-resolved function pointer via trampoline |

The control-flow flattening is the primary obstacle. Every function is transformed into a TBH/TBB switch-based state machine. Ghidra's "Could not recover jumptable" error fires on the majority of functions, including the critical key derivation routines.

## Unpacking Methodology

### Frida Hook (Recommended)

Hook the decrypt function at runtime to extract the 16-byte key and decrypted DEX. The `.so` self-unpacks at runtime, so the function offset needs to be resolved dynamically.

```javascript
var base = Module.findBaseAddress("libSecShell.so");
var decryptFunc = base.add(DECRYPT_OFFSET);

Interceptor.attach(decryptFunc, {
    onEnter: function(args) {
        this.buf = args[0];
        this.len = args[1].toInt32();
    },
    onLeave: function(retval) {
        var f = new File("/data/local/tmp/decrypted_" + Date.now() + ".dex", "wb");
        f.write(this.buf.readByteArray(this.len));
        f.close();
    }
});
```

`DECRYPT_OFFSET` must be determined at runtime since the `.so` self-unpacks. Scan for the RC4 KSA initialization pattern (sequential byte array `0x00, 0x01, 0x02...`) in the loaded library to locate the decrypt function. The 128KB cap per call means the hook may fire multiple times for a full DEX.

Root/emulator/Magisk detection in the native code must be bypassed first. Use an API < 28 device or emulator to force the disk-writing code path if filesystem extraction is preferred.

### Runtime DEX Dump

On a rooted device with API < 28, SecShell writes the decrypted DEX to disk before loading it. Check `/data/data/<package>/files/`, `/data/data/<package>/cache/`, and `assetsCacheDir`-related subdirectories after the app boots.

On API 28+, the DEX is loaded in-memory only. Use [frida-dexdump](https://github.com/hluwa/frida-dexdump) to scan process memory for DEX magic bytes after SecShell completes initialization.

### Static .so Unpacking

The `.so` self-packing is fully defeatable offline:

1. Parse the ELF and locate `DT_INIT` from the dynamic section
2. Read the config struct at the offset referenced by `DT_INIT`
3. Extract compressed data from the `.so` at the config offset
4. Apply aPLib decompression
5. If the XOR key (config `+0x20`) is non-zero, XOR-decrypt in 4-byte chunks
6. Load the decompressed blob into Ghidra/IDA at the base address from config `+0x0c`, selecting ARM Thumb / ARMv7

This reveals the full native code, but the DEX decryption key derivation remains blocked by control-flow flattening. Static `.so` unpacking is useful for understanding the protection architecture, not for recovering the DEX.

### Emulation (Unicorn/QEMU)

For offline unpacking without a device. `DT_INIT` emulation works (aPLib decompression completes successfully). DEX decryption requires a full JNI environment mock (simulating `FindClass`, `GetMethodID`, `CallObjectMethod` to return appropriate values when the code calls Android APIs for certificate and package data), which is significant work.

## Crypto Summary

| Algorithm | Location | Purpose |
|-----------|----------|---------|
| RC4 | Dual-mode cipher (mode 0) | DEX payload decryption |
| SM4-ECB | Dual-mode cipher (mode 1) | DEX payload decryption (alternate mode) |
| SM4 (separate path) | Independent code path with MD5 + S-box key derivation | Unknown (not used by main decrypt orchestrator in analyzed samples) |
| RC4 drop-52 | Separate RC4 variant | `.so` self-unpacking (not DEX) |
| RSA-1024 | Integrity check | Signature verification of `manifest.mf` |
| MD5 | Three copies in native code | Manifest hash verification, JNI string hashing |
| SHA-1 | Native code | Manifest entry hash verification |

## Comparison with Bangcle

| Aspect | [Bangcle](bangcle.md) | SecShell |
|--------|---------|----------|
| Native library | `libsecexe.so`, `libsecmain.so` | `libSecShell.so` (self-packed) |
| DEX encryption | Simple encryption in assets | Dual RC4/SM4 with runtime mode selection |
| Native protection | None | aPLib self-packing + CFF on all functions |
| Key derivation | Simple | JNI-based with CFF protection |
| SDK support | Basic | SDK 4-28+ with version-specific injection |
| Anti-analysis | ptrace, basic root check | CFF, MD5-hashed symbols, instruction overlap, opaque predicates, inotify |
| AppComponentFactory | No | Yes (SDK 28+) |
| Unpacking difficulty | Easy | Hard |

## Notable Strings

| String | Significance |
|--------|-------------|
| `classes.dgg` | SecShell's internal name for encrypted DEX format |
| `aliyun Zip to %s error!` | Alibaba Cloud code heritage |
| `--compiler-filter=verify-none` | ART verification bypass |
| `ndk-r13-release` | Built with Android NDK r13 |
| `__b_a_n_g_c_l_e__check1234567_` | Bangcle lineage marker |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [frida-dexdump](https://github.com/hluwa/frida-dexdump)
