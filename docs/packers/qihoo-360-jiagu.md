# Qihoo 360 Jiagu

Free protection from Qihoo 360 (奇虎360), one of China's largest security companies. "Jiagu" (加固) means "hardening/reinforcement" in Chinese. Frequently seen in both legitimate Chinese apps and malware, including trojanized app clones.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | Qihoo 360 |
| **Free Tier** | Yes |
| **APKiD Signature** | `packer : Qihoo 360` |
| **Unpacking Difficulty** | Medium (standard), Hard (function-level encryption) |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so`, `libjgdtc.so` |
| DEX stub | Stub application class (`com.stub.StubApp`) loading encrypted payload |
| Asset files | `classes.dat`, `classes0.dex` in `assets/` |
| Package prefix | Loader classes in `com.qihoo.util` or `com.stub` |
| Extraction directory | `.jiagu/` in app data |
| Encrypted assets | Non-Latin filenames (Odia, Thai, CJK characters) in `assets/` |

## Protection

- Multi-layer DEX encryption with native decryption via `libjiagu.so`
- Native anti-debugging with signal handlers
- VM detection via `/proc/cpuinfo` and hardware serial
- Function-level encryption (selected methods encrypted individually, decrypted on first call)
- Anti-memory-dump techniques (mprotect manipulation)
- XOR string obfuscation in stub classes (single-byte key, typically `0x10`)
- Hidden API bypass on Android 9+: uses reflection to set `mHiddenApiWarningShown = true` on the current `ActivityThread`, disabling hidden API usage warnings for unrestricted reflection
- Encrypted assets with non-Latin filenames to confuse analysis tools and file listings

## Runtime Loading Process

1. `com.stub.StubApp` replaces the real `Application` class in the manifest
2. `StubApp.attachBaseContext()` extracts `libjiagu.so` from assets to a `.jiagu/` directory in app data
3. `System.load()` loads the native library, calling `interface5()` to decrypt and load the real DEX
4. Native method `interface7()` swaps the Application class in the Android framework, delegating to the real app's Application
5. The stub exposes 60+ obfuscated native methods (`n0000`, `n0001`, etc.) for DEX loading, string decryption, resource interception, and anti-tampering checks

## Unpacking

### Standard Approach

Hook `dvmLoadNativeCode` or `JNI_OnLoad` in the jiagu library. The decrypted DEX is written to a temporary file before loading; monitoring file creation in the app's data directory can capture it.

For apps using the full protection suite, hooking `DexClassLoader` alone may not suffice. The native library intercepts asset and resource loading, meaning `frida-dexdump` may miss dynamically-decrypted resources. A more reliable approach: hook the native `interface5()` or `interface7()` methods and dump the decrypted DEX buffer before it is loaded.

### Function-Level Decryption

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

## Malware Usage

| Family | Notes |
|--------|-------|
| Banking trojans | Common protection on budget banking malware |
| Trojanized app clones | Used by cloning tools (AppCloner + Jiagu) for trojanized legitimate apps |
| Chinese-origin malware | Default choice for Chinese threat actors |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [frida-dexdump](https://github.com/hluwa/frida-dexdump)
- [FART -- Frida ART Runtime](https://github.com/AnyThinker/FART)
