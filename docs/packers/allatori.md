# Allatori

Allatori is a commercial Java obfuscator developed by Smardec, available since 2006 and currently at version 9.5. While not Android-specific, it is used to obfuscate Android applications at the Java/Kotlin source or bytecode level before compilation to DEX. Allatori provides string encryption, control flow obfuscation, watermarking, and decompiler-resistant bytecode transforms that go beyond what [R8/ProGuard](r8-proguard.md) offers, without the full native packing and runtime protection of tools like [DexGuard](dexguard.md) or [Virbox](virbox.md).

## Overview

| Attribute | Details |
|-----------|---------|
| Vendor | Smardec |
| Type | Commercial Java/Android obfuscator |
| First Release | 2006 |
| Current Version | 9.5 |
| License | Commercial (per-developer, perpetual) |
| Platform | Java bytecode (JVM and Android) |
| Website | [allatori.com](https://allatori.com/) |

## Protection Mechanisms

### String Encryption

Allatori replaces string literals with encrypted byte arrays or encoded values, decrypted at runtime through generated static methods. Unlike R8/ProGuard, which leaves all strings as plaintext, Allatori's string encryption hides C2 URLs, API keys, and configuration data from static analysis.

Encrypted strings typically appear as calls to a generated decryption method:

```java
String url = ALLATORIxDEMO("3F 2A 1B 4C ...");
```

The decryption method name often contains `ALLATORI` in demo/trial builds. Licensed builds use obfuscated method names.

### Control Flow Obfuscation

Allatori restructures method control flow by:

- Inserting opaque predicates (conditions that always evaluate the same way but are difficult to determine statically)
- Replacing sequential code with switch-based dispatch loops
- Adding dead code branches that are never executed but complicate decompilation
- Flattening nested control structures into a single loop with state variables

The result is methods that jadx and other decompilers struggle to reconstruct cleanly, producing `goto` statements, unreachable code warnings, and mangled variable names.

### Name Obfuscation

Similar to R8/ProGuard but with additional techniques:

- Uses Unicode characters and non-printable identifiers that are valid in bytecode but difficult to display in decompilers
- Can produce identifiers that differ only in character case or Unicode normalization, causing collisions in case-insensitive file systems
- Overloads method names aggressively (multiple methods with the same name but different parameter types)

### Watermarking

Allatori can embed invisible watermarks in obfuscated bytecode. Watermarks encode a customer-specific identifier into the class files without affecting functionality. This allows Smardec and licensees to trace leaked or pirated builds back to a specific customer. The watermark is embedded in bytecode instruction sequences that are functionally equivalent but structurally unique.

### Decompiler-Resistant Transforms

Allatori applies bytecode-level transforms that exploit weaknesses in specific decompilers:

| Transform | Effect |
|-----------|--------|
| Illegal bytecode sequences | Valid for JVM/ART execution but cause decompiler crashes |
| Overlapping exception handlers | Create ambiguous try-catch structures that decompilers cannot resolve |
| JSR/RET instruction abuse | Uses deprecated subroutine instructions in unexpected ways |
| Synthetic bridge methods | Generates bridge methods that confuse type inference |

## Identification

### File Artifacts

| Indicator | Details |
|-----------|---------|
| `allatori.xml` | Configuration file, sometimes left in the build directory or bundled in the APK |
| `ALLATORIxDEMO` | Method or class names containing this string indicate a trial/demo version |
| String decryption stubs | Static methods with byte array parameters returning strings, called at every string usage site |
| Unicode class names | Non-ASCII identifiers in class/method names beyond what R8/ProGuard produces |

### APKiD Detection

APKiD does not currently have dedicated Allatori detection rules. Identification relies on manual inspection of the patterns above.

### Distinguishing from R8/ProGuard

| Feature | R8/ProGuard | Allatori |
|---------|-------------|----------|
| String encryption | No (plaintext strings) | Yes (runtime decryption) |
| Control flow obfuscation | No | Yes (opaque predicates, dispatch loops) |
| Unicode identifiers | No (ASCII a-z only) | Yes |
| Decompiler crashes | No | Possible (bytecode-level tricks) |
| Watermarking | No | Yes |
| Configuration file | `proguard-rules.pro` | `allatori.xml` |

### Distinguishing from DexGuard

| Feature | Allatori | DexGuard |
|---------|----------|----------|
| Native protection | No | Yes (`libdexguard.so`) |
| DEX encryption | No | Yes |
| Runtime integrity checks | No | Yes (tamper detection, root/emulator checks) |
| Certificate pinning | No | Yes |
| String encryption | Yes (Java-level) | Yes (native-level) |
| Scope | Java bytecode only | Full APK protection |

Allatori operates at the Java bytecode level only. It does not add native libraries, encrypt DEX files, or perform any runtime environmental checks. If an APK has string encryption but no native protection layer, Allatori (or a similar Java-level obfuscator) is more likely than DexGuard.

## Reversing Allatori

### String Decryption with Frida

Hook the string decryption methods to log all decrypted strings at runtime:

```javascript
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            try {
                var cls = Java.use(className);
                var methods = cls.class.getDeclaredMethods();
                methods.forEach(function (method) {
                    var name = method.getName();
                    var retType = method.getReturnType().getName();
                    var params = method.getParameterTypes();
                    if (retType === "java.lang.String" && params.length === 1
                        && params[0].getName() === "java.lang.String") {
                        cls[name].overload("java.lang.String").implementation = function (enc) {
                            var dec = this[name](enc);
                            console.log("[Allatori] " + className + "." + name + ": " + dec);
                            return dec;
                        };
                    }
                });
            } catch (e) {}
        },
        onComplete: function () {}
    });
});
```

This hooks all static methods that take a single `String` and return a `String`, logging the decrypted output. Filter by package name to reduce noise from legitimate library methods.

### Static Decryption

For offline analysis, extract the decryption method bytecode from the DEX and re-implement it. Allatori's string encryption typically uses:

1. A per-class or per-method XOR key
2. Base64 or custom encoding of the ciphertext
3. A static initializer that sets up decryption state

The decryption logic is straightforward once identified. Tools like jadx can usually decompile the decryption method itself, even if the surrounding code is obfuscated.

### Control Flow Deobfuscation

For switch-based dispatch loops (control flow flattening):

1. Identify the state variable and the dispatch switch statement
2. Trace the state transitions to reconstruct the original sequential flow
3. Tools like [Ghidra](https://ghidra-sre.org/) with custom scripts or [radare2](https://rada.re/) can automate this for native code, but for DEX bytecode, manual analysis in jadx is often faster

## Malware Usage

Allatori is occasionally found in Android malware, particularly samples developed by actors with Java development backgrounds. Its commercial license means most malware authors either use cracked versions (identifiable by `ALLATORIxDEMO` markers) or strip the watermark to avoid attribution.

Compared to Chinese packers ([Tencent Legu](tencent-legu.md), [Baidu](baidu.md), [Qihoo 360](qihoo-360-jiagu.md)) and commercial Android protectors ([DexGuard](dexguard.md), [Virbox](virbox.md)), Allatori provides weaker protection because it lacks DEX encryption and runtime anti-analysis. However, its string encryption alone is sufficient to bypass basic static analysis tools and signature-based AV detection.

## References

- [Allatori Official Documentation](https://allatori.com/doc.html)
