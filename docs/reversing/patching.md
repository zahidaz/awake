# Patching

Modifying an APK's code or resources, then repackaging and signing it for installation. Used to remove security checks (root detection, SSL pinning, integrity verification), inject instrumentation, or alter app behavior for analysis.

## Workflow

### 1. Disassemble

```bash
apktool d target.apk -o target_patched/
```

This produces Smali code (Dalvik assembly), decoded resources, and the manifest.

### 2. Locate Target Code

Find the code to patch. Common targets:

| Target | What to Search For |
|--------|-------------------|
| Root detection | "su", "Superuser", "Magisk", "RootBeer", `isRooted` |
| SSL pinning | "CertificatePinner", "X509TrustManager", "SSL", `checkServerTrusted` |
| Emulator detection | "generic", "sdk", "Build.FINGERPRINT", "goldfish" |
| Integrity checks | "signature", "PackageInfo", "GET_SIGNATURES" |
| Debug detection | "isDebuggerConnected", "Debug.waitForDebugger" |
| Frida detection | "frida", "27042", "linjector" |

Use grep across the Smali directory:

```bash
grep -r "isRooted" target_patched/smali/
```

### 3. Patch Smali

Smali is register-based Dalvik assembly. Common patches:

**Make a method always return true:**

```smali
.method public isRooted()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```

**Make a method do nothing (NOP):**

```smali
.method public checkIntegrity()V
    .locals 0
    return-void
.end method
```

**Change a conditional branch (replace the branch instruction with nop to prevent the jump):**

Original:

```smali
if-nez v0, :exit_app
```

Patched:

```smali
nop
```

### 4. Reassemble

```bash
apktool b target_patched/ -o target_patched.apk
```

### 5. Sign

Android requires all APKs to be signed. Use a debug keystore or generate one:

```bash
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android -dname "CN=Debug"

apksigner sign --ks debug.keystore --ks-key-alias debug --ks-pass pass:android target_patched.apk
```

### 6. Install

```bash
adb install target_patched.apk
```

If the original app is installed, uninstall first (signatures won't match):

```bash
adb uninstall com.target.app
adb install target_patched.apk
```

## Common Patching Targets

A reference for the most frequent patching targets during malware analysis, organized by what you need to disable and where to find it:

| Target | Search Strings | Smali Patch | Purpose |
|--------|---------------|-------------|---------|
| SSL pinning | `CertificatePinner`, `checkServerTrusted`, `X509TrustManager` | Replace `check` method body with `return-void` | Intercept HTTPS traffic with a proxy |
| Root detection | `isRooted`, `RootBeer`, `su`, `Superuser`, `Magisk` | Force `return false` (const/4 v0, 0x0) | Run on rooted analysis device |
| Emulator detection | `Build.FINGERPRINT`, `generic`, `goldfish`, `sdk`, `isEmulator` | Force `return false` or patch string comparisons | Run in emulated environment |
| Debug detection | `isDebuggerConnected`, `Debug.waitForDebugger`, `TracerPid` | Force `return false` or `return-void` | Attach debugger for step-through analysis |
| Frida detection | `frida`, `27042`, `linjector`, `/proc/self/maps` | Replace detection method with `return false` | Allow Frida hooking without detection |
| C2 URL replacement | Encrypted or hardcoded C2 strings | Replace C2 URL with controlled server address | Redirect traffic to analyst-controlled infrastructure |
| Geofencing | `getSimCountryIso`, `getNetworkCountryIso`, locale checks | Patch branch to always proceed, or replace country string | Execute region-locked malware in analysis lab |
| Kill switch | Locale checks (CIS exclusion), date checks, remote kill | NOP the kill branch or force the safe path | Prevent self-termination during analysis |
| Tamper detection | `PackageManager.GET_SIGNATURES`, CRC checks, hash validation | Replace verification method with constant `return true` | Allow repackaged APK to run |
| Device admin enforcement | `DevicePolicyManager`, `isAdminActive` | Bypass admin requirement branch | Analyze without granting device admin |

## Integrity Check Bypass

Malware frequently verifies its own integrity to detect tampering. After patching and re-signing, these checks will fire. Bypass them or the patched APK refuses to run.

### APK Signature Verification

The most common integrity check reads the APK's signing certificate at runtime and compares it against a hardcoded hash:

```smali
invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
move-result-object v0
invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
move-result-object v1
const/16 v2, 0x40
invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
```

Patch approaches:

**1. NOP the entire check method:**

```smali
.method private verifySignature()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```

**2. Patch the comparison to always match:**

Find the `String.equals()` or `Arrays.equals()` call that compares the signature hash and replace the conditional branch:

Original:

```smali
if-eqz v0, :sig_mismatch
```

Patched:

```smali
goto :sig_valid
```

**3. Replace the expected hash:**

If the malware stores the expected certificate hash as a string constant, replace it with the hash of your signing key:

```bash
keytool -exportcert -keystore debug.keystore -alias debug | sha256sum
```

Then patch the `const-string` in Smali with the new hash value.

### CRC / Checksum Verification

Some malware computes CRC32 or SHA-256 over its own DEX file or specific resource files:

```smali
invoke-static {v0}, Ljava/util/zip/CRC32;->getValue()J
```

Patch strategies:

- Replace the CRC comparison with a constant `true` return
- Find where the expected CRC value is stored (often in a static field or resource file) and update it to match the patched binary
- NOP the entire `checkCRC` method body

### PackageManager Proxy Detection

Advanced malware doesn't just check the signature once -- it hooks into `PackageManager` calls throughout the app lifecycle. Some families create a wrapper around `getPackageInfo` that caches the result and checks it periodically.

For these cases, search for all call sites:

```bash
grep -r "GET_SIGNATURES\|GET_SIGNING_CERTIFICATES\|0x40\|0x8000000" target_patched/smali*/
```

Patch every verification call site, or replace the central verification utility method.

### Native Signature Verification

When signature checks live in native code (`.so` files), Smali patching is not sufficient. The native library calls JNI functions to read the signature and verify it in C/C++. See the Binary Patching section below for handling these cases.

## Binary Patching (Native Libraries)

When malware implements security checks, crypto routines, or core logic in native code (`.so` files), Smali patching is insufficient. Binary patching modifies the compiled ARM/ARM64 instructions directly.

### Ghidra Workflow

```
1. Open the APK's lib/<arch>/ directory in Ghidra
2. Import the target .so file (ELF format, ARM or AARCH64)
3. Run auto-analysis (F5 for decompiler view)
4. Locate the target function (JNI_OnLoad, anti-debug checks, etc.)
5. Patch instructions using "Patch Instruction" (Ctrl+Shift+G)
6. Export the patched binary (File > Export Program > ELF)
7. Replace the original .so in the APK's lib/ directory
```

### NOP'ing Anti-Tamper Checks

Native anti-tamper checks typically read `/proc/self/maps`, compute hashes, or call `ptrace` to detect debuggers. In ARM64, NOP is encoded as `0x1F2003D5`:

**Patching a branch in Ghidra:**

Find the conditional branch after the integrity check:

```
CBNZ X0, #anti_tamper_detected
```

Replace with NOP:

```
NOP
```

Or replace with an unconditional branch past the check:

```
B #continue_normal_execution
```

### Patching JNI_OnLoad Anti-Debug

Many malware families run anti-debug and anti-tamper checks in `JNI_OnLoad`, which executes when the native library is loaded via `System.loadLibrary`. Common patterns:

| Check in JNI_OnLoad | What It Does | Patch |
|---------------------|-------------|-------|
| `ptrace(PTRACE_TRACEME, 0, 0, 0)` | Self-trace to prevent debugger attach | NOP the `ptrace` call and force return value to 0 |
| `fopen("/proc/self/status")` + `TracerPid` check | Detect attached debugger via proc filesystem | NOP the `fopen` call or patch the comparison |
| `fopen("/proc/self/maps")` + string scan | Detect Frida, Xposed, or debugger libraries in memory | NOP the scan loop or patch the string comparison |
| `getpid()` + `kill(pid, 0)` timing check | Detect debugging via execution timing | NOP the timing check branch |
| APK hash computation | Verify APK hasn't been modified | Replace hash comparison with unconditional success |

### IDA Pro + Keypatch Workflow

For IDA users, the [Keypatch](https://www.keystone-engine.org/) plugin simplifies binary patching:

```
1. Load .so in IDA, wait for auto-analysis
2. Navigate to target instruction
3. Edit > Keypatch > Patcher (or Ctrl+Alt+K)
4. Enter replacement instruction (e.g., "NOP" or "MOV W0, #1")
5. Apply patches: Edit > Patch program > Apply patches to input file
```

### Replacing the Patched Library

After patching, place the modified `.so` back into the APK:

```bash
apktool d target.apk -o target_patched/
cp patched_libnative.so target_patched/lib/arm64-v8a/libnative.so
apktool b target_patched/ -o target_patched.apk
uber-apk-signer -a target_patched.apk
```

Patch all architectures the APK ships (arm64-v8a, armeabi-v7a, x86, x86_64) or remove the directories for architectures you don't need -- Android will skip missing ABIs and fall back to available ones.

## Automated Patching Tools

Manual Smali editing is precise but slow. These tools automate common patching workflows:

### apktool + uber-apk-signer

The standard manual workflow, streamlined:

```bash
apktool d target.apk -o target_patched/
apktool b target_patched/ -o target_patched.apk
uber-apk-signer -a target_patched.apk
adb install target_patched-aligned-debugSigned.apk
```

[uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) handles zipalign + signing in one step, supports v1/v2/v3 signature schemes, and auto-generates a debug keystore if none is provided.

### Objection patchapk

[Objection](https://github.com/sensepost/objection) can inject Frida Gadget into an APK automatically:

```bash
objection patchapk -s target.apk
```

This decompiles the APK, injects the Frida Gadget `.so` into the native library directory, adds a `System.loadLibrary` call in the entry activity, repackages, and signs. The result is a self-instrumenting APK that spawns a Frida listener on launch without needing frida-server or root.

Options:

```bash
objection patchapk -s target.apk -a arm64-v8a
objection patchapk -s target.apk --gadget-version 16.1.0
objection patchapk -s target.apk -c gadget-config.json
```

The gadget config file controls Frida's behavior (listen mode, script to load, interaction type):

```json
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/hook.js"
  }
}
```

### reflutter (Flutter Apps)

[reflutter](https://github.com/Impact-I/reFlutter) patches Flutter-based apps to disable SSL pinning and enable traffic interception:

```bash
reflutter target.apk
```

reflutter patches the `libflutter.so` binary to redirect SSL verification and can also set up a MITM proxy configuration. This is necessary because Flutter apps use their own TLS stack (BoringSSL compiled into `libflutter.so`) and ignore system-level proxy settings and certificate stores.

### APKLab (VS Code Extension)

[APKLab](https://github.com/APKLab/APKLab) integrates apktool, jadx, and signing into VS Code. Right-click to decompile, edit Smali with syntax highlighting, and rebuild with one click. Useful for iterative patching workflows where you need to patch, test, and re-patch multiple times.

## Common Pitfalls

### Signature Verification

Many apps verify their own signature at runtime:

```java
PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
String sig = info.signatures[0].toCharsString();
if (!sig.equals(EXPECTED_SIGNATURE)) { System.exit(0); }
```

After repackaging with a different key, this check fails. See the Integrity Check Bypass section above for patching strategies, or hook `PackageManager.getPackageInfo()` via Frida.

### Multi-DEX

Large apps have multiple DEX files (`classes.dex`, `classes2.dex`, etc.). The target code may be in any of them. apktool handles this automatically, but search across all Smali directories:

```bash
grep -r "targetMethod" target_patched/smali*/
```

### Native Integrity Checks

Native libraries (`.so` files) may verify DEX checksums or APK signatures. See the Binary Patching section above for handling these with Ghidra or IDA.

### Resource ID Conflicts

Modifying resources can shift resource IDs, breaking references. Prefer code-only patches when possible.

## Smali Basics

Quick reference for reading and writing Smali:

| Smali | Meaning |
|-------|---------|
| `v0`, `v1` | Local registers |
| `p0`, `p1` | Parameter registers (p0 = `this` for instance methods) |
| `const/4 v0, 0x0` | Set v0 to 0 (false) |
| `const/4 v0, 0x1` | Set v0 to 1 (true) |
| `return v0` | Return value in v0 |
| `return-void` | Return nothing |
| `invoke-virtual` | Call instance method |
| `invoke-static` | Call static method |
| `move-result v0` | Get return value of last invoke |
| `if-eqz v0, :label` | Jump to label if v0 == 0 |
| `if-nez v0, :label` | Jump to label if v0 != 0 |
| `goto :label` | Unconditional jump |

## Tools

| Tool | Purpose |
|------|---------|
| [apktool](https://github.com/iBotPeaches/Apktool) | Disassemble/reassemble APKs |
| [apksigner](https://developer.android.com/tools/apksigner) | Sign APKs (Android SDK) |
| [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) | Simplified APK signing (zipalign + sign in one step) |
| [Ghidra](https://ghidra-sre.org/) | Native code analysis and binary patching |
| [Keypatch](https://www.keystone-engine.org/) | Binary patching plugin for IDA |
| [Objection](https://github.com/sensepost/objection) | Automated Frida Gadget injection into APKs |
| [reflutter](https://github.com/Impact-I/reFlutter) | SSL pinning bypass for Flutter apps |
| [APKLab](https://github.com/APKLab/APKLab) | VS Code extension integrating apktool, jadx, and signing |

## Family-Specific Patching Scenarios

Malware analysis often requires patching specific protection mechanisms before analysis can proceed:

| Family | What to Patch | Why |
|--------|--------------|-----|
| [Chameleon](../malware/families/chameleon.md) | Biometric prompt bypass check | Force PIN/password input path to study credential capture mechanism |
| [Cerberus](../malware/families/cerberus.md) lineage | Geofencing kill switch | Remove CIS country exclusion list to allow execution in analysis environments |
| [Klopatra](../malware/families/klopatra.md) | Virbox unpacking stub | Patch the native loader to dump DEX before execution, bypassing VM interpretation |
| [Brokewell](../malware/families/brokewell.md) | Android 13+ restriction bypass loader | Patch the loader's `SessionInstaller` calls to study the payload directly |
| [Frogblight](../malware/families/frogblight.md) | Geofencing check | Remove US-avoidance SIM/locale check to allow execution outside Turkey |
| [GodFather](../malware/families/godfather.md) | Post-Soviet language kill switch | Patch out system locale check that prevents execution on Russian/Ukrainian devices |
| [TrickMo](../malware/families/trickmo.md) | JSONPacker unpacking | Patch the custom packer's decryption routine to dump the cleartext payload |
| [Mandrake](../malware/families/mandrake.md) | OLLVM control flow flattening | Patch branch conditions in native code to linearize execution flow for analysis |

### Patching Geofencing

Many banking trojans restrict execution to specific regions. The geofence check typically reads the SIM country code or device locale:

```smali
invoke-virtual {p0}, Landroid/telephony/TelephonyManager;->getSimCountryIso()Ljava/lang/String;
move-result-object v0
const-string v1, "tr"
invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
move-result v0
if-eqz v0, :not_target_country
```

To bypass, patch the conditional branch to always proceed, or replace the country code comparison string with your analysis environment's locale.

### Patching Anti-Frida Checks

Malware detecting Frida (see [Hooking](hooking.md)) can be patched at the Smali level instead of hooking:

```smali
.method private checkFrida()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

Replace the entire method body with a constant `false` return. This avoids the cat-and-mouse game of hook-based Frida hiding.

## When to Patch vs. Hook

| Situation | Prefer |
|-----------|--------|
| Persistent change needed | Patch |
| Exploring/investigating | Hook (Frida) |
| Many checks to bypass | Hook (one script, multiple hooks) |
| Native code checks | Either (Frida can hook native too) |
| No root access available | Patch (works on non-rooted device) |
| App uses integrity verification | Hook (avoid signature mismatch) |
| Geofencing / kill switch bypass | Patch (one-time removal is cleaner) |
| Frida detection that's hard to hook | Patch (remove detection entirely) |
