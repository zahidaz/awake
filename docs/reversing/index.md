# Reversing

Practical methodology for reversing Android applications, from initial triage to full unpacking. Each page covers the approach, tools, and target-specific techniques for defeating protections.

## Methodology

| Approach | When to Use |
|----------|-------------|
| [Static Analysis](static-analysis.md) | First pass on any APK: manifest review, decompilation, string extraction, identifying protections |
| [Dynamic Analysis](dynamic-analysis.md) | Runtime behavior observation: tracing API calls, monitoring file/network activity, capturing decrypted payloads |
| [Hooking](hooking.md) | Intercepting and modifying function calls at runtime using Frida, Xposed, or native hooks |
| [Patching](patching.md) | Modifying APK or DEX bytecode: disabling checks, injecting instrumentation, repackaging |
| [Network Analysis](network-analysis.md) | Intercepting C2 traffic: proxy setup, SSL pinning bypass, protocol identification, exfiltration channel mapping |
| [Development Frameworks](frameworks/index.md) | Identifying and reversing cross-platform apps: React Native, Flutter, Xamarin, Unity, Cordova, and others |

## Triage Workflow

When a new sample arrives, follow this sequence to identify what you're dealing with before deep-diving:

```
1. Static triage
   - File hashes (MD5, SHA-256) for VT/MalwareBazaar lookup
   - AndroidManifest.xml: permissions, components, intent filters
   - strings / grep for URLs, IPs, API keys, crypto constants
   - Identify packer (APKiD or manual native lib inspection):
     Virbox, DexGuard, DexProtector, Tencent Legu, 360 Jiagu,
     Bangcle, AppSealing, LIAPP, Appdome, zShield, Verimatrix,
     Arxan, Promon, or custom packer
   - Identify framework: check for React Native, Flutter, Xamarin,
     Unity, Cordova indicators (see Development Frameworks page)

2. If packed: unpack first
   - Chinese packers (Tencent Legu, 360 Jiagu, Bangcle): memory dump via Frida (DexClassLoader hook)
   - DexGuard: string decryption hooks, class name deobfuscation
   - Virbox: native unpacking from libvdog.so
   - AppSealing: AppPealing Xposed module or Frida kill/signal/alarm hooks
   - LIAPP: frida-dexdump on physical device, server-side token replay
   - Appdome: layered bypass (anti-debug, anti-root, anti-Frida, SSL)
   - zShield: XXTEA ELF unpacker for native libs, .szip DEX extraction
   - Verimatrix: decrypt libencryption_*.so, handle inlined string decryption
   - Arxan: guard network mapping with Frida Stalker, Ghidra + D-810
   - Promon: RASP bypass via Shamiko + ZygiskFrida on physical device
   - DexProtector: white-box crypto analysis, native bridge hooks
   - See Packers section for family-specific techniques

3. Identify framework (if not native Android)
   - React Native: extract and beautify JS bundle or decompile Hermes bytecode
   - Flutter: run blutter against libapp.so for Dart symbol recovery
   - Xamarin: decompile assemblies/*.dll with dnSpy/ILSpy
   - Unity: Il2CppDumper for IL2CPP, dnSpy for Mono backend
   - Cordova: all logic in assets/www/ as readable JavaScript
   - See Development Frameworks page for full detection and analysis

4. Decompile and analyze
   - JADX for Java/Smali, Ghidra/IDA for native libs
   - Map class structure: identify C2 handler, command dispatcher, payload classes
   - Extract encryption keys, C2 URLs, target app lists

5. Dynamic validation
   - Run in emulator or physical device with proxy
   - Capture C2 registration and first beacon
   - Trigger key behaviors: overlay injection, accessibility activation, data exfiltration
   - Hook crypto functions to capture plaintext C2 traffic

6. Network capture
   - Set up proxy (Burp/mitmproxy) with SSL pinning bypass
   - Map API endpoints and command protocol
   - Identify exfiltration channels and data format
   - Extract IOCs: domains, IPs, paths, bot IDs
```

!!! tip "Physical device strongly preferred"
    LIAPP, Appdome, Arxan, DexProtector, and Promon all aggressively detect emulators and virtual environments. Use a rooted Pixel with Magisk + Zygisk + Shamiko + ZygiskFrida for these protectors. Chinese packers, AppSealing, DexGuard, and Verimatrix are generally workable in emulators with basic evasion.

## Framework Identification

Before diving into decompilation, determine whether the app was built with a cross-platform framework. The framework dictates the entire toolchain -- a Flutter app has zero useful DEX code, and a Cordova app stores all logic as plaintext JavaScript.

| Framework | Quick Indicator | Analysis Approach |
|-----------|----------------|-------------------|
| React Native | `assets/index.android.bundle`, `libhermes.so` or `libjsc.so` | Decompile Hermes bytecode or beautify JS bundle |
| Flutter | `libflutter.so`, `libapp.so` | Run blutter for Dart AOT symbol recovery, Ghidra for native analysis |
| Xamarin / .NET MAUI | `assemblies/*.dll`, `libmonosgen-2.0.so` | Decompile .NET DLLs with dnSpy or ILSpy |
| Unity (IL2CPP) | `libil2cpp.so`, `global-metadata.dat` | Il2CppDumper for metadata extraction, Ghidra for native code |
| Unity (Mono) | `assets/bin/Data/Managed/*.dll` | dnSpy decompilation of Assembly-CSharp.dll |
| Cordova / Ionic | `assets/www/index.html`, `assets/www/cordova.js` | Read JavaScript directly, beautify if minified |
| Godot | `libgodot_android.so`, `assets/*.pck` | gdsdecomp for .pck extraction, GDScript recovery |
| B4A | `anywheresoftware.b4a.*` classes | Standard jadx decompilation, fully readable |
| Kivy (Python) | `libpython*.so`, `libSDL2.so`, `org.kivy.*` | Extract and decompile Python bytecode (.pyc) |
| Qt | `libQt5Core_*.so` or `libQt6Core_*.so` | Ghidra/IDA for native C++, QML files may be readable |

28 frameworks documented with detection scripts, individual analysis workflows, SSL pinning bypass methods, and hooking strategies. See [Development Frameworks](frameworks/index.md) for the complete reference.

## Environment Setup

### Recommended Lab Configuration

| Component | Option A (Physical) | Option B (Emulated) |
|-----------|--------------------|--------------------|
| Device | Rooted Pixel (Magisk) | Android Studio AVD or Genymotion |
| Android version | Match target's `minSdkVersion` | API 28-33 covers most samples |
| Root | Magisk + Zygisk | Built-in root (AVD) |
| Frida | frida-server on device | frida-server on emulator |
| Proxy | Burp Suite / mitmproxy on host | Same, bridge networking |
| Network isolation | Dedicated Wi-Fi AP or VLAN | NAT with host proxy |

Physical devices are preferred for samples with emulator detection (most banking trojans). Emulators work for initial triage and samples without anti-emulation.

### Anti-Analysis Checks

Most modern banking trojans implement multiple anti-analysis checks. Know what to expect:

| Check | What It Detects | Bypass |
|-------|----------------|--------|
| Root detection | Magisk, su binary, root management apps | MagiskHide / Shamiko, Frida hook |
| Emulator detection | Build properties, sensors, telephony | Frida property spoofing, physical device |
| Frida detection | Port 27042, process name, `/proc/self/maps` | Rename binary, non-default port, Magisk module |
| Debugger detection | `Debug.isDebuggerConnected()`, TracerPid | Frida hook, Smali patch |
| VPN/proxy detection | Network interface checks, proxy settings | Transparent proxy via iptables |
| Geofencing | SIM country, locale, timezone, IP geolocation | Frida spoof, Smali patch |
| Google Play Services | SafetyNet/Play Integrity attestation | Magisk modules (Play Integrity Fix) |

For packer-specific protections and bypass techniques, see [Packers](../packers/index.md). Individual packer pages document their anti-Frida, anti-root, and anti-emulator implementations along with targeted bypass methods.

## Cross-References

Target-specific reversing (e.g., unpacking Virbox, bypassing anti-debug) is documented in the relevant [Packers](../packers/index.md) and [Attack Techniques](../attacks/index.md) pages. Individual [malware family](../malware/families/index.md) pages include reversing notes specific to each family's protections. The [Development Frameworks](frameworks/index.md) page covers framework detection, tooling, and analysis workflows for React Native, Flutter, Xamarin, Unity, Cordova, and other cross-platform technologies.
