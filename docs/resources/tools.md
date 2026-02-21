# Tools

Open-source and commercial tools for Android security analysis, device management, network interception, reverse engineering, and sandboxing.

## Analysis & Detection

| Tool | Purpose |
|------|---------|
| [Androguard](https://github.com/androguard/androguard) | Python framework for Android app analysis |
| [APKiD](https://github.com/rednaga/APKiD) | Packer, protector, obfuscator identification |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | Extract URLs, endpoints, and secrets from APK files |
| [dex2jar](https://github.com/pxb1988/dex2jar) | DEX to JAR conversion |
| [Droidlysis](https://github.com/cryptax/droidlysis) | Automated Android malware property extraction (permissions, receivers, services) |
| [Drozer](https://github.com/WithSecureLabs/drozer) | Android security assessment framework. IPC probing, provider testing. |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated mobile security analysis |
| [Quark Engine](https://github.com/quark-engine/quark-engine) | Android malware scoring and behavior analysis |
| [SUPER](https://github.com/SUPERAndroidAnalyzer/super) | Secure, Unified, Powerful and Extensible Rust Android Analyzer |
| [VirusTotal](https://www.virustotal.com/) | Multi-engine malware scanning. 70+ AV engines. See [Naming Conventions](../malware/naming-conventions.md) for detection name formats. |

## Device

| Tool | Purpose |
|------|---------|
| [LSPosed](https://github.com/LSPosed/LSPosed) | Xposed framework for modern Android |
| [Magisk](https://github.com/topjohnwu/Magisk) | Root management with detection bypass |

## Network

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS proxy and traffic interception |
| [mitmproxy](https://mitmproxy.org/) | Scriptable HTTPS proxy |

## Reverse Engineering

| Tool | Purpose |
|------|---------|
| [apktool](https://github.com/iBotPeaches/Apktool) | APK disassembly and reassembly |
| [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) | Multi-decompiler view (Procyon, CFR, FernFlower, jadx side-by-side) |
| [Frida](https://frida.re/) | Dynamic instrumentation: hooking, tracing, modifying runtime behavior |
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Dump DEX files from packed apps at runtime |
| [Ghidra](https://ghidra-sre.org/) | Native code reverse engineering (NSA, free) |
| [jadx](https://github.com/skylot/jadx) | DEX to Java decompiler |
| [medusa](https://github.com/Ch0pin/medusa) | Extensible framework combining Frida scripts for Android dynamic analysis |
| [Objection](https://github.com/sensepost/objection) | Frida-powered runtime exploration |
| [reFrida](https://github.com/zahidaz/refrida) | Browser-based Frida IDE with Monaco editor, disassembler, memory search, Stalker tracing, and visual interceptor builder |
| [r2frida](https://github.com/nowsecure/r2frida) | Radare2 + Frida integration |
| [radare2](https://rada.re/) | Open-source reverse engineering framework |

## Emulation & Sandboxing

| Tool | Purpose |
|------|---------|
| [Android Emulator](https://developer.android.com/studio/run/emulator) | Official Android emulator with AVD manager |
| [Genymotion](https://www.genymotion.com/) | High-performance Android emulator for testing |
| [rootAVD](https://github.com/newbit1/rootAVD) | Root Android Virtual Devices for Frida and dynamic analysis |
| [Cuckoo Droid](https://github.com/idanr1986/cuckoo-droid) | Automated Android malware sandbox |
| [Joe Sandbox Mobile](https://www.joesecurity.org/) | Commercial automated malware analysis sandbox |
