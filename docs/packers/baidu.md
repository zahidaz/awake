# Baidu Reinforcement

Baidu's free app protection service. Less sophisticated than [Tencent Legu](tencent-legu.md) or [Qihoo 360 Jiagu](qihoo-360-jiagu.md) but still encountered in malware samples, particularly Chinese-targeted adware and data-harvesting families.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | Baidu |
| **Free Tier** | Yes |
| **APKiD Signature** | `packer : Baidu` |
| **Unpacking Difficulty** | Easy |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libbaiduprotect.so`, `libprotectClass.so` |
| DEX stub | Application class delegating to Baidu loader |
| Asset files | Encrypted payload in `assets/baiduprotect/` |

## Protection

- DEX encryption with custom algorithm
- Basic anti-debugging (ptrace)
- Emulator detection via Build properties
- No function-level encryption (entire DEX encrypted as blob)

## Unpacking

Straightforward DEX dump. The native library decrypts the entire DEX payload in one pass and loads via standard class loader. Hook `DexClassLoader` or dump from memory after load.

[frida-dexdump](https://github.com/hluwa/frida-dexdump) handles Baidu without special configuration.

## Malware Usage

| Family | Notes |
|--------|-------|
| Chinese adware | Common on adware targeting Chinese users |
| Data-harvesting apps | Budget protection for data collection apps |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
