# APKProtect

Nagain's free protection service. Less common than the major Chinese packers but still appears in budget malware operations. Minimal protection compared to competitors.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | Nagain |
| **Free Tier** | Yes |
| **APKiD Signature** | `packer : APKProtect` |
| **Unpacking Difficulty** | Easy |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libAPKProtect.so` |
| Asset files | Encrypted DEX in `assets/apk_protect/` |

## Protection

- DEX encryption
- Basic anti-debugging
- Minimal obfuscation compared to competitors

## Unpacking

Simple DEX dump. [frida-dexdump](https://github.com/hluwa/frida-dexdump) handles APKProtect without special configuration.

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
