# iJiami

Commercial packing service offering both free and paid tiers. The free tier provides basic DEX encryption; paid tiers add anti-tampering, root detection, and code virtualization comparable to [DexGuard](dexguard.md).

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | iJiami |
| **Free Tier** | Limited |
| **APKiD Signature** | `packer : iJiami` |
| **Unpacking Difficulty** | Medium (free), Hard (paid with code virtualization) |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libexecmain.so`, `libexec.so` |
| DEX stub | Shell class invoking native decryption |
| Asset files | `ijiami.dat` or encrypted DEX in `assets/ijiami/` |
| Metadata | `ijiami` references in APK resources |

## Protection

- Multi-layer DEX encryption
- Anti-debugging with signal handling
- Root detection (su, Magisk, system partition checks)
- Paid tier: method-level encryption, code virtualization

## Unpacking

Free tier: standard DEX dump via [frida-dexdump](https://github.com/hluwa/frida-dexdump) or class loader hook.

Paid tier with method-level encryption requires hooking individual method decryption calls, similar to [DexGuard](dexguard.md) string decryption approach.

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
