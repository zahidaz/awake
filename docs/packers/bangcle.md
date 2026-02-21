# Bangcle (SecNeo)

One of the earliest Chinese packers. While the vendor has evolved into SecNeo, older Bangcle versions are still encountered in legacy malware samples. The protection is basic by modern standards and straightforward to unpack.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | Bangcle / SecNeo |
| **Free Tier** | Yes |
| **APKiD Signature** | `packer : Bangcle` |
| **Unpacking Difficulty** | Easy |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libsecexe.so`, `libsecmain.so`, `libSecShell.so` |
| DEX stub | Minimal loader calling native initialization |
| Asset files | `classes.jar` or encrypted DEX in `assets/` |

## Protection

- DEX encryption and dynamic loading
- Anti-debugging via ptrace
- Root detection
- Basic emulator detection

## Unpacking

Older Bangcle versions use straightforward DEX-in-assets encryption. The native library decrypts and writes a temporary DEX file. Hook file operations or dump from `/proc/<pid>/maps`.

[frida-dexdump](https://github.com/hluwa/frida-dexdump) handles Bangcle without special configuration.

## Malware Usage

| Family | Notes |
|--------|-------|
| [BankBot](../malware/families/bankbot.md) | Older variants |
| Older banking trojans | Common on 2015-2018 era samples |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
