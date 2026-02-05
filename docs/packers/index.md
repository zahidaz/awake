# Android Packers

## Overview

Android packers (also known as protectors or armoring tools) are software solutions that transform APK files to protect their code from reverse engineering, tampering, and analysis. While legitimate developers use packers to protect intellectual property, malware authors frequently abuse these tools to evade detection and hinder analysis.

## How Packers Work

Packers typically employ multiple layers of protection:

- **Code encryption**: Encrypting DEX files and decrypting at runtime
- **Native code wrapping**: Moving critical logic to native libraries
- **Anti-debugging**: Detecting and blocking debugger attachment
- **Anti-tampering**: Integrity checks to detect modifications
- **Environment detection**: Identifying emulators and analysis environments
- **String encryption**: Obfuscating sensitive strings
- **Control flow obfuscation**: Making code logic difficult to follow

## Categories

### Commercial Packers

Enterprise-grade solutions used by legitimate developers for app protection. Often include additional features like licensing and analytics.

### Free/Open Source Packers

Publicly available tools that provide basic protection capabilities.

### Custom Packers

Proprietary solutions developed by threat actors specifically for malware distribution.

## Analysis Challenges

Packed applications present unique challenges for security researchers:

- Static analysis tools may fail to extract meaningful information
- Dynamic analysis requires bypassing anti-analysis checks
- Multiple unpacking stages may be required
- Packer-specific knowledge is often necessary

## Research Focus

Each packer page in this wiki documents:

- Identification methods and signatures
- Protection mechanisms employed
- Unpacking techniques and tools
- Detection strategies
- Sample analysis case studies

## References

- [Android Unpacking Resources](https://github.com/pxb1988/dex2jar)
- [APKiD - Android Application Identifier](https://github.com/rednaga/APKiD)
