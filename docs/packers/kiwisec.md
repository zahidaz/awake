# Kiwisec (几维安全)

Kiwisec is a commercial Chinese application security platform offering APK hardening, SO library protection, Java2C compilation, and KiwiVM code virtualization. Not to be confused with [SecShell](secshell.md), which belongs to [Bangcle/SecNeo](bangcle.md).

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Developer | 成都盈海益讯科技有限公司 |
| Origin | China (Chengdu) |
| Type | Commercial Packer/Protector/Virtualizer |
| Website | [kiwisec.com](https://en.kiwisec.com/) |

## Identification

| Artifact | Description |
|----------|-------------|
| `libkiwicrash.so` | Crash reporting library |
| `libKwProtectSDK.so` | Main protection SDK |
| `libkwsdataenc.so` | Data encryption library |
| `libkws*.so` | Various Kiwisec runtime libraries |

APKiD detects Kiwisec with the `kiwisec_apk` rule.

## Protection Capabilities

| Feature | Details |
|---------|---------|
| DEX encryption | Yes |
| SO protection | Yes (ELF encryption + anti-debugging) |
| Java2C | Converts Java bytecode to native C code at build time |
| KiwiVM | Proprietary code virtualization engine |
| Anti-debugging | Yes |
| Anti-tampering | Yes |
| Root detection | Yes |

KiwiVM is Kiwisec's code virtualization offering, comparable to [Virbox](virbox.md) VM protection. Java2C compilation converts selected Java methods to native code, removing them from the DEX entirely.
