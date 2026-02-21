# NeteaseYiDun

NetEase's application security service (易盾, "YiDun" = "Easy Shield"), integrated with their gaming ecosystem. Most commonly seen in Chinese mobile games but occasionally in malware targeting Chinese users.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | NetEase |
| **Free Tier** | Limited |
| **APKiD Signature** | `packer : NetEase` |
| **Unpacking Difficulty** | Hard |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libnesec.so`, `libNetHTProtect.so` |
| Package | `com.netease.nis.wrapper` package in DEX stub |
| Asset files | Encrypted payload in `assets/nis/` |

## Protection

- DEX encryption with multi-key scheme
- Anti-debugging and anti-hooking
- Integrity verification of native libraries
- Memory protection (mprotect on decrypted regions)

## Unpacking

NeteaseYiDun uses `mprotect` to remove read permissions from memory pages containing the decrypted DEX after loading. Hooking `mprotect` prevents this:

```javascript
var mprotect = Module.findExportByName("libc.so", "mprotect");
Interceptor.attach(mprotect, {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.prot = args[2].toInt32();
        if (this.prot === 0) {
            console.log("[mprotect] Blocking PROT_NONE at " +
                this.addr + " size=" + this.size);
            args[2] = ptr(1);
        }
    }
});
```

After bypassing, [frida-dexdump](https://github.com/hluwa/frida-dexdump) can scan the readable memory for DEX headers. Timing the dump is critical -- the decrypted DEX resides in memory briefly before protection flags are set.

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
