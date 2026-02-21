# Tencent Legu

The most widely used Chinese packer. Free protection service integrated with Tencent's app distribution ecosystem. Frequently found on both legitimate Chinese apps and malware. The protection is adequate against automated AV scanning but yields to manual analysis with Frida-based unpacking.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | Tencent |
| **Free Tier** | Yes |
| **APKiD Signature** | `packer : Tencent Legu` |
| **Unpacking Difficulty** | Medium |

## Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libshell-super.2019.so`, `libshella-*.so`, or `libtxoprot.so` |
| DEX stub | Minimal `classes.dex` with shell loader class |
| Asset files | Encrypted DEX in `assets/` (e.g., `classes.dex.dat`) |
| Metadata | `tencent_stub` in APK metadata |

## Protection

- DEX encryption with AES
- Native library anti-debugging (ptrace self-attach)
- Emulator detection via hardware properties
- Anti-Frida checks (port scanning, `/proc/maps` inspection, named pipe detection)
- String encryption in native layer
- Code segment checksumming

## Unpacking

### Standard Approach

1. Hook `DexClassLoader` or `InMemoryDexClassLoader` to intercept DEX loading
2. Dump DEX bytes from memory after native loader decrypts
3. Alternative: use [frida-dexdump](https://github.com/hluwa/frida-dexdump) which scans process memory for DEX headers

### Anti-Frida Bypass

Tencent Legu checks for Frida by scanning `/proc/self/maps` for `frida-agent` strings, probing port 27042, and checking named pipes in `/proc/self/fd/`. A combined bypass hooks these checks at the native level:

```javascript
var openPtr = Module.findExportByName("libc.so", "open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc") !== -1 &&
            this.path.indexOf("/maps") !== -1) {
            this.isMaps = true;
        }
    }
});

var readPtr = Module.findExportByName("libc.so", "read");
Interceptor.attach(readPtr, {
    onLeave: function(retval) {
        if (this.isMaps) {
            var buf = this.context.x1;
            var content = buf.readUtf8String();
            if (content && content.indexOf("frida") !== -1) {
                buf.writeUtf8String(content.replace(/frida/g, "aaaaa"));
            }
        }
    }
});

var connectPtr = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        if (port === 27042) {
            args[1] = ptr(0);
        }
    }
});
```

For Legu versions after 2023, the packer also scans for `frida-gadget` in loaded modules. The [Frida naming convention](https://frida.re/docs/gadget/) for renamed gadgets can bypass the string-based check. Using `frida-server` with `--listen 0.0.0.0:1337` on a non-standard port avoids port scanning detection.

## Malware Usage

| Family | Notes |
|--------|-------|
| [Triada](../malware/families/triada.md) | Firmware variants |
| Chinese adware | Most common protection on Chinese-origin adware |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [frida-dexdump](https://github.com/hluwa/frida-dexdump)
