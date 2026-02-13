# Network Analysis

Intercepting, decrypting, and analyzing network traffic between the malware and its C2 server. Reveals command protocols, exfiltration channels, target lists, and infrastructure. Often the fastest path to understanding a sample's purpose and operator identity.

## Setup

### Traffic Interception

| Method | Root Required | HTTPS | Notes |
|--------|--------------|-------|-------|
| Burp Suite / mitmproxy as Wi-Fi proxy | No | With cert install | Standard approach. Set device proxy to host IP. |
| iptables redirect | Yes | With cert install | Transparent proxy. Catches traffic that ignores proxy settings. |
| VPN-based (PCAPdroid, NetGuard) | No | Metadata only | Captures packet headers without root. No decryption. |
| tcpdump on device | Yes | No decryption | Raw packet capture. Useful for non-HTTP protocols. |
| Wireshark on host | No | No decryption | Capture on shared network. Requires ARP spoofing or network tap. |

### Certificate Installation

For HTTPS interception, the proxy's CA certificate must be trusted by the device:

**User certificate store** (Android 7+, apps targeting API 24+ ignore user certs by default):

```bash
adb push burp-ca.der /sdcard/
# Settings > Security > Install from storage
```

**System certificate store** (requires root):

```bash
openssl x509 -inform DER -in burp-ca.der -out burp-ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp-ca.pem | head -1)
cp burp-ca.pem /system/etc/security/cacerts/${HASH}.0
chmod 644 /system/etc/security/cacerts/${HASH}.0
```

On Android 14+, system certs are read from an APEX module. Use Magisk's `MagiskTrustUserCerts` module or patch the APEX mount.

### SSL Pinning Bypass

Most banking trojans and their target apps implement SSL pinning. Bypass approaches ranked by reliability:

| Approach | Tool | Scope |
|----------|------|-------|
| Frida script | [See Hooking](hooking.md) | Per-library bypass (OkHttp, HttpURLConnection, WebView) |
| Objection | `android sslpinning disable` | Automated, covers common libraries |
| Network security config patch | [See Patching](patching.md) | Modify `res/xml/network_security_config.xml` to trust user certs |
| Frida + reFrida | [reFrida](https://github.com/zahidaz/refrida) | Visual interceptor for pinning bypass with real-time traffic view |

For malware specifically, SSL pinning bypass is needed to observe C2 communication. Most malware uses simpler HTTP clients than legitimate apps, so a basic OkHttp or HttpURLConnection hook covers the majority.

## C2 Protocol Identification

Android malware C2 protocols fall into distinct categories. Identifying the protocol type determines the analysis approach:

| Protocol | Indicators | Families |
|----------|-----------|----------|
| HTTP/REST | Standard HTTP methods, JSON/XML payloads, URL path structure | [Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md), [GodFather](../malware/families/godfather.md), [Rafel RAT](../malware/families/rafelrat.md) |
| WebSocket | `ws://` or `wss://` URLs, `Upgrade: websocket` header, persistent connection | [TsarBot](../malware/families/tsarbot.md), [Antidot](../malware/families/antidot.md), [BlankBot](../malware/families/blankbot.md), [BTMOB RAT](../malware/families/btmob.md), [PJobRAT](../malware/families/pjobrat.md) |
| MQTT | Port 1883/8883, CONNECT/PUBLISH/SUBSCRIBE packets | [Copybara](../malware/families/copybara.md) |
| Raw TCP | Custom binary protocol, non-standard ports | [Albiriox](../malware/families/albiriox.md) (unencrypted TCP), [SpyNote](../malware/families/spynote.md) |
| Firebase Cloud Messaging | `fcm.googleapis.com`, JSON with `registration_ids` | [Vultur](../malware/families/vultur.md) v2, [PJobRAT](../malware/families/pjobrat.md), [KoSpy](../malware/families/kospy.md), [FireScam](../malware/families/firescam.md), [DeVixor](../malware/families/devixor.md) |
| Firebase Firestore | `firestore.googleapis.com`, document reads/writes | [KoSpy](../malware/families/kospy.md) (C2 config delivery) |
| Telegram Bot API | `api.telegram.org/bot<token>/`, `sendMessage`/`getUpdates` | [Rafel RAT](../malware/families/rafelrat.md), [Mamont](../malware/families/mamont.md), [DeVixor](../malware/families/devixor.md) |
| TOR | `.onion` domains, SOCKS proxy on port 9050 | [Hydra](../malware/families/hydra.md) |
| Dead drop resolvers | Pastebin, Telegram channels, X (Twitter) posts containing encoded C2 addresses | [Medusa](../malware/families/medusa.md) v2 |

### Protocol Analysis Workflow

```
1. Capture traffic (proxy or tcpdump)
2. Identify protocol type from port/headers
3. For HTTP: decode JSON payloads, map API endpoints
4. For WebSocket: capture frame-by-frame, decode message format
5. For custom protocols: identify packet structure (length prefix, command ID, payload)
6. Map command set: what commands does the C2 send, what does the bot respond
7. Extract IOCs: domains, IPs, paths, tokens, bot IDs
```

## Domain Generation Algorithms (DGA)

Some families generate C2 domains algorithmically to resist infrastructure takedown:

| Family | DGA Type | Predictability |
|--------|----------|----------------|
| [SharkBot](../malware/families/sharkbot.md) | Date-seeded domain generation | Predictable with algorithm and seed |
| [Octo](../malware/families/octo.md) v2 | Dynamic key-based DGA | Requires key extraction |
| [MoqHao](../malware/families/moqhao.md) | DNS hijacking (not DGA, but similar resilience) | Requires DNS monitoring |

To analyze a DGA: extract the algorithm from decompiled code, determine the seed (often date-based), and generate the domain list. This enables preemptive domain sinkholing.

## Exfiltration Channel Analysis

Different families exfiltrate stolen data through different channels:

| Channel | What's Sent | Families |
|---------|------------|----------|
| HTTP POST to C2 | Credentials, SMS, contacts, device info | Most banking trojans |
| SFTP | Files, documents, media | [DCHSpy](../malware/families/dchspy.md) |
| Telegram Bot | Screenshots, keylog dumps, SMS | [Rafel RAT](../malware/families/rafelrat.md), [Mamont](../malware/families/mamont.md) |
| Firebase Realtime Database | Real-time data streaming | [FireScam](../malware/families/firescam.md) |
| WebSocket streaming | Live screen data, input events | [Vultur](../malware/families/vultur.md), [BTMOB RAT](../malware/families/btmob.md) |
| AWS S3 (misconfigured) | Exfiltrated victim data | RedHook (exposed S3 bucket) |
| VNC/AlphaVNC | Screen streaming | [Vultur](../malware/families/vultur.md) v1, [BingoMod](../malware/families/bingomod.md) |
| MediaProjection stream | Screen recording/streaming | [Gigabud](../malware/families/gigabud.md), [BlankBot](../malware/families/blankbot.md), [BTMOB RAT](../malware/families/btmob.md) |

## Traffic Encryption

| Encryption | How to Decrypt | Families |
|------------|---------------|----------|
| Standard HTTPS | Proxy with cert install + pinning bypass | Most families |
| Custom AES on top of HTTPS | Hook `Cipher.doFinal` to capture plaintext | [Cerberus](../malware/families/cerberus.md) lineage |
| Unencrypted HTTP/TCP | No decryption needed | [Albiriox](../malware/families/albiriox.md), older families |
| Certificate pinning only | Bypass pinning, traffic is readable | [Anatsa](../malware/families/anatsa.md), [Xenomorph](../malware/families/xenomorph.md) |
| TOR | Run malware through transparent TOR proxy, or hook before TOR encryption | [Hydra](../malware/families/hydra.md) |
| Custom binary encoding | Reverse the encoding algorithm from decompiled code | Family-specific |

## Tools

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS interception and modification |
| [mitmproxy](https://mitmproxy.org/) | Scriptable HTTPS proxy, good for automation |
| [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | No-root Android traffic capture via local VPN |
| [Wireshark](https://www.wireshark.org/) | Packet-level protocol analysis |
| [tcpdump](https://www.tcpdump.org/) | Command-line packet capture on device |
| [reFrida](https://github.com/zahidaz/refrida) | Browser-based Frida IDE with network activity monitoring |
