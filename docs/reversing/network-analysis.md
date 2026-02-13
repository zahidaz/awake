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

### Proxy Setup: mitmproxy

**On an emulator (Android Studio AVD):**

```bash
emulator -avd Pixel_6_API_33 -http-proxy http://127.0.0.1:8080
```

```bash
mitmproxy --listen-port 8080 --set block_global=false
```

Export the CA certificate and push it to the emulator:

```bash
cp ~/.mitmproxy/mitmproxy-ca-cert.cer /tmp/mitmproxy-ca.der
adb push /tmp/mitmproxy-ca.der /sdcard/
```

Install via Settings > Security > Encryption & credentials > Install a certificate > CA certificate. This installs to the user store, which is sufficient for apps targeting API < 24 or apps without `network_security_config.xml` restrictions.

**On a physical device:**

Connect the device and analysis machine to the same Wi-Fi network. Find the host machine's local IP:

```bash
ifconfig en0 | grep "inet "
```

On the device: Settings > Wi-Fi > long-press connected network > Modify network > Advanced > Proxy > Manual. Set proxy hostname to the host IP, port to 8080. Push and install the CA cert the same way as above.

**Transparent proxy (catches traffic that ignores proxy settings):**

Some malware ignores the system proxy and connects directly. Use iptables on a rooted device to redirect all traffic:

```bash
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080"
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:8080"
```

Run mitmproxy in transparent mode:

```bash
mitmproxy --mode transparent --listen-port 8080
```

### Proxy Setup: Burp Suite

**Burp listener configuration:**

In Burp Suite, go to Proxy > Options > Proxy Listeners. Add a listener on all interfaces (bind address `0.0.0.0`) on port 8082. Enable "Support invisible proxying" for transparent mode.

**Export the Burp CA:**

Browse to `http://<burp-host>:8082` from the device and download `cacert.der`. Alternatively, export from Burp: Proxy > Options > Import / export CA certificate > Certificate in DER format.

**On an emulator:**

```bash
adb push cacert.der /sdcard/
emulator -avd Pixel_6_API_33 -http-proxy http://127.0.0.1:8082
```

**On a physical device:**

Set the device Wi-Fi proxy to the host IP on port 8082, then install the CA cert from storage.

### Certificate Installation

For HTTPS interception, the proxy's CA certificate must be trusted by the device. Android 7+ (API 24+) introduced a critical change: apps targeting API 24 or above no longer trust user-installed CA certificates by default. This means user store installation is insufficient for most modern apps and all malware analysis scenarios.

**User certificate store** (limited utility -- only works for apps targeting API < 24 or apps with explicit user cert trust):

```bash
adb push proxy-ca.der /sdcard/
```

Install via Settings > Security > Install from storage.

**System certificate store** (requires root, works for all apps):

```bash
openssl x509 -inform DER -in proxy-ca.der -out proxy-ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in proxy-ca.pem | head -1)
mv proxy-ca.pem ${HASH}.0
```

On Android 10 and below, `/system` is writable after remount:

```bash
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot
```

On Android 11-13, the system partition is read-only. Mount a tmpfs overlay:

```bash
adb shell su -c "mount -t tmpfs tmpfs /system/etc/security/cacerts"
adb shell su -c "cp /apex/com.android.conscrypt/cacerts/* /system/etc/security/cacerts/"
adb push ${HASH}.0 /tmp/
adb shell su -c "mv /tmp/${HASH}.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/*"
```

This tmpfs mount does not survive reboots. Re-run after each restart.

On Android 14+, system certs are read from the `com.android.conscrypt` APEX module, and the overlay trick no longer works. Use the Magisk module approach below.

**Magisk module for system cert installation (Android 11+, recommended):**

The `MagiskTrustUserCerts` module copies all user-installed CA certificates into the system store at boot. This is the most reliable method for rooted devices running Android 11+.

```bash
adb push MagiskTrustUserCerts.zip /sdcard/
```

Install the module via the Magisk Manager app, then reboot. After reboot, any certificate installed in the user store appears in the system store. Install the proxy CA as a user cert first, then install the module.

For Android 14+ specifically, the module patches the APEX mount to inject certificates into the Conscrypt module's cert directory.

**Emulator shortcut (writable system image):**

Android Studio AVDs with Google APIs (not Google Play) have a writable system partition when launched with `-writable-system`:

```bash
emulator -avd Pixel_6_API_33 -writable-system -http-proxy http://127.0.0.1:8080
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot
```

This is the simplest path for emulator-based analysis. No Magisk required.

### SSL Pinning Bypass

Most banking trojans and their target apps implement SSL pinning. Bypass approaches ranked by reliability:

| Approach | Tool | Scope |
|----------|------|-------|
| Frida script | [See Hooking](hooking.md) | Per-library bypass (OkHttp, HttpURLConnection, WebView) |
| Objection | `android sslpinning disable` | Automated, covers common libraries |
| Network security config patch | [See Patching](patching.md) | Modify `res/xml/network_security_config.xml` to trust user certs |
| Frida + reFrida | [reFrida](https://github.com/zahidaz/refrida) | Visual interceptor for pinning bypass with real-time traffic view |

For malware specifically, SSL pinning bypass is needed to observe C2 communication. Most malware uses simpler HTTP clients than legitimate apps, so a basic OkHttp or HttpURLConnection hook covers the majority.

### Universal SSL Pinning Bypass with Frida

The following Frida script bypasses the most common pinning implementations in a single attach. It hooks SSLContext, TrustManager, OkHttp CertificatePinner, and Conscrypt's TrustManagerImpl.

??? example "Universal SSL Pinning Bypass Script"

    ```javascript
    Java.perform(function () {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });

        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagers, null);
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, sr) {
            this.init(km, TrustManagers, sr);
        };

        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function (hostname, peerCertificates) {};
            CertificatePinner.check$okhttp.overload(
                "java.lang.String",
                "kotlin.jvm.functions.Function0"
            ).implementation = function (hostname, cleanedCertificates) {};
        } catch (e) {}

        try {
            var CertPinnerLegacy = Java.use("okhttp3.CertificatePinner");
            CertPinnerLegacy.check.overload(
                "java.lang.String",
                "[Ljava.security.cert.Certificate;"
            ).implementation = function (hostname, peerCertificates) {};
        } catch (e) {}

        try {
            var TrustManagerImpl = Java.use(
                "com.android.org.conscrypt.TrustManagerImpl"
            );
            TrustManagerImpl.verifyChain.implementation = function (
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                ocspData,
                tlsSctData
            ) {
                return untrustedChain;
            };
        } catch (e) {}

        try {
            var PlatformImpl = Java.use(
                "com.android.org.conscrypt.Platform"
            );
            PlatformImpl.checkServerTrusted.overload(
                "javax.net.ssl.X509TrustManager",
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String",
                "com.android.org.conscrypt.AbstractConscryptSocket"
            ).implementation = function (tm, chain, authType, socket) {};
        } catch (e) {}

        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (
                view,
                handler,
                error
            ) {
                handler.proceed();
            };
        } catch (e) {}
    });
    ```

Run with:

```bash
frida -U -l ssl_bypass.js -f com.target.package
```

### Objection SSL Pinning Disable

Objection provides a one-command bypass that hooks the same classes automatically:

```bash
objection -g com.target.package explore
```

```
android sslpinning disable
```

This hooks `TrustManagerImpl`, `X509TrustManager`, `SSLContext`, `OkHttp3 CertificatePinner`, and `WebViewClient.onReceivedSslError`. For most malware samples, this is sufficient. If the sample uses native pinning or a non-standard library, fall back to the manual Frida script above or a framework-specific bypass.

### SSL Pinning Bypass by Framework

Different development frameworks implement SSL pinning at different layers. The universal Frida script above covers native Android apps, but cross-platform frameworks bundle their own TLS stacks and require framework-specific bypass strategies. See [Development Frameworks](frameworks/index.md) for framework identification and reversing approaches.

| Framework / Context | Pinning Mechanism | Bypass Strategy |
|---------------------|-------------------|-----------------|
| Default Android (NetworkSecurityConfig) | XML-declared CA restrictions and `<pin-set>` | Patch `res/xml/network_security_config.xml` to add `<certificates src="user" />`, or install proxy cert as system cert |
| OkHttp `CertificatePinner` | Hash-based certificate chain pinning | Frida hook on `CertificatePinner.check()` and `check$okhttp()` to return without throwing |
| Retrofit + OkHttp | Delegates entirely to OkHttp's `CertificatePinner` | Same as OkHttp -- Retrofit adds no pinning layer of its own |
| Flutter (BoringSSL) | Native BoringSSL in `libflutter.so`, bypasses Java cert store | Hook `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so` to force return `true` |
| React Native | Depends on underlying HTTP client (OkHttp on Android) | Standard OkHttp hooks usually work. For `react-native-ssl-pinning`, hook the specific native method |
| WebView | `WebViewClient.onReceivedSslError` callback | Hook `onReceivedSslError` to call `handler.proceed()` instead of `handler.cancel()` |
| Certificate Transparency | Separate CT log verification after pinning | Requires its own bypass -- hook `CTLogVerifier` or CT policy class. Pinning bypass alone is insufficient |

!!! warning "Flutter and React Native"
    Flutter apps do not use Java HTTP clients at all. OkHttp/HttpURLConnection Frida hooks have zero effect. You must target the native BoringSSL layer inside `libflutter.so`. React Native apps typically delegate to OkHttp, so standard Java hooks work, but apps with custom native modules like `react-native-ssl-pinning` may need additional native-layer hooks.

??? example "Flutter BoringSSL Pinning Bypass (Frida)"

    ```javascript
    var flutterModule = Process.findModuleByName("libflutter.so");
    if (flutterModule) {
        var resolvedAddress = Module.findExportByName(
            "libflutter.so",
            "ssl_crypto_x509_session_verify_cert_chain"
        );

        if (!resolvedAddress) {
            var pattern = "FF C3 08 00 00 14";
            var matches = Memory.scanSync(
                flutterModule.base,
                flutterModule.size,
                pattern
            );
            if (matches.length > 0) {
                resolvedAddress = matches[0].address;
            }
        }

        if (resolvedAddress) {
            Interceptor.attach(resolvedAddress, {
                onLeave: function (retval) {
                    retval.replace(0x1);
                },
            });
        }
    }
    ```

For packed apps that encrypt the pinning implementation, unpack first using `frida-dexdump` or the appropriate unpacker before applying bypasses. See [packers](../packers/index.md) for details.

### Certificate Pinning Detection Indicators

Before attempting a bypass, identify whether pinning is present and what type:

| Indicator | What It Means |
|-----------|--------------|
| `CertificatePinner` in decompiled source | OkHttp pin-set pinning |
| `network_security_config.xml` with `<pin-set>` elements | Android declarative pinning |
| Custom `X509TrustManager` implementation | Manual trust validation |
| `libflutter.so` present in `lib/` | Flutter BoringSSL pinning likely |
| `SSL_CTX_set_verify` in native `.so` files | Native OpenSSL/BoringSSL pinning |
| Connection fails with `SSLHandshakeException` when proxied | Pinning is active |
| Connection fails with `CertPathValidatorException` when proxied | Cert not trusted (may be user store issue, not pinning) |
| Traffic goes to port 443 but nothing appears in proxy | App ignores system proxy -- use transparent proxy with iptables |

!!! tip "Quick Pinning Check"
    Run the app through the proxy without any bypass. If the app works normally, there is no pinning. If connections fail with SSL errors in logcat, pinning is active. Use `adb logcat | grep -i ssl` to see the specific error class, which tells you the pinning implementation.

### SSL Pinning Bypass by Implementation

Different pinning implementations require different bypass strategies. The table below maps each pinning method to its specific bypass.

| Pinning Implementation | Where It Appears | Bypass Method | Details |
|------------------------|-----------------|---------------|---------|
| OkHttp `CertificatePinner` | Most Java/Kotlin apps, majority of Android malware | Frida hook on `CertificatePinner.check` | Hook the `check` overload to return without throwing. See Frida script below. |
| Custom `X509TrustManager` | Apps implementing their own cert validation | Frida hook on `checkServerTrusted` | Replace `checkServerTrusted` to return empty, bypassing the custom validation logic. |
| `network_security_config.xml` with `<pin-set>` | Apps using Android's built-in pinning declaration | Repackage APK with modified XML | Decompile with apktool, edit `res/xml/network_security_config.xml` to remove `<pin-set>` and add `<trust-anchors>` for user certs. Reassemble, sign, install. |
| `network_security_config.xml` domain restrictions | Apps restricting cleartext or cert trust per domain | Repackage with permissive config | Replace the entire config with one that trusts user certs for all domains. |
| Native OpenSSL (`libssl.so`) | NDK apps making direct native TLS calls | Frida native hook on `SSL_CTX_set_verify` | Hook `SSL_CTX_set_verify` in `libssl.so` and replace the callback with one that always succeeds. |
| BoringSSL in Flutter (`libflutter.so`) | All Flutter apps | Patch `libflutter.so` or use reFlutter | Flutter bundles BoringSSL and bypasses the Android cert store entirely. Use [reFlutter](https://github.com/Impact-I/reFlutter) to patch the binary, or locate `ssl_crypto_x509_session_verify_cert_chain` with Ghidra and NOP it. See [frameworks](frameworks/index.md) for details. |
| React Native TLS | React Native apps with native pinning modules | Java-layer Frida hook or patch JS bundle | If pinning is via `react-native-ssl-pinning`, hook OkHttp at the Java layer. If pinning is in the JS fetch wrapper, patch `assets/index.android.bundle`. See [frameworks](frameworks/index.md). |
| Conscrypt / `TrustManagerImpl` | System default TLS via Conscrypt provider | Frida hook on `TrustManagerImpl.verifyChain` | Hook `com.android.org.conscrypt.TrustManagerImpl` to bypass the platform-level chain validation. |
| Xamarin `ServicePointManager` | Xamarin/.NET MAUI apps | Patch the assembly DLL or hook Mono runtime | Edit `ServerCertificateValidationCallback` in the DLL with dnSpy to always return true. See [frameworks](frameworks/index.md). |
| Packed apps with pinning | Samples protected by [commercial packers](../packers/index.md) | Unpack first, then apply standard bypass | Packers like DexGuard or Virbox may encrypt the pinning implementation. Use `frida-dexdump` to recover the DEX, then identify and bypass the pinning method. |

**Repackaging `network_security_config.xml`:**

Decompile, replace the config, reassemble:

```bash
apktool d target.apk -o target_patched/
```

Write a permissive `res/xml/network_security_config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

If the app's `AndroidManifest.xml` does not reference this file, add the attribute:

```xml
<application android:networkSecurityConfig="@xml/network_security_config" ...>
```

```bash
apktool b target_patched/ -o target_patched.apk
apksigner sign --ks debug.keystore target_patched.apk
adb install target_patched.apk
```

## C2 Protocol Identification

Android malware C2 protocols fall into distinct categories. Identifying the protocol type determines the analysis approach. For detailed C2 implementation patterns, see [C2 Communication Techniques](../attacks/c2-techniques.md).

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

### Identifying the Protocol from Captured Traffic

When capturing traffic from an unknown sample, use these indicators to classify the C2 channel:

**HTTP REST patterns:** Look for repeated POST requests to the same URL path (e.g., `/gate.php`, `/api/bot`, `/panel/`). Request bodies are typically JSON with fields like `bot_id`, `action`, `cmd`. Responses contain JSON with command instructions. Polling intervals are usually 30--120 seconds. The User-Agent header is often the default OkHttp string or a hardcoded fake browser UA.

**WebSocket upgrade:** A single HTTP request with `Connection: Upgrade` and `Upgrade: websocket` headers, followed by a persistent TCP connection. Subsequent traffic is framed WebSocket data. Malware WebSocket traffic is bidirectional -- the server pushes commands without the bot polling. Look for periodic ping/pong frames to maintain the connection.

**MQTT identification:** Connects to port 1883 (unencrypted) or 8883 (TLS). The first packet is an MQTT CONNECT with a client ID (often the bot ID). Subsequent packets are PUBLISH and SUBSCRIBE operations. Wireshark decodes MQTT natively. The topic structure often reveals the botnet organization (e.g., `bots/<bot_id>/commands`).

**Telegram Bot API:** All requests go to `api.telegram.org`. URLs contain a bot token in the format `bot<numeric_id>:<alphanumeric_key>`. Common endpoints: `/sendMessage`, `/getUpdates`, `/sendDocument`, `/sendPhoto`. The chat ID in request bodies identifies the operator's Telegram account or group.

**Firebase:** Connections to `firebaseio.com`, `fcm.googleapis.com`, or `firestore.googleapis.com`. FCM traffic uses JSON with `registration_ids` or topic subscriptions. Firestore traffic involves document read/write operations. The Firebase project ID in the hostname identifies the attacker's project.

**Custom TCP:** Non-HTTP traffic on unusual ports. Often has a fixed-size header with a length prefix, command type byte, and binary payload. Use Wireshark's "Follow TCP Stream" to examine the raw bytes. Look for repeating structures that indicate a command protocol. [SpyNote](../malware/families/spynote.md) uses a custom binary protocol on high ports.

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

## Common C2 Protocol Patterns

Practical breakdown of what each C2 protocol looks like in a network capture, with specific indicators to search for. For implementation-level analysis with code samples and family-specific protocol details, see [C2 Communication Techniques](../attacks/c2-techniques.md).

### HTTP REST Polling

The most common C2 pattern across Android malware. The bot registers on first launch, then polls at a fixed interval for commands.

- Repeating POST requests to the same URL path at regular intervals (e.g., `/gate.php`, `/api/bot`, `/panel/gate`)
- JSON request body with a `bot_id` or `device_id` as the primary device identifier
- Consistent polling interval, typically 15--60 seconds, sometimes dynamically configurable via C2 response
- First request (registration beacon) is larger than subsequent polls -- contains device info, installed apps, country code
- Response body contains command IDs/strings when commands are queued, or empty/`{"cmd":"idle"}` when not

### WebSocket Persistent Connections

Used by families that need real-time bidirectional control -- remote access, screen streaming, VNC-like functionality.

- HTTP `Upgrade: websocket` handshake followed by a persistent TCP connection
- WebSocket frames containing JSON messages or binary screen data
- Event-driven message types rather than request-response (e.g., `{"type":"screen_update","data":"..."}`)
- No polling interval -- commands arrive on demand from the C2
- Periodic ping/pong frames as keepalive

### Telegram Bot API Traffic

Abuses Telegram's infrastructure as a free, takedown-resistant C2 channel.

- HTTPS requests to `api.telegram.org/bot<TOKEN>/`
- API methods in the URL path: `sendMessage`, `getUpdates`, `sendDocument`, `sendPhoto`
- Bot token visible in the URL (format: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)
- `chat_id` parameter in request body identifies the operator's Telegram account
- Exfiltrated data often sent as document attachments via `sendDocument`

### Firebase Cloud Messaging Wake-ups

FCM acts as a wake-up channel rather than the primary C2 transport. The push notification triggers the malware to connect to the actual C2 over HTTP or WebSocket.

- Persistent connection to `mtalk.google.com` (FCM backend)
- FCM registration token exchange at startup (`fcmregistrations.googleapis.com`)
- Push payload may contain the C2 URL, a command trigger, or a "wake up and poll" signal
- Correlate FCM push timing with subsequent HTTP requests to find the actual C2 channel
- Difficult to intercept at network layer -- hook `FirebaseMessagingService.onMessageReceived` with Frida instead

### DNS Tunneling Indicators

Rare on Android but used by advanced families to bypass HTTP-layer monitoring entirely.

- Unusually long subdomain labels containing encoded data (e.g., `dGVzdGRhdGE.evil.com`)
- High volume of TXT, CNAME, or NULL record lookups to a single domain
- Subdomain strings with base32/base64-like character patterns
- DNS response records containing encoded payloads rather than legitimate IP addresses
- Query frequency far exceeding normal mobile DNS behavior

### Heartbeat Intervals by Family Type

The polling interval is a useful fingerprint for identifying the malware category during traffic analysis:

| Interval Range | Family Type | Rationale |
|---------------|-------------|-----------|
| Persistent connection (no polling) | WebSocket-based RATs: [Hook](../malware/families/hook.md), [Medusa](../malware/families/medusa.md), [Octo](../malware/families/octo.md) v2 | Real-time remote access requires instant command delivery |
| 5--15 seconds | Active RATs: [SpyNote](../malware/families/spynote.md), [BTMOB RAT](../malware/families/btmob.md) | Interactive remote control with minimal latency |
| 30--60 seconds | Banking trojans: [Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md), [GodFather](../malware/families/godfather.md) | Balance between responsiveness and battery/network stealth |
| 60--120 seconds | Overlay-focused trojans: [Anatsa](../malware/families/anatsa.md), [Xenomorph](../malware/families/xenomorph.md) | Only needs periodic check for new inject targets |
| 5--30 minutes | Spyware, stalkerware: [LightSpy](../malware/families/lightspy.md), [KoSpy](../malware/families/kospy.md) | Long-term surveillance, minimize battery and detection |
| FCM-triggered (no fixed interval) | FCM-wakeup families: [Ermac](../malware/families/ermac.md), [Vultur](../malware/families/vultur.md) v2 | No polling -- FCM push wakes the bot on demand |

### Command Types Visible in Traffic

Common command categories and how they appear in captured network traffic:

| Command Category | Traffic Pattern | Example Payload |
|-----------------|-----------------|-----------------|
| Overlay injection | C2 sends target app package names and inject page URLs | `{"cmd": "inj_enable", "apps": ["com.bank.app"], "url": "https://..."}` |
| SMS interception | Bot forwards intercepted SMS to C2 immediately | `{"cmd": "sms_log", "from": "+1555...", "body": "Your OTP is 123456"}` |
| App list request | C2 requests installed apps, bot responds with package list | `{"cmd": "get_apps"}` response: `{"apps": ["com.whatsapp", ...]}` |
| Screen capture | C2 requests screenshot, bot responds with Base64 image | `{"cmd": "screenshot"}` response: `{"img": "iVBORw0KGgo..."}` |
| Keylog upload | Bot sends accumulated keystrokes periodically | `{"cmd": "keylog", "data": "username: john\npassword: hunter2"}` |
| Contact exfiltration | C2 requests contacts, bot dumps full contact list | `{"cmd": "get_contacts"}` response: `{"contacts": [{...}]}` |
| USSD execution | C2 sends USSD code for the bot to dial | `{"cmd": "ussd", "code": "*100#"}` |
| Push notification | C2 sends notification for social engineering | `{"cmd": "push", "title": "Bank Alert", "body": "..."}` |
| App install/uninstall | C2 instructs bot to install APK from URL or remove app | `{"cmd": "install_app", "url": "https://..."}` |
| Self-destruct | C2 instructs bot to wipe itself | `{"cmd": "kill_bot"}` or `{"cmd": "uninstall"}` |

### Exfiltration Upload Indicators

Large data uploads stand out in traffic captures. Look for these patterns to identify exfiltration activity:

- Sudden spike in upload volume compared to small polling requests
- Multipart form data with file attachments (screenshots, recordings)
- SFTP connections to separate servers ([Vultur](../malware/families/vultur.md) uses SFTP for screen recordings while maintaining HTTP C2)
- Base64-encoded binary data in JSON payloads (inefficient but common)
- Telegram `sendDocument` or `sendPhoto` API calls with file attachments
- Repeated large POSTs to a `/upload` or `/data` endpoint distinct from the command polling endpoint
- Chunked transfer encoding for large payloads that exceed typical JSON body sizes

### Bot Panel URL Fingerprints

C2 panel endpoints often leak information about the malware family or the panel software:

| URL Pattern | Family / Panel Indicator |
|-------------|-------------------------|
| `/gate.php` | [Cerberus](../malware/families/cerberus.md) lineage, [Anubis](../malware/families/anubis.md) |
| `/api/mirrors` | [Anatsa](../malware/families/anatsa.md) |
| `/o/` or `/observer/` | [GodFather](../malware/families/godfather.md) |
| `/connect` WebSocket upgrade | [Hook](../malware/families/hook.md), [Medusa](../malware/families/medusa.md) |
| Non-standard high port (4000--9999) | [SpyNote](../malware/families/spynote.md), raw TCP families |
| Firebase project in hostname | [FireScam](../malware/families/firescam.md), [KoSpy](../malware/families/kospy.md) |
| `/bot<token>/sendMessage` | Telegram-based C2 ([Rafel RAT](../malware/families/rafelrat.md), [Mamont](../malware/families/mamont.md)) |
| `/api/v1/bot/` or `/api/v2/bot/` | Modern panel frameworks (Hook v2, Octo v2) |
| `gate.php` with `action=` parameter | Classic Anubis/Cerberus panel structure |
| `/panel/injects/` | Separate inject kit hosting server |

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

### Hooking javax.crypto.Cipher for Plaintext Capture

When malware applies its own encryption layer on top of HTTPS, the proxy sees encrypted blobs even after TLS termination. Hook `javax.crypto.Cipher` to capture data before encryption and after decryption.

??? example "Cipher.doFinal Hook Script"

    ```javascript
    Java.perform(function () {
        var Cipher = Java.use("javax.crypto.Cipher");
        var ENCRYPT_MODE = 1;
        var DECRYPT_MODE = 2;

        Cipher.doFinal.overload("[B").implementation = function (input) {
            var mode = this.getOpmode();
            var algo = this.getAlgorithm();
            var result = this.doFinal(input);

            if (mode === ENCRYPT_MODE) {
                send({
                    type: "cipher",
                    direction: "encrypt",
                    algorithm: algo,
                    plaintext: bytesToHex(input),
                    ciphertext: bytesToHex(result),
                });
            } else if (mode === DECRYPT_MODE) {
                send({
                    type: "cipher",
                    direction: "decrypt",
                    algorithm: algo,
                    ciphertext: bytesToHex(input),
                    plaintext: bytesToHex(result),
                });
            }

            return result;
        };

        Cipher.doFinal.overload("[B", "int", "int").implementation = function (
            input,
            offset,
            length
        ) {
            var mode = this.getOpmode();
            var algo = this.getAlgorithm();
            var slice = input.slice(offset, offset + length);
            var result = this.doFinal(input, offset, length);

            send({
                type: "cipher",
                direction: mode === ENCRYPT_MODE ? "encrypt" : "decrypt",
                algorithm: algo,
                input: bytesToHex(slice),
                output: bytesToHex(result),
            });

            return result;
        };

        function bytesToHex(bytes) {
            var hex = [];
            for (var i = 0; i < bytes.length; i++) {
                hex.push(("0" + (bytes[i] & 0xff).toString(16)).slice(-2));
            }
            return hex.join("");
        }
    });
    ```

To see the plaintext as readable strings instead of hex, add a UTF-8 decode:

```javascript
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    var StringClass = Java.use("java.lang.String");

    Cipher.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);
        var mode = this.getOpmode();

        if (mode === 1) {
            console.log("[ENCRYPT] " + StringClass.$new(input));
        } else {
            console.log("[DECRYPT] " + StringClass.$new(result));
        }

        return result;
    };
});
```

### Hooking OkHttp Interceptors for Request/Response Logging

For malware that uses OkHttp (the majority of Android banking trojans), hook the interceptor chain to capture fully formed HTTP requests and responses before any application-layer encryption is applied.

??? example "OkHttp Request/Response Logger"

    ```javascript
    Java.perform(function () {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Buffer = Java.use("okio.Buffer");

        var LogInterceptor = Java.registerClass({
            name: "com.bypass.LogInterceptor",
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    var request = chain.request();
                    var url = request.url().toString();
                    var method = request.method();
                    var headers = request.headers().toString();

                    var requestBody = "";
                    if (request.body() !== null) {
                        var buf = Buffer.$new();
                        request.body().writeTo(buf);
                        requestBody = buf.readUtf8();
                    }

                    console.log(">>> " + method + " " + url);
                    console.log("Headers: " + headers);
                    if (requestBody.length > 0) {
                        console.log("Body: " + requestBody);
                    }

                    var response = chain.proceed(request);
                    var responseBody = response.peekBody(Java.use("java.lang.Long").MAX_VALUE.value);
                    var responseString = responseBody.string();

                    console.log("<<< " + response.code() + " " + url);
                    console.log("Response: " + responseString);

                    return response;
                },
            },
        });

        OkHttpClient.$init.overload("okhttp3.OkHttpClient$Builder").implementation =
            function (builder) {
                builder.addInterceptor(LogInterceptor.$new());
                this.$init(builder);
            };
    });
    ```

### Custom Protocol Key Extraction

When malware uses a custom encryption scheme, the decryption key must be extracted at runtime. Common patterns:

**Hardcoded key in code:** Search decompiled source for `SecretKeySpec` construction. The byte array argument is the key.

**Key derived from device info:** Hook the key derivation function to capture the generated key:

```javascript
Java.perform(function () {
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (
        keyBytes,
        algorithm
    ) {
        var key = "";
        for (var i = 0; i < keyBytes.length; i++) {
            key += ("0" + (keyBytes[i] & 0xff).toString(16)).slice(-2);
        }
        console.log("[KEY] " + algorithm + ": " + key);
        return this.$init(keyBytes, algorithm);
    };
});
```

**IV extraction:** Hook `IvParameterSpec` to capture the initialization vector alongside the key:

```javascript
Java.perform(function () {
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

    IvParameterSpec.$init.overload("[B").implementation = function (iv) {
        var hex = "";
        for (var i = 0; i < iv.length; i++) {
            hex += ("0" + (iv[i] & 0xff).toString(16)).slice(-2);
        }
        console.log("[IV] " + hex);
        return this.$init(iv);
    };
});
```

**Key fetched from C2 server:** Hook the network layer to capture the key exchange, then hook `SecretKeySpec` to confirm the derived key.

**Base64 + XOR encoding:** Simpler families XOR the payload with a static key, then Base64-encode. Hook the encoding/decoding function directly, or extract the XOR key from the decompiled source and decode captured traffic in the proxy.

**Custom binary serialization:** Some families use Protobuf, MessagePack, or custom binary formats instead of JSON. Hook the serialization/deserialization methods. For Protobuf, extract the `.proto` definitions from the decompiled code or reverse them from the wire format using `protoc --decode_raw`.

**Hooking at the network layer boundary:** Instead of hooking crypto APIs (which capture all crypto operations including non-network ones), hook the app's own network methods. Find the class that builds HTTP requests (typically a class wrapping OkHttp or HttpURLConnection) and hook its send/receive methods to capture plaintext before the app's encryption layer. This is often cleaner because you get structured C2 data rather than raw bytes from every `Cipher.doFinal` call.

!!! tip "Combining Hooks"
    Run the Cipher hook, SecretKeySpec hook, and IvParameterSpec hook together to capture the key, IV, and encrypted/decrypted data simultaneously. This gives you everything needed to write a standalone decryptor for offline analysis of PCAP captures.

## Frida Scripts for Network Interception

For general Frida setup and fundamentals, see [Hooking](hooking.md). The scripts below cover network-layer hooks beyond the OkHttp interceptor above. These target alternative HTTP clients, WebSocket C2, native TLS, DNS resolution, and Telegram-based C2.

### HttpURLConnection Hook

Older malware and some families prefer `java.net.HttpURLConnection` over OkHttp. Hook the connection lifecycle to capture URLs, request methods, and response codes:

```javascript
Java.perform(function() {
    var URL = Java.use("java.net.URL");

    URL.openConnection.overload().implementation = function() {
        var conn = this.openConnection();
        send("[URL] " + this.toString());
        return conn;
    };

    var HttpURLConnection = Java.use("java.net.HttpURLConnection");

    HttpURLConnection.getInputStream.implementation = function() {
        var is = this.getInputStream();
        send("[RESP] " + this.getURL().toString() + " code=" + this.getResponseCode());
        return is;
    };

    HttpURLConnection.getOutputStream.implementation = function() {
        send("[REQ OUT] " + this.getURL().toString() + " method=" + this.getRequestMethod());
        return this.getOutputStream();
    };
});
```

To capture the actual request body written to the OutputStream, hook `OutputStream.write`:

```javascript
Java.perform(function() {
    var OutputStream = Java.use("java.io.OutputStream");

    OutputStream.write.overload("[B").implementation = function(bytes) {
        try {
            send("[WRITE] " + Java.use("java.lang.String").$new(bytes));
        } catch(e) {}
        this.write(bytes);
    };
});
```

### WebSocket Interception

For families using WebSocket C2 ([Hook](../malware/families/hook.md), [Medusa](../malware/families/medusa.md), [Octo](../malware/families/octo.md) v2, [TsarBot](../malware/families/tsarbot.md)), hook both outgoing messages and incoming commands to capture the full bidirectional command stream:

```javascript
Java.perform(function() {
    var RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");

    RealWebSocket.send.overload("java.lang.String").implementation = function(text) {
        send("[WS SEND] " + text);
        return this.send(text);
    };

    RealWebSocket.send.overload("okio.ByteString").implementation = function(bytes) {
        send("[WS SEND BIN] " + bytes.hex());
        return this.send(bytes);
    };

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var cls = Java.use(className);
                if (cls.class.getSuperclass() &&
                    cls.class.getSuperclass().getName() === "okhttp3.WebSocketListener") {
                    cls.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function(ws, text) {
                        send("[WS RECV] " + text);
                        this.onMessage(ws, text);
                    };
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
});
```

### Native SSL_write / SSL_read Hook

For malware using native TLS (NDK-based HTTP clients, custom native networking), Java-layer hooks produce nothing. Hook the OpenSSL/BoringSSL functions directly in the native layer to capture all TLS plaintext regardless of the Java HTTP client used:

```javascript
var SSL_write = Module.findExportByName("libssl.so", "SSL_write");
var SSL_read = Module.findExportByName("libssl.so", "SSL_read");

if (SSL_write) {
    Interceptor.attach(SSL_write, {
        onEnter: function(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() > 0) {
                send("[SSL_write] " + Memory.readUtf8String(this.buf, this.len));
            }
        }
    });
}

if (SSL_read) {
    Interceptor.attach(SSL_read, {
        onEnter: function(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead > 0) {
                send("[SSL_read] " + Memory.readUtf8String(this.buf, bytesRead));
            }
        }
    });
}
```

For Flutter apps that bundle BoringSSL inside `libflutter.so`, replace `libssl.so` with `libflutter.so` in the export lookup. The function names are the same. See [Development Frameworks](frameworks/index.md) for Flutter-specific analysis.

### DNS Resolution Hook

Capture all domain resolutions to identify C2 domains, DGA output, and dead drop resolver lookups:

```javascript
Java.perform(function() {
    var InetAddress = Java.use("java.net.InetAddress");

    InetAddress.getByName.overload("java.lang.String").implementation = function(host) {
        var result = this.getByName(host);
        send("[DNS] " + host + " -> " + result.getHostAddress());
        return result;
    };

    InetAddress.getAllByName.overload("java.lang.String").implementation = function(host) {
        var results = this.getAllByName(host);
        var ips = [];
        for (var i = 0; i < results.length; i++) {
            ips.push(results[i].getHostAddress());
        }
        send("[DNS ALL] " + host + " -> " + ips.join(", "));
        return results;
    };
});
```

### Telegram Bot API Interception

For families using Telegram as C2 ([Rafel RAT](../malware/families/rafelrat.md), [Mamont](../malware/families/mamont.md)), hook HTTP requests and filter for the Telegram API to extract bot tokens and chat IDs:

```javascript
Java.perform(function() {
    var URL = Java.use("java.net.URL");

    URL.openConnection.overload().implementation = function() {
        var urlStr = this.toString();
        if (urlStr.indexOf("api.telegram.org") !== -1) {
            var parts = urlStr.split("/");
            for (var i = 0; i < parts.length; i++) {
                if (parts[i].indexOf("bot") === 0) {
                    send("[TELEGRAM] Bot token: " + parts[i].substring(3));
                }
            }
            send("[TELEGRAM] " + urlStr);
        }
        return this.openConnection();
    };
});
```

## Traffic Analysis Checklist

Systematic checklist for analyzing captured C2 traffic after interception and decryption. Work through each phase to fully characterize the malware's network behavior.

### Registration Beacon

The first request after installation or first launch. Contains device fingerprinting data used by the C2 panel to identify and categorize the bot.

- [ ] Identify the registration endpoint URL path and HTTP method
- [ ] Extract the bot ID generation logic (ANDROID_ID, IMEI, UUID, or composite hash)
- [ ] Document all device info fields: model, OS version, language, country, carrier, screen resolution
- [ ] Check for installed app list or targeted app list (drives which injection overlays the C2 serves)
- [ ] Note the C2 response -- configuration block, initial command set, or just an acknowledgment
- [ ] Determine whether registration repeats on every launch or only on first run

### Heartbeat Interval

How the bot maintains contact between active command sessions.

- [ ] Measure the polling interval (capture at least 5--10 cycles to establish the pattern)
- [ ] Determine if the interval is hardcoded in the APK or dynamically set by C2 response fields
- [ ] Look for jitter or randomization in the interval (anti-detection measure)
- [ ] Identify the keepalive transport: HTTP polling, WebSocket ping/pong, or FCM push
- [ ] Test C2 unreachable behavior: retry logic, exponential backoff, fallback URLs, DGA activation
- [ ] Check if the interval changes after receiving a command (some families poll faster during active operations)

### Command Format

The structure and encoding of commands from the C2 to the bot.

- [ ] Map the full command set -- capture as many distinct commands as possible
- [ ] Determine command identifier format: numeric IDs, string names, or mixed
- [ ] Document command parameters and expected bot response for each command type
- [ ] Check for application-layer encryption or encoding on top of HTTPS (Base64, AES, XOR)
- [ ] Identify targeted vs broadcast commands (bot ID filter, country filter, app-specific targeting)
- [ ] Look for injection/overlay URL delivery as a distinct command type
- [ ] Note the acknowledgment flow -- does the bot confirm command receipt and/or execution result?

### Exfiltration Patterns

How and when stolen data leaves the device.

- [ ] Identify the exfiltration endpoint (same C2, separate data server, or third-party service like Telegram)
- [ ] Document exfiltration triggers: on-demand via C2 command, automatic on credential capture, or periodic batch
- [ ] Distinguish real-time streaming (WebSocket, screen share) from batched uploads (HTTP POST)
- [ ] Check for file uploads (screenshots, recordings, documents) and note encoding and content type
- [ ] Look for data compression or chunking for large payloads
- [ ] Catalog exfiltrated data types: credentials, SMS, contacts, call logs, photos, keystrokes, accessibility events

## mitmproxy Scripting

[mitmproxy](https://mitmproxy.org/) provides a Python addon API for programmatic traffic analysis. Writing addon scripts automates C2 payload decoding, Base64 body decryption, and bot ID extraction during dynamic analysis -- significantly more efficient than manually inspecting each flow.

### C2 Traffic Decoder Addon

This addon intercepts traffic to known C2 domains, attempts JSON parsing and Base64 decoding on request/response bodies, extracts bot IDs, and logs everything to structured JSONL files.

??? example "mitmproxy C2 Traffic Decoder"

    ```python
    import json
    import base64
    from mitmproxy import http


    C2_DOMAINS = ["c2.example.com", "gate.malware.net"]
    BOT_ID_KEYS = ["bot_id", "device_id", "uid", "id", "botId", "deviceId"]


    class C2Decoder:
        def __init__(self):
            self.seen_bot_ids = set()

        def request(self, flow: http.HTTPFlow):
            if not any(d in flow.request.pretty_host for d in C2_DOMAINS):
                return

            entry = {
                "direction": "request",
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "timestamp": flow.request.timestamp_start,
            }

            body = flow.request.get_text()
            if body:
                entry["body"] = self._try_decode(body)
                self._extract_bot_id(entry["body"])

            self._log(entry)

        def response(self, flow: http.HTTPFlow):
            if not any(d in flow.request.pretty_host for d in C2_DOMAINS):
                return

            if not flow.response or not flow.response.content:
                return

            entry = {
                "direction": "response",
                "url": flow.request.pretty_url,
                "status": flow.response.status_code,
                "body": self._try_decode(flow.response.get_text()),
            }

            self._log(entry)

        def _try_decode(self, data: str):
            try:
                return json.loads(data)
            except (json.JSONDecodeError, TypeError):
                pass

            try:
                decoded = base64.b64decode(data).decode("utf-8", errors="replace")
                try:
                    return json.loads(decoded)
                except (json.JSONDecodeError, TypeError):
                    return {"base64_decoded": decoded}
            except Exception:
                pass

            return data

        def _extract_bot_id(self, body):
            if not isinstance(body, dict):
                return
            for key in BOT_ID_KEYS:
                if key in body and body[key] not in self.seen_bot_ids:
                    self.seen_bot_ids.add(body[key])
                    with open("/tmp/c2_bot_ids.txt", "a") as f:
                        f.write(f"{body[key]}\n")

        def _log(self, entry):
            with open("/tmp/c2_traffic.jsonl", "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")


    addons = [C2Decoder()]
    ```

Set `C2_DOMAINS` to the malware's C2 infrastructure, then run:

```bash
mitmdump -s c2_decoder.py --set block_global=false -p 8080
```

After the analysis session, review captured data:

```bash
cat /tmp/c2_traffic.jsonl | python3 -m json.tool --no-ensure-ascii
sort -u /tmp/c2_bot_ids.txt
```

For live interactive analysis with simultaneous logging:

```bash
mitmproxy -s c2_decoder.py --set block_global=false -p 8080
```

The addon logs decoded C2 traffic (JSON-parsed or Base64-decoded) to `/tmp/c2_traffic.jsonl` and extracted bot IDs to `/tmp/c2_bot_ids.txt`, while the TUI lets you inspect individual flows in real time.

## IOC Extraction from Network Traffic

After capturing and decrypting C2 traffic, extract indicators of compromise (IOCs) systematically. These IOCs feed into detection rules, threat intelligence platforms, and infrastructure tracking.

### What to Extract

| IOC Type | Where to Find It | Example |
|----------|------------------|---------|
| C2 domains | DNS queries, HTTP Host header, URL paths | `evil-panel.com`, `api.malware-c2.xyz` |
| C2 IP addresses | DNS resolution, direct IP connections | `185.215.113.x`, `91.92.240.x` |
| URL paths | HTTP request URIs | `/gate.php`, `/api/v2/bot`, `/panel/injects` |
| Bot registration format | First POST request after install | `{"bot_id": "...", "tag": "...", "country": "..."}` |
| Bot ID generation | Registration payload, User-Agent, or URL param | IMEI, Android ID, or random UUID |
| Command polling interval | Time between repeated GET/POST requests | 30s, 60s, 120s between identical requests |
| Command format | C2 response bodies | `{"command": "sms_intercept", "params": {...}}` |
| Exfiltration data format | POST bodies containing stolen data | JSON with SMS content, contacts, credentials |
| Inject kit download URLs | Responses containing overlay/phishing page URLs | `https://cdn.evil.com/injects/com.bank.app.html` |
| Telegram bot tokens | URLs to `api.telegram.org` | `bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11` |
| Firebase project IDs | Hostnames in Firebase API calls | `malware-project-12345.firebaseio.com` |
| Encryption keys | `SecretKeySpec` hook output, hardcoded strings | AES keys, XOR keys, RC4 keys |
| User-Agent strings | HTTP request headers | Custom or default OkHttp UA |
| TLS certificate fingerprints | Pinned certificates in the APK or observed in traffic | SHA-256 hash of the C2 server certificate |

### Bot Registration Analysis

The first network request after installation typically registers the bot with the C2 panel. This registration request reveals the botnet's organization:

```json
{
    "bot_id": "a1b2c3d4e5f6",
    "tag": "campaign_2024_q1",
    "country": "US",
    "operator": "main",
    "model": "Pixel 6",
    "android_version": "13",
    "app_list": ["com.bank.app1", "com.bank.app2"],
    "permissions": ["accessibility", "sms", "overlay"]
}
```

Key fields to note:

- **bot_id** -- how the operator tracks individual victims. Often derived from Android ID, IMEI, or a random UUID stored in SharedPreferences.
- **tag** -- campaign identifier. Links this sample to a specific distribution campaign.
- **app_list** -- list of installed apps sent to the C2 so it knows which inject overlays to serve. Reveals the target list.
- **permissions** -- tells the C2 what capabilities the bot has, which determines what commands it can receive.

### Command Polling Pattern Identification

Monitor the timing and structure of repeated requests to understand the C2 polling mechanism:

```
[00:00] POST /gate.php  {"action": "register", "bot_id": "abc123", ...}
[00:01] POST /gate.php  {"action": "poll", "bot_id": "abc123"}
[01:01] POST /gate.php  {"action": "poll", "bot_id": "abc123"}
[02:01] POST /gate.php  {"action": "poll", "bot_id": "abc123"}
[02:02] POST /gate.php  {"action": "result", "bot_id": "abc123", "sms": [...]}
```

From this pattern: registration happens once, polling occurs every 60 seconds, and exfiltration requests are sent immediately when new data is available.

### Inject Kit URL Extraction

Banking trojans download HTML/JS overlay pages (inject kits) from the C2 to display over legitimate banking apps. These URLs are high-value IOCs:

```
GET /injects/list?bot_id=abc123&apps=com.bank.app1,com.bank.app2
```

Response:

```json
{
    "injects": [
        {
            "app": "com.bank.app1",
            "url": "https://cdn.evil.com/injects/com.bank.app1.html"
        },
        {
            "app": "com.bank.app2",
            "url": "https://cdn.evil.com/injects/com.bank.app2.html"
        }
    ]
}
```

Download and archive these inject pages -- they contain the phishing forms and reveal which financial institutions the campaign targets.

### Automated IOC Extraction with mitmproxy

Use a mitmproxy script to automatically extract and log IOCs from intercepted traffic:

??? example "mitmproxy IOC Extraction Script"

    ```python
    import json
    import re
    from mitmproxy import http

    iocs = {
        "domains": set(),
        "ips": set(),
        "paths": set(),
        "bot_ids": set(),
        "telegram_tokens": set(),
    }

    telegram_re = re.compile(r"bot(\d+:[A-Za-z0-9_-]+)")
    ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def response(flow: http.HTTPFlow):
        iocs["domains"].add(flow.request.host)
        iocs["paths"].add(flow.request.path)

        ip_match = ip_re.match(flow.request.host)
        if ip_match:
            iocs["ips"].add(flow.request.host)

        tg_match = telegram_re.search(flow.request.url)
        if tg_match:
            iocs["telegram_tokens"].add(tg_match.group(1))

        if flow.response and flow.response.content:
            try:
                body = json.loads(flow.response.content)
                if isinstance(body, dict):
                    for key in ["bot_id", "botId", "id", "uid"]:
                        if key in body:
                            iocs["bot_ids"].add(str(body[key]))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        with open("/tmp/iocs.json", "w") as f:
            json.dump(
                {k: list(v) for k, v in iocs.items()},
                f,
                indent=2,
            )
    ```

Run with:

```bash
mitmproxy --mode transparent --listen-port 8080 -s ioc_extract.py
```

### IOC Extraction from Raw Packet Captures

For non-HTTP protocols or when proxy interception is not possible, extract IOCs directly from pcap files using tshark:

```bash
tshark -r capture.pcap -T fields -e dns.qry.name | sort -u
```

```bash
tshark -r capture.pcap -T fields -e ip.dst | sort -u
```

```bash
tshark -r capture.pcap -Y "mqtt" -T fields -e mqtt.topic -e mqtt.msg
```

```bash
tshark -r capture.pcap -Y "tcp.port == 443" -T fields -e tls.handshake.extensions_server_name | sort -u
```

For custom TCP protocols, export the TCP stream as raw bytes and analyze the binary structure to extract embedded strings, IPs, or domain names:

```bash
tshark -r capture.pcap -Y "tcp.stream eq 0" -T fields -e data.data | xxd -r -p > stream0.bin
strings stream0.bin
```

### IOC Pivot Points

Extracted IOCs can be pivoted to discover related infrastructure, additional samples, and operator identity:

| IOC Type | Pivot Method | What It Reveals |
|----------|-------------|-----------------|
| C2 domain | Passive DNS (VirusTotal, SecurityTrails, Farsight DNSDB) | IP address history, co-hosted domains, registration timeline |
| C2 IP address | Shodan/Censys scan, reverse DNS, certificate search | Open admin panels, other services on same IP, hosting provider |
| Telegram bot token | Query `https://api.telegram.org/bot<token>/getMe` | Bot name, username, and whether the token is still active |
| Firebase project ID | Cross-reference with other samples using the same project | Campaign scope, shared infrastructure across families |
| SSL certificate hash | Certificate transparency logs (crt.sh) | All domains using the same certificate, issuance timeline |
| Overlay injection URLs | WHOIS, hosting provider, URL scan on VirusTotal | Shared injection hosting infrastructure across campaigns |
| Campaign tag | Search tag across your sample corpus and threat intel feeds | Distribution campaigns, dropper apps, target geography |
| Bot ID format | Compare generation logic across samples | Family lineage, code reuse between campaigns |
| User-Agent string | Search in proxy logs and threat intel databases | Other samples using the same hardcoded UA string |
| Encryption key | Compare static keys across samples | Shared builder, same operator, campaign correlation |

For detailed C2 protocol structures and command mappings, see [C2 Communication Techniques](../attacks/c2-techniques.md).

## Tools

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS interception and modification |
| [mitmproxy](https://mitmproxy.org/) | Scriptable HTTPS proxy with Python addon API for automated C2 analysis |
| [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | No-root Android traffic capture via local VPN |
| [Wireshark](https://www.wireshark.org/) | Packet-level protocol analysis (MQTT, WebSocket, custom TCP) |
| [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) | Command-line Wireshark for scripted pcap analysis and IOC extraction |
| [tcpdump](https://www.tcpdump.org/) | Command-line packet capture on device |
| [Frida](https://frida.re/) | Runtime instrumentation for network hooks, SSL bypass, crypto capture |
| [Objection](https://github.com/sensepost/objection) | One-command SSL pinning bypass and runtime exploration |
| [reFrida](https://github.com/zahidaz/refrida) | Browser-based Frida IDE with network activity monitoring |
| [reFlutter](https://github.com/Impact-I/reFlutter) | Flutter `libflutter.so` patching for BoringSSL bypass |
| [MagiskTrustUserCerts](https://github.com/NVISOsecurity/MagiskTrustUserCerts) | Magisk module to move user CA certs to system store |
| [apktool](https://apktool.org/) | APK decompilation for `network_security_config.xml` patching |
| [CyberChef](https://gchq.github.io/CyberChef/) | Browser-based decoder for AES, Base64, XOR on captured payloads |
