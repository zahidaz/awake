# Network Traffic Interception

Intercepting, modifying, and redirecting network traffic on Android devices through VPN service abuse, DNS manipulation, proxy configuration, and certificate store attacks. Malware uses these techniques to capture credentials transmitted over HTTPS, redirect banking traffic to phishing servers, and exfiltrate data through controlled network tunnels.

See also: [C2 Communication](c2-techniques.md), [WebView Exploitation](webview-exploitation.md), [Phishing Techniques](phishing-techniques.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1638](https://attack.mitre.org/techniques/T1638/) | Adversary-in-the-Middle | Credential Access, Collection |

    T1638 covers network-level interception including VPN abuse, DNS hijacking, and MITM attacks for credential capture and traffic manipulation.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | VPN interception | `BIND_VPN_SERVICE` (user must approve VPN connection dialog) |
    | DNS manipulation | WiFi network access + router default credential exploitation |
    | Proxy configuration | `BIND_ACCESSIBILITY_SERVICE` or `BIND_DEVICE_ADMIN` to modify WiFi settings |
    | Certificate installation | User CA: Settings navigation; System CA: root access (Android 14+ requires APEX modification) |

## VpnService Abuse

### How VpnService Works

Android's `VpnService` API creates a TUN (network tunnel) interface that captures all device traffic. The app receives raw IP packets, can inspect, modify, or forward them to any destination. Only one VPN service can be active at a time.

```java
public class MaliciousVpn extends VpnService {
    @Override
    public void onCreate() {
        Builder builder = new Builder();
        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        ParcelFileDescriptor tun = builder.establish();
    }
}
```

The `establish()` call triggers a system dialog requiring explicit user consent. Once approved, all network traffic flows through the TUN interface. The VPN icon appears in the status bar.

### Legitimate Architecture

[NetGuard](https://github.com/M66B/NetGuard) and [TrackerControl](https://github.com/TrackerControl/tracker-control-android) (a NetGuard fork) demonstrate the legitimate architecture: a local VPN that routes all traffic through the app's process for per-app firewall filtering and tracker blocking. No traffic leaves the device through an external VPN tunnel.

This same architecture enables malicious use. An app could capture all HTTP/HTTPS traffic (TLS handshake visible, payload encrypted), DNS queries (in plaintext unless DoH/DoT), and per-app network activity. For TLS-encrypted traffic, the malware would additionally need to install a certificate to perform MITM decryption.

### Malicious VPN Apps

| App/Campaign | Scale | Technique | Source |
|-------------|-------|-----------|--------|
| Free VPN apps (28 flagged) | 700M+ combined users | Security flaws, traffic logging, China-linked ownership | [Malwarebytes 2025](https://www.malwarebytes.com/blog/news/2025/09/popular-android-vpn-apps-found-to-have-security-flaws-and-china-links) |
| Proxylib SDK | Embedded in VPN apps | Converts devices into residential proxy nodes | [HUMAN Security](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-proxylib-android) |
| MVDroid study | 14,000+ VPN apps analyzed | 18% did not encrypt traffic, 38% injected malware/ads | [PMC/Neural Networks study](https://pmc.ncbi.nlm.nih.gov/articles/PMC10069720/) |

### Per-App Traffic Control

`VpnService.Builder` supports per-app routing:

- `addAllowedApplication(String packageName)`: Route only this app's traffic through VPN
- `addDisallowedApplication(String packageName)`: Exclude this app from VPN

Malware can selectively intercept only banking app traffic while leaving other traffic untouched, reducing the chance of detection through general browsing disruption.

## DNS Manipulation

### Roaming Mantis DNS Changer

[Kaspersky documented Roaming Mantis](https://securelist.com/roaming-mantis-dns-changer-in-malicious-mobile-app/108464/) (also known as Shaoye, using the Wroba.o/MoqHao/XLoader malware) implementing a DNS changer function in September 2022 targeting WiFi routers used primarily in South Korea.

The attack flow:

1. Malware on the infected Android device scans the local network for the WiFi router gateway
2. Attempts to log in using [default admin credentials](https://www.bleepingcomputer.com/news/security/roaming-mantis-android-malware-adds-dns-changer-to-hack-wifi-routers/) (e.g., `admin:admin`) common to consumer routers
3. If successful, changes the router's DNS settings to attacker-controlled DNS servers
4. All devices on the network now resolve domains through the rogue DNS
5. Banking domains resolve to phishing servers that serve credential harvesting pages

The DNS changer generates URL queries with rogue DNS IPs tailored to the specific router model detected. The attacker can then redirect to malicious hosts and interfere with security product updates from any device on the compromised network.

### On-Device DNS Modification

On rooted devices, malware can modify `/etc/hosts` or DNS resolver configuration directly. On non-rooted devices, the VpnService approach is the primary vector: the VPN intercepts DNS queries and returns forged responses pointing to attacker-controlled IPs.

Android 9 introduced Private DNS (DNS-over-TLS), and Android 13 added DNS-over-HTTPS support. These encrypt DNS queries, but malware running as a VPN service intercepts traffic before it reaches the DNS resolver, so encrypted DNS does not protect against on-device VPN-based interception.

## Proxy Configuration Attacks

### WiFi Proxy Manipulation

Malware with accessibility service or device admin privileges can modify WiFi proxy settings to route HTTP(S) traffic through an attacker-controlled proxy:

1. **Accessibility-based**: Navigate `Settings > WiFi > [Network] > Proxy` and configure manual proxy pointing to attacker server
2. **Device admin**: Use `DevicePolicyManager` global proxy setting
3. **Programmatic**: `WifiManager` API to modify network configuration (requires `CHANGE_WIFI_STATE`)

Proxy trojans [dynamically configure proxy settings only when triggered by C2](https://zimperium.com/glossary/proxy-trojans/), minimizing their footprint and making detection harder during static analysis.

### Residential Proxy Conversion

Some malware converts infected devices into residential proxy nodes. The device's IP address is sold to proxy services, routing third-party traffic through the victim's connection. The Proxylib SDK was embedded in multiple VPN apps on the Play Store for this purpose.

## Certificate Store Attacks

### User Certificate Installation

Installing a user-trusted CA certificate enables MITM decryption of HTTPS traffic. Android 7.0+ changed the default trust behavior:

| Android Version | User CA Trust Behavior |
|----------------|----------------------|
| Pre-7.0 | User CAs trusted by all apps by default |
| 7.0+ | User CAs trusted only by apps that explicitly opt in via `network_security_config.xml` |
| 7.0+ | System CAs still trusted by all apps |

This means that on Android 7.0+, installing a user CA only intercepts traffic from apps that have `<trust-anchors>` configured to include user certificates. Most banking apps do not, making user CA installation insufficient for banking credential interception.

### System Certificate Installation

Installing a system-level CA certificate enables universal HTTPS interception. This requires root access to write to the system certificate store.

| Android Version | System CA Store Location | Root Write Method |
|----------------|------------------------|-------------------|
| Pre-14 | `/system/etc/security/cacerts/` | Remount `/system` as read-write |
| 14+ | `/apex/com.android.conscrypt/cacerts/` (immutable) | APEX mount cannot be remounted |

[Android 14 moved system certificates into the Conscrypt APEX module](https://httptoolkit.com/blog/android-14-breaks-system-certificate-installation/), making them immutable even with root access. The entire `/apex` filesystem is read-only. [HTTP Toolkit documented workarounds](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/) involving mount namespace manipulation, but these are fragile and process-specific.

Android 14's change also enables [remote certificate store updates via Google Play](https://www.xda-developers.com/android-14-root-certificates-updatable/) system updates, allowing Google to revoke compromised CAs without waiting for OEM OTA updates.

### Certificate Pinning

Apps can additionally implement certificate pinning to reject any CA not matching a specific pin, including system CAs:

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">bank.example.com</domain>
        <pin-set expiration="2025-01-01">
            <pin digest="SHA-256">base64EncodedPin=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

Pinning is bypassed by hooking the TLS verification at runtime (Frida, Xposed), patching the `network_security_config.xml`, or hooking `TrustManager` implementations. Malware performing MITM does not typically need to bypass pinning because it controls the device and can hook the verification process.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| Pre-7.0 | <24 | All CAs (system + user) trusted by default | User CA MITM trivial for all apps |
| 7.0 | 24 | [Network Security Config](https://developer.android.com/privacy-and-security/security-config) introduced; user CAs untrusted by default | MITM requires root for system CA or app-specific config |
| 7.0 | 24 | Declarative certificate pinning support | Apps can pin without code changes; attackers hook `TrustManager` to bypass |
| 9.0 | 28 | [Cleartext (HTTP) traffic blocked by default](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted) | Apps must explicitly allow HTTP; credential sniffing over HTTP eliminated for compliant apps |
| 9.0 | 28 | Private DNS (DNS-over-TLS) support | DNS queries encrypted when configured; VPN-based interception still works |
| 10 | 29 | TLS 1.3 enabled by default | Stronger encryption, but irrelevant if VPN intercepts pre-TLS |
| 13 | 33 | DNS-over-HTTPS support | Additional DNS encryption option |
| 14 | 34 | [System CA store moved to immutable APEX](https://httptoolkit.com/blog/android-14-breaks-system-certificate-installation/) | Even root cannot permanently modify trust store |
| 14 | 34 | [Updatable root certificates via Google Play](https://www.xda-developers.com/android-14-root-certificates-updatable/) | Faster CA revocation response |

## Families Using Network Interception

| Family | Technique | Target | Source |
|--------|-----------|--------|--------|
| [MoqHao](../malware/families/moqhao.md) / Roaming Mantis | WiFi router DNS hijacking | South Korean users | [Kaspersky](https://securelist.com/roaming-mantis-dns-changer-in-malicious-mobile-app/108464/) |
| BTMOB RAT | Accessibility + proxy configuration | Banking apps | [Cyble](https://cyble.com/blog/btmob-rat-newly-discovered-android-malware/) |
| Proxy trojans (generic) | VpnService residential proxy | Device IP monetization | [Zimperium](https://zimperium.com/glossary/proxy-trojans/) |
| [Mandrake](../malware/families/mandrake.md) | Certificate installation + traffic routing | Targeted surveillance | [Kaspersky](https://securelist.com/mandrake-apps-return-to-google-play/113024/) |
| Stalkerware (generic) | MDM profile with proxy + CA cert | Domestic surveillance | Commercial stalkerware vendors |

## Detection During Analysis

??? example "Static Indicators"

    - `BIND_VPN_SERVICE` permission in manifest
    - `VpnService` subclass with `establish()` call
    - Router default credential strings (e.g., `admin:admin`, `admin:password`)
    - DNS server IP addresses hardcoded in code
    - `WifiManager` configuration modification calls
    - `KeyStore` or `CertificateFactory` usage for CA certificate installation
    - `X509TrustManager` custom implementation that accepts all certificates

??? example "Dynamic Indicators"

    - VPN icon appearing in status bar without user-initiated VPN connection
    - DNS queries resolving to unexpected IP addresses
    - WiFi proxy settings changed without user action
    - New user CA certificate appearing in Settings > Security > Trusted Credentials
    - All HTTPS traffic routing through a single proxy IP
    - Router DNS settings changed after malware installation
