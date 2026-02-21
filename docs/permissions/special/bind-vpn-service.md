# BIND_VPN_SERVICE

System permission that allows an app to bind to the VPN service framework, routing all device network traffic through the app. A VPN app sees every packet entering and leaving the device, making this the most powerful network interception capability available without root. Malicious VPN apps have been downloaded over 700 million times, and the VPN permission model creates a trust inversion: users install VPN apps specifically to protect their traffic, but a malicious VPN captures everything. The permission requires explicit user consent through a system confirmation dialog, but social engineering easily overcomes this since users expect VPN apps to request network access.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.BIND_VPN_SERVICE` |
| Protection Level | `signature` |
| Grant Method | System VPN consent dialog (`VpnService.prepare()`) |
| Introduced | API 14 (Android 4.0) |
| User Visibility | System dialog: "Allow [app] to set up a VPN connection that allows it to monitor network traffic?" |
| Play Store Policy | Restricted to apps whose core function is VPN service |

The `signature` protection level means only the system can bind to the VPN service. The app declares the service; the system manages the binding. The user must approve a system-level dialog before the VPN activates. Android displays a persistent key icon in the status bar while a VPN is active.

## What It Enables

### VPN Service Implementation

```java
public class MaliciousVpn extends VpnService {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Builder builder = new Builder();
        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("8.8.8.8");
        ParcelFileDescriptor tunnel = builder.establish();
        return START_STICKY;
    }
}
```

`addRoute("0.0.0.0", 0)` captures all IPv4 traffic. The VPN service receives raw IP packets through the tunnel file descriptor, can inspect, modify, log, or redirect any packet before forwarding it.

### Capabilities

| Capability | Technical Detail |
|-----------|-----------------|
| Full traffic capture | All TCP/UDP/ICMP packets pass through the VPN tunnel |
| DNS interception | Custom DNS server specification; can log or modify all DNS queries |
| Traffic modification | Packets can be altered in transit (inject ads, modify responses) |
| Selective routing | Route specific IP ranges through the VPN, bypass others |
| TLS interception | With a trusted CA certificate installed, can perform MITM on HTTPS |
| Per-app filtering | `addAllowedApplication()` / `addDisallowedApplication()` to target specific apps |

## Abuse in Malware

### Traffic Interception

The primary threat. A malicious VPN silently captures:

| Data | How |
|------|-----|
| Unencrypted HTTP traffic | Read directly from tunnel packets |
| DNS queries | All domain lookups visible, revealing browsing history and app usage |
| TLS metadata | Server Name Indication (SNI) in TLS ClientHello reveals domain names |
| Connection patterns | Timing, frequency, and volume of connections to specific servers |
| App-level traffic | Per-app VPN routing identifies which app generates each connection |

### DNS Manipulation

Malicious VPNs can redirect DNS queries:

- Redirect banking domains to phishing servers
- Block security update and AV signature domains
- Inject ads by redirecting content domains
- Exfiltrate DNS query logs (full browsing history)

### Malicious VPN App Scale

[Multiple studies have documented](https://www.top10vpn.com/research/free-vpn-investigations/) the scale of the threat:

| Finding | Source |
|---------|--------|
| 700M+ downloads of potentially malicious free VPN apps on Google Play | Top10VPN (2024) |
| 38% of free VPN apps on Android contain malware indicators | CSIRO study |
| 75% of free VPN apps use at least one tracking library | CSIRO study |
| 18% of free VPN apps do not encrypt traffic at all | CSIRO study |
| VPN apps are in the top 5 most requested app categories by malware-laced apps | Multiple researchers |

### Iranian Surveillanceware

State-sponsored actors use fake VPN apps to target dissidents:

| Family | Technique |
|--------|-----------|
| [DCHSpy](../../malware/families/dchspy.md) | Fake VPN apps (Earth VPN, Comodo VPN, Hide VPN) targeting Iranian dissidents |
| [Hermit](../../malware/families/hermit.md) | RCS Lab's commercial spyware distributed as connectivity tools |

### Network-Based Attacks

| Attack | Mechanism |
|--------|-----------|
| Credential theft | Capture unencrypted login forms in HTTP traffic |
| Session hijacking | Steal session cookies from unencrypted connections |
| Ad injection | Modify HTTP responses to inject advertising content |
| Phishing redirect | DNS redirect banking domains to look-alike phishing pages |
| Data exfiltration logging | Record all traffic destinations and volumes |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 4.0 | 14 | VPN Service API introduced | Third-party VPN apps possible |
| 4.2 | 17 | Always-on VPN option | Device can enforce traffic only through VPN |
| 7.0 | 24 | Per-app VPN filtering | `addAllowedApplication()` enables targeting specific apps |
| 8.0 | 26 | Always-on VPN in Settings | Users can require VPN for all traffic |
| 12 | 31 | VPN lockdown mode improvements | Block non-VPN traffic more strictly |
| 14 | 34 | Foreground service type declarations required | VPN services must declare appropriate type |

### System VPN Dialog

The consent dialog cannot be customized by the app. It explicitly states the app will "monitor network traffic." However, for a VPN app, users expect this warning and approve it without concern, since monitoring traffic is the stated purpose of a VPN.

## Detection Indicators

### Manifest Signals

- `BIND_VPN_SERVICE` in apps that are not established VPN providers
- VPN service declaration combined with data exfiltration code (HTTP upload, C2 communication)
- VPN + tracking SDKs + advertising libraries (data harvesting VPN)
- Missing encryption implementation alongside VPN service (traffic not being protected)

### Behavioral Signals

- VPN that captures DNS queries and transmits them to non-standard servers
- VPN that does not encrypt tunnel traffic (defeating its stated purpose)
- VPN service that routes traffic through servers in sanctioned or high-risk jurisdictions
- VPN that injects content into HTTP responses

## See Also

- [Network Traffic Interception](../../attacks/network-traffic-interception.md)
- [DCHSpy](../../malware/families/dchspy.md)
- [INTERNET](../normal/internet.md)
