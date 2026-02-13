# INTERNET

Allows opening network sockets. Required by virtually all Android malware for C2 communication, data exfiltration, payload download, and inject kit retrieval. Granted silently at install time.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.INTERNET` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time |
| Introduced | API 1 |

## What It Enables

Full network access: HTTP/HTTPS requests, raw sockets, WebSocket connections, DNS queries. No restrictions on destination, port, or protocol.

## Relevance to Malware

Every malware family that communicates with a remote server needs this permission. Without it, the malware is limited to local-only operations (which are rarely useful).

Network functions in malware:

| Function | Usage |
|----------|-------|
| C2 communication | Receive commands, send status updates |
| Data exfiltration | Upload stolen credentials, SMS, contacts, files |
| Payload download | Fetch second-stage APKs, inject kits, configuration |
| Inject kit retrieval | Download HTML overlay templates per target app |
| Screen streaming | VNC-like remote access (Hook, Octo) |
| Update mechanism | Download updated versions of the malware |

## Detection Value

`INTERNET` alone is meaningless as an indicator since the vast majority of legitimate apps also request it. Its value is in combination: `INTERNET` + `RECEIVE_BOOT_COMPLETED` + `BIND_ACCESSIBILITY_SERVICE` is a different story than `INTERNET` alone.

## Network Security Config

Apps can declare a network security configuration that controls TLS behavior:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>
```

When analyzing an app, this file reveals:

- Whether cleartext (HTTP) traffic is allowed (and to which domains)
- Custom certificate pins
- Trusted CA certificates (including user-installed certs)
- Debug-only trust overrides

On Android 9+, cleartext traffic is blocked by default unless explicitly allowed in the network security config.
