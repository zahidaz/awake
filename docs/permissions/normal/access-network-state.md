# ACCESS_NETWORK_STATE

Normal permission that allows an app to query the device's network connectivity status: whether WiFi or mobile data is active, the network type (4G, 5G, WiFi), and whether internet is reachable. Auto-granted at install with no user interaction. Present in virtually every malware manifest because it is the prerequisite for reliable C2 communication, sandbox detection, and network-aware payload delivery.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.ACCESS_NETWORK_STATE` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 1 |
| User Visibility | None |
| Play Store Policy | No restrictions |

## What It Enables

### ConnectivityManager

```java
ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);

NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
boolean isConnected = activeNetwork != null && activeNetwork.isConnected();
int type = activeNetwork.getType();
String typeName = activeNetwork.getTypeName();
String subtype = activeNetwork.getSubtypeName();
boolean isWifi = type == ConnectivityManager.TYPE_WIFI;
boolean isMobile = type == ConnectivityManager.TYPE_MOBILE;
```

### NetworkCapabilities (API 21+)

```java
Network network = cm.getActiveNetwork();
NetworkCapabilities caps = cm.getNetworkCapabilities(network);

boolean hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
boolean isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
boolean isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
int downBandwidth = caps.getLinkDownstreamBandwidthKbps();
```

| Data Point | API | Use |
|-----------|-----|-----|
| Connected/disconnected | 1+ | Gate C2 communication |
| Network type (WiFi/mobile/VPN) | 1+ | Adjust exfiltration strategy |
| Subtype (LTE, 5G, HSPA) | 1+ | Fingerprint device environment |
| Bandwidth estimate | 21+ | Throttle data exfiltration to avoid detection |
| VPN active | 21+ | Detect security tools or enterprise MDM |
| Metered network | 21+ | Avoid metered connections to reduce user suspicion |

## Abuse in Malware

### C2 Communication Gating

Every banking trojan, RAT, and spyware family checks network state before attempting C2 contact. Without connectivity, C2 calls fail and generate errors that could trigger retry loops, drain battery, and alert the user. The standard pattern:

```java
public boolean shouldContactC2() {
    ConnectivityManager cm = (ConnectivityManager)
        context.getSystemService(Context.CONNECTIVITY_SERVICE);
    NetworkInfo ni = cm.getActiveNetworkInfo();
    return ni != null && ni.isConnected();
}
```

### Sandbox and Emulator Detection

Emulators and automated analysis sandboxes often have distinctive network configurations that malware checks:

| Check | Sandbox Indicator | Rationale |
|-------|------------------|-----------|
| No mobile network | `TYPE_MOBILE` absent | Real phones almost always have a SIM/mobile connection |
| WiFi only | `TYPE_WIFI` with no mobile fallback | Common in emulators using host NAT |
| No network at all | `getActiveNetworkInfo()` returns null | Some sandboxes run offline |
| VPN active | `TRANSPORT_VPN` present | May indicate analysis environment routing through inspection proxy |
| Unusual bandwidth | Extremely high or zero bandwidth | Emulators report unrealistic values |

```java
public boolean isLikelySandbox() {
    ConnectivityManager cm = (ConnectivityManager)
        context.getSystemService(Context.CONNECTIVITY_SERVICE);
    NetworkInfo mobile = cm.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);
    if (mobile == null || !mobile.isAvailable()) {
        return true;
    }
    return false;
}
```

[GodFather](../../malware/families/godfather.md), [Cerberus](../../malware/families/cerberus.md), and [Anubis](../../malware/families/anubis.md) all include network-based sandbox checks alongside other anti-analysis techniques like SIM state verification and sensor data validation. See [Anti-Analysis Techniques](../../attacks/anti-analysis-techniques.md) for the full detection matrix.

### Network-Aware Exfiltration

Spyware families adapt their exfiltration strategy based on connection type:

| Connection | Strategy |
|-----------|----------|
| WiFi | Bulk upload: photos, videos, call recordings, databases |
| Mobile (unmetered) | Medium uploads: screenshots, contact lists, SMS dumps |
| Mobile (metered) | Minimal: text-only data, GPS coordinates, keylog buffers |
| No connection | Queue to local storage, upload when connection resumes |

This prevents high data usage charges that would alert the victim and avoids exfiltration over slow connections that could timeout.

### Network Change Receiver

Malware registers for `CONNECTIVITY_ACTION` broadcasts to re-establish C2 when network comes back:

```java
public class NetworkReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        ConnectivityManager cm = (ConnectivityManager)
            context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        if (ni != null && ni.isConnected()) {
            startC2Service(context);
        }
    }
}
```

This is documented on the [`RECEIVE_BOOT_COMPLETED`](receive-boot-completed.md) page as `ACTION_CONNECTIVITY_CHANGE`, a common fallback persistence trigger when boot receivers are killed.

### VPN Detection

```java
Network activeNetwork = cm.getActiveNetwork();
NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
    // VPN is active
}
```

Some families use VPN detection to:

- Pause operations when enterprise MDM VPN is detected (avoids traffic inspection)
- Detect security researcher analysis environments
- Adjust C2 routing to avoid VPN-based SSL inspection

### Families Using Network State

Effectively universal. Every family in the AWAKE database requests this permission. Representative examples of network-aware behavior:

| Family | Network-Specific Behavior |
|--------|--------------------------|
| [GodFather](../../malware/families/godfather.md) | Network type check as part of multi-factor sandbox detection |
| [Cerberus](../../malware/families/cerberus.md) | WiFi-only bulk exfiltration, mobile data for text payloads |
| [SpyNote](../../malware/families/spynote.md) | Bandwidth-aware screen streaming quality adjustment |
| [Pegasus](../../malware/families/pegasus.md) | WiFi-only for large file uploads, connection gating for all C2 |
| [Vultur](../../malware/families/vultur.md) | Network state check before VNC streaming sessions |
| [FluBot](../../malware/families/flubot.md) | Network availability check before smishing distribution |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | `ACCESS_NETWORK_STATE` introduced | Basic connectivity queries |
| 5.0 | 21 | `NetworkCapabilities` API added | Richer network metadata (transport type, bandwidth, VPN) |
| 7.0 | 24 | `CONNECTIVITY_ACTION` broadcast restricted for manifest receivers | Apps must use `registerReceiver()` or `JobScheduler` |
| 9.0 | 28 | `NetworkInfo` deprecated | Replaced by `NetworkCapabilities` and `LinkProperties` |
| 10 | 29 | MAC randomization by default | `ACCESS_NETWORK_STATE` no longer exposes real WiFi MAC |
| 12 | 31 | Exact alarm restrictions affect network retry scheduling | `WorkManager` or `JobScheduler` preferred for deferred C2 contact |

## Detection Indicators

### Manifest Signals

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

Zero signal on its own since nearly all apps request it. Only meaningful in combination analysis:

- `ACCESS_NETWORK_STATE` + `INTERNET` + no visible network functionality = potential C2 client
- `ACCESS_NETWORK_STATE` + `ACCESS_WIFI_STATE` + `READ_PHONE_STATE` = device fingerprinting stack

### Behavioral Signals

- Network type checks immediately followed by conditional C2 contact
- `TYPE_MOBILE` null check as first anti-sandbox gate
- `NetworkCallback` registration that triggers data upload on WiFi connect
- VPN transport detection followed by behavioral changes (pausing, switching C2 endpoints)

## See Also

- [ACCESS_WIFI_STATE](access-wifi-state.md)
- [Anti-Analysis Techniques](../../attacks/anti-analysis-techniques.md)
- [C2 Communication](../../attacks/c2-techniques.md)
- [Data Exfiltration](../../attacks/data-exfiltration.md)
- [RECEIVE_BOOT_COMPLETED](receive-boot-completed.md)
