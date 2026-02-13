# PWA / TWA (Progressive Web Apps / Trusted Web Activities)

Progressive Web Apps (PWAs) wrapped as Trusted Web Activities (TWAs) are web applications packaged inside a minimal Android APK shell. The APK contains almost no native code -- it exists solely to launch Chrome Custom Tabs pointed at a web origin. All application logic, UI, and data handling live on a remote web server, not inside the APK. This makes the reverse engineering target the web application itself rather than the Android package. TWAs use Android's Digital Asset Links protocol to verify that the APK publisher controls the target web domain.

## Architecture

### PWA Fundamentals

A Progressive Web App is a web application that uses modern browser APIs to provide app-like capabilities:

| Component | Role |
|-----------|------|
| **Service Worker** | JavaScript proxy between the app and network -- handles caching, offline support, push notifications |
| **Web App Manifest** | JSON file (`manifest.json`) defining app name, icons, start URL, display mode |
| **HTTPS Origin** | All PWA features require a secure origin |
| **Application Shell** | Cached HTML/CSS/JS skeleton that loads instantly, then hydrates with dynamic content |

### TWA Wrapper

A Trusted Web Activity is an Android activity that launches a Chrome Custom Tab in full-screen mode (no browser chrome) to display a PWA. On launch, the APK's `LauncherActivity` delegates to Chrome Custom Tabs, which verifies the Digital Asset Links relationship between the APK and the target domain. If verification passes, Chrome renders the PWA full-screen with no browser UI. If verification fails, Chrome shows the URL bar as a fallback.

### Key Distinction from WebView Apps

TWAs are fundamentally different from WebView-based frameworks (Cordova, Capacitor, uni-app):

| Aspect | TWA | WebView Framework |
|--------|-----|-------------------|
| Rendering engine | System Chrome (always up to date) | Embedded WebView (varies by OS version) |
| Code location | Remote server | Bundled in APK (`assets/www/`) |
| Offline capability | Service Worker cache (optional) | Full offline by default |
| Native bridge | None -- browser sandbox only | JavaScript bridge to native APIs |
| APK size | Tiny (< 1 MB typically) | Larger (includes web assets + native plugins) |

## Identification

| Indicator | Location |
|-----------|----------|
| Very small APK size (< 2 MB) | Overall package |
| `com.google.androidbrowserhelper` | DEX classes -- Google's TWA support library |
| `LauncherActivity` or `TWALauncherActivity` | Main activity in manifest |
| `androidx.browser.trusted.*` | Trusted Web Activity classes |
| `asset_statements` string resource | Digital Asset Links declaration |
| No `assets/www/` or bundled web code | Absence of local web content |
| `org.chromium.chrome.browser.browserservices` | Chrome TWA service references |
| `META-INF/services/` with Chrome entries | Service provider configuration |

Quick check:

```bash
unzip -l target.apk | wc -l
aapt dump xmltree target.apk AndroidManifest.xml | grep -iE "(launcher|twa|browser|customtab)"
```

A TWA APK typically has fewer than 100 files. Compare this to a Cordova app which may have thousands.

### Bubblewrap Detection

Most TWAs are built using [Bubblewrap](https://github.com/GoogleChromeLabs/bubblewrap), Google's CLI tool for generating TWA wrapper APKs. Bubblewrap-generated APKs have a predictable structure:

```bash
unzip -l target.apk | grep -E "(LauncherActivity|DelegationService|chromium)"
```

## Code Location

### What Is in the APK

The APK contains only:

- `AndroidManifest.xml` -- activity declarations, Digital Asset Links references
- Thin Java/Kotlin launcher code (delegate to Chrome)
- App icons and splash screen resources
- `res/values/strings.xml` -- may contain the target URL
- Digital Asset Links configuration

### Extracting the Target URL

All application logic (HTML, JavaScript, CSS, Service Workers) resides on the remote server. The only useful artifact in the APK is the target URL.

The target web origin is the critical piece of information in the APK:

```bash
aapt dump resources target.apk | grep -A2 "hostName\|startUrl\|origin"
```

From decompiled Java (jadx):

```bash
jadx -d decompiled/ target.apk
grep -rn "https://" decompiled/ --include="*.java"
```

The URL is typically stored in `res/values/strings.xml` or hardcoded in `LauncherActivity`.

### Digital Asset Links

The APK references a `/.well-known/assetlinks.json` file hosted on the target domain. This JSON file proves the domain owner authorized the APK:

```bash
curl -s https://target-domain.com/.well-known/assetlinks.json | python3 -m json.tool
```

The response contains the APK's package name and signing certificate fingerprint:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.twa",
    "sha256_cert_fingerprints": ["AB:CD:EF:..."]
  }
}]
```

## Analysis Approach

### Web-Focused Analysis

Since the code lives on the server, standard web application analysis techniques apply:

| Technique | Tool | Purpose |
|-----------|------|---------|
| Browser DevTools | Chrome/Firefox | Inspect DOM, network requests, service worker, local storage |
| Proxy interception | mitmproxy, Burp Suite | Capture and modify HTTP/S traffic |
| Service Worker analysis | Chrome DevTools (Application tab) | Examine caching strategy, push notification handlers |
| JavaScript analysis | Browser DevTools Sources | Read, debug, and breakpoint application code |
| API enumeration | Burp Suite, Postman | Map backend endpoints discovered through traffic analysis |

### Proxy Setup for TWA

Intercept TWA traffic by configuring a system-wide proxy on the Android device and installing the proxy CA certificate:

```bash
adb shell settings put global http_proxy 192.168.1.100:8080
adb push burp-cert.pem /sdcard/
```

### Service Worker and Cache Extraction

Service Workers are cached by Chrome on the device. Access them through Chrome DevTools remote debugging:

```bash
adb forward tcp:9222 localabstract:chrome_devtools_remote
```

Then navigate to `chrome://inspect` on the desktop browser. On a rooted device, Chrome's cache directories under `/data/data/com.android.chrome/app_chrome/Default/Service Worker/CacheStorage/` contain cached responses and service worker scripts.

## Security Implications

### Origin Verification Bypass

The TWA trust model depends on Digital Asset Links verification. If an attacker can:

1. Register a domain and host `assetlinks.json` pointing to their APK
2. Build a TWA targeting that domain
3. Later modify the web content to be malicious

The APK signature verification only proves the APK publisher owns the domain -- it says nothing about the safety of the web content. The web application can change at any time without updating the APK.

### No Native Bridge

TWAs run inside Chrome's sandbox with no JavaScript bridge to native Android APIs. The PWA is limited to browser-granted capabilities: camera/microphone (via permissions prompt), GPS (Geolocation API), push notifications (Push API), local storage (IndexedDB), and same-origin network requests. No access to contacts, SMS, call logs, or file system beyond browser sandbox.

### Phishing Surface

TWAs are effective phishing vectors because the thin APK passes static analysis (no malicious native code), web content can change after app store review, full-screen mode hides the URL bar making origin verification impossible for the user, and the app icon/splash screen mimic legitimate applications.

## Hooking Strategy

### Limited Native Hooks

The TWA APK contains minimal code, so Frida hook surface is small:

```javascript
Java.perform(function() {
    var Builder = Java.use("androidx.browser.customtabs.CustomTabsIntent$Builder");
    Builder.build.implementation = function() {
        console.log("[TWA] CustomTabsIntent built");
        return this.build();
    };
});
```

### Network-Level Interception

Proxy-based interception is the most effective approach. Use mitmproxy or Burp Suite with iptables on a rooted device to force traffic through the proxy:

```bash
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080
```

## SSL Pinning

TWAs inherit Chrome's certificate handling. Chrome does not support user-installed CA certificates for HTTPS interception by default on Android 7+. Options:

| Method | Requirement |
|--------|-------------|
| System CA installation | Root access to place cert in `/system/etc/security/cacerts/` |
| Magisk module | [MagiskTrustUserCerts](https://github.com/NVISOsecurity/MagiskTrustUserCerts) moves user certs to system store |
| Patched Chrome | Use a Chromium build with certificate verification disabled |
| Network Security Config | Not applicable -- TWA uses Chrome, not a WebView you control |

## Malware Context

TWAs are used in phishing and scam campaigns where the threat actor wants:

| Use Case | Details |
|----------|---------|
| Phishing | Full-screen app mimicking banking/payment sites, no visible URL bar to alert the user |
| Scam storefronts | Fake e-commerce sites wrapped as apps, content changes post-review |
| Credential harvesting | Login forms that POST to attacker-controlled servers |
| Dynamic payload | APK passes store review with benign content, switches to malicious web content later |

The thin APK passes most static analysis tools because there is no malicious code in the package. All malicious behavior exists on the remote server and can be toggled at will.

## RE Difficulty Assessment

| Aspect | Assessment |
|--------|-----------|
| APK analysis | Trivial -- minimal code, extract target URL |
| Web code access | Depends on server -- visible via DevTools and proxy |
| String extraction | N/A -- no code in APK to extract strings from |
| Dynamic analysis | Standard web security testing |
| Patching | Not applicable -- code is server-side |
| Overall difficulty | **Easy** for APK, **Variable** for web application (rank 4/28) |

The APK is trivial to analyze -- extract the target URL and shift to standard web application penetration testing (OWASP Testing Guide). The difficulty depends entirely on the server-side web application.

## References

- [Trusted Web Activities -- Google Developers](https://developer.chrome.com/docs/android/trusted-web-activity)
- [Bubblewrap -- TWA Generator](https://github.com/GoogleChromeLabs/bubblewrap)
- [Digital Asset Links Documentation](https://developers.google.com/digital-asset-links)
- [mitmproxy](https://mitmproxy.org/)
- [MagiskTrustUserCerts](https://github.com/NVISOsecurity/MagiskTrustUserCerts)
- [Frida](https://frida.re/)
- [jadx](https://github.com/skylot/jadx)
