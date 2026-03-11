# Carrier Billing Fraud

Automated subscription fraud that silently subscribes victims to premium services via Direct Carrier Billing (DCB), charging their phone bill without their knowledge. The malware automates the entire subscription flow in hidden WebViews: navigating carrier portals, filling forms, intercepting OTP confirmation codes, and confirming subscriptions. The victim's only clue is unexpected charges on their phone bill.

DCB fraud is one of the oldest and most profitable mobile fraud categories. Unlike banking trojans that target individual high-value accounts, DCB fraud operates at scale across millions of devices with small per-device charges ($1-10/week) that often go unnoticed.

## How Direct Carrier Billing Works

DCB lets users pay for digital content by charging their phone bill instead of a credit card:

1. User visits a subscription page (games, entertainment, ringtones)
2. The carrier detects their phone number from the mobile data connection (header enrichment)
3. The carrier sends an OTP via SMS or push notification
4. User enters the OTP to confirm
5. The charge appears on the phone bill

The malware automates steps 1-4 invisibly.

## Attack Flow

### Hidden WebView Automation

The fraud engine operates through WebViews the user never sees. The WebView is rendered on an invisible surface (tiny [VirtualDisplay](../grayware/ad-fraud.md#virtualdisplay-invisible-rendering) or off-screen positioning). The automation:

1. Navigates to carrier subscription portals
2. Parses HTML to extract form tokens (`authenticity_token`, `sessionID`, `transactionID`)
3. Fills and submits forms programmatically via JavaScript injection
4. Follows redirects and handles multi-step subscription flows
5. Manipulates DOM elements via `evaluateJavascript()`

The WebView disables the `X-Requested-With` header (via `WebViewXRequestedWithHeaderControl` flags) so the carrier portal cannot identify the originating app.

### OTP Interception

The critical step: stealing the confirmation code before the user sees it.

| Method | Mechanism |
|--------|-----------|
| [NotificationListenerService](notification-suppression.md) | Read OTP from notification text, then `cancelAllNotifications()` to hide it |
| [Runtime listener hijacking](notification-suppression.md#runtime-listener-hijacking) | Hot-swap an existing listener's handler via reflection to intercept without registering a new component |
| [SMS BroadcastReceiver](sms-interception.md) | High-priority receiver intercepts SMS before the default handler |
| Default SMS handler | Become the default SMS app to receive all messages directly |

The stolen OTP is extracted via regex patterns tailored to each carrier's message format and automatically submitted to the subscription confirmation page.

### Carrier-Specific Modules

Mature DCB fraud engines carry dedicated modules per carrier, each handling the unique subscription page structure, authentication flow, and OTP format. Common target regions:

| Region | Targeted Carriers |
|--------|-------------------|
| Southeast Asia | Thai carriers (DTAC, AIS, TrueCorp), Indonesian carriers (Telkomsel), Malaysian carriers |
| Europe | Polish carriers (Teleaudio), Austrian, German, Spanish, Greek carriers |
| Middle East | Saudi Arabian, UAE, Iraqi carriers |
| Africa | Nigerian, South African, Kenyan, Ghanaian carriers |

Each module handles carrier-specific form fields, session management, multi-step flows, and success/failure detection.

### Anti-Fraud Platform Bypass

Carriers deploy DCB fraud detection platforms ([Evina](https://www.evina.com/), [Upstream Secure-D](https://www.upstreamsystems.com/secure-d/)) that analyze subscription requests for automated behavior. The malware actively works around these protections by:

- Spoofing browser headers and User-Agent strings using the device's real Android version and model
- Timing actions to appear as legitimate user interaction rather than automated clicks
- Handling reCAPTCHA challenges via remote solving services (task/solution API pattern)
- Manipulating WebView behavior to pass JavaScript-based bot detection

### CAPTCHA Solving

When subscription pages present CAPTCHA challenges, the malware:

1. Extracts the `siteKey` from the page source
2. Sends a `createTask` request to a remote solving service (consistent with 2captcha/anti-captcha API pattern)
3. Polls for the solution token
4. Injects the solved token back into the page via JavaScript

## Connection to Other Techniques

DCB fraud engines are typically Stage 2 or Stage 3 payloads in multi-stage dropper architectures:

- **Stage 1**: Clean-looking utility app passes Play Store review
- **Stage 2**: Orchestrator loaded via [dynamic code loading](dynamic-code-loading.md), sets up [notification hijacking](notification-suppression.md), [background activity launch bypass](anti-analysis-techniques.md#background-activity-launch-bypass-mediasession), and [WebView package spoofing](../grayware/ad-fraud.md#webview-package-name-spoofing)
- **Stage 3**: DCB fraud engine downloaded from C2 or decrypted from embedded fallback

The orchestrator stage often also runs [attribution fraud](../grayware/ad-fraud.md#attribution-theft) in parallel, logging fake install events to analytics SDKs to claim CPI (cost-per-install) payouts.

## SSL Certificate Bypass

DCB fraud engines commonly install a trust-all `TrustManager` and `HostnameVerifier` to communicate with any HTTPS server regardless of certificate validity. This enables interception of carrier portal traffic and communication with C2 servers using self-signed certificates.

```java
TrustManager[] trustAll = {new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] chain, String type) {}
    public void checkServerTrusted(X509Certificate[] chain, String type) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, trustAll, new SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
```

## Families Using This Technique

| Family | DCB Approach |
|--------|-------------|
| [Joker](../malware/families/joker.md) | Hidden WebView subscribes to premium services; intercepts SMS confirmation |
| [Harly](../malware/families/harly.md) | Encrypted payload automates subscription flows in invisible WebView |
| [Etinu](../malware/families/etinu.md) | SMS interception + hidden WebView subscription automation |
| [GriftHorse](../malware/families/grifthorse.md) | 10M+ victims across 70+ countries; $1.5M+/month in fraudulent charges |
| [FakePlayer](../malware/families/fakeplayer.md) | One of the earliest Android trojans (2010); sent premium SMS to Russian shortcodes |

## Detection

| Indicator | Where to Look |
|-----------|---------------|
| Hidden WebView creation | `WebView` instantiated without being added to a visible layout or rendered on a `VirtualDisplay` |
| OTP regex patterns | String constants matching carrier-specific PIN formats (e.g., `(kod\|PIN\|code).*?(\d{3,6})`) |
| `cancelAllNotifications()` | Called after reading notification text content |
| Carrier portal URLs | Hardcoded subscription endpoints in strings or WebView navigation history |
| `X-Requested-With` header suppression | WebView settings disabling the header |
| SSL trust-all | Custom `TrustManager` accepting all certificates + `HostnameVerifier` accepting all hostnames |
| MCC-based targeting | `TelephonyManager.getSimOperator()` used to gate fraud activation by country |
