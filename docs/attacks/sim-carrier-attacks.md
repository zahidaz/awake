# SIM & Carrier-Level Attacks

Exploiting the cellular infrastructure layer -- SIM cards, carrier billing systems, USSD codes, and baseband processors -- to steal money, intercept communications, and bypass authentication. Many of these attacks operate below the Android OS, making them invisible to on-device security tools. When combined with on-device malware, they form a complete attack chain: the malware handles credential theft while carrier-level manipulation defeats 2FA and enables silent monetization.

See also: [SMS Interception](sms-interception.md), [Call Interception](call-interception.md), [Phishing Techniques](phishing-techniques.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1451](https://attack.mitre.org/techniques/T1451/) | SIM Card Swap | Credential Access, Initial Access |
    | [T1449](https://attack.mitre.org/techniques/T1449/) | Exploit SS7 to Track Device Location | Collection, Discovery |
    | [T1640](https://attack.mitre.org/techniques/T1640/) | Generate Fraudulent Advertising Revenue | Impact |

    T1451 covers SIM swapping and eSIM manipulation for 2FA bypass. T1449 covers carrier-infrastructure-level location tracking and interception. Carrier billing fraud and USSD exploitation do not have dedicated MITRE techniques; this is an area where AWAKE provides deeper coverage. Simjacker and WIBattack (SIM toolkit attacks) are not represented in ATT&CK Mobile.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | On-device (carrier billing) | [`SEND_SMS`](../permissions/sms/send-sms.md), [`RECEIVE_SMS`](../permissions/sms/receive-sms.md), [`RECEIVE_WAP_PUSH`](../permissions/sms/receive-wap-push.md), `CHANGE_WIFI_STATE`, `INTERNET` |
    | On-device (USSD) | [`CALL_PHONE`](../permissions/phone/call-phone.md) |
    | SIM-level (Simjacker, WIBattack) | No Android permissions required -- attack targets the SIM card directly via specially crafted SMS |
    | SIM swapping | No device access needed -- social engineering of carrier employees |
    | eSIM manipulation | `WRITE_EMBEDDED_SUBSCRIPTIONS` (carrier/system only) |

## SIM Swapping

SIM swapping is not an on-device attack, but it is the single most relevant carrier-level threat to Android security because it defeats SMS-based 2FA entirely. The attacker convinces a carrier employee (via social engineering, bribery, or insider access) to port the victim's phone number to a SIM card the attacker controls. All incoming calls and SMS messages -- including OTP codes -- now route to the attacker.

### How It Works

1. Attacker identifies the target and gathers personal information (name, phone number, SSN, account PIN) through phishing, data breaches, or OSINT
2. Attacker contacts the carrier's support (in person, by phone, or via online portal) posing as the victim
3. Carrier employee processes the number transfer to a new SIM
4. Victim's phone loses cellular service immediately
5. Attacker receives all SMS and calls, including 2FA codes
6. Attacker uses stolen credentials + intercepted OTP to drain bank accounts, take over email, and reset passwords

### Impact on Android

Once the number is ported, every SMS-based authentication mechanism fails. Banking apps that send OTP via SMS, password reset flows that use SMS verification, and any app relying on phone number as identity (WhatsApp, Telegram, Signal registration) are all compromised. The victim's device shows "No Service" or "Emergency calls only," but many victims attribute this to network issues and do not react immediately.

### Scale and Notable Cases

The [FBI IC3 reported $68 million in SIM swap losses in 2021](https://www.ic3.gov/Media/Y2022/PSA220208) across 1,611 complaints, up from $12 million the year before. Real-world cases include:

| Case | Year | Details |
|------|------|---------|
| Jack Dorsey (Twitter CEO) | 2019 | Phone number hijacked, attacker posted from his Twitter account via SMS-to-tweet |
| Michael Terpin | 2018 | $23.8 million in crypto stolen; [sued AT&T for $200M](https://www.reuters.com/legal/litigation/att-reaches-settlement-with-cryptocurrency-investor-over-sim-swap-hack-2023-01-03/) |
| European arrest (Europol) | 2021 | [10 arrests across 8 countries](https://www.europol.europa.eu/media-press/newsroom/news/10-arrested-for-sim-swapping-attacks-against-high-profile-individuals), $100M+ in crypto stolen |
| FCC rulemaking | 2023 | [New rules requiring carriers to authenticate identity](https://www.fcc.gov/document/fcc-adopts-rules-protect-consumers-sim-swapping) before processing SIM changes |

### Relationship to Android Malware

Banking trojans combine SIM swapping with on-device attacks for maximum effectiveness. The malware steals credentials via [overlay attacks](overlay-attacks.md) or [keylogging](keylogging.md), while a collaborating SIM swapper intercepts the OTP. This two-pronged approach defeats both on-device and network-based security. Some operations run as organized crime groups where separate teams handle the malware and the SIM swaps.

## eSIM Profile Manipulation

Embedded SIMs (eSIMs) introduce a software-defined attack surface. Instead of a physical SIM card, eSIM profiles are downloaded and activated programmatically. Android exposes the `EuiccManager` API for eSIM management.

### API Surface

```java
EuiccManager em = (EuiccManager) getSystemService(EUICC_SERVICE);
em.downloadSubscription(
    DownloadableSubscription.forActivationCode("LPA:1$smdp.example.com$ACTIVATION_CODE"),
    true,
    PendingIntent.getBroadcast(this, 0, new Intent("DOWNLOAD_COMPLETE"), 0)
);
```

The `WRITE_EMBEDDED_SUBSCRIPTIONS` permission is required, and it is restricted to carrier apps and system-privileged apps. Regular third-party apps cannot call this API. This makes direct eSIM manipulation from malware extremely difficult on stock Android.

### Attack Vectors

| Vector | Feasibility | Description |
|--------|-------------|-------------|
| Carrier-level social engineering | High | Same as physical SIM swapping -- attacker convinces carrier to provision a new eSIM profile |
| QR code phishing | Medium | Tricking victim into scanning an eSIM activation QR code that provisions the attacker's profile, effectively porting the number |
| Compromised carrier app | Low | Exploiting a vulnerability in a carrier's privileged eSIM management app |
| System-level exploit | Very low | Gaining system privileges to call `EuiccManager` directly |

eSIM QR code phishing is the most practical on-device vector. The attacker sends a phishing message claiming the victim needs to "update" or "reactivate" their SIM by scanning a QR code. The QR encodes an eSIM activation string that provisions a profile controlled by the attacker, effectively executing a SIM swap without contacting the carrier.

### Known Research

Researchers at [Kigen](https://www.kigen.com/) have documented vulnerabilities in eUICC implementations, including issues with profile provisioning authentication and insufficient validation of SM-DP+ server certificates. The overall risk remains low for on-device exploitation because the API restrictions are sound, but carrier-side eSIM provisioning processes are subject to the same social engineering risks as traditional SIM swaps.

## Carrier Billing Fraud

The most financially impactful carrier-level attack category for Android malware. Carrier billing lets subscribers charge purchases to their phone bill without a credit card. Malware exploits this by silently subscribing victims to premium services.

### WAP Billing Fraud

Wireless Application Protocol (WAP) billing allows one-click purchases on mobile data connections. The carrier identifies the subscriber by their IP address on the cellular network, so no additional authentication is required beyond being connected via mobile data.

**Attack flow:**

1. Malware disables WiFi to force mobile data connection (subscriber identity tied to cellular IP)
2. Navigates to a WAP billing page (HTTP request over mobile data)
3. Carrier injects subscriber identity headers into the HTTP request
4. Malware auto-clicks the "Subscribe" button (via WebView JavaScript injection or accessibility)
5. Confirmation SMS arrives from the carrier
6. Malware intercepts and deletes the confirmation SMS before the user sees it
7. Victim is charged recurring fees on their phone bill

```java
WifiManager wm = (WifiManager) getSystemService(WIFI_SERVICE);
wm.setWifiEnabled(false);

WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl("http://premium-service.example/subscribe");
wv.setWebViewClient(new WebViewClient() {
    @Override
    public void onPageFinished(WebView view, String url) {
        view.evaluateJavascript(
            "document.querySelector('.subscribe-btn').click();", null);
    }
});
```

### Joker: The King of WAP Billing Fraud

[Joker](../malware/families/joker.md) (also known as Bread) is the most prolific carrier billing fraud family ever observed. [Google's own analysis](https://security.googleblog.com/2020/01/pha-family-highlights-bread-aka-joker.html) documented it as one of the most persistent threats to the Play Store, with over 1,700 infected apps removed since 2017. Joker's techniques evolved continuously to evade detection:

| Era | Technique | Evasion |
|-----|-----------|---------|
| 2017 | Premium SMS to hardcoded short codes | Basic obfuscation |
| 2018 | WAP billing with WebView automation | Encrypted C2, delayed payload |
| 2019 | Dynamic code loading from C2 | Payload not in APK at scan time |
| 2020+ | Native code (NDK) for billing logic | Harder to decompile than DEX |
| 2021+ | Flutter/React Native wrappers | Framework-specific analysis needed |

Joker subscribed victims to premium services costing $5-$15/week per subscription, often stacking multiple subscriptions per device.

### GriftHorse

[GriftHorse](../malware/families/grifthorse.md), [documented by Zimperium in September 2021](https://www.zimperium.com/blog/grifthorse-android-trojan-steals-millions-from-over-10-million-victims-globally/), infected over 10 million devices across 70+ countries through 200+ trojanized Play Store apps. Unlike Joker's automated approach, GriftHorse used a localized social engineering flow: after installation, it bombarded the user with fake "prize winner" notifications. Tapping the notification loaded a geo-targeted WAP billing page in a WebView. Victims were charged approximately $35/month in recurring premium service fees, totaling over $35 million stolen.

### Harly

[Harly](../malware/families/harly.md), [reported by Kaspersky in 2022](https://www.kaspersky.com/blog/harly-trojan-subscriber/45573/), operated similarly to Joker but focused on Direct Carrier Billing (DCB). It subscribed victims to paid services by completing the entire subscription flow programmatically: opening an invisible WebView, filling in the victim's phone number, and entering the confirmation code intercepted from the carrier's verification SMS.

### Premium SMS Fraud

The original carrier billing attack. Malware sends SMS messages to premium-rate short codes (numbers that charge per received message). Each SMS costs the victim $1-$10, charged directly to their phone bill.

```java
SmsManager sm = SmsManager.getDefault();
sm.sendTextMessage("7890", null, "SUBSCRIBE", null, null);
```

The subscription flow requires intercepting the carrier's confirmation SMS and replying to complete the opt-in. Modern carriers flag premium SMS traffic more aggressively, but the technique still works in regions with weaker carrier-side fraud detection. See [SMS Interception -- Premium SMS Fraud](sms-interception.md#premium-sms-fraud) for the detailed flow.

### Microsoft's Toll Fraud Taxonomy

[Microsoft documented the toll fraud ecosystem](https://www.microsoft.com/en-us/security/blog/2022/06/30/toll-fraud-malware-how-an-android-application-can-drain-your-wallet/) in June 2022, classifying it as the most prevalent category of Android malware on the Play Store. Their analysis broke down the standard toll fraud kill chain: disable WiFi, load WAP billing page over cellular, auto-subscribe, intercept confirmation SMS. They noted that toll fraud malware specifically targets Android 9.0 and below because `WifiManager.setWifiEnabled()` was deprecated in Android 10 and requires `CHANGE_WIFI_STATE` plus location permissions on newer versions.

## USSD Code Exploitation

Unstructured Supplementary Service Data (USSD) codes are carrier-level commands dialed like phone numbers. They interact directly with the carrier's Home Location Register (HLR) to query account information, activate services, and modify call routing. Malware with [`CALL_PHONE`](../permissions/phone/call-phone.md) permission can dial USSD codes programmatically without user interaction.

### Commonly Exploited USSD Codes

| Code | Function | Malware Use |
|------|----------|-------------|
| `*21*[number]#` | Enable unconditional call forwarding | Redirect all calls to attacker number |
| `*67*[number]#` | Forward when busy | Selective call interception |
| `*61*[number]#` | Forward when unanswered | Intercept missed calls |
| `*62*[number]#` | Forward when unreachable | Capture calls when victim has no signal |
| `##21#` | Disable call forwarding | Cleanup after operation |
| `*#06#` | Display IMEI | Device fingerprinting |
| `*123#` / `*100#` | Balance check (carrier-specific) | Recon for airtime theft |
| `*141*[number]*[amount]#` | Airtime transfer (carrier-specific) | Direct financial theft in prepaid markets |

### Programmatic USSD Dialing

```java
Intent ussd = new Intent(Intent.ACTION_CALL);
ussd.setData(Uri.parse("tel:" + Uri.encode("*21*+1234567890#")));
startActivity(ussd);
```

On Android 8.0+, the `TelephonyManager.sendUssdRequest()` API provides a cleaner interface with a callback:

```java
TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
tm.sendUssdRequest("*21*+1234567890#",
    new TelephonyManager.UssdResponseCallback() {
        @Override
        public void onReceiveUssdResponse(TelephonyManager tm, String req, CharSequence resp) {
            exfiltrate(resp.toString());
        }

        @Override
        public void onReceiveUssdResponseFailed(TelephonyManager tm, String req, int failCode) {}
    },
    new Handler(Looper.getMainLooper())
);
```

### FakeCall/FakeCalls USSD Abuse

[FakeCall](../malware/families/fakecalls.md) (Korean banking trojan) uses USSD codes to set up call forwarding to attacker-controlled numbers. After the victim grants [`CALL_PHONE`](../permissions/phone/call-phone.md) permission, FakeCall silently dials `*21*[attacker_number]#` to redirect all incoming calls. When the bank calls the victim for fraud verification, the call goes to the attacker instead. See [Call Interception -- USSD Code Forwarding](call-interception.md#ussd-code-forwarding) for the full technique breakdown.

### Samsung USSD Vulnerability (CVE-2012-4001)

In 2012, [Ravi Borgaonkar demonstrated](https://www.youtube.com/watch?v=Q2-0B04HPhs) that Samsung devices would execute USSD codes embedded in `tel:` URIs without user confirmation. Visiting a webpage containing `<iframe src="tel:*2767*3855#">` triggered a factory reset on vulnerable Samsung Galaxy S III devices. The USSD code `*2767*3855#` is Samsung's factory reset code. The attack worked via:

- NFC tags with `tel:` URI payloads
- QR codes resolving to `tel:` URIs
- Web pages with `tel:` URI iframes or redirects
- SMS messages containing clickable `tel:` links

Samsung patched this, and modern Android versions display a confirmation dialog before dialing USSD codes via `tel:` URIs. The incident demonstrated why programmatic USSD execution without user consent is dangerous.

### Platform Lifecycle (USSD)

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| Pre-4.2 | <17 | No confirmation required for `tel:` URI USSD codes | Silent factory reset via web page ([CVE-2012-4001](#samsung-ussd-vulnerability-cve-2012-4001)) |
| 4.2 | 17 | `tel:` URI USSD codes show confirmation dialog | Direct web-triggered USSD eliminated |
| 8.0 | 26 | [`sendUssdRequest()`](https://developer.android.com/reference/android/telephony/TelephonyManager#sendUssdRequest(java.lang.String,%20android.telephony.TelephonyManager.UssdResponseCallback,%20android.os.Handler)) API with proper permission checks | Programmatic USSD execution still works with `CALL_PHONE` |
| 10 | 29 | [Background activity launch restrictions](https://developer.android.com/about/versions/10/privacy/changes#background-activity-starts) | Silent USSD dialing from background limited |

## SIM Toolkit (STK) Attacks

SIM Toolkit is a set of commands built into the SIM card itself. STK applications are Java Card applets running on the SIM's microprocessor, entirely separate from Android. The SIM can instruct the phone to send SMS, initiate calls, launch browsers, and display menus -- all without the Android OS having a say.

### Simjacker (2019)

[Simjacker](https://simjacker.com/), discovered by [AdaptiveMobile Security in September 2019](https://www.adaptivemobile.com/blog/simjacker-next-generation-spying-over-mobile), is the most significant SIM-level attack ever disclosed. It exploits S@T Browser (SIMalliance Toolbox Browser), a legacy application present on SIM cards from virtually every manufacturer.

**Attack flow:**

1. Attacker sends a specially crafted binary SMS (SMS-PP) to the target
2. The SMS is routed directly to the SIM card's S@T Browser, not to Android
3. S@T Browser executes STK commands embedded in the SMS payload
4. Commands can: retrieve location (Cell ID), retrieve IMEI, send SMS, initiate calls, launch browser
5. Results are sent back to the attacker via SMS from the SIM card
6. The entire attack is invisible to the Android OS -- no notifications, no logs

**Scale:** AdaptiveMobile estimated over 1 billion SIM cards across 30+ countries were vulnerable. The attack was actively exploited in the wild by a surveillance company working with government clients. Specific targets received hundreds of Simjacker attacks per week over a period of years.

**STK commands used by Simjacker:**

| STK Command | Function |
|-------------|----------|
| PROVIDE LOCAL INFORMATION | Get Cell ID (location), IMEI, battery status |
| SEND SHORT MESSAGE | Send SMS from victim's SIM to any number |
| SET UP CALL | Initiate voice calls |
| OPEN CHANNEL | Establish data connections |
| SEND DTMF | Send DTMF tones during active calls |
| RUN AT COMMAND | Execute AT commands on the baseband modem |

### WIBattack

[WIBattack](https://ginno.com/blog/wibattack/), disclosed by Ginno Security Lab shortly after Simjacker, targets the Wireless Internet Browser (WIB) -- another SIM-resident application similar to S@T Browser. The attack mechanism is identical: a crafted binary SMS triggers STK commands on the SIM. WIB is maintained by SmartTrust (now Giesecke+Devrient) and is present on SIM cards from different carriers than those running S@T Browser.

### Why STK Attacks Bypass Android

STK attacks operate at the SIM card layer, below the Android operating system:

- The SIM card has its own processor and runs its own Java Card OS
- Binary SMS (SMS-PP) messages are routed directly to the SIM card by the baseband modem
- Android never sees the attack SMS or the SIM's response
- No Android permission, security tool, or antivirus can detect or prevent the attack
- The SIM card can instruct the phone to perform actions (send SMS, make calls) through the baseband, bypassing Android's permission model

Mitigation is entirely on the carrier side: updating SIM card firmware to remove or restrict S@T Browser and WIB, or deploying network-level SMS filtering to block malformed SMS-PP messages.

## Baseband/Modem Attacks

The baseband processor handles all cellular communication (2G/3G/4G/5G) and is directly connected to the SIM card interface. Vulnerabilities in the baseband firmware enable remote code execution via crafted cellular signals, potentially compromising the device before Android even processes the data.

### Samsung Exynos Baseband (Project Zero, 2023)

[Google Project Zero disclosed 18 vulnerabilities in Samsung Exynos modems](https://googleprojectzero.blogspot.com/2023/03/multiple-internet-to-baseband-remote-rce.html) in March 2023. Four were rated critical -- allowing Internet-to-baseband remote code execution with no user interaction. An attacker only needed the victim's phone number. Affected chipsets powered Samsung Galaxy S22, Pixel 6/7, and various Vivo devices. Samsung delayed patches, leading Project Zero to publicly disclose the bugs after 90 days.

These baseband vulnerabilities are relevant to SIM/carrier attacks because:

- The baseband is the gateway between the cellular network and the SIM card
- Baseband compromise gives full access to all cellular communications
- An attacker with baseband control can intercept all calls, SMS, and data before encryption
- STK commands pass through the baseband, so a compromised baseband can inject or modify them

Baseband exploitation is covered in more depth in the context of privilege escalation and zero-click attacks. The key point for this page is that the baseband/SIM/carrier stack forms a single attack surface that operates independently of the Android OS.

## Families Using These Techniques

| Family | Technique | Target | Revenue/Impact |
|--------|-----------|--------|----------------|
| [Joker](../malware/families/joker.md) | WAP billing, premium SMS | Global, Play Store | 1,700+ malicious apps removed |
| [GriftHorse](../malware/families/grifthorse.md) | WAP billing via social engineering | 70+ countries | 10M+ victims, $35M+ stolen |
| [Harly](../malware/families/harly.md) | DCB subscription fraud | Global, Play Store | Premium service subscriptions |
| [FakeCall](../malware/families/fakecalls.md) | USSD call forwarding | South Korean banks | Banking fraud via call redirection |
| [FluBot](../malware/families/flubot.md) | Premium SMS, SMS worm | Europe | Millions of SMS/day at peak |
| [MoqHao](../malware/families/moqhao.md) | Premium SMS, smishing | Japan, South Korea | SMS-based propagation |
| [Rafel RAT](../malware/families/rafelrat.md) | USSD code execution, SMS fraud | Global | Airtime theft, account manipulation |
| [TrickMo](../malware/families/trickmo.md) | SMS OTP interception (SIM swap assist) | European banks | Combined with credential theft |
| Simjacker (surveillance tool) | STK command execution via S@T Browser | 30+ countries | State-sponsored surveillance |
| WIBattack (research) | STK command execution via WIB | Carrier-dependent | Demonstrated, real-world use unknown |

## Detection Challenges

These attacks are difficult to detect because many of them operate outside the Android OS entirely.

| Attack | Visibility to Android | Detection Method |
|--------|----------------------|------------------|
| SIM swapping | None (carrier-side) | Loss of cellular signal; carrier notification (post-2023 FCC rules) |
| eSIM social engineering | None (carrier-side) | Loss of cellular signal |
| WAP billing fraud | Partial (WebView, WiFi toggle, SMS) | Monitor for WiFi disable + WebView + SMS intercept pattern |
| Premium SMS | Full (uses `SEND_SMS` API) | Standard permission analysis and behavioral monitoring |
| USSD dialing | Full (uses `CALL_PHONE` API) | Monitor for `tel:` intents with USSD code patterns |
| Simjacker/WIBattack | None (SIM-level) | Only detectable at carrier network level via SMS-PP inspection |
| Baseband exploitation | None (below OS) | Only detectable via baseband firmware analysis or network anomaly detection |

??? example "Static Indicators"

    - `WifiManager.setWifiEnabled(false)` combined with WebView creation (WAP billing pattern)
    - `RECEIVE_WAP_PUSH` permission in manifest
    - Premium short code numbers in strings or resources
    - USSD code patterns (`*21*`, `*67*`, `*#06#`, `*123#`) in strings or encoded resources
    - `ACTION_CALL` intents with `tel:` URIs containing `#` or `*`
    - `TelephonyManager.sendUssdRequest()` calls
    - `EuiccManager` API references (rare but notable)
    - JavaScript injection strings targeting subscription buttons (`querySelector('.subscribe')`)

??? example "Dynamic Indicators"

    - WiFi disabled immediately followed by HTTP requests over mobile data
    - WebView loading known WAP billing domains
    - SMS sent to premium short codes
    - SMS received from carrier billing services, immediately deleted
    - `ACTION_CALL` intents with USSD code payloads
    - Outbound SMS the user did not initiate
    - Sudden loss of cellular connectivity (potential SIM swap in progress)
