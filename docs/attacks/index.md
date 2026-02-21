# Attack Techniques

Documented exploitation techniques targeting Android applications and the OS. Each technique covers what it is, the preconditions required, how it works in practice, real-world malware that uses it, and how it has evolved across Android versions.

Organized by the Android component or mechanism being targeted.

## Techniques

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Overlay Attacks](overlay-attacks.md) | Window Manager | `SYSTEM_ALERT_WINDOW` |
| [Accessibility Abuse](accessibility-abuse.md) | Accessibility Service | `BIND_ACCESSIBILITY_SERVICE` |
| [Screen Capture](screen-capture.md) | MediaProjection / Accessibility | `FOREGROUND_SERVICE`, `BIND_ACCESSIBILITY_SERVICE` |
| [Keylogging](keylogging.md) | InputMethodService / Accessibility | `BIND_ACCESSIBILITY_SERVICE` |
| [SMS Interception](sms-interception.md) | SMS / BroadcastReceiver | `RECEIVE_SMS`, `READ_SMS` |
| [Notification Listener Abuse](notification-listener-abuse.md) | NotificationListenerService | `BIND_NOTIFICATION_LISTENER_SERVICE` |
| [Automated Transfer Systems](automated-transfer-systems.md) | Accessibility + Banking Apps | `BIND_ACCESSIBILITY_SERVICE` |
| [Phishing Techniques](phishing-techniques.md) | UI / Social Engineering | `SYSTEM_ALERT_WINDOW` (optional) |
| [C2 Communication](c2-techniques.md) | Network / IPC | `INTERNET` |
| [Dynamic Code Loading](dynamic-code-loading.md) | ClassLoader / Runtime | None (app-private storage) |
| [Device Admin Abuse](device-admin-abuse.md) | DevicePolicyManager | `BIND_DEVICE_ADMIN` |
| [Persistence Techniques](persistence-techniques.md) | Services / Receivers | `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE` |
| [Intent Hijacking](intent-hijacking.md) | Activities, Services | None (component export) |
| [Deep Link Exploitation](deep-link-exploitation.md) | Activities | None (URI scheme) |
| [WebView Exploitation](webview-exploitation.md) | WebView | Varies |
| [Content Provider Attacks](content-provider-attacks.md) | Content Providers | None (provider export) |
| [Tapjacking](tapjacking.md) | Touch Events | `SYSTEM_ALERT_WINDOW` |
| [Task Affinity Attacks](task-affinity-attacks.md) | Activity Stack | None (manifest config) |
| [Broadcast Theft](broadcast-theft.md) | Broadcast Receivers | Varies |
| [NFC Relay](nfc-relay.md) | NFC / Host Card Emulation | NFC (normal) |
| [Clipboard Hijacking](clipboard-hijacking.md) | ClipboardManager | None (foreground) or `BIND_ACCESSIBILITY_SERVICE` |
| [App Virtualization](app-virtualization.md) | VirtualApp / DroidPlugin | None (app-level) |
| [App Collusion](app-collusion.md) | IPC / Shared Storage / SDKs | Varies (distributed across apps) |
| [AI-Assisted Malware](ai-assisted-malware.md) | LLMs / Deepfakes / Adversarial ML | Varies |
| [Anti-Analysis Techniques](anti-analysis-techniques.md) | Emulator / Root / Frida / Debugger | `QUERY_ALL_PACKAGES` |
| [Call Interception](call-interception.md) | TelecomManager / CallRedirectionService | `CALL_PHONE`, `READ_PHONE_STATE` |
| [Camera & Mic Surveillance](camera-mic-surveillance.md) | Camera / MediaRecorder / MediaProjection | `CAMERA`, `RECORD_AUDIO` |
| [Device Wipe & Ransomware](device-wipe-ransomware.md) | DevicePolicyManager / File System | `BIND_DEVICE_ADMIN`, `MANAGE_EXTERNAL_STORAGE` |
| [Mass Malware Generation](mass-malware-generation.md) | MaaS Builders / Crypters / Repackaging | None (tooling-level) |
| [Network Traffic Interception](network-traffic-interception.md) | VpnService / DNS / Certificate Store | [`BIND_VPN_SERVICE`](../permissions/special/bind-vpn-service.md) |
| [Notification Suppression](notification-suppression.md) | NotificationListenerService / AudioManager | `BIND_NOTIFICATION_LISTENER_SERVICE` |

## Kill Chain

How attacks chain together in a typical Android banking trojan or spyware operation. Each stage builds on the previous one.

| Stage | Objective | Techniques / Permissions | What Happens |
|-------|-----------|--------------------------|-------------|
| **1. Delivery** | Get on device | [Phishing](phishing-techniques.md), sideloading, Play Store dropper, smishing link | APK delivered as fake app (Chrome update, Flash Player, bank app) |
| **2. Dropper** | Install payload | [`REQUEST_INSTALL_PACKAGES`](../permissions/special/request-install-packages.md), [Dynamic Code Loading](dynamic-code-loading.md) | Dropper downloads and installs the real malware APK at runtime |
| **3. Persistence** | Survive reboots | [Persistence Techniques](persistence-techniques.md): [`RECEIVE_BOOT_COMPLETED`](../permissions/normal/receive-boot-completed.md) + [`FOREGROUND_SERVICE`](../permissions/normal/foreground-service.md) | Boot receiver re-launches malware; foreground service prevents kill |
| **4. Privilege escalation** | Gain control | [Accessibility Abuse](accessibility-abuse.md), [Device Admin Abuse](device-admin-abuse.md) | User tricked into enabling accessibility service or device admin; malware can now auto-grant permissions, read screens, inject input, resist uninstall |
| **5. Credential theft** | Steal logins | [Overlay Attacks](overlay-attacks.md), [Keylogging](keylogging.md), [Screen Capture](screen-capture.md), [Clipboard Hijacking](clipboard-hijacking.md) | Phishing overlay injected over banking app, keystrokes captured, screen recorded, clipboard monitored for seed phrases |
| **6. 2FA bypass** | Intercept OTPs | [SMS Interception](sms-interception.md), [Notification Listener Abuse](notification-listener-abuse.md) | SMS OTPs intercepted via broadcast receiver or read from notification shade; push-based OTPs captured via notification listener |
| **7. On-device fraud** | Move money | [Automated Transfer Systems](automated-transfer-systems.md) | ATS fills in transfer fields, confirms transactions, hides SMS confirmations |
| **8. Exfiltration** | Send data to C2 | [C2 Communication](c2-techniques.md): [`INTERNET`](../permissions/normal/internet.md) | Credentials, SMS, contacts, screen recordings sent to C2 over HTTP/WebSocket |
| **9. Anti-analysis** | Avoid detection | [Anti-Analysis Techniques](anti-analysis-techniques.md), [Device Admin Abuse](device-admin-abuse.md) | Check for [emulators/AV/Frida](anti-analysis-techniques.md), [suppress notifications](notification-suppression.md), [wipe device](device-wipe-ransomware.md) on detection |

## Technique Combinations

Attacks rarely operate alone. These are the most common pairings observed in active malware families.

| Combination | Result | Families Using It |
|-------------|--------|-------------------|
| [Overlay](overlay-attacks.md) + [Accessibility](accessibility-abuse.md) | Credential theft with ATS -- overlay steals creds, accessibility automates transfers | [Cerberus](../malware/families/cerberus.md), [Ermac](../malware/families/ermac.md), [Hook](../malware/families/hook.md), [Xenomorph](../malware/families/xenomorph.md), [Octo](../malware/families/octo.md), [GodFather](../malware/families/godfather.md), [TsarBot](../malware/families/tsarbot.md) |
| [Accessibility](accessibility-abuse.md) + [Screen Capture](screen-capture.md) | Remote access / VNC -- accessibility provides input control, screen capture provides visual feed | [Hook](../malware/families/hook.md), [Octo](../malware/families/octo.md), [Vultur](../malware/families/vultur.md), [BingoMod](../malware/families/bingomod.md), [Brokewell](../malware/families/brokewell.md) |
| [Accessibility](accessibility-abuse.md) + [Keylogging](keylogging.md) | Full input capture -- every keystroke and text field value recorded | [Cerberus](../malware/families/cerberus.md), [Ermac](../malware/families/ermac.md), [TrickMo](../malware/families/trickmo.md), [SpyNote](../malware/families/spynote.md) |
| [Accessibility](accessibility-abuse.md) + [Clipboard Hijacking](clipboard-hijacking.md) | Crypto theft -- accessibility reads screen content, clipboard captures wallet addresses | [SparkCat](../malware/families/sparkcat.md), [SpyAgent](../malware/families/spyagent.md), Clipper variants |
| [Notification Listener](notification-listener-abuse.md) + [SMS Interception](sms-interception.md) | Complete OTP theft -- SMS receiver grabs text-based codes, notification listener catches push-based codes | [Anatsa](../malware/families/anatsa.md), [Xenomorph](../malware/families/xenomorph.md), [GodFather](../malware/families/godfather.md) |
| [Dynamic Code Loading](dynamic-code-loading.md) + [Phishing](phishing-techniques.md) | Dropper with clean initial scan -- benign APK passes Play Protect, downloads payload post-install | [Anatsa](../malware/families/anatsa.md), [SharkBot](../malware/families/sharkbot.md), [Joker](../malware/families/joker.md) |
| [Device Admin](device-admin-abuse.md) + [Persistence](persistence-techniques.md) | Unremovable malware -- device admin blocks uninstall, persistence survives reboots | [BRATA](../malware/families/brata.md), [Cerberus](../malware/families/cerberus.md), [Rafel RAT](../malware/families/rafelrat.md) |
| [Overlay](overlay-attacks.md) + [Tapjacking](tapjacking.md) | Layered UI deception -- overlay captures input while tapjacking forces user interaction | [Anubis](../malware/families/anubis.md), [BankBot](../malware/families/bankbot.md) (older families pre-Android 12) |
| [Accessibility](accessibility-abuse.md) + [NFC Relay](nfc-relay.md) | Contactless payment fraud -- accessibility extracts card PINs, NFC relay clones tap-to-pay | [NGate](../malware/families/ngate.md), [GoldPickaxe](../malware/families/goldpickaxe.md) |
| [Deep Links](deep-link-exploitation.md) + [WebView](webview-exploitation.md) | Token theft -- deep link redirects into malicious WebView that leaks auth tokens | App-specific exploits, [Mandrake](../malware/families/mandrake.md) |
| [Intent Hijacking](intent-hijacking.md) + [Broadcast Theft](broadcast-theft.md) | SMS interception -- hijack SMS broadcast to steal OTPs before the real app sees them | [FluBot](../malware/families/flubot.md), [Anatsa](../malware/families/anatsa.md), most banking trojans |
| [Accessibility](accessibility-abuse.md) + [Content Provider](content-provider-attacks.md) | Data exfiltration -- accessibility navigates apps, content provider queries extract stored data | Spyware families ([Pegasus](../malware/families/pegasus.md), [Predator](../malware/families/predator.md)) |
| [App Virtualization](app-virtualization.md) + [Accessibility](accessibility-abuse.md) | Overlay-free credential theft -- real banking app runs in hostile sandbox, accessibility redirects launch intents | [GodFather](../malware/families/godfather.md) v3, FjordPhantom |
| [App Collusion](app-collusion.md) + [Persistence](persistence-techniques.md) | Resilient multi-app architecture -- payload survives deletion of the visible dropper app | [PixPirate](../malware/families/pixpirate.md) |
| [Mass Malware Generation](mass-malware-generation.md) + [Play Store Evasion](play-store-evasion.md) | Volume-based evasion -- hundreds of variants submitted across distributed developer accounts overwhelm review | Vapor (331 apps), Konfety (250+ apps), [Joker](../malware/families/joker.md) (1,700+ variants) |
| [Notification Suppression](notification-suppression.md) + [ATS](automated-transfer-systems.md) | Invisible fraud -- transaction alerts dismissed while ATS moves money | [Cerberus](../malware/families/cerberus.md), [Hook](../malware/families/hook.md), [Octo](../malware/families/octo.md), [Xenomorph](../malware/families/xenomorph.md) |
| [Call Interception](call-interception.md) + [Phishing](phishing-techniques.md) | Voice phishing -- victim calls real bank number but reaches attacker IVR | [Fakecalls](../malware/families/fakecalls.md), Letscall |
| [Device Wipe](device-wipe-ransomware.md) + [ATS](automated-transfer-systems.md) | Post-fraud cleanup -- factory reset destroys evidence after money transfer | [BRATA](../malware/families/brata.md), [BingoMod](../malware/families/bingomod.md) |
| [Camera/Mic Surveillance](camera-mic-surveillance.md) + [Accessibility](accessibility-abuse.md) | Full device surveillance -- camera/mic capture with screen reading and input injection | [SpyNote](../malware/families/spynote.md), [Pegasus](../malware/families/pegasus.md) |
| [Anti-Analysis](anti-analysis-techniques.md) + [Dynamic Code Loading](dynamic-code-loading.md) | Staged evasion -- environment checks before loading payload; sandbox sees nothing | [Anatsa](../malware/families/anatsa.md), [Mandrake](../malware/families/mandrake.md), [Octo](../malware/families/octo.md) |
| [Network Interception](network-traffic-interception.md) + [DNS Manipulation](network-traffic-interception.md#dns-manipulation) | Network-level phishing -- DNS hijacking redirects banking domains to credential harvesting | [MoqHao](../malware/families/moqhao.md) / Roaming Mantis |

## Defense Priority

Ranked by prevalence in modern (2024-2025) Android malware. Priority reflects how frequently the technique appears in active campaigns and how much damage it enables.

| Rank | Technique | Prevalence | Why It Matters |
|-----:|-----------|-----------|----------------|
| 1 | [Accessibility Abuse](accessibility-abuse.md) | Nearly universal in banking trojans | Enables everything: auto-granting permissions, reading screens, performing ATS, bypassing 2FA |
| 2 | [Overlay Attacks](overlay-attacks.md) | High (banking trojans) | Primary credential harvesting method; still effective despite Android restrictions |
| 3 | [Screen Capture](screen-capture.md) | High (banking trojans, RATs) | Real-time VNC and screen recording for credential theft and remote control |
| 4 | [Keylogging](keylogging.md) | High (banking trojans, spyware) | Captures passwords and OTPs as users type; pairs with accessibility for full coverage |
| 5 | [C2 Communication](c2-techniques.md) | Universal | Every malware family needs a command channel; multi-channel C2 is the norm |
| 6 | [Persistence Techniques](persistence-techniques.md) | Universal (supporting) | Required for any long-running operation; boot receivers and foreground services are baseline |
| 7 | [Automated Transfer Systems](automated-transfer-systems.md) | High (banking trojans) | On-device fraud that bypasses bank-side device fingerprinting and session checks |
| 8 | [SMS Interception](sms-interception.md) | High (declining on newer OS) | Original 2FA bypass method; restricted by Play Store policy but still used in sideloaded malware |
| 9 | [Notification Listener Abuse](notification-listener-abuse.md) | High (rising) | Replaced SMS interception as primary OTP theft vector; reads all app notifications |
| 10 | [Dynamic Code Loading](dynamic-code-loading.md) | High (droppers) | Foundation of Play Store evasion; clean APK downloads malicious payload post-install |
| 11 | [Phishing Techniques](phishing-techniques.md) | High (delivery) | Primary infection vector; smishing, fake Play Store pages, social engineering for permissions |
| 12 | [Clipboard Hijacking](clipboard-hijacking.md) | Rising (crypto-targeting) | Growing alongside cryptocurrency adoption; minimal permissions required from foreground |
| 13 | [NFC Relay](nfc-relay.md) | Emerging | Bypasses contactless payment security entirely; hard to detect at the device level |
| 14 | [Device Admin Abuse](device-admin-abuse.md) | Moderate (declining) | Prevents uninstall and enables device wipe; being replaced by accessibility-based persistence |
| 15 | [Intent Hijacking](intent-hijacking.md) | Moderate | Enables SMS/OTP theft and IPC interception; foundational for many attack chains |
| 16 | [WebView Exploitation](webview-exploitation.md) | Moderate | Targets hybrid apps; token theft, JavaScript injection, MITM within the app |
| 17 | [Broadcast Theft](broadcast-theft.md) | Moderate (declining) | SMS interception still works but restricted on newer Android versions |
| 18 | [Deep Link Exploitation](deep-link-exploitation.md) | Moderate | OAuth redirect attacks, app navigation hijacking; underestimated in mobile pentests |
| 19 | [Tapjacking](tapjacking.md) | Low (declining) | Largely mitigated by `filterTouchesWhenObscured` and Android 12+ restrictions |
| 20 | [Task Affinity Attacks](task-affinity-attacks.md) | Low | Niche but effective for targeted phishing within the task switcher |
| 21 | [Content Provider Attacks](content-provider-attacks.md) | Low | App-specific; dangerous when providers are exported without proper permissions |
| 22 | [App Virtualization](app-virtualization.md) | Emerging (high impact) | Runs real banking apps inside malware-controlled sandbox; bypasses overlay detection, repackaging checks, and root detection |
| 23 | [App Collusion](app-collusion.md) | Moderate (SDK-mediated) | SDK-based cross-app data aggregation is the dominant model; multi-app malware architectures emerging |
| 24 | [AI-Assisted Malware](ai-assisted-malware.md) | Rising | LLM-assisted development, deepfake biometric fraud, underground AI tools lowering skill barriers |
| 25 | [Mass Malware Generation](mass-malware-generation.md) | High (infrastructure) | MaaS builders, crypter services, and coordinated store submission produce variants faster than detection can scale |
| 26 | [Anti-Analysis Techniques](anti-analysis-techniques.md) | Universal (supporting) | Nearly every family implements emulator/root/Frida detection; determines whether payload executes at all |
| 27 | [Notification Suppression](notification-suppression.md) | High (banking trojans) | Hides transaction alerts during fraud; dual-purpose with OTP theft via notification listener |
| 28 | [Camera & Mic Surveillance](camera-mic-surveillance.md) | High (spyware, RATs) | Core capability of state-sponsored spyware and surveillance RATs; increasingly restricted by OS |
| 29 | [Call Interception](call-interception.md) | Moderate (region-specific) | Voice phishing via call redirection; dominant in Korean-targeting campaigns |
| 30 | [Device Wipe & Ransomware](device-wipe-ransomware.md) | Moderate (declining for ransomware, rising for evidence destruction) | File encryption declining due to scoped storage; factory reset as post-fraud cleanup is growing |
| 31 | [Network Traffic Interception](network-traffic-interception.md) | Moderate | DNS hijacking, VPN abuse, proxy configuration; Android 14 APEX certificate store makes MITM harder |
