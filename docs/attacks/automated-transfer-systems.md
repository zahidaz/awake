# Automated Transfer Systems (ATS)

On-device fraud that automates money transfers without user interaction. Rather than stealing credentials and replaying them from an attacker-controlled device, ATS operates the victim's real banking app directly using accessibility services. The transaction originates from the victim's trusted device, IP address, and session -- making it nearly invisible to bank-side fraud detection.

See also: [Accessibility Abuse](accessibility-abuse.md), [Overlay Attacks](overlay-attacks.md), [Notification Suppression](notification-suppression.md), [Device Wipe & Ransomware](device-wipe-ransomware.md#post-fraud-factory-reset)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1516](https://attack.mitre.org/techniques/T1516/) | Input Injection | Defense Evasion, Impact |
    | [T1453](https://attack.mitre.org/techniques/T1453/) | Abuse Accessibility Features | Collection, Credential Access |

    MITRE ATT&CK has no standalone technique for Automated Transfer Systems. ATS is a compound banking fraud methodology combining accessibility abuse (T1453) for device control with input injection (T1516) for automated UI interaction. This is a gap in ATT&CK's coverage that AWAKE addresses.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) |
    | Banking App | Target banking app installed and authenticated |
    | Configuration | Recipient account, transfer amount, app-specific UI navigation script |

## ATS vs Overlay vs VNC

Three distinct approaches to banking fraud, often combined within a single family.

| Aspect | Overlay | ATS | VNC / RAT |
|--------|---------|-----|-----------|
| Where fraud happens | Attacker's device (credentials exfiltrated) | Victim's device (automated) | Victim's device (remote-controlled) |
| Credential exfiltration | Yes -- sent to C2 | Not required (uses existing session) | Optional |
| Detection by bank | Different device/IP/fingerprint | Same device, same session | Same device, same session |
| Operator involvement | Manual (attacker logs in remotely) | None (fully scripted) | Manual (attacker controls device live) |
| Scalability | Moderate (requires human operators) | High (runs unattended) | Low (1:1 operator-to-victim ratio) |
| Behavioral biometrics | Fails (different typing/interaction patterns) | Can mimic human behavior | Partially detectable |

## How ATS Works

### The Transfer Workflow

1. **Wait for authentication** -- the malware waits for the user to log into the banking app, or triggers the app open and uses previously stolen credentials via overlay
2. **Navigate to transfer screen** -- accessibility gestures scroll, tap menu items, and navigate to the money transfer section
3. **Fill transfer fields** -- the recipient IBAN/account and amount are injected into text fields using `AccessibilityNodeInfo.ACTION_SET_TEXT`
4. **Confirm transaction** -- the malware clicks through confirmation dialogs, including "Are you sure?" screens
5. **Handle 2FA** -- intercepts SMS OTP from notifications or reads it via `NotificationListenerService`, then enters it into the confirmation field
6. **Clean up** -- deletes confirmation SMS, dismisses push notifications from the bank, clears recent transactions view if possible

### Anti-Detection During Transfer

ATS families employ stealth measures to prevent the user from noticing the fraud in progress:

| Technique | Purpose | Implementation |
|-----------|---------|----------------|
| Screen brightness to 0 | User cannot see device activity | `Settings.System.SCREEN_BRIGHTNESS` set to 0 |
| Mute all audio | Suppress notification sounds | `AudioManager.setStreamMute()` on all streams |
| Enable Do Not Disturb | Block incoming calls/notifications during transfer | `NotificationManager.setInterruptionFilter()` |
| Black overlay | Cover screen with opaque window | `TYPE_APPLICATION_OVERLAY` with `Color.BLACK` |
| Fake "updating" screen | Explain device unresponsiveness | Overlay displaying "System update in progress..." |
| Disable notifications | Prevent bank alerts during transfer | Accessibility dismisses notifications as they arrive |
| Lock user out | Prevent interference mid-transfer | Custom lock screen overlay or `GLOBAL_ACTION_LOCK_SCREEN` |

### Scripting Engines

Early ATS implementations were hardcoded per banking app. Modern families use configurable scripting systems.

**Xenomorph v3 ATS Engine**: introduced a JSON-based scripting language that defines UI navigation as a sequence of operations. Scripts are downloaded from C2 per target app, making it possible to add new bank targets without updating the malware binary.

??? example "Xenomorph v3 ATS Script Example"

    ```json
    {
      "module": "ats",
      "target": "com.target.bankapp",
      "steps": [
        {"action": "open_app", "package": "com.target.bankapp"},
        {"action": "wait", "condition": "text_visible", "value": "Transfer"},
        {"action": "click", "selector": {"text": "Transfer"}},
        {"action": "set_text", "selector": {"id": "recipient_field"}, "value": "<iban>"},
        {"action": "set_text", "selector": {"id": "amount_field"}, "value": "<amount>"},
        {"action": "click", "selector": {"text": "Confirm"}},
        {"action": "wait", "condition": "text_visible", "value": "SMS code"},
        {"action": "set_text", "selector": {"id": "otp_field"}, "value": "<intercepted_sms>"}
      ]
    }
    ```

**SharkBot**: uses a similar declarative approach where each target bank has a configuration defining the UI element IDs, button text, and navigation paths. The C2 pushes updated configs when banking apps change their UI.

**Hook / Octo**: instead of scripted ATS, these families provide full VNC-based remote access, letting the operator navigate the banking app manually. This is more flexible but less scalable.

## Bypassing Transaction Limits

Banks enforce per-transaction and daily transfer limits. ATS handles this by:

- **Splitting transfers** -- breaking a large amount into multiple smaller transfers below the per-transaction threshold
- **Modifying beneficiary lists** -- adding the mule account to the trusted recipient list first (some banks skip 2FA for trusted recipients)
- **Timing across days** -- spreading transfers across multiple days to stay under daily limits
- **Draining all accounts** -- iterating through savings, checking, and linked accounts

## Account Takeover Workflow

A full ATS-driven account takeover chains multiple techniques:

1. Victim installs dropper from phishing SMS or Play Store
2. Dropper requests accessibility permission via social engineering overlay
3. Malware uses accessibility to auto-grant all additional permissions
4. Overlay phishes banking credentials when user opens banking app
5. Malware waits for idle period (typically 2-4 AM local time)
6. ATS opens banking app, authenticates with stolen credentials
7. ATS changes registered phone number and email to attacker-controlled values
8. ATS initiates transfer, intercepts OTP, confirms transaction
9. ATS repeats until accounts are drained or limits are hit
10. Some families wipe the device post-fraud to destroy evidence (BRATA, BingoMod)

## Families With ATS Capability

| Family | ATS Type | Scripting | First ATS Version | Targets |
|--------|----------|-----------|-------------------|---------|
| [Gustuff](../malware/families/gustuff.md) | Scripted | Hardcoded per app | 2019 | Australian banks |
| [Cerberus](../malware/families/cerberus.md) | Scripted | Hardcoded | v2 (2020) | European banks |
| [SharkBot](../malware/families/sharkbot.md) | Scripted | JSON config | v1 (2021) | EU/UK banks |
| [Anatsa](../malware/families/anatsa.md) | Scripted | Configurable | 2021 | EU/US banks |
| [Ermac](../malware/families/ermac.md) | Scripted | Hardcoded | v2 (2022) | 400+ targets |
| [Xenomorph](../malware/families/xenomorph.md) | Scripted | JSON ATS engine | v3 (2023) | 400+ targets |
| [Hook](../malware/families/hook.md) | VNC + ATS | Operator-assisted | 2023 | 400+ targets |
| [Octo](../malware/families/octo.md) | VNC + ATS | Operator-assisted | v2 (2023) | 200+ targets |
| [GodFather](../malware/families/godfather.md) | Scripted | Configurable | v2 (2023) | 400+ targets |
| [Medusa](../malware/families/medusa.md) | VNC-based | Operator-controlled | v2 (2024) | European banks |
| [BingoMod](../malware/families/bingomod.md) | VNC + scripted | Hybrid | 2024 | Italian banks |
| [Albiriox](../malware/families/albiriox.md) | VNC-based | Operator-controlled | 2025 | 400+ targets |
| [RatOn](../malware/families/raton.md) | Scripted | Accessibility-driven | 2025 | Czech/Slovak banks |
| [TsarBot](../malware/families/tsarbot.md) | Scripted | Configurable | 2024 | 750+ targets |
| [Copybara](../malware/families/copybara.md) | VNC + scripted | Hybrid | 2024 | Italian banks |
| [Herodotus](../malware/families/herodotus.md) | Scripted | Human behavior mimicry | 2025 | EU banks |

## Accessibility Code for ATS

??? example "Core accessibility operations used in ATS"

    ```java
    public void fillField(AccessibilityNodeInfo root, String viewId, String value) {
        List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByViewId(viewId);
        if (!nodes.isEmpty()) {
            Bundle args = new Bundle();
            args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value);
            nodes.get(0).performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args);
        }
    }

    public void clickButton(AccessibilityNodeInfo root, String buttonText) {
        List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByText(buttonText);
        for (AccessibilityNodeInfo node : nodes) {
            if (node.isClickable()) {
                node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                return;
            }
            AccessibilityNodeInfo parent = node.getParent();
            if (parent != null && parent.isClickable()) {
                parent.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                return;
            }
        }
    }

    public void navigateToTransfer(AccessibilityService service) {
        Intent intent = service.getPackageManager()
            .getLaunchIntentForPackage("com.target.bankapp");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        service.startActivity(intent);
    }
    ```

## Platform Lifecycle

| Android Version | API | Change | ATS Impact |
|----------------|-----|--------|------------|
| 7.0 | 24 | [`dispatchGesture()`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService#dispatchGesture(android.accessibilityservice.GestureDescription,%20android.accessibilityservice.AccessibilityService.GestureResultCallback,%20android.os.Handler)) API added | Makes ATS viable: programmatic gestures can navigate banking app UI |
| 7.0 | 24 | Background execution limits | Minimal, accessibility runs as foreground service |
| 10 | 29 | Background activity launch restrictions | ATS must wait for user interaction or use `USE_FULL_SCREEN_INTENT` |
| 12 | 31 | [Untrusted touch blocking](https://developer.android.com/about/versions/12/behavior-changes-all#untrusted-touch-events) | Does not affect accessibility-based input injection |
| 13 | 33 | [Restricted settings](https://developer.android.com/about/versions/13/behavior-changes-13#restricted_non_sdk) for sideloaded apps | Accessibility harder to enable; bypassed via session-based install |
| 13 | 33 | Non-dismissible notification for active accessibility | User may notice; malware hides behind legitimate-looking service name |
| 14 | 34 | Accessibility declaration restrictions | Apps must declare specific accessibility capabilities |
| 15 | 35 | Expanded restricted settings enforcement | Closes session-installer bypass for some OEMs |

!!! danger "Fundamental Limitation"

    Once accessibility is granted, there is no OS-level mechanism to distinguish ATS operations from legitimate accessibility tool usage. The permission model is all-or-nothing.

## Detection During Analysis

??? example "Static Indicators"

    - Accessibility service config requesting `flagDefault` or `flagRetrieveInteractiveWindows`
    - References to banking app package names in strings or assets
    - `ACTION_SET_TEXT` and `ACTION_CLICK` usage patterns on `AccessibilityNodeInfo`
    - JSON/XML configuration files mapping package names to UI navigation sequences
    - `AudioManager`, `Settings.System.SCREEN_BRIGHTNESS` manipulation

??? example "Dynamic Indicators"

    - Accessibility service performing actions while screen is off or brightness is 0
    - Automated navigation through banking app UI at non-human speeds
    - SMS read/delete operations immediately following a transfer confirmation
    - Network traffic to C2 containing transaction confirmation details

??? example "Frida Hook to Intercept ATS Actions"

    ```javascript
    Java.perform(function() {
        var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        ANI.performAction.overload("int", "android.os.Bundle").implementation = function(action, args) {
            if (action === 0x200000) {
                console.log("[ATS] SET_TEXT: " + args.getCharSequence("ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE"));
            }
            if (action === 0x10) {
                console.log("[ATS] CLICK on: " + this.getViewIdResourceName());
            }
            return this.performAction(action, args);
        };
    });
    ```
