# Keylogging & Input Capture

Intercepting user keystrokes and text input to steal credentials, OTPs, and sensitive data. On Android, there is no kernel-level keylogger equivalent -- input capture operates through the accessibility framework or by replacing the system keyboard with a malicious Input Method Editor (IME). Both approaches are well-documented abuse paths that require user interaction to enable.

See also: [Camera & Mic Surveillance](camera-mic-surveillance.md), [Screen Capture](screen-capture.md)

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1417.001](https://attack.mitre.org/techniques/T1417/001/) | Input Capture: Keylogging | Credential Access, Collection |

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Accessibility keylogging | [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) enabled by user |
    | IME keylogging | Malicious IME installed and selected as default keyboard |
    | Targeted capture | Package name list of target apps from C2 |

## Techniques

### Accessibility-Based Keylogging

The dominant method. An enabled accessibility service receives `TYPE_VIEW_TEXT_CHANGED` events every time the user types or modifies text in any app. Each event contains the current text content, the source package name, and the view's resource ID.

```java
@Override
public void onAccessibilityEvent(AccessibilityEvent event) {
    if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
        CharSequence pkg = event.getPackageName();
        List<CharSequence> textList = event.getText();
        String fieldId = event.getSource() != null
            ? event.getSource().getViewIdResourceName()
            : "unknown";

        String captured = "";
        for (CharSequence t : textList) {
            captured += t.toString();
        }

        if (isTargetPackage(pkg.toString())) {
            exfiltrate(pkg.toString(), fieldId, captured);
        }
    }
}
```

The accessibility service configuration in `res/xml/accessibility_service_config.xml`:

```xml
<accessibility-service
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeViewTextChanged|typeViewFocused"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:notificationTimeout="100"
    android:accessibilityFlags="flagRetrieveInteractiveWindows|flagRequestFilterKeyEvents"
    android:canRetrieveWindowContent="true" />
```

The `flagRequestFilterKeyEvents` flag enables the service to receive raw `KeyEvent` objects via `onKeyEvent()`, providing individual key presses rather than accumulated text:

```java
@Override
protected boolean onKeyEvent(KeyEvent event) {
    if (event.getAction() == KeyEvent.ACTION_DOWN) {
        int keyCode = event.getKeyCode();
        logKeystroke(keyCode, event.getUnicodeChar());
    }
    return false;
}
```

Returning `false` allows the key event to pass through to the target app normally. Returning `true` would consume it, which would alert the user.

### Custom IME Keylogging

A malicious `InputMethodService` replaces the device keyboard. Every keystroke across every app flows through the malware's code, including characters the user deletes before submission -- something accessibility keylogging cannot capture.

```java
public class MaliciousIME extends InputMethodService {
    @Override
    public View onCreateInputView() {
        return getLayoutInflater().inflate(R.layout.keyboard, null);
    }

    @Override
    public void onStartInput(EditorInfo attribute, boolean restarting) {
        super.onStartInput(attribute, restarting);
        logTargetField(attribute.packageName, attribute.fieldId, attribute.inputType);
    }

    public void onKeyPress(int keyCode) {
        InputConnection ic = getCurrentInputConnection();
        if (ic != null) {
            ic.commitText(String.valueOf((char) keyCode), 1);
            exfiltrate(keyCode, getCurrentPackage());
        }
    }
}
```

The `EditorInfo` object reveals the input field type (`TYPE_TEXT_VARIATION_PASSWORD`, `TYPE_CLASS_NUMBER` for PINs, etc.), allowing the malware to flag high-value captures automatically.

Activation requires two steps: the user must install the IME and then select it as the default keyboard. Malware automates the second step by using accessibility to navigate Settings > Language & Input and toggle the keyboard selection.

### /proc-Based Monitoring (Historical)

Older technique from pre-Android 7 era. The malware reads `/proc/self/inputflinger` or parses `/dev/input/eventX` (requires root or specific SELinux context) to intercept raw input events at the Linux kernel level. Android's SELinux policies and procfs restrictions have made this approach non-viable on modern devices without a kernel exploit.

## Accessibility vs IME Comparison

| Aspect | Accessibility Keylogging | Custom IME |
|--------|------------------------|------------|
| Activation | User enables accessibility service | User selects as default keyboard |
| Capture scope | Text after each change event | Individual keystrokes including deleted characters |
| Password fields | May receive masked text (dots) in some apps | Sees raw characters before masking |
| Package context | Package name + resource ID available | Package name + EditorInfo available |
| Persistence | Survives app restarts, sometimes device reboots | Persists as default keyboard until changed |
| Android restrictions | Increasingly restricted per version | Minimal restrictions, user choice respected |
| Stealth | No visible change to user | Keyboard UI must look legitimate |
| Additional capabilities | Full accessibility suite (clicks, gestures, screen reading) | Limited to input capture only |
| Prevalence in malware | Dominant approach (~90% of banking trojans) | Rare, used by a few specialized families |

## Targeted Field Capture

Banking trojans do not log everything. They maintain a target list (downloaded from C2) mapping package names to fields of interest. This reduces noise and data volume.

| Target | How Identified | Event Pattern |
|--------|---------------|---------------|
| Username/email | Resource ID containing `login`, `email`, `username`, `user_id` | `TYPE_VIEW_TEXT_CHANGED` on matching view |
| Password | `TYPE_TEXT_VARIATION_PASSWORD` input type, or resource ID containing `password`, `pass`, `pin` | `TYPE_VIEW_TEXT_CHANGED` (may be masked) or `onKeyEvent` for raw keys |
| OTP/2FA code | Resource ID containing `otp`, `code`, `token`, 6-digit numeric input after SMS arrival | `TYPE_VIEW_TEXT_CHANGED` on numeric field |
| Card number | `TYPE_CLASS_NUMBER` with 16-digit pattern, resource ID containing `card`, `pan` | Sequential numeric input matching card format |
| CVV | 3-digit numeric field after card number entry | `TYPE_VIEW_TEXT_CHANGED` on short numeric field |

Some families also monitor `TYPE_VIEW_FOCUSED` events to detect when the user enters a login form, then activate intensive logging only for that session.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 4.0 | 14 | `AccessibilityService` with `canRetrieveWindowContent` | Accessibility keylogging becomes viable |
| 4.0 | 14 | `TYPE_VIEW_TEXT_CHANGED` events | Real-time text capture from any app |
| 4.0 | 14 | `flagRequestFilterKeyEvents` | Raw `KeyEvent` interception via `onKeyEvent()` |
| 8.0 | 26 | Accessibility services must declare handled event types | Malware declares all types in config XML |
| 11 | 30 | `isAccessibilityTool` metadata for Play Store visibility | Sideloaded malware unaffected |
| 12 | 31 | Accessibility services cannot observe password fields in some contexts | Partial, depends on app implementation |
| 13 | 33 | [Restricted settings](https://developer.android.com/about/versions/13/behavior-changes-13#restricted_non_sdk) blocks accessibility for sideloaded apps | Bypassed via [session-based package installer](play-store-evasion.md) |
| 14 | 34 | [`accessibilityDataSensitive`](https://developer.android.com/reference/android/view/View#setAccessibilityDataSensitive(int)) attribute lets apps mark views as sensitive | Only effective if target apps adopt the attribute |
| 15 | 35 | Expanded restricted settings enforcement | Closes some session-installer bypass routes |

The `accessibilityDataSensitive` attribute (Android 14+) is the most significant development. When an app marks an `EditText` as sensitive, accessibility services not flagged as `isAccessibilityTool` cannot read its content. Adoption is slow: most banking apps have not yet implemented it.

## Families Using This Technique

| Family | Method | Specifics |
|--------|--------|-----------|
| [Cerberus](../malware/families/cerberus.md) | Accessibility | Logs all text input, filters by target package list from C2 |
| [Ermac](../malware/families/ermac.md) | Accessibility | Keylogging module inherited from Cerberus codebase |
| [Hook](../malware/families/hook.md) | Accessibility | Keylogging combined with VNC for real-time credential observation |
| [SpyNote](../malware/families/spynote.md) | Accessibility + IME | Deploys custom keyboard alongside accessibility for comprehensive capture |
| [BankBot](../malware/families/bankbot.md) | Accessibility | Early adopter of accessibility keylogging, targeted field capture |
| [Anubis](../malware/families/anubis.md) | Accessibility | Dedicated keylogger module with per-app targeting |
| [TrickMo](../malware/families/trickmo.md) | Accessibility | Screen content capture via tree traversal, targets banking and OTP fields |
| [BlankBot](../malware/families/blankbot.md) | Custom IME | Replaces system keyboard, uses accessibility to auto-enable the IME |
| [Frogblight](../malware/families/frogblight.md) | Custom IME | Custom keyboard with accessibility-assisted activation |
| [Antidot](../malware/families/antidot.md) | Accessibility | Keylogging with VNC-based remote access |
| [Xenomorph](../malware/families/xenomorph.md) | Accessibility | Targeted keylogging as part of ATS workflow |
| [Octo](../malware/families/octo.md) | Accessibility | Combines keylogging with screen streaming |
| [Vultur](../malware/families/vultur.md) | Accessibility | Keylogging alongside MediaProjection screen recording |
| [BTMOB RAT](../malware/families/btmob.md) | Accessibility | Keystroke capture across all apps, combined with WebView credential phishing |

## Credential Theft Workflow

Keylogging rarely operates in isolation. The typical credential theft chain:

1. **Target detection** -- accessibility monitors `TYPE_WINDOW_STATE_CHANGED` to detect when a banking app opens
2. **Keylogging activation** -- intensive logging begins for the target package
3. **Credential capture** -- username and password captured via `TYPE_VIEW_TEXT_CHANGED`
4. **OTP interception** -- SMS intercepted via [`READ_SMS`](../permissions/sms/read-sms.md) or notification reading, or the OTP input field is logged directly
5. **Exfiltration** -- captured data sent to C2, tagged with package name and timestamp
6. **Account takeover** -- attacker uses credentials on their own device, or initiates [on-device fraud via ATS](accessibility-abuse.md)

In families with VNC/remote access (Hook, Octo), the attacker may skip keylogging entirely and instead watch the victim's screen during login via [screen capture](screen-capture.md), then take over the session directly.

## Detection During Analysis

??? example "Static Indicators"

    - `TYPE_VIEW_TEXT_CHANGED` in decompiled accessibility service code
    - `InputMethodService` subclass in the APK
    - `flagRequestFilterKeyEvents` in accessibility service configuration
    - `canRetrieveWindowContent="true"` in service config
    - `EditorInfo` field inspection in IME code
    - Network calls correlated with `onAccessibilityEvent` or `onKeyEvent` handlers

??? example "Dynamic Indicators"

    - Accessibility service actively receiving events from banking app packages
    - Data exfiltration spikes correlating with text input activity
    - Custom IME registered in `Settings.Secure.DEFAULT_INPUT_METHOD`
    - Outbound POST requests containing form field names and values

### Frida Detection Script

Monitor accessibility keylogging in real time:

```javascript
Java.perform(function() {
    var AccessibilityEvent = Java.use("android.view.accessibility.AccessibilityEvent");
    AccessibilityEvent.getText.implementation = function() {
        var result = this.getText();
        var eventType = this.getEventType();
        if (eventType === 16) {
            console.log("[*] TYPE_VIEW_TEXT_CHANGED from: " + this.getPackageName());
            console.log("    Text: " + result.toString());
            console.log("    Source: " + this.getSource());
        }
        return result;
    };
});
```

## Relationship to Other Techniques

- [Accessibility abuse](accessibility-abuse.md) is the foundation -- keylogging is one of many capabilities gained through an accessibility service
- [Overlay attacks](overlay-attacks.md) capture credentials through fake UI, while keylogging captures them from the real UI
- [Screen capture](screen-capture.md) provides visual observation of the same data that keylogging captures as text
