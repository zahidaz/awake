# Tapjacking

Tricking the user into tapping on something they didn't intend to by placing a transparent or partially obscuring overlay over a sensitive UI element. A specific application of [overlay attacks](overlay-attacks.md) focused on manipulating touch events rather than phishing credentials.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | [`SYSTEM_ALERT_WINDOW`](../permissions/special/system-alert-window.md) |
    | Condition | Target app does not filter obscured touches |

## How It Works

1. Malware draws a transparent or partially transparent overlay over the target UI
2. The overlay shows a benign message ("Tap to continue", a game, a fake dialog)
3. When the user taps, the touch passes through to the UI element underneath
4. The underlying element could be a permission grant button, an install confirmation, or a settings toggle

The key is `FLAG_NOT_TOUCHABLE` on the overlay window: when set, touches pass through the overlay to whatever is beneath it. The user sees the overlay content but their tap hits the hidden target.

### Classic Scenario

Malware wants the user to click "Allow" on a permission dialog:

1. Permission dialog appears behind the overlay
2. Overlay shows an innocuous UI with a button positioned exactly over "Allow"
3. User taps the overlay button
4. Touch passes through to "Allow"
5. Permission granted without user awareness

## Variants

### Full Overlay Passthrough

Entire screen covered with `FLAG_NOT_TOUCHABLE`. User sees the overlay but all touches go to the app behind it. Used to hide what the user is actually interacting with.

### Partial Overlay

Only part of the screen is covered. The unobscured area contains the target (e.g., the "Install" button), while the overlay hides surrounding context that would alert the user.

### Timing-Based

The overlay appears and disappears rapidly, showing for just long enough to catch a tap the user was already making. Harder to detect but less reliable.

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 4.0.3 | `filterTouchesWhenObscured` attribute added | Opt-in; most apps don't implement it |
| Android 6.0 | `SYSTEM_ALERT_WINDOW` moved to special permission (Settings toggle) | Accessibility service can auto-enable |
| Android 8.0 | `TYPE_APPLICATION_OVERLAY` renders below system dialogs | Third-party app UIs remain vulnerable |
| Android 12 | System dialogs set `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`; overlays untouchable over sensitive system UI | Accessibility gestures bypass all overlay mitigations entirely |

### Remaining Gaps

- `filterTouchesWhenObscured` is opt-in. Apps must set it explicitly. Many don't.
- Third-party app UIs (not system dialogs) are still vulnerable.
- Accessibility service gestures bypass all overlay-based mitigations entirely.

## Detection During Analysis

??? example "Static Indicators"

    - `WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE` combined with `TYPE_APPLICATION_OVERLAY` and translucent/transparent pixel format
    - Overlay window dimensions and position matching known system dialog button locations

    ```java
    WindowManager.LayoutParams params = new WindowManager.LayoutParams(
        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
        WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE | WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
        PixelFormat.TRANSLUCENT
    );
    ```

## Families Using This Technique

Modern banking trojans have largely moved past tapjacking toward [accessibility abuse](accessibility-abuse.md), which provides more reliable and comprehensive device control. Tapjacking was primarily seen in earlier malware generations (2014-2017) before accessibility service abuse became the standard approach. Current families that use overlays focus on credential phishing via [overlay attacks](overlay-attacks.md) rather than touch manipulation.

However, tapjacking still appears in specific contexts:

| Family | Usage |
|--------|-------|
| [Anatsa](../malware/families/anatsa.md) | Overlay to trick user into enabling accessibility service by placing transparent "Allow" button over permission dialog |
| [MoqHao](../malware/families/moqhao.md) | Overlay to trick user into granting default SMS app permission |
| [Chameleon](../malware/families/chameleon.md) | Overlay guiding user to disable biometric authentication in favor of PIN entry |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | Overlay prompting facial biometric capture disguised as verification step |
| [TrickMo](../malware/families/trickmo.md) | Overlay to capture the device screen lock PIN, displayed when the user attempts to unlock their phone or open a targeted app |
| [SpyNote](../malware/families/spynote.md) | Overlay that guides the user step-by-step through enabling accessibility service, showing arrows and instructions over the real Settings UI |

The primary modern use is not stealing tap events (the classic tapjacking definition) but rather using transparent or misleading overlays to guide users through permission-granting flows. This is a social engineering application of the same overlay mechanism.

## Accessibility Gesture Alternative

The accessibility service API provides `dispatchGesture()`, which programmatically injects touch events into any app on screen. This eliminates the need for tapjacking entirely -- no overlay required, no user interaction needed.

```java
GestureDescription.Builder builder = new GestureDescription.Builder();
Path clickPath = new Path();
clickPath.moveTo(targetX, targetY);
builder.addStroke(new GestureDescription.StrokeDescription(clickPath, 0, 50));
dispatchGesture(builder.build(), null, null);
```

With accessibility service access, the malware can:

- Click any button on any screen, including permission grant dialogs
- Perform swipe gestures to navigate through settings menus
- Type text into input fields using `Bundle` arguments with `ACTION_SET_TEXT`
- Scroll to find specific UI elements using `AccessibilityNodeInfo.ACTION_SCROLL_FORWARD`

This is strictly superior to tapjacking in every way. There is no timing dependency, no overlay to detect, and no user action to intercept. The only requirement is that the user has granted accessibility service permission to the malware, which is itself often obtained through tapjacking or overlay-guided social engineering -- creating a bootstrap chain where tapjacking enables the more powerful accessibility approach.

Modern banking trojans ([Anatsa](../malware/families/anatsa.md), [Xenomorph](../malware/families/xenomorph.md), [Hook](../malware/families/hook.md)) use tapjacking or overlay guidance as a one-time step to obtain accessibility access, then switch entirely to `dispatchGesture()` and `AccessibilityNodeInfo` actions for all subsequent device manipulation. The overlay is the scaffolding; accessibility is the building.

## Testing for Tapjacking Vulnerability

### Checking App-Level Protection

An app is vulnerable to tapjacking if its sensitive UI elements do not reject touches when an overlay is present. The defense is `filterTouchesWhenObscured`, which can be set per-view in XML or programmatically.

In layout XML:

```xml
<Button
    android:filterTouchesWhenObscured="true"
    android:text="Confirm Payment" />
```

Or in code:

```java
button.setFilterTouchesWhenObscured(true);
```

Or by checking `MotionEvent.FLAG_WINDOW_IS_OBSCURED` in `onTouchEvent()` / `onFilterTouchEventForSecurity()`.

To determine if an app is vulnerable, decompile the APK and search for these indicators. If none are present on security-sensitive views (payment confirmation, permission grants, login), the app is likely vulnerable.

### Testing with ADB

Create a test overlay without writing a full app:

```bash
adb shell settings put system show_touches 1
```

For a more thorough test, use a minimal overlay app or the `WindowManager` shell commands available on rooted devices. The steps:

1. Install a simple overlay app (or use an existing screen dimmer/filter app)
2. Activate the overlay so it covers the target app's UI
3. Attempt to tap through the overlay onto sensitive buttons
4. If the taps register, the app does not filter obscured touches

### Automated Detection with Drozer

```bash
dz> run app.activity.info -a com.target.app
```

Check for activities that handle sensitive actions and cross-reference with static analysis for `filterTouchesWhenObscured` usage. Drozer does not directly test tapjacking, but it identifies the attack surface (exported activities with sensitive functionality) that you then test manually with an overlay.

### What to Look For

| Indicator | Verdict |
|-----------|---------|
| `filterTouchesWhenObscured="true"` on all sensitive views | Protected |
| `onFilterTouchEventForSecurity()` override checking obscured flag | Protected |
| No obscured touch handling anywhere in the codebase | Vulnerable |
| `FLAG_WINDOW_IS_OBSCURED` check only on some views | Partially vulnerable |
