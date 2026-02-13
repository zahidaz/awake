# Biometric Authentication

Android's biometric authentication framework lets apps verify user identity through fingerprint, face, or iris recognition. The BiometricPrompt API (introduced in Android 9, API 28) provides a standardized system-managed authentication dialog. From an offensive perspective, biometric authentication is only as strong as its implementation -- and most apps implement it poorly. The gap between "uses BiometricPrompt" and "cryptographically bound biometric authentication" is where nearly every bypass lives.

## BiometricPrompt API

BiometricPrompt replaced the fragmented landscape of `FingerprintManager` (API 23) and vendor-specific biometric APIs with a single, system-managed interface. The system controls the UI, the sensor interaction, and the result callback. Apps cannot customize the prompt appearance or intercept the biometric data.

### Authentication Flow

```
App calls BiometricPrompt.authenticate()
    -> System shows BiometricPrompt dialog
        -> User provides biometric
            -> Sensor validates against enrolled template
                -> System calls onAuthenticationSucceeded(result)
                    -> App receives AuthenticationResult
                        -> If CryptoObject was provided: key is unlocked
                        -> If no CryptoObject: app trusts the boolean result
```

### Two Authentication Modes

| Mode | How It Works | Security Level |
|------|-------------|----------------|
| **Without CryptoObject** | `authenticate(cancellationSignal, executor, callback)` -- app receives a boolean success/failure | Weak -- result can be spoofed by hooking the callback |
| **With CryptoObject** | `authenticate(cryptoObject, cancellationSignal, executor, callback)` -- biometric unlocks a Keystore key for cryptographic operations | Strong -- the key material is hardware-protected and only released after genuine biometric verification in TEE |

The critical difference: without CryptoObject, the app is trusting a software callback that says "authentication succeeded." With CryptoObject, the [hardware Keystore](keystore.md) enforces that a valid biometric was presented before releasing the key for use.

## Biometric Classes

The Android [Compatibility Definition Document (CDD)](https://source.android.com/docs/security/features/biometric) defines three biometric strength classes:

| Class | Name | Spoofing Acceptance Rate | Use Cases |
|-------|------|-------------------------|-----------|
| Class 3 | Strong | SAR < 7% | Keystore key release, CryptoObject binding, app authentication |
| Class 2 | Weak | SAR < 20% | Lockscreen unlock, non-cryptographic app auth |
| Class 1 | Convenience | SAR >= 20% | Not usable for any security-sensitive operation |

### Class 3 (Strong) Requirements

- Must resist presentation attacks (fake fingerprints, photos for face unlock) with < 7% acceptance rate
- Must be tested by an independent lab against the Android Biometric Security Guidelines
- Can be used with `setAllowedAuthenticators(BIOMETRIC_STRONG)` to restrict apps to Class 3 only
- Required for CryptoObject-bound authentication
- Required for Keystore keys with `setUserAuthenticationRequired(true)` using biometric binding

### Class 2 (Weak) Face Unlock

Most Android face unlock implementations are Class 2 (camera-based 2D face matching without IR depth sensing). This includes the majority of non-Pixel, non-Samsung flagship face unlock implementations. A printed photo or video of the device owner can bypass Class 2 face unlock on many devices.

The Pixel 4 was one of the few Android devices with a Class 3 face unlock (using Soli radar + IR dot projector, similar to Apple Face ID). Google removed the hardware in subsequent Pixel models.

### Fingerprint vs Face Security

| Property | Fingerprint (capacitive/optical/ultrasonic) | Face (2D camera) | Face (3D structured light) |
|----------|---------------------------------------------|-------------------|---------------------------|
| Typical class | Class 3 | Class 2 | Class 3 |
| Spoofing difficulty | Medium (requires physical mold or high-res print) | Low (photo or video) | High (requires 3D model) |
| CryptoObject support | Yes | Only if Class 3 | Yes |
| Common bypass | Lifted fingerprint on gelatin/silicone | Photo of face | No practical bypass known |
| Darkness/mask operation | Works in all conditions | Fails in low light, varies with masks | Works with IR illumination |

## CryptoObject Binding

CryptoObject is the mechanism that makes biometric authentication cryptographically meaningful. It wraps a `Cipher`, `Signature`, or `Mac` object backed by a hardware Keystore key.

### Secure Implementation

```kotlin
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("biometric_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        .setInvalidatedByBiometricEnrollment(true)
        .build()
)
keyGenerator.generateKey()

val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey("biometric_key", null)
cipher.init(Cipher.ENCRYPT_MODE, key)

val cryptoObject = BiometricPrompt.CryptoObject(cipher)
biometricPrompt.authenticate(promptInfo, cryptoObject)
```

When configured this way, the AES key is locked inside the [TEE/StrongBox](keystore.md) until a Class 3 biometric is verified. The `setInvalidatedByBiometricEnrollment(true)` flag ensures the key is destroyed if new biometrics are enrolled, preventing an attacker from adding their own fingerprint and using the existing key.

### Why Most Apps Get This Wrong

The majority of banking apps use BiometricPrompt without CryptoObject. They call `authenticate()` without passing a `CryptoObject`, receive the boolean success callback, and then proceed to release a stored token or credential. This pattern is vulnerable to Frida bypass because the security decision is made in software, not in hardware.

[SEC Consult's research on biometric bypass](https://sec-consult.com/blog/detail/bypassing-android-biometric-authentication/) and [OWASP's MASTG guidance](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/) both document this as the most common weakness in Android biometric implementations.

## Downgrade Attacks

### Biometric to PIN/Pattern

BiometricPrompt allows fallback to device credential (PIN, pattern, password) through `setAllowedAuthenticators(BIOMETRIC_STRONG | DEVICE_CREDENTIAL)` or the deprecated `setDeviceCredentialAllowed(true)`. When this is configured:

- User is shown the biometric prompt with a "Use PIN" or "Use password" option
- If the user (or an attacker with device access) selects the fallback, authentication proceeds with the device credential instead of biometric
- The app receives the same success callback regardless of which method was used

This is a design-level downgrade: a device PIN is typically 4-6 digits and can be shoulder-surfed or captured by malware. If the app accepts device credential as equivalent to biometric, the security of the authentication is reduced to the strength of the weakest allowed method.

### Exploiting Biometric Timeout

Keystore keys with `setUserAuthenticationValidityDurationSeconds()` remain unlocked for a time window after authentication. During this window, any code running in the app's process can use the key without re-authentication. If the timeout is too long (e.g., 300 seconds), an attacker who gains code execution in the app's process (through a WebView vulnerability, deep link exploit, or library compromise) can use the key freely.

## Malware Techniques

### TrickMo Fake Lockscreen

[TrickMo](../malware/families/trickmo.md) banking trojan deploys a [fake lockscreen that captures the device PIN or unlock pattern](https://www.bleepingcomputer.com/news/security/trickmo-malware-steals-android-pins-using-fake-lock-screen/). Discovered in October 2024 by Zimperium across 40 new variants, the technique works as follows:

1. TrickMo displays a full-screen HTML page hosted on an external server
2. The HTML is styled to mimic the device's actual lockscreen (PIN pad or pattern grid)
3. The page is rendered in full-screen mode, making it visually indistinguishable from the real lockscreen
4. When the user enters their PIN or draws their pattern, the input is captured
5. The captured credential is transmitted to a C2 PHP endpoint along with the device's Android ID

The captured PIN/pattern enables the attackers to unlock the device remotely (or during physical access) to perform on-device fraud during off-hours. At least 13,000 victims were identified across Canada, UAE, Turkey, and Germany.

This attack is not a biometric bypass -- it captures the device credential that biometric authentication falls back to. If a banking app accepts device credential as a biometric fallback, the TrickMo-captured PIN is sufficient to authenticate.

### TsarBot Pattern Capture

[TsarBot](../malware/families/tsarbot.md), discovered by [Cyble in March 2025](https://cyble.com/blog/tsarbot-using-overlay-attacks-targeting-bfsi-sector/), implements a similar lockscreen capture with additional sophistication:

1. TsarBot uses `LockTypeDetector` to determine the device's lock type via accessibility service
2. It reads on-screen text and descriptions ("PIN area", "Device password", pattern grid elements) to identify whether the device uses PIN, password, or pattern
3. On the first `USER_PRESENT` broadcast, TsarBot loads a fake lockscreen matched to the detected lock type
4. Captured credentials are exfiltrated to the C2 server

TsarBot targets 750+ banking, finance, and cryptocurrency applications, making the captured device credential useful for unlocking the device and potentially bypassing biometric fallback in hundreds of apps.

### Overlay-Based Biometric Phishing

Malware families using [overlay attacks](../attacks/overlay-attacks.md) can display fake biometric prompts that look like the system BiometricPrompt dialog. Since BiometricPrompt's UI is controlled by the system and appears as a bottom sheet, an overlay that mimics this appearance can trick users into touching the real fingerprint sensor while a malicious overlay captures other inputs. This is a social engineering attack rather than a technical bypass -- the user genuinely authenticates with the system, but the malware has already stolen credentials through the overlay displayed before or after the biometric prompt.

## Frida Bypass Techniques

### Universal Biometric Bypass (No CryptoObject)

When an app uses BiometricPrompt without CryptoObject, the authentication is a software check that [Frida can trivially bypass](https://github.com/ax/android-fingerprint-bypass):

```javascript
Java.perform(function() {
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    var CryptoObject = Java.use("android.hardware.biometrics.BiometricPrompt$CryptoObject");
    var AuthenticationResult = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult");

    BiometricPrompt.authenticate.overload(
        "android.os.CancellationSignal",
        "java.util.concurrent.Executor",
        "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
    ).implementation = function(cancel, executor, callback) {
        console.log("[BYPASS] BiometricPrompt.authenticate() called without CryptoObject");
        var result = AuthenticationResult.$new(null);
        callback.onAuthenticationSucceeded(result);
    };
});
```

This hooks the `authenticate` overload that takes no CryptoObject and directly invokes the success callback with a null CryptoObject. The app receives `onAuthenticationSucceeded` and proceeds as if the user provided a valid biometric.

The [Universal Android Biometric Bypass script on Frida CodeShare](https://codeshare.frida.re/@ax/universal-android-biometric-bypass/) handles both the modern BiometricPrompt API and the legacy FingerprintManager API, resolving constructor arguments at runtime for compatibility across Android versions.

### Why CryptoObject Prevents This

When `authenticate(cryptoObject, ...)` is used, the `AuthenticationResult` returned in `onAuthenticationSucceeded` contains an initialized `CryptoObject` whose underlying `Cipher` or `Signature` has been unlocked by the TEE. If the Frida script passes a null CryptoObject or a CryptoObject with an un-initialized cipher, the app's subsequent attempt to use the cipher for encryption/decryption will throw `IllegalStateException` or `KeyPermanentlyInvalidatedException`.

The TEE enforces the biometric check -- no amount of Frida hooking in the Android framework can convince the hardware to release a key without a genuine biometric presentation. This is the fundamental difference between "event-based" and "crypto-based" biometric authentication.

### Bypassing CryptoObject-Bound Authentication

CryptoObject-bound authentication is resistant to simple callback hooking but not invulnerable:

| Attack | Feasibility | Requirement |
|--------|-------------|-------------|
| Hook the callback with null CryptoObject | Does not work -- app crash or key error | None |
| Enroll attacker's fingerprint on device | Works -- TEE accepts any enrolled biometric | Physical access + device credential |
| Exploit TEE vulnerability | Theoretically works -- extract or use key without biometric | TEE exploit (rare, high-value) |
| Downgrade to device credential fallback | Works if app allows `DEVICE_CREDENTIAL` | Captured PIN/pattern |
| Re-create key without biometric requirement | Works if app doesn't validate key properties server-side | Root + Frida |
| Exploit authentication timeout | Works during validity window | Code execution in app process during window |

## CVE-2024-53835 / CVE-2024-53840

Patched in the [December 2024 Pixel security bulletin](https://source.android.com/docs/security/bulletin), these vulnerabilities allowed "possible biometric bypass due to an unusual root cause." While details are limited, these were lockscreen-level biometric bypasses on Pixel devices -- distinct from app-level BiometricPrompt bypasses. A rooted attacker could chain these with app-level weaknesses to bypass in-app biometric checks as well.

## Implementation Audit Checklist

When analyzing an app's biometric implementation for weaknesses:

| Check | Vulnerable If |
|-------|--------------|
| CryptoObject usage | `authenticate()` called without CryptoObject parameter |
| Key auth binding | `setUserAuthenticationRequired(true)` not set on Keystore key |
| Biometric strength | `setAllowedAuthenticators` includes `DEVICE_CREDENTIAL` or `BIOMETRIC_WEAK` |
| Enrollment invalidation | `setInvalidatedByBiometricEnrollment(false)` or not set |
| Auth timeout | `setUserAuthenticationValidityDurationSeconds` > 0 (creates a bypass window) |
| Server-side validation | Server accepts authentication without verifying a cryptographic proof (signed challenge) |
| Fallback mechanism | App stores plaintext credentials that are released on biometric success |
| Result handling | App checks `result.getCryptoObject()` is non-null after success |

## Banking App Patterns

### Common Architecture

Most banking apps implement biometric authentication in one of these patterns:

**Pattern 1 (Weak)**: Store encrypted token locally, decrypt on biometric success callback. The encryption key is in software or Keystore without biometric binding. Frida bypass works.

**Pattern 2 (Medium)**: Store encrypted token, use Keystore key with `setUserAuthenticationRequired(true)` but allow device credential fallback. CryptoObject-bound but downgradable to PIN.

**Pattern 3 (Strong)**: Store nothing locally. On biometric success, use CryptoObject to sign a server challenge with a hardware-backed key. Server validates the signature. No fallback to device credential. This is the only pattern resistant to all known bypass techniques (short of TEE exploitation or enrolled biometric compromise).

Pattern 3 is rare. Most banking apps in the wild use Pattern 1 or Pattern 2, making them vulnerable to Frida bypass or PIN capture respectively. [Guardsquare's research on hardware-backed key attestation](https://www.guardsquare.com/blog/hardware-backed-key-attestation-security-guardsquare) documents how few apps actually verify attestation server-side.

## Cross-References

- [Overlay Attacks](../attacks/overlay-attacks.md) can display fake biometric prompts to phish credentials before or after real authentication
- [Keystore](keystore.md) provides the hardware-backed keys that make CryptoObject binding meaningful
- [TrickMo](../malware/families/trickmo.md) captures device PINs that are the fallback for biometric authentication
- [Play Integrity](play-integrity.md) uses hardware attestation (built on the same Keystore infrastructure) for device trust
