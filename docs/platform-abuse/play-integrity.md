# Play Integrity

Google's device attestation framework, replacing SafetyNet. Apps use it to verify the device has not been tampered with -- not rooted, not running a custom ROM, bootloader locked. Banking apps, streaming services, and payment apps rely on it to gate access. For attackers and security researchers, bypassing Play Integrity is a prerequisite for dynamic analysis on modified devices.

## Evolution from SafetyNet

### Timeline

| Date | Event |
|------|-------|
| 2014 | SafetyNet Attestation API launched |
| 2017 | SafetyNet adds hardware attestation option via key attestation |
| 2017 | Magisk introduces MagiskHide to bypass SafetyNet |
| 2020 | Google enables hardware key attestation in SafetyNet |
| 2021 | topjohnwu deprecates MagiskHide, introduces Zygisk |
| 2022 | Play Integrity API announced as SafetyNet replacement |
| 2022 | kdrag0n's Universal SafetyNet Fix provides last major SafetyNet bypass |
| 2023 | Play Integrity Fix (PIF) module released by chiteroman |
| 2023 | Google begins enforcing Play Integrity for new apps |
| October 2023 | Google announces SafetyNet end-of-life by January 2025 |
| 2024 | TrickyStore released for hardware attestation bypass |
| April 2025 | Hardware-backed key attestation returned by default for all developers |
| May 2025 | [SafetyNet fully decommissioned](https://developer.android.com/privacy-and-security/safetynet/attestation), breaking apps that had not migrated |
| May 2025 | Google enforces "device/strong" integrity with hardware-backed signals |

### Key Architectural Changes

SafetyNet provided a binary pass/fail response (`ctsProfileMatch` and `basicIntegrity`). Play Integrity provides granular verdict levels with multiple signals. SafetyNet's software attestation was relatively easy to spoof; Play Integrity's hardware attestation ties verification to the device's Trusted Execution Environment (TEE).

## Verdict Levels

The [Play Integrity API](https://developer.android.com/google/play/integrity/overview) returns a `deviceRecognitionVerdict` containing one or more labels:

| Verdict | Meaning | Hardware Required | What Passes |
|---------|---------|-------------------|-------------|
| `MEETS_BASIC_INTEGRITY` | Device runs a recognized Android build | No | Stock or some custom ROMs with locked bootloader |
| `MEETS_DEVICE_INTEGRITY` | Genuine Android build, locked bootloader, passes CTS | No (software-based on Android < 13) | Unmodified stock ROM |
| `MEETS_STRONG_INTEGRITY` | Hardware-backed attestation, recent security patch | Yes (TEE/StrongBox) | Fully stock, patched, locked bootloader |

### Additional Signals

| Signal | Content |
|--------|---------|
| `appRecognitionVerdict` | Whether the calling app is the genuine Play-distributed version |
| `accountDetails` | Whether the device has a licensed Google Play account |
| `environmentDetails` | Whether other apps are running that could capture the screen |
| `recentDeviceActivity` | Rate of integrity token requests (detects token farming) |

### Verdict Decision Matrix

| Condition | Basic | Device | Strong |
|-----------|-------|--------|--------|
| Stock ROM, locked bootloader, patched | Pass | Pass | Pass |
| Stock ROM, locked bootloader, outdated patch | Pass | Pass | Fail |
| Stock ROM, unlocked bootloader | Pass | Fail | Fail |
| Custom ROM (signed) | Pass | Fail | Fail |
| Custom ROM (unsigned) | Fail | Fail | Fail |
| Rooted device (Magisk + PIF) | Pass | Pass (software) | Fail |
| Rooted device (no hiding) | Fail | Fail | Fail |
| Emulator (standard) | Fail | Fail | Fail |

## How Apps Use It

Banking and financial apps call the Play Integrity API during launch or before sensitive operations:

```java
IntegrityManager manager = IntegrityManagerFactory.create(context);
Task<IntegrityTokenResponse> task = manager.requestIntegrityToken(
    IntegrityTokenRequest.builder()
        .setNonce(generateNonce())
        .build());
task.addOnSuccessListener(response -> {
    String token = response.token();
    sendToBackendForVerification(token);
});
```

The token is a signed JWT sent to the app's backend. The backend calls [Google's Integrity API](https://developer.android.com/google/play/integrity/verdict) to decode the verdict. The app never sees the raw verdict locally, preventing client-side bypass.

### Banking App Integration Patterns

| Pattern | Behavior |
|---------|----------|
| Login gate | Block authentication on devices failing strong integrity |
| Transaction gate | Allow login but block transfers on non-passing devices |
| Degraded mode | Reduce transaction limits on devices passing only basic integrity |
| Warning only | Display warning but allow full functionality |

The [May 2025 enforcement of hardware-backed strong integrity](https://proandroiddev.com/play-integrity-api-googles-new-security-gatekeeper-and-why-safetynet-is-gone-e204f35278a8) significantly impacted security researchers. Banking apps requiring strong integrity cannot be analyzed on unlocked-bootloader devices without hardware attestation bypass.

## Hardware vs Software Attestation

### Software Attestation

The Play Integrity server evaluates device signals sent by the client (build fingerprint, boot state, etc.) and makes a server-side determination. These signals can be spoofed by modifying system properties and Build fields.

### Hardware Attestation

The device's TEE generates a certificate chain bound to hardware-fused keys. Google's server verifies this chain against a known database of legitimate device keys.

### Key Attestation Chain

```
Google Root CA
  └── Google Intermediate CA
       └── Device Attestation Key (in TEE/StrongBox)
            └── App-specific attestation key
```

The TEE-generated attestation certificate includes fields that describe the device state:

| Field | Content |
|-------|---------|
| `attestationSecurityLevel` | TEE or StrongBox |
| `verifiedBootState` | Green (locked), Yellow (custom), Orange (unlocked), Red (unverifiable) |
| `osVersion` | Android version |
| `osPatchLevel` | Security patch date |
| `rootOfTrust` | Verified boot key hash, lock state |

Hardware attestation is cryptographically bound to the device. Without access to the TEE's private keys, it cannot be spoofed in software. Google can revoke leaked keys via [Certificate Revocation Lists](https://developer.android.com/privacy-and-security/security-key-attestation) in the Play Integrity backend.

## Bypass Techniques

### Magisk Hide (Deprecated)

The original root hiding mechanism. MagiskHide unmounted Magisk's overlays from the target app's mount namespace and hid the `su` binary. [Deprecated by topjohnwu](https://github.com/topjohnwu/Magisk/pull/5318) in Magisk v24 (2022) in favor of Zygisk.

### Zygisk + Shamiko

[Zygisk](https://github.com/topjohnwu/Magisk) operates within the Zygote process, injecting code before app processes fork. [Shamiko](https://github.com/LSPosed/LSPosed.github.io/releases) (from the LSPosed team) hooks into the process startup sequence to:

- Hide Magisk's presence from target apps
- Remove root-related artifacts from the process environment
- Mask SELinux status modifications
- Filter `/proc` entries that reveal root

Shamiko works because it intervenes before the target app's security checks execute. However, it cannot spoof hardware attestation.

### Play Integrity Fix (PIF)

[Originally developed by chiteroman](https://xdaforums.com/t/module-play-integrity-fix.4607985/), PIF is a Zygisk module that spoofs device properties to pass software-based integrity checks. It modifies `android.os.Build` class fields and system properties to match a known-good device fingerprint:

1. Injects a `classes.dex` to override Build fields (`FINGERPRINT`, `MODEL`, `MANUFACTURER`, `PRODUCT`)
2. Hooks native code to modify system property reads
3. Downloads or bundles a device fingerprint profile from a certified device
4. Passes `MEETS_DEVICE_INTEGRITY` on software attestation

PIF requires periodic fingerprint updates as Google revokes known-bypassed fingerprints. The community maintains fingerprint databases tracking which device profiles currently pass.

Active forks as of 2025:

| Fork | Maintainer | Focus |
|------|-----------|-------|
| [PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork) | osm0sis | Broad device support, custom field spoofing |
| [PlayIntegrityFix](https://github.com/KOWX712/PlayIntegrityFix) | KOWX712 | Continued development of chiteroman's approach |
| [PIF-NEXT](https://github.com/EricInacio01/PlayIntegrityFix-NEXT) | EricInacio01 | TrickyStore integration for hardware attestation |
| [Zygisk-Assistant](https://github.com/snake-4/Zygisk-Assistant) | snake-4 | Lightweight root hiding for KernelSU, Magisk, APatch |

### TrickyStore and Hardware Attestation Bypass

[TrickyStore](https://github.com/5ec1cff/TrickyStore) manipulates the Keystore attestation chain to pass hardware-backed integrity checks on devices with unlocked bootloaders:

1. Intercepts Keystore attestation requests
2. Substitutes a valid attestation certificate chain from a stock device
3. Signs the attestation with the substitute key

This requires a valid leaked or extracted attestation key from a device with the same model. The supply of valid keys is limited and Google periodically revokes compromised keys, making this an ongoing arms race.

### Bypass Evolution

| Era | Technique | Defeated By |
|-----|-----------|-------------|
| 2017-2020 | MagiskHide | SafetyNet hardware attestation (opt-in) |
| 2020-2022 | Universal SafetyNet Fix (kdrag0n) | Play Integrity API migration |
| 2022-2023 | Early PIF modules | Google tightening fingerprint validation |
| 2023-2024 | PIF + Shamiko | Hardware attestation default enforcement |
| 2024-2025 | TrickyStore + PIF-NEXT | Key revocation, certificate transparency |
| 2025+ | ? | Hardware attestation at scale with strong integrity |

## Malware Detection of Rooted Devices

Malware uses Play Integrity as one signal among many to detect analysis environments:

```java
private boolean isAnalysisEnvironment() {
    boolean rooted = new File("/system/bin/su").exists() ||
                     new File("/system/xbin/su").exists();
    boolean magisk = new File("/sbin/.magisk").exists();
    boolean emulator = Build.FINGERPRINT.contains("generic") ||
                       Build.MODEL.contains("Emulator");
    return rooted || magisk || emulator;
}
```

Banking trojans like [Cerberus](../malware/families/cerberus.md) and [Hook](../malware/families/hook.md) check for root not to refuse running but to adapt behavior -- avoiding analysis-specific actions on rooted/emulated devices while operating normally on consumer devices. Some families ([Anatsa](../malware/families/anatsa.md), [Hook](../malware/families/hook.md)) check whether the device passes basic integrity before executing their payload.

### Common Detection Checks Beyond Play Integrity

| Check | What It Detects |
|-------|----------------|
| `su` binary existence | Root access |
| Magisk/KernelSU packages | Root management apps |
| Xposed/LSPosed artifacts | Hooking frameworks |
| Build.FINGERPRINT contents | Emulator or custom ROM |
| `/proc/self/maps` inspection | Frida agent loaded in memory |
| `ro.debuggable` property | Debug build or modified system |
| SELinux permissive mode | Modified security policy |

## Implications for Security Researchers

| Scenario | Impact |
|----------|--------|
| Malware analysis on rooted device | PIF + Shamiko required or malware detects analysis |
| Banking app testing | Must pass `MEETS_DEVICE_INTEGRITY` or app refuses to start |
| Custom ROM users | Cannot use banking apps without PIF unless ROM passes CTS |
| Enterprise MDM | Hardware attestation used for device compliance checks |
| Forensics | Unlocked bootloader fails all integrity checks |

The trend toward hardware attestation narrows the gap for researchers. Practical workarounds:

- Using Pixel devices with locked bootloaders and Magisk installed via boot image patching
- Patching target apps to remove integrity checks (static analysis + smali patching)
- Using instrumentation frameworks that don't require root (Objection on debug builds)
- Maintaining separate stock analysis devices alongside rooted research devices

## Detection During Analysis

??? example "Checking Play Integrity Status"

    - `adb shell dumpsys package com.google.android.gms | grep version` (GMS version)
    - Run a Play Integrity checker app (YASNAC, PIF checker) to see current verdict
    - Check `logcat` for `com.google.android.play.core.integrity` entries
    - Monitor Keystore attestation requests via Frida

??? example "Identifying Integrity Checks in Apps"

    - Search decompiled code for `IntegrityManager`, `IntegrityTokenRequest`
    - Look for `com.google.android.play.core.integrity` package references
    - Check for SafetyNet fallback: `SafetyNetClient`, `SafetyNet.getClient`
    - Look for nonce generation and server-side verification endpoints

## Cross-References

- [App Sandbox](app-sandbox.md) -- the sandbox that Play Integrity verifies has not been compromised
- [Packers](../packers/index.md) -- commercial protectors often integrate Play Integrity checks
- [Dynamic Analysis](../reversing/dynamic-analysis.md) -- Play Integrity complicates dynamic analysis on modified devices
