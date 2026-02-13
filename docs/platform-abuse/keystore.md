# Keystore

The Android Keystore system provides hardware-backed cryptographic key storage, binding keys to the device's Trusted Execution Environment (TEE) or StrongBox secure element. Keys stored in hardware cannot be extracted -- even with root access, the key material never leaves the secure processor. This makes the Keystore the foundation for device trust, app authentication, and DRM. For attackers, breaking or circumventing the Keystore means defeating the strongest security guarantee Android offers.

## Architecture

The Keystore system spans multiple layers from the Android framework down to dedicated security hardware:

```
App (KeyStore API)
    -> Keystore2 Service (system_server)
        -> KeyMint HAL (vendor implementation)
            -> TEE / StrongBox Hardware
```

### Components

| Component | Role |
|-----------|------|
| `java.security.KeyStore` | Android framework API for key generation, storage, and use |
| Keystore2 | System service managing key access, permissions, and user authentication binding |
| KeyMint HAL | Hardware abstraction layer defining the interface to secure hardware (replaced Keymaster HAL in Android 12) |
| TEE (TrustZone) | ARM TrustZone-based isolated execution environment on the main processor |
| StrongBox | Discrete secure element (separate chip) with its own CPU, RAM, and storage |

### KeyMaster to KeyMint Evolution

| HAL | Android Version | Key Features |
|-----|----------------|--------------|
| Keymaster 1.0 | Android 6.0 | Basic hardware-backed key operations |
| Keymaster 2.0 | Android 7.0 | Key attestation support |
| Keymaster 3.0 | Android 8.0 | HIDL interface |
| Keymaster 4.0 | Android 9.0 | StrongBox support, ID attestation |
| Keymaster 4.1 | Android 10 | Identity credential, early boot keys |
| KeyMint 1.0 | Android 12 | AIDL interface, replaced Keymaster |
| KeyMint 2.0 | Android 13 | Curve 25519 support |
| KeyMint 3.0 | Android 14 | ECDH key agreement improvements |

## TEE vs StrongBox

| Property | TEE (TrustZone) | StrongBox |
|----------|-----------------|-----------|
| Hardware | Isolated execution on main application processor | Discrete secure element (separate chip) |
| CPU | Shared with main processor (isolated world) | Dedicated processor |
| Performance | Fast -- shares SoC resources | Slow -- constrained hardware |
| Tamper resistance | Limited physical tamper protection | Designed for physical tamper resistance, side-channel resistance |
| Key algorithms | Full suite (RSA, EC, AES, HMAC, 3DES) | Limited (RSA 2048, EC P-256, AES-256, HMAC-SHA256) |
| Availability | All Android devices since Android 6.0 | Pixel 3+, Samsung Galaxy S10+, select devices since Android 9.0 |
| Attack surface | Larger -- runs a full trusted OS (Trustonic Kinibi, Qualcomm QSEE, etc.) | Smaller -- minimal firmware on dedicated hardware |
| Common implementations | Trustonic Kinibi (Samsung), Qualcomm QSEE, Huawei iTrustee | Titan M (Google Pixel), Samsung eSE, NXP SE050 |

For apps, the choice is explicit:

```kotlin
val keyGenParameterSpec = KeyGenParameterSpec.Builder("my_key", PURPOSE_SIGN)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setIsStrongBoxBacked(true)
    .build()
```

If StrongBox is unavailable, the call throws `StrongBoxUnavailableException`. Most apps fall back to TEE-backed keys.

## Key Attestation

Key attestation proves that a key was generated inside secure hardware on a genuine Android device. The attestation produces a certificate chain that can be verified by a remote server.

### Certificate Chain

```
Attestation Certificate (leaf)
    -> Intermediate CA (device-specific)
        -> Google Attestation Root Key
```

The leaf certificate contains an extension (OID `1.3.6.1.4.1.11129.2.1.17`) with structured attestation data including:

| Field | Meaning |
|-------|---------|
| `attestationSecurityLevel` | TEE or StrongBox (or Software for non-hardware keys) |
| `keymasterSecurityLevel` | Security level of the KeyMint implementation |
| `attestationChallenge` | Server-provided nonce to prevent replay |
| `verifiedBootState` | GREEN, YELLOW, ORANGE, or RED |
| `deviceLocked` | Whether bootloader is locked |
| `osVersion` | Android OS version |
| `osPatchLevel` | Security patch level |

### What Attestation Proves

Key attestation cryptographically proves:

1. The key was generated inside TEE/StrongBox hardware (not in software)
2. The key has specific properties (algorithm, purpose, user auth requirements)
3. The device's [verified boot state](verified-boot.md) at the time of key generation
4. The device runs a specific Android version and patch level
5. The attestation certificate chains to the [Google attestation root key](https://developer.android.com/privacy-and-security/security-key-attestation)

### What Attestation Does Not Prove

- That the device is not rooted (a rooted device with locked bootloader and GREEN boot state passes attestation)
- That the app environment is unmodified (attestation is about the hardware and OS, not the app)
- That the device is malware-free

### Verification

A server verifying attestation must:

1. Validate the entire certificate chain up to the Google root
2. Check the [certificate revocation status list](https://android.googleapis.com/attestation/status) for revoked intermediate keys
3. Verify the attestation challenge matches the server-provided nonce
4. Check that `attestationSecurityLevel` is `TrustedEnvironment` or `Strongbox`
5. Verify `verifiedBootState` is GREEN and `deviceLocked` is true

If any check fails, the server should not trust the attestation. [Play Integrity API](play-integrity.md) builds on this same mechanism for broader device integrity verdicts.

## Historic Vulnerabilities

### Samsung TrustZone Keymaster (CVE-2021-25444, CVE-2021-25490)

The most significant Keystore vulnerability to date was [published by researchers at Tel Aviv University](https://eprint.iacr.org/2022/208.pdf) in February 2022, affecting approximately 100 million Samsung Galaxy devices.

Samsung's Keymaster Trusted Application (TA) running in the Trustonic Kinibi TEE contained fundamental cryptographic flaws in how it wrapped (encrypted) key material:

**CVE-2021-25444 -- IV Reuse**: Samsung's key blob encryption used AES-GCM but allowed the caller to specify the initialization vector (IV). By providing the same IV for different key operations, an attacker with privileged access could decrypt hardware-protected key blobs. This affected Galaxy S9, J3, J7, TabS4, A6 Plus, and A9S models.

**CVE-2021-25490 -- Downgrade Attack**: Even after Samsung patched the IV reuse vulnerability on newer devices (S10, S20, S21), the researchers demonstrated a downgrade attack. The patched Keymaster TA still supported the old, vulnerable key blob format for backward compatibility. An attacker could force key operations to use the legacy format, then exploit the IV reuse vulnerability. Samsung patched this by removing support for the legacy blob format on devices originally shipped with Android 9.0 or later.

The [keybuster](https://github.com/shakevsky/keybuster) proof-of-concept tool demonstrates both attacks. The research fundamentally undermined the "hardware-protected keys cannot be extracted" guarantee for affected Samsung devices.

### Qualcomm QSEE Key Extraction

[Research by Gal Beniamini](https://www.epanorama.net/newepa/2016/07/02/bits-please-extracting-qualcomms-keymaster-keys-breaking-android-full-disk-encryption/) demonstrated that Qualcomm's QSEE (Qualcomm Secure Execution Environment) implementation tied key material to a device-specific hardware key (SHK) but made it accessible to software running inside the TEE. A vulnerability in the QSEE kernel or any Trusted Application could expose the KeyMaster keys, enabling off-device brute-force attacks against Android Full Disk Encryption.

The core issue: rather than using a hardware-bound key that is inaccessible to all software (including TEE software), Qualcomm's implementation derived keys from a value readable by TEE code. Any TEE vulnerability became a key extraction vulnerability.

### Trustonic Kinibi TA Exploitation

[Synacktiv's research on Kinibi TEE](https://www.synacktiv.com/en/publications/kinibi-tee-trusted-application-exploitation) revealed that Trustonic's TEE, despite its security objectives, lacked basic exploit mitigations in Trusted Applications:

- No stack canaries (stack buffer overflows are directly exploitable)
- No guard pages between global variables and stack (heap/stack confusion attacks possible)
- Globals and stack allocated from the same data segment

These missing mitigations mean that a memory corruption vulnerability in any TA running on Kinibi (including Samsung's Keymaster TA) is significantly easier to exploit than equivalent vulnerabilities in modern userspace applications.

### Quarkslab Samsung Boot Chain Research

[Quarkslab's analysis of the Samsung Galaxy A series boot chain](https://blog.quarkslab.com/attacking-the-samsung-galaxy-a-boot-chain.html) documented vulnerabilities in the chain of trust leading to the TEE. Compromising the boot chain before the TEE initializes can undermine all TEE-based security guarantees, including Keystore.

## Device Binding and Bootloader Unlock

Hardware-backed keys are bound to the device's security state. When the bootloader is unlocked:

| Key Property | Behavior |
|-------------|----------|
| `setUserAuthenticationRequired(true)` | Key remains usable if user authentication succeeds |
| Key attestation `verifiedBootState` | Reports ORANGE instead of GREEN |
| Key attestation `deviceLocked` | Reports false |
| Existing keys | Remain in hardware but attestation reflects new boot state |
| Factory reset | Destroys all Keystore keys (user data wipe on unlock) |

Banking apps that verify attestation at every session will reject the device after bootloader unlock because the attestation certificate reports ORANGE boot state even though the keys themselves remain in hardware. This is a policy decision by the server, not a technical limitation of the key material.

On Samsung devices, unlocking the bootloader trips the Knox e-fuse permanently. Even if the bootloader is re-locked, the Knox warranty bit remains tripped and Samsung Pay, Secure Folder, and other Knox-dependent features are permanently disabled.

## How Banking Apps Use Key Attestation

Banking and financial apps use key attestation as a device trust signal during enrollment and at runtime:

### Enrollment Flow

1. App generates an asymmetric key pair in hardware with `setAttestationChallenge(serverNonce)`
2. App sends the attestation certificate chain to the server
3. Server validates the chain, checks boot state, confirms hardware-backed generation
4. Server associates the public key with the user account
5. Subsequent authentication requires signing a challenge with the hardware-backed private key

### Runtime Verification

Each authentication session:

1. Server sends a fresh challenge
2. App signs the challenge using the hardware-backed key (requires user biometric/PIN if `setUserAuthenticationRequired(true)`)
3. Server verifies the signature with the stored public key
4. Some apps re-attest the key periodically to detect boot state changes

### Common Weaknesses

| Weakness | Impact |
|----------|--------|
| Software-backed key fallback | If hardware attestation fails, some apps fall back to software keys that can be extracted with root |
| No attestation verification | App generates hardware key but never sends attestation chain to server for validation |
| Challenge not bound to session | Replay attacks possible if the attestation challenge is predictable or reused |
| Certificate chain not fully validated | Skipping revocation list check allows use of compromised device keys |
| Boot state not checked | Server accepts attestation from ORANGE (unlocked) devices |
| Key not bound to biometric | Key usable without user authentication, defeating the device-binding purpose |

## Implications for Forensics

Hardware-backed Keystore has direct implications for mobile forensics:

| Scenario | Forensic Impact |
|----------|----------------|
| Locked device, locked bootloader | Keys in TEE/StrongBox cannot be extracted, encrypted data is inaccessible without user credentials |
| Unlocked device, locked bootloader | Keys usable through normal APIs but not extractable for offline analysis |
| Unlocked bootloader | Factory reset on unlock destroys keys; if keys were backed up before unlock, attestation state has changed |
| TEE vulnerability | Exploit may enable key extraction on affected chipsets/firmware versions |
| StrongBox | No known extraction technique -- physically separated hardware with tamper resistance |

For forensic tool vendors (Cellebrite, GrayKey), TEE vulnerabilities are high-value targets. A working TEE exploit on a popular chipset enables extraction of encryption keys, biometric templates, and other hardware-protected secrets across all devices using that chipset.

The distinction between TEE and StrongBox matters: StrongBox's physical separation and tamper resistance make it substantially harder to attack than TrustZone-based TEE implementations that share the SoC with the application processor.

## Cross-References

- [Play Integrity](play-integrity.md) uses hardware key attestation as the foundation for device integrity verdicts
- [Biometric Authentication](biometric-auth.md) binds biometric verification to Keystore keys through CryptoObject
- [Verified Boot](verified-boot.md) state is embedded in key attestation certificates
- [SELinux](selinux.md) policy controls which processes can access Keystore APIs
