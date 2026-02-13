# Platform Abuse

Android's security model exists to protect users, apps, and data. Every mechanism documented here has been bypassed, circumvented, or abused in practice by malware, exploit chains, or security researchers. The focus is on how these protections work, where they fail, and how they are defeated.

The [Permissions](../permissions/index.md) section documents Android's permission system and how every abusable permission is exploited by malware.

## Security Architecture

| Layer | Mechanism | How It Is Abused |
|-------|-----------|-----------------|
| Hardware | [Verified Boot](verified-boot.md), TEE/StrongBox, [hardware-backed Keystore](keystore.md) | Firmware persistence, key extraction, bootloader exploits |
| Kernel | [SELinux](selinux.md), seccomp-bpf, dm-verity | Privilege escalation, policy bypass, kernel exploits |
| Framework | [App sandbox](app-sandbox.md), permission model, [Play Integrity](play-integrity.md) | Sandbox escapes, permission abuse, attestation bypass |
| Application | Scoped storage, [biometric authentication](biometric-auth.md), app signing | Storage access, authentication bypass, signature verification |

## Pages

| Page | Scope |
|------|-------|
| [App Sandbox](app-sandbox.md) | Process isolation, UID-based separation, IPC restrictions, sandbox escape history |
| [SELinux](selinux.md) | Mandatory access control on Android, policy structure, known bypasses, context transitions |
| [Verified Boot](verified-boot.md) | Boot chain verification, dm-verity, AVB, rollback protection, bootloader unlocking implications |
| [Keystore](keystore.md) | Hardware-backed key storage, TEE vs StrongBox, key attestation, extraction research |
| [Play Integrity](play-integrity.md) | SafetyNet to Play Integrity evolution, attestation verdicts, bypass techniques, device trust |
| [Biometric Authentication](biometric-auth.md) | BiometricPrompt, CryptoObject binding, fallback to PIN, downgrade attacks |

### Planned

| Page | Scope |
|------|-------|
| Scoped Storage | Storage access framework, MediaStore restrictions, legacy bypass, malware adaptation |
| Permission Model | Runtime permissions, auto-revoke, one-time permissions, restricted settings, grant flow abuse |

## Cross-References

- [Accessibility Abuse](../attacks/accessibility-abuse.md) bypasses many platform mechanisms through the accessibility API
- [Persistence Techniques](../attacks/persistence-techniques.md) details how malware survives across reboots despite platform restrictions
- [Dynamic Code Loading](../attacks/dynamic-code-loading.md) circumvents app signing verification by loading unsigned code at runtime
- [Permissions](../permissions/index.md) documents how every abusable Android permission is exploited
