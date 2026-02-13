# Verified Boot

Android Verified Boot (AVB) establishes a cryptographic chain of trust from the hardware root of trust through the bootloader, kernel, and system partitions. Its purpose is to guarantee that all executed code comes from a trusted source and has not been tampered with. From an offensive perspective, Verified Boot determines what persists across reboots, what firmware modifications are possible, and what the consequences of bootloader unlocking are for security research and real-world attacks.

## Boot Chain

The boot chain verifies each stage before transferring control to the next:

```
Hardware Root of Trust
    -> Primary Bootloader (PBL, in ROM)
        -> Secondary Bootloader (SBL / ABL)
            -> Boot Image (kernel + ramdisk)
                -> System partition (dm-verity)
                    -> Vendor partition (dm-verity)
```

Each stage verifies the cryptographic signature of the next stage using keys embedded in the current stage. The hardware root of trust is burned into the SoC at manufacturing and cannot be modified. If any stage fails verification, the boot process halts or displays a warning depending on the device's lock state.

### Key Components

| Component | Role |
|-----------|------|
| Hardware Root of Trust | Immutable key in SoC, verifies first-stage bootloader |
| PBL (Primary Bootloader) | ROM-based, loads and verifies SBL |
| SBL/ABL (Secondary Bootloader) | Verifies and loads boot image, handles fastboot |
| boot.img | Contains kernel and ramdisk, verified by bootloader |
| vbmeta.img | AVB metadata containing hashes and signatures for all verified partitions |
| dm-verity | Kernel-level block verification for system/vendor partitions |

## dm-verity

dm-verity provides transparent integrity checking of block devices using a Merkle hash tree. Every 4KB block on the system partition has a hash stored in the tree. The root hash of the tree is signed and embedded in the boot image or vbmeta partition.

During runtime, the kernel checks each block's hash on read. If a block has been modified, the hash check fails and the read returns an I/O error. This makes persistent modification of the system partition impossible on devices with locked bootloaders and enforcing dm-verity.

### Hash Tree Structure

```
                Root Hash (signed)
               /                  \
        Hash Node             Hash Node
       /        \            /        \
  Block Hash  Block Hash  Block Hash  Block Hash
      |           |           |           |
  Block 0     Block 1     Block 2     Block 3
```

The root hash is the single value that, when verified against the embedded signature, guarantees the integrity of the entire partition. Modifying any block invalidates its hash, which propagates up the tree to invalidate the root hash.

### Enforcement Modes

| Mode | Behavior |
|------|----------|
| Enforcing | I/O error on corrupted blocks, system may restart |
| Logging | Corruption logged but reads succeed (development builds) |
| EIO | Default for production, returns EIO on corrupted blocks |
| Restart | Reboots the device when corruption is detected |

## Android Verified Boot 2.0 (AVB)

AVB 2.0 (introduced in Android 8.0, mandatory since Android 9.0) extends verification beyond the boot image to cover all partitions through a unified metadata structure.

### vbmeta Structure

The `vbmeta.img` partition contains:

- Hash descriptors for partitions verified at boot time (boot, dtbo)
- Hashtree descriptors for dm-verity protected partitions (system, vendor, product)
- The public key used to verify the vbmeta signature
- Rollback index values for anti-downgrade protection
- Flags controlling verification behavior

All descriptors are signed with the OEM's private key. The corresponding public key is embedded in the bootloader. The vbmeta signature is the single point of trust -- if it verifies, all partition hashes are trusted.

### Chained Partitions

AVB supports delegated verification where individual partitions can be signed with different keys. The vbmeta for each partition is chained to the root vbmeta through a chain of public keys. This allows different teams (SoC vendor, device OEM, carrier) to independently sign their respective partitions while maintaining a single chain of trust.

## Rollback Protection

Rollback protection prevents downgrading to older, vulnerable firmware versions. Each vbmeta structure contains a rollback index -- a monotonically increasing integer stored in tamper-evident hardware (typically a RPMB partition on eMMC or a fuse-based counter).

| Component | Storage |
|-----------|---------|
| Rollback index in vbmeta | Embedded in the signed vbmeta metadata |
| Stored rollback index | Written to RPMB or hardware fuses on the device |

During boot, the bootloader compares the vbmeta rollback index against the stored value. If the vbmeta index is lower than the stored index, boot is rejected. When a new image with a higher index boots successfully, the stored index is updated.

Google made rollback protection [mandatory for devices launching with Android 9.0](https://www.xda-developers.com/android-pie-rollback-protection/). On Xiaomi devices, the anti-rollback mechanism is particularly aggressive -- attempting to flash firmware with a lower rollback index on a locked bootloader [can permanently brick the device](https://xdaforums.com/t/anti-rollback-google-and-xiaomi-what-it-means-and-what-is-important.4662801/).

### Offensive Implications

Rollback protection prevents attackers from exploiting known vulnerabilities in older firmware. Without it, an attacker with physical access could flash an older, vulnerable bootloader or system image, exploit a patched vulnerability, and then reflash current firmware. The rollback index makes this downgrade path unavailable on locked-bootloader devices.

On unlocked bootloaders, rollback protection [can be bypassed](https://xdaforums.com/t/advanced-bypassing-rollback-protection-to-downgrade-the-os.4511501/) by flashing custom vbmeta with the verification flags disabled or by modifying the RPMB-stored index through vendor-specific tooling.

## Boot States

Android defines four verified boot states that indicate the integrity of the boot chain. These states are displayed to the user as colored warning screens during boot and are exposed to apps through system properties and attestation.

| State | Color | Meaning | Bootloader | Warning |
|-------|-------|---------|------------|---------|
| GREEN | None | Fully verified chain of trust, OEM-signed images | Locked | No warning screen |
| YELLOW | Yellow | Verified boot with custom root of trust (user-provided key) | Locked | 10-second warning screen |
| ORANGE | Orange | Bootloader unlocked, verification disabled | Unlocked | 10-second warning screen |
| RED | Red | Verification failed -- corrupted or unsigned boot image on locked device | Locked | Warning screen, user must confirm to continue |

The [AOSP boot flow documentation](https://source.android.com/docs/security/features/verifiedboot/boot-flow) specifies that the RED state warning screen requires the user to press a physical button to continue booting, and the screen cannot be dismissed by software alone. The ORANGE and YELLOW screens auto-dismiss after 10 seconds.

### Boot State in Attestation

The verified boot state is included in [hardware key attestation](keystore.md) certificates and is checked by [Play Integrity API](play-integrity.md). A device in ORANGE state (unlocked bootloader) fails the `MEETS_DEVICE_INTEGRITY` verdict, which banking apps and other security-sensitive applications use to deny service on modified devices.

## Bootloader Unlocking

Unlocking the bootloader is the prerequisite for all firmware-level modifications. It disables verification enforcement (transitioning to ORANGE state) and typically wipes all user data.

### What Unlocking Enables

- Flashing custom boot images (including Magisk-patched images)
- Flashing custom ROMs (LineageOS, GrapheneOS, CalyxOS)
- Disabling dm-verity via modified vbmeta
- Running custom kernels for research and exploit development
- Fastboot access for partition-level read/write

### What Unlocking Breaks

| Capability | Impact |
|------------|--------|
| Play Integrity `MEETS_DEVICE_INTEGRITY` | Fails -- banking apps, DRM, and enterprise MDM may block the device |
| Hardware key attestation boot state | Reports ORANGE/unlocked to attestation servers |
| Factory reset protection (FRP) | May be circumvented depending on OEM implementation |
| Warranty | Voided on most OEM devices |
| Samsung Knox | Permanently tripped e-fuse (irreversible, even if bootloader is re-locked) |
| Widevine L1 | Some devices downgrade to L3, losing HD DRM playback |

### OEM Unlock Policies

Not all devices support bootloader unlocking. Carriers (especially US carriers) frequently request OEMs to disable the unlock capability. Samsung, Xiaomi, and Huawei require account-based unlock authorization with waiting periods. Apple's iOS has no equivalent -- the bootloader is permanently locked.

## Firmware Persistence Attacks

### Triada Preinstalled on Devices

The [Triada](../malware/families/triada.md) trojan represents the most significant real-world abuse of the boot chain. In March 2025, [Kaspersky discovered](https://securelist.com/triada-trojan-modules-analysis/116380/) a new variant of Triada embedded directly in the firmware of counterfeit Android smartphones, affecting over 4,500 devices worldwide.

The infection occurs during manufacturing -- before devices reach end users. The supply chain compromise inserts Triada into the system partition, where it runs with system-level privileges and persists across factory resets because it is part of the verified system image.

Triada's firmware-level capabilities include:

- Intercepting and manipulating SMS messages
- Stealing cryptocurrency by replacing wallet addresses in clipboard
- Downloading and executing additional payloads
- Hijacking browser sessions and replacing links
- Controlling social media accounts

Since the malware is part of the OEM-signed system image, dm-verity and AVB protect the malicious code with the same integrity guarantees that protect legitimate system components. The verified boot chain trusts whatever the OEM signs -- if the OEM's build pipeline is compromised, verified boot protects the attacker's payload.

[Google previously documented](https://www.techtarget.com/searchsecurity/news/252464873/Google-Triada-backdoors-were-pre-installed-on-Android-devices) Triada firmware infections traced to third-party vendors in the manufacturing supply chain. The xHelper variant affected thousands of low-cost devices sold in emerging markets.

### Other Firmware Persistence

Beyond Triada, firmware-level persistence has been observed in:

| Campaign | Vector | Year |
|----------|--------|------|
| Lemon Group / Guerrilla | Preinstalled on budget devices, 8.9M+ devices affected | 2023 |
| BadBox | Preinstalled backdoor on off-brand Android TV boxes | 2023 |
| Triada supply chain | Counterfeit smartphones with firmware-embedded trojan | 2025 |

These campaigns share a common pattern: the compromise occurs before the device reaches the consumer, and the malicious code is protected by the same verified boot guarantees that protect the legitimate OS.

## Magisk Boot Image Patching

[Magisk](https://github.com/topjohnwu/Magisk) achieves root access by patching the boot image rather than modifying the system partition. This is the standard approach for security researchers and the rooting community because it preserves dm-verity on the system partition.

### How It Works

The patching process, [implemented in `boot_patch.sh`](https://github.com/topjohnwu/Magisk/blob/master/scripts/boot_patch.sh), modifies the boot image ramdisk:

1. **Unpack**: `magiskboot` extracts the boot image into its components (kernel, ramdisk, dtb, etc.)
2. **Backup**: The original ramdisk is compressed and stored for later restoration
3. **Inject magiskinit**: The stock `/init` binary in the ramdisk is replaced with `magiskinit`
4. **Add overlay**: Magisk binaries (`magisk`, `magiskinit`, `magiskpolicy`) are added to an overlay directory within the ramdisk
5. **Configure**: Environment variables control whether dm-verity and forced encryption are preserved (`KEEPVERITY`, `KEEPFORCEENCRYPT`)
6. **Repack**: `magiskboot` reassembles the patched boot image

The patched boot image is then flashed via fastboot:

```bash
fastboot flash boot magisk_patched.img
```

### Boot Sequence with Magisk

When the device boots the patched image:

1. Kernel loads and executes `/init` from the ramdisk -- which is now `magiskinit`
2. `magiskinit` loads the stock SELinux policy
3. `magiskinit` [patches the policy in memory](selinux.md) to inject the `magisk` domain with broad permissions
4. `magiskinit` sets up overlay mounts for read-only root filesystems
5. `magiskinit` executes the real `init` to continue normal boot
6. The Magisk daemon starts as a system service, providing root access through the `magisk` domain

### Systemless Root

Because Magisk only modifies the boot image ramdisk, the system and vendor partitions remain untouched and pass dm-verity verification. This "systemless" approach means:

- OTA updates can still be applied (the boot image may need re-patching afterward)
- SafetyNet/Play Integrity `ctsProfileMatch` can potentially pass with additional modules
- The root modification is contained to a single partition, simplifying reversal

### avbroot

[avbroot](https://github.com/chenxiaolong/avbroot) takes a different approach: it patches full OTA images, re-signs all partitions with custom AVB keys, and can integrate Magisk or KernelSU into A/B OTA packages. This allows maintaining a fully verified boot chain (YELLOW state) with custom-signed images rather than the ORANGE state that standard Magisk produces.

## Custom ROM Implications

Running a custom ROM (LineageOS, GrapheneOS, CalyxOS) on an unlocked bootloader creates a specific security research environment:

| Aspect | Implication |
|--------|-------------|
| Root access | Available through Magisk, KernelSU, or built-in su |
| SELinux policy | Custom policy may be more or less restrictive than stock |
| Kernel source | Available for modification, custom module loading |
| dm-verity | Typically disabled for the system partition |
| OTA updates | ROM-specific update mechanism, not OEM |
| Play Integrity | Fails `MEETS_DEVICE_INTEGRITY` without additional spoofing |
| Bootloader state | ORANGE (unlocked) or YELLOW (re-locked with custom keys, GrapheneOS) |

GrapheneOS is notable for supporting re-locking the bootloader with custom keys on Pixel devices, achieving YELLOW boot state and enabling hardware-backed attestation for its own [Auditor](https://attestation.app/) tool. This is the only aftermarket OS that maintains a verified boot chain comparable to the stock OS.

## Offensive Relevance

### Persistence Boundaries

Verified Boot defines what survives across reboots:

- **Locked bootloader, stock firmware**: Only data partition modifications persist. Malware must operate within app sandbox constraints.
- **Unlocked bootloader**: Boot image modifications persist. Root access, custom kernels, and system modifications are possible.
- **Supply chain compromise**: System image modifications persist and are protected by verified boot. This is the most powerful persistence vector.

### Exploit Chain Targets

A full firmware persistence exploit chain on a locked-bootloader device requires:

1. A vulnerability to achieve code execution
2. Privilege escalation to kernel or bootloader level
3. A method to modify the boot image or system partition in a way that survives dm-verity
4. Updating the vbmeta hash to match the modified partition (requires the OEM signing key or a bootloader vulnerability)

Step 4 is the fundamental barrier. Without the OEM's private signing key, an attacker cannot produce a valid vbmeta signature for modified partitions. This is why supply chain attacks (compromising the OEM's build infrastructure) are the practical route to firmware persistence on locked devices.

### For Malware Analysis

When analyzing a sample, consider what boot state it expects:

- Malware targeting stock locked devices must operate entirely within the app sandbox and data partition
- Malware that modifies system files (like Triada firmware variants) requires supply chain access or an unlocked bootloader
- Samples that check `ro.boot.verifiedbootstate` or `ro.boot.flash.locked` are adapting behavior based on the device's integrity state

## Cross-References

- [SELinux](selinux.md) policy integrity depends on verified boot protecting the policy files from modification
- [Keystore](keystore.md) key attestation includes the verified boot state in its certificate chain
- [Play Integrity](play-integrity.md) relies on the verified boot state as a primary signal for device integrity verdicts
- [Triada](../malware/families/triada.md) is the primary example of firmware-level malware persistence protected by verified boot
- [Persistence Techniques](../attacks/persistence-techniques.md) documents how malware persists within the constraints verified boot imposes
