# Clipboard Hijacking

Monitoring or modifying clipboard contents to steal sensitive data. Android's `ClipboardManager` API provides a system-wide clipboard that any foreground app can read and write. Malware abuses this to intercept cryptocurrency wallet addresses, passwords, OTPs, and banking data as users copy and paste between apps. The most destructive variant, the crypto clipper, silently replaces a copied wallet address with one controlled by the attacker, redirecting transactions without the victim noticing.

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1414](https://attack.mitre.org/techniques/T1414/) | Clipboard Data | Collection, Credential Access |

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | None for foreground access. [`BIND_ACCESSIBILITY_SERVICE`](../permissions/special/bind-accessibility-service.md) for background or silent clipboard reads on Android 10+. |
    | Condition | App must be in foreground, or running an accessibility service, to access clipboard on Android 10+ |

## How It Works

### ClipboardManager Listener

The primary mechanism. The app registers a listener that fires every time clipboard content changes:

```java
ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
cm.addPrimaryClipChangedListener(() -> {
    ClipData clip = cm.getPrimaryClip();
    String text = clip.getItemAt(0).getText().toString();
    if (matchesCryptoAddress(text)) {
        cm.setPrimaryClip(ClipData.newPlainText("", attackerWallet));
    }
});
```

The listener runs in the app's process. On Android 10+, the app must be in the foreground or running a foreground service to receive clipboard change events. Malware circumvents this by maintaining a persistent foreground notification (often disguised as a system service) or by using an accessibility service.

### Accessibility-Based Clipboard Reading

An accessibility service can read clipboard contents without triggering the user-visible clipboard access toast introduced in Android 12. The service monitors `TYPE_VIEW_TEXT_CHANGED` and `TYPE_WINDOW_CONTENT_CHANGED` events, then reads the clipboard when it detects the user has performed a paste action or is interacting with a text field in a target app.

On pre-Android 10 devices, accessibility services can read clipboard at any time without restriction. On Android 10+, the accessibility service still has unrestricted clipboard access, making it the preferred method for modern malware.

### ContentObserver on Clipboard URI

Some families register a `ContentObserver` on the clipboard content URI to detect changes passively. This is less common than the listener approach but achieves the same result with a different triggering mechanism.

## Attack Patterns

### Crypto Address Replacement (Clipper)

The highest-value clipboard attack. The malware monitors for cryptocurrency wallet addresses using regex patterns, then replaces them with attacker-controlled addresses before the user pastes:

| Cryptocurrency | Address Pattern | Example Regex |
|---------------|----------------|---------------|
| Bitcoin (BTC) | Starts with `1`, `3`, or `bc1`, 26-62 chars | `^(bc1\|[13])[a-zA-HJ-NP-Z0-9]{25,62}$` |
| Ethereum (ETH) | Starts with `0x`, 42 hex chars | `^0x[0-9a-fA-F]{40}$` |
| TRON (TRX) | Starts with `T`, 34 chars | `^T[1-9A-HJ-NP-Za-km-z]{33}$` |
| Litecoin (LTC) | Starts with `L`, `M`, or `ltc1` | `^(ltc1\|[LM])[a-zA-HJ-NP-Z0-9]{25,62}$` |
| Ripple (XRP) | Starts with `r`, 25-35 chars | `^r[0-9a-zA-Z]{24,34}$` |

The replacement is instant. The user copies a legitimate address from an exchange or message, the malware swaps it, and the user pastes the attacker's address into their wallet app. The transaction confirmation screen shows the attacker's address, but most users don't compare the full address string.

Some families maintain multiple attacker wallets and select the replacement address based on the cryptocurrency type and address format detected.

### Credential Harvesting

Malware monitors clipboard for patterns matching:

- Passwords (copied from password managers)
- Email addresses
- Phone numbers
- Banking card numbers (matching Luhn algorithm patterns)
- API keys and tokens

Anything copied is logged and exfiltrated to C2. Users routinely copy credentials from password managers, notes apps, and messages, creating a steady stream of sensitive data through the clipboard.

### OTP Theft

When a user receives a one-time password via SMS or authenticator app and copies it, the clipboard briefly contains the OTP. Malware with a clipboard listener captures this immediately. Combined with other stolen credentials, this enables account takeover. Some banking apps auto-fill OTPs from SMS, but users who manually copy-paste from their SMS app or authenticator expose the code through clipboard.

## Platform Lifecycle

| Android Version | API | Change | Offensive Impact |
|----------------|-----|--------|-----------------|
| 1.0 | 1 | `ClipboardManager` API available | Any app can read/write clipboard at any time |
| 10 | 29 | [Background clipboard access restricted](https://developer.android.com/about/versions/10/privacy/changes#clipboard-data) | Malware must maintain foreground state or use accessibility service |
| 12 | 31 | Toast notification when an app reads clipboard | User sees "[App] pasted from your clipboard"; accessibility services bypass this |
| 12 | 31 | `ClipDescription.getConfidential()` flag | Keyboard/IME apps can mark content as sensitive; does not prevent programmatic reads |
| 13 | 33 | [Clipboard auto-cleared after ~1 hour](https://developer.android.com/about/versions/13/behavior-changes-all#clipboard-preview) | Active listeners still capture in real-time; crypto clippers unaffected |
| 14 | 34 | Background activity launch restrictions tightened | Harder for background apps to reach foreground for clipboard access; accessibility unaffected |

The clipboard access toast in Android 12 is the most visible mitigation, but it only appears for reads, not for the initial copy event. A crypto clipper that replaces clipboard content on the `OnPrimaryClipChangedListener` callback operates before the user pastes, so the toast for the malware's clipboard write may flash briefly but is easily missed or attributed to the legitimate app.

Accessibility services remain the consistent bypass across all Android versions. Every restriction introduced since Android 10 has an exception for accessibility, making it the reliable path for clipboard-based attacks.

## Families Using This Technique

| Family | Clipboard Capability | Primary Target |
|--------|---------------------|---------------|
| [Cerberus](../malware/families/cerberus.md) | Clipboard monitoring via accessibility keylogger | Credentials, banking data |
| [Hook](../malware/families/hook.md) | Clipboard read/write, inherits Cerberus-lineage clipboard access | Credentials, banking data |
| [FireScam](../malware/families/firescam.md) | Continuous clipboard capture, exfiltrates copied passwords and tokens | Credentials, OTPs |
| [SparkCat](../malware/families/sparkcat.md) | OCR-based crypto theft from screenshots (complements clipboard attack) | Crypto seed phrases |
| [SpyAgent](../malware/families/spyagent.md) | OCR-based crypto theft from screenshots (complements clipboard attack) | Crypto seed phrases |
| [Triada](../malware/families/triada.md) | System-level clipboard replacement, swaps wallet addresses during copy-paste | Cryptocurrency addresses |
| [Gigabud](../malware/families/gigabud.md) | Replaces bank card numbers in clipboard with attacker-controlled numbers | Banking card numbers |
| [BTMOB RAT](../malware/families/btmob.md) | Continuous clipboard monitoring for wallet addresses, passwords, and OTPs | Crypto, credentials, OTPs |
| [SpyNote](../malware/families/spynote.md) | Clipboard monitoring and capture as part of full surveillance suite | General data exfiltration |
| [Hermit](../malware/families/hermit.md) | Clipboard monitoring module in state-sponsored spyware toolkit | Intelligence collection |
| [Gustuff](../malware/families/gustuff.md) | Clipboard injection to fill banking transfer fields on older Android versions | Banking ATS |

[Triada](../malware/families/triada.md) operates at the system level through Zygote injection or firmware-level implantation, giving it clipboard access across every process on the device without any permission requirements. [Gigabud](../malware/families/gigabud.md) specifically targets banking card numbers rather than cryptocurrency, replacing copied card numbers with attacker-controlled numbers to redirect card-based payments.

SparkCat and SpyAgent represent an adjacent technique: rather than intercepting clipboard contents at copy time, they use OCR to scan gallery images for screenshots of crypto seed phrases. The two approaches are complementary, and a sophisticated operation could deploy both.

## Detection During Analysis

??? example "Static Indicators"

    - `ClipboardManager` usage with `addPrimaryClipChangedListener`
    - `setPrimaryClip` or `setPrimaryClipData` calls (indicates clipboard writing/replacement)
    - Regex patterns matching cryptocurrency address formats (BTC, ETH, TRON, etc.)
    - `ContentObserver` registered against clipboard URI
    - Accessibility service with `flagRetrieveInteractiveWindows` or `flagRequestAccessibilityButton`

??? example "Dynamic Indicators"

    - Clipboard content changes immediately after user copies a cryptocurrency address
    - App maintains a foreground service with minimal visible UI
    - Network exfiltration of clipboard contents to C2 after copy events
    - Multiple attacker wallet addresses hardcoded or fetched from C2 configuration
