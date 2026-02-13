# NFC Relay Attacks

Relaying NFC (Near Field Communication) data from a victim's payment card to an attacker-controlled device for unauthorized transactions. An emerging attack category first seen in Android malware in 2024, enabling ATM cash withdrawal and POS fraud using cloned contactless card data.

!!! warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | NFC access (normal permission, auto-granted) |
    | Condition | Victim places physical payment card against infected device |
    | Infrastructure | Second device (mule) with NFC and HCE (Host Card Emulation) near ATM or POS terminal |

## How It Works

### Attack Flow

1. Malware phishes the victim for their card PIN via a fake banking WebView
2. Malware instructs the victim to hold their physical payment card against the phone ("verify your card")
3. The infected device reads the card's NFC data
4. Card data is relayed in real time to a mule's device via a C2 server
5. The mule's device emulates the card using HCE at a physical ATM or POS terminal
6. The mule enters the stolen PIN and withdraws cash or makes purchases

The relay happens in real time. The NFC protocol has tight timing requirements, so the relay infrastructure must be low-latency.

### Technical Mechanism

| Component | Role |
|-----------|------|
| Victim device | Reads NFC tag data from the physical card using Android's NFC stack |
| Relay server | Forwards NFC APDU (Application Protocol Data Unit) commands between victim and mule devices |
| Mule device | Emulates the card using Android's Host Card Emulation (HCE) API, responding to the POS/ATM terminal as if it were the real card |

The key insight: Android's HCE API allows any app to respond to NFC readers as if it were a contactless card. By relaying the real card's responses through a mule device, the ATM or POS terminal cannot distinguish the relay from a genuine tap.

### NFCGate

[NFCGate](https://github.com/nfcgate/nfcgate) is an open-source academic NFC relay tool developed at TU Darmstadt for security research. It provides the relay infrastructure that [NGate](../malware/families/ngate.md) repurposed for malicious use. NFCGate itself is a legitimate research tool; the malware weaponizes its relay capability.

## Families Using This Technique

| Family | Year | Approach | Target |
|--------|------|----------|--------|
| [NGate](../malware/families/ngate.md) | 2024 | NFCGate-based relay, credential phishing via WebView | Czech banks, ATM withdrawal |
| [RatOn](../malware/families/raton.md) | 2025 | NFC relay + ATS combination, crypto wallet seed extraction | Czech/Slovak banks, POS fraud |
| GhostTap | 2025 | Scanner/tapper pairs, Telegram-based data exfiltration | Multi-region, POS fraud |
| SuperCard | 2025 | NFC relay with expanded card type support | European banks |

[Zimperium identified 760+ malicious apps](https://zimperium.com/blog/tap-and-steal-the-rise-of-nfc-relay-malware-on-mobile-devices) exploiting NFC and HCE by late 2025, with 70+ C2 servers targeting Russia, Poland, Czech Republic, Slovakia, and other European countries.

### Evolution

NGate pioneered the approach in 2024 with a straightforward NFC relay for ATM withdrawal. [RatOn](../malware/families/raton.md) evolved the technique in 2025 by combining NFC relay with ATS (Automated Transfer System) capabilities, enabling both physical card cloning and automated bank transfers from a single trojan. [ESET's H2 2025 threat report](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h2-2025/) documented an 87% increase in NFC threats on Android and a 35x increase in NFC-based fraud.

## Practical Limitations

| Limitation | Details |
|------------|---------|
| Physical card required | Victim must physically tap their card against the infected device |
| Real-time relay | NFC protocol timing constraints require low-latency relay infrastructure |
| Mule required | An in-person accomplice must be at an ATM or POS terminal during the relay |
| Single-use risk | Some banks block cards after suspicious contactless transactions |
| Geographic constraint | Mule must be at a physical terminal; cannot be done fully remotely |

Despite these constraints, the attack is effective because contactless payment terminals perform limited verification. The terminal trusts the HCE-emulated card as long as the relayed APDU responses are valid.

## Detection During Analysis

??? example "Static Indicators"

    - `android.nfc` and `android.nfc.cardemulation` imports
    - `HostApduService` implementation (HCE)
    - `AID_GROUP` declarations in XML for payment card emulation
    - WebSocket or raw TCP connections for real-time data relay
    - UI strings asking user to "tap" or "hold" their card

??? example "Dynamic Indicators"

    - NFC read operations followed by immediate network transmission
    - HCE service activation without legitimate payment functionality
    - WebView loading card PIN entry forms

## APDU Command Flow

NFC relay attacks work at the APDU (Application Protocol Data Unit) layer defined by ISO 7816-4. Every contactless EMV transaction follows a structured sequence of command-response pairs between the terminal and card. In a relay attack, the mule device's HCE service receives commands from the terminal and forwards them through the relay infrastructure to the victim's device, which passes them to the real card and returns the responses.

### EMV Transaction Sequence

| Step | APDU Command | Purpose | Relayed or Cacheable |
|------|-------------|---------|---------------------|
| 1 | `SELECT (PPSE)` | Terminal selects Proximity Payment Systems Environment to discover available payment apps | Cacheable -- response is static per card |
| 2 | `SELECT (AID)` | Terminal selects a specific payment application (e.g., Visa AID `A0000000031010`) | Cacheable -- AID list doesn't change |
| 3 | `GET PROCESSING OPTIONS` | Terminal sends transaction parameters (amount, currency, date); card returns Application Interchange Profile (AIP) and Application File Locator (AFL) | Must relay -- card may use terminal-provided data to determine CDA/DDA mode |
| 4 | `READ RECORD` (multiple) | Terminal reads card records indicated by AFL: cardholder name, PAN, expiry, certificates | Cacheable -- these records are static |
| 5 | `GET DATA` | Terminal requests additional data objects (e.g., ATC, log entries) | Depends -- ATC (Application Transaction Counter) is dynamic |
| 6 | `GENERATE AC` | Terminal requests an Application Cryptogram; card produces ARQC using its secret key, the ATC, and transaction data | Must relay -- this is the dynamic cryptogram that authenticates the card |

The critical insight for relay optimization: steps 1, 2, and 4 return static data that can be cached after the first relay session. This reduces the number of round trips needed during subsequent attacks. Steps 3 and 6 must always be relayed because they involve transaction-specific dynamic data. Step 6 is the most time-sensitive -- the terminal expects the cryptogram response within a tight window, so relay latency directly determines success or failure.

### Timing Constraints

The EMV contactless specification allows around 500ms for the full transaction. Each relay hop adds latency:

- Card-to-victim-device: near-instant (local NFC)
- Victim-device-to-relay-server: 30-100ms (network dependent)
- Relay-server-to-mule-device: 30-100ms
- Mule-device-to-terminal: near-instant (local NFC)

A single round trip through the relay adds 60-200ms. With multiple APDU exchanges required, the total relay overhead can approach or exceed the terminal's timeout. This is why caching static responses and minimizing network hops is essential for a reliable relay.

## NFC Relay vs Card Cloning

| Aspect | NFC Relay | Card Cloning |
|--------|-----------|-------------|
| Timing | Real-time -- victim card must be present during the transaction | Offline -- cloned data is used independently |
| Authentication | Defeats EMV dynamic authentication (ARQC cryptograms generated by the real card) | Only works with static data (magstripe CVV, static CVC3) |
| Data captured | Full APDU conversation including dynamic cryptograms | Card number, expiry, static authentication data |
| Reusability | Each transaction requires a new relay session | Cloned data can be reused until card is blocked |
| Complexity | Requires two devices, relay infrastructure, real-time coordination | Requires one device and a blank card or emulator |
| Scope | Works against modern chip-and-PIN and contactless EMV | Limited to terminals that accept magstripe fallback or static contactless |

EMV's core defense against cloning is the dynamic Application Cryptogram generated during `GENERATE AC`. The card uses a symmetric key shared only with the issuer to produce a cryptogram over the transaction data, including the unpredictable number from the terminal and the card's own transaction counter. An attacker who clones static card data cannot produce valid cryptograms for new transactions because they lack the card's secret key.

Relay bypasses this entirely. The real card generates the cryptogram in response to the terminal's challenge, and the relay infrastructure simply forwards it. From the issuer's perspective, the cryptogram is valid because it was produced by the genuine card. The issuer has no way to know the card was physically in a different location than the terminal.

## Extending Beyond Payment

NFC relay is not limited to payment cards. Any system that uses NFC challenge-response authentication is vulnerable.

### Access Control Badges

Corporate and government buildings use contactless smart cards (MIFARE DESFire, HID iCLASS SE) for physical access. The relay attack works identically: one device reads the victim's badge, relays APDU data to a second device at the door reader. The access control system sees valid credentials and unlocks. Unlike payment systems, most physical access systems have no transaction counter or backend authorization check, making relay even simpler.

### Transit Cards

Closed-loop transit systems (Oyster, Clipper, OMNY) use NFC cards with stored value or account-linked identifiers. Relaying a transit card allows fare evasion by tapping the mule device at a turnstile while the victim's card is read remotely. Transit systems typically have weaker anti-relay protections than payment networks because the fraud value per transaction is low.

### Digital Identity Documents

ePassports and national ID cards (compliant with ICAO 9303) use NFC for machine-readable verification. The chip stores biometric data, personal details, and digital signatures. While Basic Access Control (BAC) and Password Authenticated Connection Establishment (PACE) protect against unauthorized reading, once the optical MRZ is known (or relay is initiated during a legitimate verification), the full chip contents can be relayed. This enables identity document relay during remote verification scenarios where the verifier expects physical document presence.

### Hotel Key Cards

Many modern hotel systems use NFC-based room keys issued to guests' phones or physical cards. These typically use static or weakly dynamic authentication, making them straightforward relay targets. The mule device can open doors while the victim's key is read at a different location.

## Building a Test Lab

Testing NFC relay detection requires a controlled environment that replicates the attack chain.

### Hardware

| Component | Purpose | Notes |
|-----------|---------|-------|
| Android device #1 (reader) | Reads the target NFC card | Must support NFC; acts as the "victim-side" relay endpoint |
| Android device #2 (emulator) | Emulates the card at a terminal using HCE | Must support HCE; acts as the "mule-side" relay endpoint |
| Contactless test card | EMV test card from a payment card test kit or expired contactless card | Do not use live payment cards for testing |
| NFC-capable POS terminal (optional) | Validates end-to-end relay against a real reader | Test terminals available from payment processor dev programs |

### Software

| Tool | Purpose |
|------|---------|
| [NFCGate](https://github.com/nfcgate/nfcgate) | Open-source NFC relay framework from TU Darmstadt; supports on-device relay mode and server relay mode |
| Frida | Hook Android NFC stack (`android.nfc.tech.IsoDep`) to log APDU commands during relay |
| Wireshark + USBPcap | Capture NFC traffic when using USB-connected NFC readers |
| nfcpy (Python) | Scriptable NFC library for crafting custom APDU sequences on a desktop with an ACR122U reader |

### Setup Steps

1. Install NFCGate on both Android devices from the GitHub releases (requires root for on-device relay mode, though server relay mode works without root on some builds)
2. Configure one device as "reader" mode and the other as "relay" mode
3. Set the relay server address -- NFCGate supports direct device-to-device relay over a network or through an intermediary server
4. Place the test card against the reader device
5. Hold the emulator device against a POS terminal or use a desktop NFC reader with nfcpy to simulate terminal commands
6. Observe the relayed APDU traffic in NFCGate's log view
7. Measure round-trip latency per APDU exchange to determine relay viability under EMV timing constraints

### What to Test

- **Relay latency**: measure whether the full EMV transaction completes within the terminal's timeout window
- **Selective caching**: verify which APDU responses can be cached without breaking the transaction
- **Distance limits**: test maximum practical distance between reader and emulator (network-limited, not NFC-limited)
- **Detection evasion**: check whether relay introduces detectable timing anomalies that issuer-side fraud systems could flag
