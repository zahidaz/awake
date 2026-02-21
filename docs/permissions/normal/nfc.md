# NFC

Auto-granted permission that provides full access to the device's NFC hardware. Since NFC is a normal-protection-level permission, it requires no user prompt and is silently granted at install. Malware exploits this to relay payment card data from a victim's device to an attacker-controlled mule device at a physical ATM or POS terminal, enabling contactless fraud. An [87% increase in NFC-based threats](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h2-2025/) was documented in H2 2025 alone.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.NFC` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time (no user interaction) |
| Introduced | API 9 (Android 2.3) |
| User Visibility | None |
| Play Store Policy | No restrictions (used by legitimate payment, transit, and tag-reading apps) |

## What It Enables

### NFC Tag Reading

Standard `NfcAdapter` usage for reading NFC tags and contactless cards:

```java
NfcAdapter adapter = NfcAdapter.getDefaultAdapter(context);
adapter.enableForegroundDispatch(activity, pendingIntent, filters, techLists);
```

When an NFC tag or contactless card is tapped, the app receives an `Intent` containing the tag data. For ISO-DEP (ISO 14443-4) cards (payment cards, access badges), the app can open an `IsoDep` connection and exchange raw APDU commands:

```java
IsoDep isoDep = IsoDep.get(tag);
isoDep.connect();
byte[] response = isoDep.transceive(selectPpseCommand);
```

### Host Card Emulation (HCE)

The more dangerous capability. HCE allows an app to emulate a contactless smart card, responding to NFC readers as if the device were a physical card:

```java
public class RelayService extends HostApduService {
    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        byte[] relayedResponse = sendToRelayServer(commandApdu);
        return relayedResponse;
    }
}
```

HCE requires the `BIND_NFC_SERVICE` permission (signature-level, only bindable by the system) in the manifest service declaration, but the NFC permission itself is all that's needed for the app to register as an HCE handler.

### Manifest Declaration

```xml
<uses-permission android:name="android.permission.NFC" />
<uses-feature android:name="android.hardware.nfc" android:required="true" />

<service
    android:name=".RelayService"
    android:exported="true"
    android:permission="android.permission.BIND_NFC_SERVICE">
    <intent-filter>
        <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />
    </intent-filter>
    <meta-data
        android:name="android.nfc.cardemulation.host_apdu_service"
        android:resource="@xml/apduservice" />
</service>
```

## Abuse in Malware

### NFC Relay Attacks

The primary abuse vector. Malware reads a victim's payment card via NFC and relays the card data in real time to a mule device at a physical terminal. See [NFC Relay Attacks](../../attacks/nfc-relay.md) for full technical breakdown.

| Family | Year | Technique | Target |
|--------|------|-----------|--------|
| [NGate](../../malware/families/ngate.md) | 2024 | NFCGate-based APDU relay | Czech banks, ATM cash withdrawal |
| [RatOn](../../malware/families/raton.md) | 2025 | NFC relay + ATS, crypto wallet seed theft | Czech/Slovak banks, POS fraud |
| GhostTap | 2025 | Scanner/tapper pairs via Telegram | Multi-region POS fraud |
| SuperCard | 2025 | Extended card type support | European banks |

[Zimperium identified 760+ malicious apps](https://zimperium.com/blog/tap-and-steal-the-rise-of-nfc-relay-malware-on-mobile-devices) exploiting NFC and HCE by late 2025.

### Attack Chain

1. Victim installs malicious app (phishing, fake banking, fake utility)
2. App phishes the victim for their card PIN via a fake banking WebView
3. App instructs victim to hold their physical card against the phone ("verify your card")
4. App reads card NFC data via `IsoDep.transceive()`
5. Card APDU data is relayed in real time to a mule's device via C2 server
6. Mule device emulates the card at a physical ATM/POS using HCE
7. Mule enters the stolen PIN and withdraws cash

### Beyond Payment Cards

NFC relay is not limited to financial fraud. Any NFC challenge-response system is vulnerable:

| Target | Risk |
|--------|------|
| Corporate access badges | Physical building access via badge relay |
| Transit cards | Fare evasion by relaying stored-value cards |
| Hotel key cards | Room access via relay of guest's key |
| ePassports | Identity document relay during verification |

## Android Version Changes

| Version | API | Change | Impact |
|---------|-----|--------|--------|
| 2.3 | 9 | NFC API introduced | Basic tag reading |
| 4.4 | 19 | Host Card Emulation (HCE) introduced | Apps can emulate contactless cards |
| 4.4 | 19 | Tap & Pay settings | Users can select default payment app, but non-payment HCE services aren't restricted |
| 12 | 31 | `NfcAdapter.enableReaderMode()` requires foreground activity | Limits background NFC reads |
| 14 | 34 | Foreground service type declarations required | NFC services must declare appropriate foreground service type |

HCE (API 19) was the turning point. Before HCE, NFC on Android was limited to reading tags. After HCE, any app could respond to NFC readers as a contactless card, creating the relay attack surface.

## Detection Indicators

### Manifest Signals

- `android.permission.NFC` combined with `HostApduService` declaration
- `AID_GROUP` XML config referencing payment AIDs (e.g., `A0000000031010` for Visa, `A0000000041010` for Mastercard)
- Network permissions (`INTERNET`) combined with NFC and HCE
- WebView activity with card PIN entry strings alongside NFC usage

### High-Confidence Indicators

- `IsoDep.transceive()` calls followed by immediate network transmission
- `HostApduService` that forwards received APDUs to a remote server rather than processing locally
- UI strings referencing "tap your card", "hold card against phone", "verify card" in a non-payment app

## See Also

- [NFC Relay Attacks](../../attacks/nfc-relay.md)
- [NGate](../../malware/families/ngate.md)
- [RatOn](../../malware/families/raton.md)
