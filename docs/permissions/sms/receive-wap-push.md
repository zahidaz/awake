# RECEIVE_WAP_PUSH

Allows receiving WAP push messages, which are used to deliver MMS notifications and OMA (Open Mobile Alliance) provisioning messages. Historically abused for premium service subscription fraud and MMS-based exploits.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.RECEIVE_WAP_PUSH` |
| Protection Level | `dangerous` |
| Permission Group | `SMS` |
| Grant Method | Runtime permission dialog |
| Introduced | API 1 |

## What It Enables

Receive `WAP_PUSH_RECEIVED` broadcasts containing WAP Service Indication (SI) and Service Loading (SL) messages.

WAP push messages can:

- Deliver MMS download URLs
- Trigger automatic URL loading (SL messages)
- Carry OMA provisioning data (network configuration)

## Abuse in Malware

### WAP Billing Fraud

Joker (Bread) malware family heavily abused WAP push:

1. Malware subscribes user to premium WAP billing services
2. WAP push confirmation messages arrive
3. Malware intercepts and confirms them automatically
4. User is charged on their phone bill

This was one of the most persistent Play Store threats. Google removed 1700+ Joker-infected apps over its lifetime.

### MMS Exploit Delivery

Stagefright (2015) exploited the media processing pipeline through MMS messages. WAP push delivers the MMS notification, and the media framework automatically processes the attached content. While Stagefright itself was a framework vulnerability (not a permission issue), the WAP push reception path was part of the attack chain.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.RECEIVE_WAP_PUSH" />
```

Combined with `SEND_SMS` and `RECEIVE_SMS`, indicates potential WAP billing fraud. Subject to the same Google Play policy restrictions as other SMS permissions.
