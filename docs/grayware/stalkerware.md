# Stalkerware / Spouseware

Commercial surveillance apps marketed for "parental monitoring" or "employee tracking" but predominantly used for intimate partner surveillance. These are sold openly with customer support, subscription billing, and terms of service, yet provide capabilities identical to state-sponsored spyware.

## Major Stalkerware Products

| Product | Price | Status |
|---------|-------|--------|
| mSpy | $30-70/month | Active, one of the largest operators |
| FlexiSpy | $70-200/month | Active, premium tier with call interception |
| Cocospy / Spyic | $40-50/month | Active, same parent company (1TopSpy) |
| Hoverwatch | $25-50/month | Active, markets as "invisible phone tracker" |
| eyeZy | $10-40/month | Active, AI-powered monitoring features |
| uMobix | $30-60/month | Active, real-time phone tracker with dashboard |
| Spyzie | $30-40/month | Active, sold as parental monitoring tool |
| iKeyMonitor | $30-50/month | Active, keylogger-focused with screenshot capture |
| XNSpy | $30-36/month | Active, remote microphone and camera activation |
| TheTruthSpy | $20-30/month | Breached in 2022, 60GB of victim photos/data exposed |
| pcTattletale | $100/year | Hacked and shut down in 2024 |
| LetMeSpy | Free-$6/month | Breached and shut down in 2023 |
| SpyFone | ~$100/year | Banned by FTC in 2021 |

## Technical Capabilities

| Capability | Implementation |
|------------|---------------|
| Real-time GPS tracking | Background location service with [ACCESS_BACKGROUND_LOCATION](../permissions/location/access-background-location.md) |
| Call recording | Audio recording during calls via [RECORD_AUDIO](../permissions/microphone/record-audio.md) |
| SMS/MMS reading | [READ_SMS](../permissions/sms/read-sms.md) content provider monitoring |
| Social media monitoring | [Accessibility service](../attacks/accessibility-abuse.md) reads screen content from WhatsApp, Instagram, Snapchat |
| Ambient microphone | Silent [RECORD_AUDIO](../permissions/microphone/record-audio.md) activation on command |
| Keylogging | Accessibility service captures all text input |
| Screenshot capture | [Screen capture](../attacks/screen-capture.md) at intervals or on demand |
| Browser history | Read browser content providers or accessibility scraping |
| Camera capture | Silent [CAMERA](../permissions/camera/camera.md) activation |

## Installation and Concealment

Requires physical access to the target device. Installers guide the abuser through disabling Play Protect, enabling unknown sources, granting all permissions, then activating device administrator. After installation:

- App icon hidden from launcher (removed from `CATEGORY_LAUNCHER`)
- Process name disguised as system component ("System Service", "Battery Optimizer", "Sync Service")
- Runs as a [foreground service](../permissions/normal/foreground-service.md) with a blank or misleading notification
- Registered as [device administrator](../attacks/device-admin-abuse.md) to resist uninstallation
- [RECEIVE_BOOT_COMPLETED](../permissions/normal/receive-boot-completed.md) for persistence across reboots

## Detection

- Hidden [accessibility services](../permissions/special/bind-accessibility-service.md) with generic names
- Elevated battery consumption from continuous location and sensor polling
- Background data usage to stalkerware C2 servers
- Device administrator registered to unknown app
- Coalition Against Stalkerware maintains detection signatures shared with AV vendors
- Check `Settings > Accessibility > Installed Services` for unknown entries
- Check `Settings > Security > Device admin apps` for apps not installed by user

## Legal Landscape

Enforcement against stalkerware has intensified, though the industry remains largely unregulated:

| Action | Year | Details |
|--------|------|---------|
| FTC vs SpyFone | 2021 | FTC banned SpyFone from the surveillance industry and ordered deletion of all collected data |
| FTC vs Support King (SpyFone parent) | 2022 | Company and CEO personally prohibited from offering surveillance products |
| FTC vs InvisiMon | 2023 | Fined for selling stalkerware marketed as "parental monitoring" |
| EU Digital Services Act | 2024 | Platforms required to remove stalkerware distribution channels; enforcement varies by member state |
| Coalition Against Stalkerware | 2019-present | Industry coalition (Kaspersky, EFF, NNEDV, others) standardizing detection and providing victim resources |

The Coalition Against Stalkerware maintains shared detection definitions and IOCs that participating AV vendors incorporate into their products. Their [detection criteria](https://stopstalkerware.org/) focus on apps that operate covertly, transmit PII without prominent notification, and resist uninstallation.

## Android Platform Defenses

Google has progressively restricted the capabilities stalkerware relies on:

| Year | Change | Impact |
|------|--------|--------|
| 2019 | Play Store policy bans apps marketed for surveillance | Forces distribution through sideloading |
| 2020 | Background location access restrictions (Android 11) | Stalkerware must justify background location or use foreground service |
| 2021 | Play Protect stalkerware detection | Warns users when known stalkerware is detected on device |
| 2022 | Privacy dashboard (Android 12) | Users can see which apps accessed camera, microphone, location in last 24 hours |
| 2023 | Notification listener restrictions (Android 13) | Limits which apps can read notifications |
| 2024 | Play Protect live threat detection | On-device ML scanning detects stalkerware behavior patterns |

These restrictions have not eliminated stalkerware but have forced it off the Play Store and into manual sideloading with ADB or developer mode. Installation guides provided by stalkerware vendors now require disabling Play Protect as a mandatory step.

## Dual-Use Apps

Legitimate apps repurposed for stalkerware-like surveillance without the target's meaningful consent:

| App | Legitimate Purpose | Abuse Scenario |
|-----|-------------------|----------------|
| Google Find My Device | Locate lost/stolen device | Covert location tracking of partner's phone |
| Life360 | Family location sharing | Coercive location monitoring in intimate partner abuse |
| AirDroid | Remote device management | Remote screen viewing and file access without target awareness |
| Cerberus Anti-Theft | Anti-theft protection | Full surveillance suite (audio, camera, location, SMS) deployed covertly |

These apps occupy a different legal space than purpose-built stalkerware because they have legitimate use cases and operate with visible notifications. However, in coercive relationships where one partner controls the other's device, the distinction between "family safety" and surveillance breaks down.

## Data Breaches

Stalkerware companies are frequent breach targets because they store massive datasets of intimate victim data with poor security:

- **TheTruthSpy** (2022): 60GB of victim photos, audio recordings, and messages exposed
- **LetMeSpy** (2023): Entire database leaked, company shut down
- **pcTattletale** (2024): Hacked, data exposed, company permanently closed
- **SpyFone** (2021): FTC ordered data deletion, banned from surveillance industry
- **mSpy** (2015, 2018): Breached twice, millions of customer records exposed
