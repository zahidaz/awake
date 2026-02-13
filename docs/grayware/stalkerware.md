# Stalkerware / Spouseware

Commercial surveillance apps marketed for "parental monitoring" or "employee tracking" but predominantly used for intimate partner surveillance. These are sold openly with customer support, subscription billing, and terms of service, yet provide capabilities identical to state-sponsored spyware.

## Major Stalkerware Products

| Product | Price | Status |
|---------|-------|--------|
| mSpy | $30-70/month | Active, one of the largest operators |
| FlexiSpy | $70-200/month | Active, premium tier with call interception |
| Cocospy / Spyic | $40-50/month | Active, same parent company (1TopSpy) |
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

## Data Breaches

Stalkerware companies are frequent breach targets because they store massive datasets of intimate victim data with poor security:

- **TheTruthSpy** (2022): 60GB of victim photos, audio recordings, and messages exposed
- **LetMeSpy** (2023): Entire database leaked, company shut down
- **pcTattletale** (2024): Hacked, data exposed, company permanently closed
- **SpyFone** (2021): FTC ordered data deletion, banned from surveillance industry
- **mSpy** (2015, 2018): Breached twice, millions of customer records exposed
