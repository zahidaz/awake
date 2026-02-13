# Riskware / Dual-Use Apps

Legitimate apps with capabilities that can be -- or have been -- repurposed for surveillance, data harvesting, or abuse.

## Documented Cases

**VPN apps selling browsing data**: Sensor Tower, an analytics company, operated at least 20 VPN and ad-blocker apps (including Luna VPN and AdBlock Focus) to collect app usage data from millions of users. The apps required root certificate installation, giving Sensor Tower visibility into all network traffic. BuzzFeed News exposed this in 2020.

**Keyboard apps exfiltrating keystrokes**: ai.type, a popular custom keyboard with 40M+ downloads, was found sending keystroke data including passwords to remote servers. A 2017 breach of ai.type's unprotected database exposed personal data of 31M users including phone numbers, device details, and typing patterns.

**File manager apps harvesting data**: Several Chinese-developed file manager apps on Google Play (File Manager by sharkApp, File Recovery & Data Recovery) were found by Pradeo exfiltrating contacts, device location, photos, audio, and network information to servers in China despite claiming no data collection in their Play Store listings.

**Free antivirus as data collection**: DU Antivirus (by Baidu spin-off DU Group) collected device data, installed app lists, and call logs, then sold aggregated data. 10M+ installs before removal. Multiple free AV apps on Play Store operate primarily as data collection platforms with minimal actual detection capability.

**Utility apps with unnecessary permissions**: Flashlight apps requesting [camera](../permissions/camera/camera.md), [microphone](../permissions/microphone/record-audio.md), [contacts](../permissions/contacts/read-contacts.md), and [location](../permissions/location/access-fine-location.md) permissions. The permissions serve no function within the app's stated purpose but enable data harvesting.
