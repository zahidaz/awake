# Android Dangerous Permissions

## Overview

Android's permission system is designed to protect user privacy and system security by controlling access to sensitive data and device features. Permissions are categorized into different protection levels, with **dangerous permissions** being those that could potentially affect user privacy or device operation.

Dangerous permissions are runtime permissions that must be explicitly granted by the user. However, these permissions are frequently abused by malicious applications and are common targets for exploitation.

## Permission Model

Starting from Android 6.0 (API level 23), dangerous permissions must be requested at runtime rather than being granted at install time. Users can revoke these permissions at any time through system settings.

### Protection Levels

- **Normal**: Low-risk permissions granted automatically
- **Dangerous**: Runtime permissions that access sensitive user data
- **Signature**: Only granted to apps signed with the same certificate
- **SignatureOrSystem**: Reserved for system apps

## Dangerous Permission Groups

Android dangerous permissions are organized into logical groups. Granting one permission in a group automatically grants all other permissions in that same group (for targetSdkVersion < 23).

### [Calendar](calendar/index.md)
Access to calendar events and reminders.

### [Call Log](call-log/index.md)
Read and write access to call history.

### [Camera](camera/index.md)
Access to device cameras for capturing photos and videos.

### [Contacts](contacts/index.md)
Access to user contact information and accounts.

### [Location](location/index.md)
Access to device location through GPS, network, or other sources.

### [Microphone](microphone/index.md)
Access to audio capture from device microphones.

### [Phone](phone/index.md)
Access to phone state, call management, and telephony features.

### [Sensors](sensors/index.md)
Access to body sensor data like heart rate monitors.

### [Activity Recognition](activity-recognition/index.md)
Access to user physical activity data.

### [SMS](sms/index.md)
Send, receive, and read SMS and MMS messages.

### [Storage](storage/index.md)
Read and write access to external storage and media files.

### [Nearby Devices](nearby-devices/index.md)
Access to Bluetooth, Wi-Fi, and Ultra-Wideband for device discovery.

## Common Abuse Patterns

Dangerous permissions are frequently abused through:

- **Over-permission**: Requesting more permissions than functionally necessary
- **Permission creep**: Gradually requesting additional permissions through updates
- **Social engineering**: Misleading users about permission purposes
- **Exploitation**: Leveraging granted permissions for unintended purposes
- **Privilege escalation**: Chaining multiple permissions to gain elevated access

## Security Considerations

When analyzing applications or permission usage:

1. **Principle of least privilege**: Apps should only request necessary permissions
2. **Purpose limitation**: Permissions should only be used for stated purposes
3. **Temporal constraints**: Consider when and how frequently permissions are accessed
4. **Data minimization**: Limit the scope and duration of sensitive data access
5. **User transparency**: Users should understand why permissions are needed

## Research Focus

Each permission page in this wiki documents:

- Technical implementation details
- Known vulnerabilities and exploits
- Abuse patterns observed in malware
- Bypass techniques and escalation vectors
- Defensive recommendations
- Real-world case studies

## References

- [Android Permissions Overview](https://developer.android.com/guide/topics/permissions/overview)
- [Android Manifest Permissions](https://developer.android.com/reference/android/Manifest.permission)
- [Permission Best Practices](https://developer.android.com/training/permissions/requesting)
