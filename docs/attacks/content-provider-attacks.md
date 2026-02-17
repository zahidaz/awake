# Content Provider Attacks

Exploiting exposed or misconfigured `ContentProvider` components to read, modify, or delete app data. Content providers are Android's standard mechanism for sharing structured data between apps. When exported without proper permission checks, they expose databases, files, and internal state.

??? abstract "MITRE ATT&CK"

    | ID | Technique | Tactic |
    |---|---|---|
    | [T1409](https://attack.mitre.org/techniques/T1409/) | Stored Application Data | Collection |

    No dedicated MITRE technique for content provider exploitation. T1409 covers accessing data stored by applications, which includes insecure content providers. MITRE treats content provider access as a data collection vector rather than a standalone technique.

??? warning "Requirements"

    | Requirement | Details |
    |-------------|---------|
    | Permission | None (if provider is exported without permission protection) |
    | Condition | Target app exports a ContentProvider with insufficient access controls |

## How Content Providers Work

A content provider exposes data through a URI-based interface:

```
content://com.target.app.provider/users
content://com.target.app.provider/users/42
```

Other apps query this using `ContentResolver`:

```java
Cursor cursor = getContentResolver().query(
    Uri.parse("content://com.target.app.provider/users"),
    null, null, null, null
);
```

Providers can also serve files via `openFile()`.

## Attack Patterns

### SQL Injection

If the provider builds SQL queries from user-supplied input without parameterization:

```java
// Vulnerable
String selection = "name = '" + userInput + "'";
cursor = db.query("users", null, selection, null, null, null, null);
```

Attack:

```java
Uri uri = Uri.parse("content://com.target.app.provider/users");
Cursor c = getContentResolver().query(uri, null,
    "1=1) UNION SELECT password,2,3 FROM credentials--", null, null);
```

### Path Traversal

Providers that serve files via `openFile()` may be vulnerable to path traversal:

```java
// Vulnerable
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
}
```

Attack:

```
content://com.target.app.fileprovider/../../shared_prefs/credentials.xml
```

If `../` sequences are not stripped, the attacker reads arbitrary files within the app's storage.

### Exported Provider Data Leakage

Providers exported without permission restrictions expose all their data:

```xml
<provider
    android:name=".UserProvider"
    android:authorities="com.target.app.provider"
    android:exported="true" />
```

Any app on the device can query all data. [Oversecured's research on app protected components](https://blog.oversecured.com/Android-Access-to-app-protected-components/) found that more than 80% of apps contain content provider or intent redirection vulnerabilities.

### Permission Confusion

Even "protected" providers can be exploitable:

- `android:readPermission` and `android:writePermission` set globally but overridden per-path with weaker permissions
- `android:grantUriPermissions="true"` allows temporary URI grants that bypass protection
- `path-permission` elements that don't cover all paths

### URI Grant Exploitation

Apps grant temporary access to content URIs:

```java
Intent intent = new Intent();
intent.setData(contentUri);
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
```

If the receiving app doesn't properly scope the grant, or if `grantUriPermissions` is enabled with broad `pathPattern`, an attacker may access more data than intended. [Oversecured's content provider research](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/) details how intent redirection followed by URI grant exploitation provides access to arbitrary content providers. The common chain: force intent redirection to a vulnerable activity, then use `FLAG_GRANT_READ_URI_PERMISSION` with a broad `grantUriPermissions="true"` declaration to access any content URI within the target app.

### `FileProvider` Misconfiguration

`FileProvider` (from AndroidX) is meant to safely share files. Misconfigurations:

```xml
<paths>
    <root-path name="root" path="/" />
</paths>
```

This exposes the entire filesystem. The default template from StackOverflow answers often includes overly broad paths. [Oversecured's content provider weakness catalog](https://blog.oversecured.com/Content-Providers-and-the-potential-weak-spots-they-can-have/) documents the complete chain from intent redirection to FileProvider path traversal exploitation.

## Android Mitigations

| Version | Mitigation | Bypass |
|---------|-----------|--------|
| Android 10 (API 29) | `android:exported` defaults to `false` for providers without intent filters | Only protects providers without intent filters; many still explicitly set `exported="true"` |
| Android 12 (API 31) | Apps must explicitly declare `android:exported` on all components | Developers often set `exported="true"` to resolve build errors without considering security implications |

## Families Using This Technique

| Family | Usage | Details |
|--------|-------|---------|
| [Goldoson](../malware/families/goldoson.md) | Data harvesting SDK | SDK queried content providers for device info, installed app list, and location data |
| [Triada](../malware/families/triada.md) | System-level abuse | Pre-installed in firmware, accessed content providers with system-level permissions |
| [SpyNote](../malware/families/spynote.md) | Data exfiltration | Queries SMS, contacts, and call log content providers after obtaining permissions |

Content provider attacks are more commonly exploited in app-to-app vulnerability research than in malware. [Oversecured's research](https://blog.oversecured.com/Android-Access-to-app-protected-components/) has documented these vulnerabilities across Google, Samsung, TikTok, and banking applications.

## Detection During Analysis

??? example "Static Indicators"

    - Providers with `android:exported="true"` and no `android:readPermission`/`android:writePermission`
    - `openFile()` implementations without path validation
    - Raw SQL concatenation in `query()`, `update()`, `delete()` methods
    - `grantUriPermissions="true"` with broad `path-pattern`
    - `FileProvider` paths including `root-path` or broad `external-path`
    - `res/xml/file_paths.xml` or `provider_paths.xml` for FileProvider configuration

??? example "Dynamic Indicators"

    - [Drozer](https://github.com/WithSecureLabs/drozer) enumeration of exported content providers
    - Unexpected data returned from provider queries by third-party apps
    - Path traversal attempts via `openFile()` returning files outside intended directory
    - URI grant escalation via `FLAG_GRANT_READ_URI_PERMISSION`

### Vendor-Specific Content Provider Vulnerabilities

OEM customizations introduce content provider attack surface beyond AOSP. [Oversecured's Samsung research](https://blog.oversecured.com/Two-weeks-of-securing-Samsung-devices-Part-2/) found SMS/MMS database access via path traversal using `Uri.getLastPathSegment()`, and a content provider in `com.sec.imsservice` exposing arbitrary files. [Oversecured's Xiaomi research](https://blog.oversecured.com/20-Security-Issues-Found-in-Xiaomi-Devices/) documented 20 security issues including multiple content provider access vulnerabilities in Xiaomi system apps. [Oversecured's methodology guide for vendor-specific vulnerabilities](https://blog.oversecured.com/Discovering-vendor-specific-vulnerabilities-in-Android/) covers how to systematically analyze OEM modifications for content provider exposure beyond stock Android.

## Chained Attacks

Content provider vulnerabilities are frequently the second stage in multi-step attack chains:

1. **Intent redirection to content provider access**: Force an app to launch an internal activity via intent redirection, then exploit that activity's access to content providers. [Oversecured's dynamic code loading research](https://blog.oversecured.com/Why-dynamic-code-loading-could-be-dangerous-for-your-apps-a-Google-example/) demonstrated this chain: intent redirection gave access to a vulnerable content provider, which allowed writing an arbitrary Google Play Core library module, resulting in persistent local code execution.

2. **Content provider to WebView exploitation**: Access file-based content providers to inject content into WebViews. [Oversecured's TikTok research](https://blog.oversecured.com/Oversecured-detects-dangerous-vulnerabilities-in-the-TikTok-Android-app/) found 4 high-severity vulnerabilities including 3 persistent arbitrary code execution paths through this type of chain.
