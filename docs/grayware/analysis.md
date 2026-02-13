# Analysis Approach

When investigating a sample flagged as PUP, riskware, or suspected grayware:

## Permission Audit

Compare the app's requested permissions against its stated functionality. A weather app requesting [READ_CONTACTS](../permissions/contacts/read-contacts.md) and [READ_SMS](../permissions/sms/read-sms.md) is a red flag. Use the [permissions section](../permissions/index.md) for detailed analysis of each permission's abuse potential.

## Network Traffic Analysis

Intercept outbound connections and look for:

| Signal | Indicates |
|--------|-----------|
| Connections to known data broker domains | SDK-based data harvesting |
| Large POST requests containing device/user data | Data exfiltration |
| Periodic beaconing with device identifiers | Tracking SDK activity |
| Connections to ad networks without visible ads | Ad fraud |
| TLS certificate pinning on non-app-core endpoints | Attempt to hide SDK traffic from analysis |

## SDK Identification

After decompilation, check for embedded third-party SDKs:

| Check | Method |
|-------|--------|
| Package names | Search for known broker SDK package prefixes in smali/classes |
| Manifest components | Services and receivers not attributable to the app's core function |
| String constants | API keys, SDK version strings, initialization tokens |
| Network endpoints | Hardcoded URLs pointing to broker/analytics infrastructure |
| Gradle dependencies | `build.gradle` references to SDK artifacts (if source available) |

## Data Flow Tracking

Trace how permission-protected data moves from acquisition to network transmission:

1. Identify all `ContentResolver.query()` calls for contacts, SMS, call log
2. Follow data through local processing and serialization
3. Identify the network call that transmits the data
4. Determine destination: is it the app's own backend or a third-party SDK endpoint?

## Known Data Broker Domains

Domains associated with data harvesting SDKs, useful for network traffic filtering during analysis.

| Domain Pattern | Associated Entity | Data Type |
|----------------|-------------------|-----------|
| `*.xmode.io` | X-Mode / Outlogic | Location |
| `*.huq.io` | Huq Industries | Location, footfall |
| `*.cuebiq.com` | Cuebiq | Location |
| `*.safegraph.com` | SafeGraph | Location, foot traffic |
| `*.predic.io` | Predicio | Location |
| `*.tutela.com` | Tutela | Network quality + location |
| `*.measurementsys.com` | Measurement Systems | Location, PII, device data |
| `*.placed.com` | Foursquare (Placed) | Location attribution |
| `*.kochava.com` | Kochava | Attribution, device data |
| `*.mxplay.com` | MX Player analytics | Usage, device data |
| `*.gravityinsights.com` | Gravy Analytics | Location |

This list is not exhaustive. New SDKs and broker domains emerge continuously. Cross-reference with AppCensus, Exodus Privacy, and IDAC research for updated indicators.

## Legal Gray Area

Understanding the legal context matters for analysts because it determines how to classify and report findings.

### Enforcement Actions

**FTC vs. SpyFone (2021)**: FTC banned SpyFone and its CEO from the surveillance business, ordered deletion of all collected data. First FTC action banning a company from the stalkerware industry entirely.

**FTC vs. X-Mode / Outlogic (2024)**: FTC banned X-Mode from selling sensitive location data (near medical facilities, religious organizations, domestic violence shelters) and required deletion of previously collected data.

**FTC vs. InMarket (2024)**: FTC settled with data broker InMarket over selling precise geolocation data without informed consent.

**FTC vs. Avast (2024)**: FTC fined Avast $16.5M for selling browsing data collected through its antivirus products and browser extensions via subsidiary Jumpshot.

### Google Play Policy Evolution

Google has progressively restricted data harvesting through Play Store policy changes:

- 2021: Banned X-Mode and similar location SDKs, required disclosure of all SDKs
- 2022: Banned stalkerware distribution, restricted `QUERY_ALL_PACKAGES` usage
- 2023: Expanded data safety section requirements, restricted background location access
- 2024: Further SDK transparency requirements, restricted accessibility service use for non-accessibility purposes

### Why This Matters for Analysts

When a client sends a sample and asks "is this malware?", the answer for grayware requires context beyond technical analysis. An app collecting location data and selling it to brokers is legal in many jurisdictions if disclosed in the privacy policy, regardless of whether users actually read it. The same app collecting the same data and selling it to a military contractor may trigger different legal frameworks. An analyst's job is to document what the app does technically and let the legal and compliance teams determine the classification. The categories on this page help frame the conversation.
