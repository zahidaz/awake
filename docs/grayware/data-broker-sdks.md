# Data Broker SDKs

Third-party SDKs embedded in otherwise legitimate apps that silently collect and sell user data. The app developer integrates the SDK in exchange for per-device-per-month payments. The SDK harvests device data in the background. The data flows to brokers, advertisers, and in documented cases, government agencies.

## How SDK Monetization Works

1. SDK vendor approaches app developer with monetization offer
2. Developer integrates SDK (usually a few lines in Gradle + manifest entries)
3. SDK activates on app launch, begins collecting permitted data
4. Data uploaded to SDK vendor's servers on a schedule or in real time
5. Vendor aggregates data across all apps embedding their SDK
6. Aggregated datasets sold to data brokers, analytics firms, advertisers, and government contractors
7. Developer receives payment based on active device count (typically $0.01-$0.05 per device per month)

## What They Collect

| Data Type | Method | Notes |
|-----------|--------|-------|
| GPS location (continuous) | `ACCESS_FINE_LOCATION` / `ACCESS_BACKGROUND_LOCATION` | High-frequency polling, often every few minutes |
| WiFi SSIDs and BSSIDs | WiFi scan APIs | Enables indoor positioning and location inference without GPS |
| Bluetooth beacons | Bluetooth scan APIs | Proximity detection, retail analytics |
| Installed apps list | `QUERY_ALL_PACKAGES` or `PackageManager` | App usage profiling, interest inference |
| Device identifiers | AAID, IMEI (pre-Android 10), MAID | Cross-app and cross-device tracking |
| Contacts | `READ_CONTACTS` | Social graph mapping |
| Accelerometer / gyroscope | Sensor APIs | Activity recognition, transport mode detection |
| Browsing history | Accessibility service or custom browser SDK | Interest profiling |

## Documented Cases

**X-Mode (now Outlogic)**: Collected location data from 400+ apps including Muslim prayer apps (Muslim Pro, Muslim Mingle) and dating apps. Data sold to US military contractors and defense agencies. [The Wall Street Journal exposed the pipeline](https://www.wsj.com/articles/u-s-military-buys-location-data-harvested-from-popular-apps-11604516406) in 2020. Google and Apple required X-Mode removal from all apps in early 2021. X-Mode rebranded to Outlogic and was acquired by Digital Envoy. [FTC banned X-Mode from selling sensitive location data](https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-prohibits-data-broker-x-mode-social-outlogic-selling-sensitive-location-data) in January 2024.

**Measurement Systems SDK**: [Discovered by AppCensus researchers](https://www.appcensus.io/blog/2022/04/06/the-google-play-data-safety-section) in 60M+ downloads across weather apps, highway radar apps, QR scanners, and religious apps. The SDK collected phone numbers, email addresses, exact location, nearby WiFi and Bluetooth device information, and clipboard contents. Registered to a Virginia company (Vostrom Holdings) linked to a US defense contractor ([Packet Forensics](https://www.theregister.com/2022/04/07/google_boots_data_harvesting_code/)) with a history of selling lawful intercept equipment to governments. Google removed the SDK from Play Store in April 2022, but some apps reintegrated it later.

**Patternz**: Israeli surveillance company (run by ISA, Nuviad's parent) using SDK data from popular apps for intelligence purposes. Patternz's pitch deck claimed access to data from 600,000 apps, enabling tracking of nearly any mobile user globally. ISA operated a legitimate ad network (Nuviad) that served as the data collection front. The system exploited the [real-time bidding ad ecosystem](surveillance-data-trade.md) to harvest device data without embedding SDKs directly.

**Predicio / Gravy Analytics**: French data broker Predicio and US-based Gravy Analytics collected location data through SDK partnerships and the real-time bidding (RTB) ad ecosystem. [Gravy Analytics was hacked in January 2025](https://techcrunch.com/2025/01/13/gravy-analytics-data-broker-breach-trove-of-location-data-threatens-privacy-millions/), exposing location data for millions of devices globally. The hacker posted a 1.4 GB fragment containing approximately 30 million records, claiming the full stolen database was 17 terabytes (potentially 200+ billion records). The leaked data included coordinates from apps like Tinder, Grindr, Candy Crush, and various pregnancy tracking apps, with [researchers able to track individuals from workplaces to their homes](https://www.404media.co/hackers-claim-massive-breach-of-location-data-giant-threaten-to-leak-data/).

## SDK Identification

When analyzing a suspect app, identify embedded SDKs through:

| Indicator | Location |
|-----------|----------|
| Package names | `com.xmode.sdk`, `io.huq`, `com.cuebiq`, `com.safegraph`, `com.predicio`, `com.tutela`, `com.measurementsys` |
| Manifest receivers/services | Look for services not attributable to the app's core functionality |
| Network traffic | Connections to `api.xmode.io`, `sdk.huq.io`, `ingest.cuebiq.com`, known broker endpoints |
| Gradle dependencies | Check `build.gradle` for SDK artifact references |
| String artifacts | API keys, SDK initialization tokens in resources or `BuildConfig` |
