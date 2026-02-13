# Advertising Fraud

Apps that generate fake ad impressions, clicks, or installs in the background to steal advertising revenue. Not data theft but device abuse at the expense of battery, bandwidth, and advertiser budgets.

## Fraud Types

| Type | Mechanism | Detection Signal |
|------|-----------|-----------------|
| Click injection | Listens for `PACKAGE_ADDED` broadcast, injects attribution click before new app finishes installing | `PACKAGE_ADDED` receiver + immediate HTTP request to attribution URL |
| Ad stacking | Multiple invisible ads loaded behind a single visible ad | Multiple ad SDK network calls per visible impression |
| Pixel stuffing | Ads loaded in 1x1 pixel containers, invisible to user | Tiny WebView or ImageView with ad network traffic |
| Background ad rendering | Hidden [WebView](../attacks/webview-exploitation.md) loads and "views" ads with screen off | WebView activity without corresponding UI, battery drain |
| Click flooding | Mass generation of fake ad clicks to poison attribution data | High-volume HTTP requests to ad tracking endpoints |
| SDK spoofing | Forge ad impressions by replaying legitimate SDK traffic patterns | Network traffic mimicking ad SDK protocols without actual ad display |

## Notable Cases

**Grabos** (2017): [McAfee discovered 144 trojanized apps on Google Play](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-grabos-exposed-millions-to-pay-per-install-scam-on-google-play/) running a pay-per-install scam. First found in "Aristotle Music audio player 2017," 34 analyzed apps had an average 4.4 rating with 4.2-17.5M downloads. A commercial obfuscator protected the malicious code, making it difficult to detect without runtime analysis.

**Chamois** (2017-2019): Google-discovered ad fraud botnet pre-installed in firmware on 21M+ devices. Operated through the supply chain, with malicious code embedded during manufacturing. Generated fraudulent ad revenue through background ad clicks and premium SMS.

**Judy** (2017): Ad click malware in 41 apps from a Korean developer on Google Play. Used a C2 server to deliver JavaScript payloads that clicked ads via WebView. Estimated 8.5M-36.5M infected devices.

**DrainerBot** (2019): SDK embedded in 10M+ downloads that downloaded video ads in the background, consuming 10GB+ of mobile data per month per device. Users experienced massive data charges and battery drain with no visible cause.

**LeifAccess** (2019): [McAfee documented a trojan](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-leifaccess-a-is-the-silent-fake-reviewer-trojan/) abusing accessibility services to post fake Google Play reviews and simulate legitimate ad clicks. Loaded ads via floating overlays and direct ad-network links, combining ad fraud with review manipulation.

**Tekya** (2020): Auto-clicker malware in 56 Google Play apps (24 children's apps). Used `MotionEvent` API to simulate legitimate ad clicks. Check Point documented the use of Android's `MotionEvent.obtain()` to generate touch events programmatically.

**HiddenAds** (2020-2022): [McAfee tracked multiple HiddenAds campaigns](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-hiddenads-malware-that-runs-automatically-and-hides-on-google-play-1m-users-affected/) affecting 1M+ users via Google Play cleaner apps. The malware ran malicious ad services automatically on installation without requiring user launch, then [changed its icon to the Google Play icon](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/hiddenads-spread-via-android-gaming-apps-on-google-play/) and renamed itself "Google Play" or "Setting" to hide from the user. A separate campaign infected 38 games reaching 35M+ users.

**Clicker** (2022): [McAfee found 16 clicker apps on Google Play with 20M+ combined downloads](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-malicious-clicker-found-in-apps-installed-by-20m-users/) using the `com.click.cas` and `com.liveposting` libraries. The malware delayed activation by over an hour after installation and paused when the user was actively using the device, making detection through manual testing nearly impossible.

**Invisible Adware** (2023): [McAfee uncovered 43 apps on Google Play](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/invisible-adware-unveiling-ad-fraud-targeting-android-users/) with 2.5M downloads that loaded ads only when the device screen was off. The apps waited multiple weeks after installation before activating and requested "power saving exclusion" and "draw over other apps" permissions to maintain background execution.

## Technical Indicators

- `PACKAGE_ADDED` broadcast receiver (click injection vector)
- `MotionEvent.obtain()` or `dispatchTouchEvent()` calls without user interaction
- Hidden or zero-dimension `WebView` instances
- Abnormal battery drain and background data consumption
- Ad SDK network traffic volume disproportionate to app usage
- Wake locks held during screen-off periods for background rendering

## Notification & Ad Injection

Apps that monetize by injecting ads outside their own UI context -- into the notification shade, lock screen, or as system-level overlays.

| Technique | Implementation | Android Restrictions |
|-----------|---------------|---------------------|
| Notification ads | High-priority notifications with ad content, mimicking system alerts | Android 8.0+ notification channels; Android 13+ `POST_NOTIFICATIONS` permission |
| Lock screen ads | Custom lock screen replacement or overlay drawn via `SYSTEM_ALERT_WINDOW` | Android 6.0+ requires explicit grant; Android 10+ overlay touch restrictions |
| Full-screen interstitials | `SYSTEM_ALERT_WINDOW` overlays triggered on screen unlock or app switch | Android 12+ overlay deprioritization |
| Foreground service notifications | Persistent notification used as ad surface under the guise of "running service" | Android 14+ foreground service type declarations |

[HiddenAds](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-hiddenads-malware-that-runs-automatically-and-hides-on-google-play-1m-users-affected/) campaigns changed their app icon to the Google Play icon and renamed themselves "Google Play" or "Setting" to hide from users while delivering persistent ads. [Invisible Adware](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/invisible-adware-unveiling-ad-fraud-targeting-android-users/) (2023, 43 apps, 2.5M downloads) loaded ads only when the device screen was off, waiting multiple weeks after installation before activating.

## Fleeceware

Apps that exploit free trial mechanics and subscription billing to charge excessive fees for minimal functionality.

### Pattern

1. Offer a "free trial" (typically 3 days) requiring payment method entry
2. Auto-renew at $30-$200/week for commodity functionality (flashlight, QR scanner, wallpaper, horoscope)
3. Make cancellation deliberately confusing: uninstalling the app does not cancel the subscription
4. Target users unfamiliar with app store subscription management
5. Use misleading UI that obscures the subscription cost or implies the trial is truly free

### Scale

Avast identified 200+ fleeceware apps with 1B+ combined downloads in 2020. Sophos coined the term "fleeceware" in 2019 after finding apps charging $100+/month for basic calculator and QR scanner functionality. Apple and Google have both tightened trial disclosure requirements in response, but enforcement remains inconsistent.

### Technical Indicators

- Short trial period (1-3 days) followed by high weekly/monthly charge
- Minimal app functionality relative to subscription cost
- Subscription initiation flow that obscures pricing
- In-app purchase / subscription APIs invoked immediately during onboarding
- No meaningful feature gating between free and paid tiers
