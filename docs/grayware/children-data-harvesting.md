# Children's App Data Harvesting

Children's apps represent a high-value target for data harvesting SDKs because children cannot meaningfully consent, parents are rarely informed, and the apps are free (monetized entirely through data extraction).

## COPPA Violation Scale

A [landmark 2018 study by ICSI Berkeley researchers](https://petsymposium.org/2018/files/papers/issue3/popets-2018-0021.pdf) ("Won't Somebody Think of the Children?") analyzed 5,855 of the most popular free children's apps on Google Play:

| Finding | Percentage |
|---------|-----------|
| Apps potentially violating COPPA | 57% |
| Apps sharing persistent identifiers against Google ToS | 39% (2,281 apps) |
| Apps collecting PII via SDKs whose own terms prohibit use in children's apps | 19% |
| Apps harvesting location or contact data without parental consent | 5% |

1,280 children's apps contained the Facebook SDK. 318 transmitted data to Kochava (attribution/ad measurement provider). Most apps with COPPA-compliant SDK options either did not enable them or incorrectly propagated settings across mediation SDKs.

## Enforcement

**"Operation Child Tracker"** (2016): [New York AG investigation](https://ag.ny.gov/press-release/2016/ag-schneiderman-announces-results-operation-child-tracker-ending-illegal-online) targeting Viacom ($500,000), Mattel ($250,000), JumpStart ($85,000), and Hasbro for tracking children's online activity illegally through their apps (Nick Jr., Barbie, Hot Wheels, Neopets). Combined penalties: $835,000.

**Disney/Viacom class action**: SDK companies named as defendants included AdColony, Chartboost, Flurry, InMobi, ironSource, Tapjoy, Vungle, Unity Technologies, Comscore, and Upsight -- all for placing tracking software in children's apps. [Settled in 2020](https://www.lieffcabraser.com/2020/08/proposed-settlement-reached-in-disney-and-viacom-child-privacy-violation-lawsuits/).

**FTC v. Disney** (2025): [$10 million civil penalty](https://www.ftc.gov/news-events/news/press-releases/2025/12/court-approves-order-requiring-disney-pay-10-million-settle-ftc-allegations-firm-enabled-unlawful) for failing to properly label child-directed YouTube videos, enabling YouTube to collect children's personal data for targeted advertising.

[Tekya malware](https://research.checkpoint.com/2020/google-play-store-played-again-tekya-clicker-hides-in-24-childrens-games-and-32-utility-apps/) (2020, Check Point) infected 56 Google Play apps with over 1 million combined downloads. 24 of the infected apps were children's games. The ad fraud clicker used native code (`MotionEvent` API) to simulate user taps on ads.
