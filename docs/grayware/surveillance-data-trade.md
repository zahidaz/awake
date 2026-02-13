# Surveillance & Data Trade

The programmatic advertising ecosystem, government procurement channels, and data broker marketplaces form a surveillance supply chain that operates entirely within legal boundaries in most jurisdictions. Data flows from mobile devices through ad auctions and SDK pipelines into the hands of intelligence agencies, law enforcement, and commercial buyers at industrial scale.

## Real-Time Bidding as Surveillance

The programmatic advertising ecosystem leaks granular user data at industrial scale -- not through SDK abuse, but through the normal functioning of the ad auction system. Every time an ad loads in an Android app, the device broadcasts a bid request containing device identifiers, GPS coordinates, IP address, app name, device model, carrier information, and more. This data reaches hundreds of demand-side platforms (DSPs) in milliseconds, most of which do not win the auction but retain the data.

### How RTB Data Leaks Work

The [OpenRTB protocol](https://www.iab.com/guidelines/openrtb/) defines the bid request format. When an app displays an ad, the supply-side platform (SSP) sends a bid request to potentially hundreds of DSPs. Each bid request contains:

| Field | Data | Privacy Impact |
|-------|------|---------------|
| `device.geo.lat/lon` | GPS coordinates (often to 6 decimal places) | Meter-level location tracking |
| `device.ifa` | Advertising ID (GAID/IDFA) | Persistent cross-app identifier |
| `device.ip` | IP address | Approximate location, ISP identification |
| `device.model` | Device model + manufacturer | Device fingerprinting |
| `device.carrier` | Mobile carrier name | Network identification |
| `app.bundle` | App package name | Activity inference (health, dating, political apps) |
| `user.data` | Interest segments, demographics | Behavioral profiling |

The [Irish Council for Civil Liberties (ICCL) reported](https://www.iccl.ie/digital-data/new-data-on-the-scale-of-real-time-bidding-data-broadcasts-in-the-us-and-europe/) that US users' online activity and location are broadcast 747 times per day on average through RTB, and European users 376 times per day. This data reaches thousands of companies per broadcast.

### Intelligence Agencies Buying Bid Stream Data

RTB data is commercially available for purchase without a warrant. [Senator Ron Wyden's investigation](https://www.wyden.senate.gov/news/press-releases/wyden-reveals-nsa-purchase-of-americans-internet-metadata-and-phone-location-data-demand-intelligence-community-report-on-data-purchases) confirmed that the NSA purchased internet metadata and phone location data commercially. The data pipeline enables what privacy researchers call a "Fourth Amendment workaround" -- agencies buy commercially what they would need a warrant to collect directly.

**Rayzone Group** (Israel): Operates a DSP called "Echo" that participates in RTB auctions not to buy ads, but to harvest bid stream data for surveillance purposes. [Revealed by Haaretz in 2020](https://www.haaretz.com/israel-news/security-aviation/2020-10-07/ty-article-magazine/.premium/israeli-spy-tech-firm-tapped-global-phone-network-to-track-persons-of-interest/0000017f-e1bb-d97e-a37f-f3bb98750000), Rayzone could geolocate any device whose apps participate in RTB auctions.

**Intellexa "Aladdin"**: [Leaked internal documents from the December 2025 Intellexa breach](https://blog.talosintelligence.com/intellexa-and-cytrox-intel-agency-grade-spyware/) revealed a system called Aladdin that uses the ad ecosystem to deliver zero-click spyware infections. The system places a "bid" in the ad auction, wins, and delivers an exploit payload disguised as ad creative. This weaponizes the entire RTB infrastructure as a spyware delivery mechanism.

## Government Purchases of Location Data

Government agencies purchase commercially available location data from brokers, bypassing the warrant requirements established in [Carpenter v. United States (2018)](https://www.supremecourt.gov/opinions/17pdf/16-402_h315.pdf) where the Supreme Court ruled that accessing historical cell-site location records requires a warrant.

| Agency / Company | Data Source | Scale | Source |
|-------------------|-----------|-------|--------|
| [Fog Data Science](https://www.eff.org/deeplinks/2022/08/fog-revealed-new-tool-mass-surveillance) | Commercial apps via brokers | Billions of data points, sold to 18+ US law enforcement agencies | [EFF](https://www.eff.org/deeplinks/2022/08/fog-revealed-new-tool-mass-surveillance), [AP](https://apnews.com/article/technology-police-government-surveillance-d395409ef5a8c6c3f6cdab5b2e79e09d) |
| Venntel (Gravy Analytics subsidiary) | Location data brokers | Sold to IRS-CI, CBP, ICE | [WSJ](https://www.wsj.com/articles/federal-agencies-use-cellphone-location-data-for-immigration-enforcement-11581078600) |
| [Babel Street / Locate X](https://www.eff.org/deeplinks/2023/01/how-government-uses-babel-streets-locate-x) | Ad ecosystem location data | Used by DHS, CBP, Secret Service | [EFF](https://www.eff.org/deeplinks/2023/01/how-government-uses-babel-streets-locate-x) |
| NSA | Internet metadata + phone location | Bulk purchasing confirmed by Wyden inquiry | [Wyden press release](https://www.wyden.senate.gov/news/press-releases/wyden-reveals-nsa-purchase-of-americans-internet-metadata-and-phone-location-data-demand-intelligence-community-report-on-data-purchases) |

Fog Data Science is notable for its low price point: [subscriptions start under $10,000](https://www.eff.org/deeplinks/2022/08/fog-revealed-new-tool-mass-surveillance), making mass surveillance accessible to local police departments. The [Wyden letter to DOJ](https://www.wyden.senate.gov/imo/media/doc/wyden_letter_to_doj_on_smartphone_surveillance.pdf) questioned whether these purchases constitute a Fourth Amendment workaround, but no court has definitively ruled on the practice.

## Data Broker Industry Economics

### Market Size

The global data broker market was estimated at [USD 278 billion in 2024](https://www.grandviewresearch.com/industry-analysis/data-broker-market-report), projected to reach USD 512 billion by 2033 at 7.3% CAGR. North America holds 41.2% revenue share. Mobile apps and SDKs account for [35.74% of data acquisition](https://www.knowledge-sourcing.com/report/global-data-broker-market). An estimated 5,000 data brokers operate globally.

### The Supply Chain

```
App SDK → Aggregator → Data Broker → Buyer
(device)   (Gravy)     (Venntel)    (gov, advertiser, hedge fund)
```

Per-device revenue for app developers: $0.01-$0.05 per device per month for location data. The average cost of an individual data profile (ages 18-25): $0.36. Fog Data Science law enforcement subscriptions start under $10,000 -- making mass surveillance accessible to local police.

### Major Consolidation Events

**Oracle's data broker empire (built 2014-2018, collapsed 2024)**: Oracle acquired [BlueKai (~$400M, 2014)](https://www.oracle.com/corporate/pressrelease/oracle-buys-bluekai-022414.html), Datalogix (~$1.2B, 2014), and AddThis for web tracking. Combined Oracle Advertising revenue peaked at $2B (2022). [GDPR enforcement destroyed the model](https://www.adexchanger.com/marketers/inside-the-fall-of-oracles-advertising-business/) -- BlueKai lost 85% of European revenue overnight. Facebook pulled its third-party data marketplace. [Oracle exited advertising entirely as of October 2024](https://www.theregister.com/2024/06/13/oracle_online_ads/), revenue having fallen to $300M.

**Foursquare** acquired Placed (attribution) and Factual (location data), consolidating location intelligence under one roof.

The Gravy Analytics hack (January 2025) exposed the fragility of the entire ecosystem: a single compromised key to an Amazon cloud environment potentially exposed 17 terabytes of location data including coordinates at the White House, the Kremlin, Vatican City, and military bases worldwide.
