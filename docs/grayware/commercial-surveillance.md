# Commercial Surveillance Vendor Market

Commercial spyware sold to governments occupies the extreme end of the grayware spectrum: technically legal under the laws of the selling country, marketed as law enforcement tools, but routinely deployed against journalists, dissidents, and opposition politicians. These vendors' Android implants are the most sophisticated malware in the wild.

## Vendors and Pricing

| Vendor | Product | Pricing | Status | Source |
|--------|---------|---------|--------|--------|
| NSO Group (Israel) | [Pegasus](../malware/families/pegasus.md) | [$500K setup + $650K per 10 targets](https://prodefence.io/news/pegasus-spyware-operating-costs-complete-financial-breakdown); Ghana deployment: $8M | US Entity List (Nov 2021) | [Commerce Dept.](https://www.bis.gov/press-release/commerce-adds-nso-group-other-foreign-companies-entity-list-malicious-cyber-activities) |
| Intellexa/Cytrox | [Predator](../malware/families/predator.md) | [EUR 8-13.6M per deployment](https://blog.talosintelligence.com/intellexa-and-cytrox-intel-agency-grade-spyware/) | US Entity List (Jul 2023), Treasury sanctions (Mar + Sep 2024) | [Treasury](https://home.treasury.gov/news/press-releases/jy2155) |
| Candiru (Israel) | DevilsTongue | Unknown | US Entity List (Nov 2021) | [Kaspersky](https://www.kaspersky.com/blog/commercial-spyware/50813/) |
| QuaDream (Israel) | REIGN | Unknown | Shut down Apr 2023 after Citizen Lab/Microsoft exposure | [Citizen Lab](https://citizenlab.ca/2023/04/spyware-vendor-quadream-exploits-victims-customers/) |
| Paragon (Israel) | Graphite | Unknown | Active; severed Italian government contract after exposure | [Citizen Lab](https://citizenlab.ca/research/a-first-look-at-paragons-proliferating-spyware-operations/) |
| Variston IT (Spain) | Heliconia | Unknown | [Exposed by Google TAG Nov 2022](https://blog.google/threat-analysis-group/new-details-on-commercial-spyware-vendor-variston/) | Chrome, Firefox, Windows Defender exploits |
| RCS Lab (Italy) | [Hermit](../malware/families/hermit.md) | Unknown | Active | [Lookout](https://www.lookout.com/threat-intelligence/article/hermit-spyware-discovery) |

Sales are typically limited to a single phone country code prefix, with additional countries available for extra fees. Annual maintenance runs 17-22% of the system cost.

## International Response

The [Pall Mall Process](https://www.gov.uk/government/publications/the-pall-mall-process-declaration-tackling-proliferation-and-irresponsible-use-of-commercial-cyber-intrusion-capabilities) (February 2024): 35 nations convened at Lancaster House, London, establishing guiding principles on commercial spyware. A Code of Practice was agreed in April 2025. US Entity List additions have had limited practical impact -- Intellexa continued operations despite sanctions. Paragon's January 2025 WhatsApp zero-click campaign [targeting ~90 accounts](https://www.securityweek.com/paragon-graphite-spyware-linked-to-zero-click-hacks-on-newest-iphones/) (including journalists) occurred while the company was ostensibly "responsible" under its own ethical framework.
