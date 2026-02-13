# Predatory Lending Apps (SpyLoan)

Apps offering quick microloans that demand excessive permissions, then weaponize collected data for extortion when borrowers cannot repay. Detailed technical analysis in the dedicated family page: [SpyLoan](../malware/families/spyloan.md).

## Business Model

1. Target users in regions with limited formal banking access (India, Southeast Asia, Latin America, Africa)
2. Offer instant loan approval through Google Play apps with polished UI
3. Request [contacts](../permissions/contacts/read-contacts.md), [camera](../permissions/camera/camera.md), [SMS](../permissions/sms/read-sms.md), [location](../permissions/location/access-fine-location.md), [storage](../permissions/storage/read-external-storage.md) during "verification"
4. Approve microloans at 300-500% APR with hidden fees
5. When borrowers miss payments: contact their entire phone book with threatening messages, share personal photos, send fake legal notices to employers
6. Data exfiltration begins immediately on permission grant, retained server-side even if app is uninstalled

## Scale and Impact

Google removed 2000+ SpyLoan apps from Play Store between 2023 and 2024. Targeting concentrates in India, Philippines, Indonesia, Kenya, Nigeria, Mexico, and Colombia. Documented suicide cases linked to SpyLoan harassment campaigns in India, the Philippines, and Kenya. McAfee reported a 75% increase in SpyLoan infections between Q2 and Q3 2024.
