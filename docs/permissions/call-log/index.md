# Call Log Permissions

Access to the device's call history database. Call logs expose who the user communicates with, when, how often, and for how long. Valuable for spyware operators conducting surveillance, social graph mapping, and building behavioral profiles. Heavily restricted by Google Play since January 2019.

## Permissions

| Permission | Abuse Potential |
|-----------|-----------------|
| [READ_CALL_LOG](read-call-log.md) | Read complete call history: numbers, timestamps, duration, call type |
| [WRITE_CALL_LOG](write-call-log.md) | Insert or delete call records, cover tracks after malicious calls |
| [PROCESS_OUTGOING_CALLS](process-outgoing-calls.md) | Intercept outgoing calls, redirect to attacker-controlled numbers |

## Why Call Logs Matter Offensively

Call history provides a structured communication timeline. Unlike contacts (which are static), call logs show active relationships: who the target actually talks to, how frequently, and when. This data enables:

- **Social graph mapping**: identify close contacts by call frequency and duration
- **Behavioral profiling**: establish daily patterns, working hours, travel (via timezone-shifted calling patterns)
- **Contact discovery**: phone numbers in call logs may not exist in the contacts database
- **Surveillance verification**: confirm whether a target communicated with a specific number
- **Correlation attacks**: cross-reference call logs from multiple compromised devices to map networks

## Play Store Policy

Since January 2019, Google restricts Call Log permissions to apps declared as the default dialer or that have an approved use case (call screening, caller ID). Apps that cannot justify the need are rejected from Play Store.

This policy change pushed call log-stealing malware toward:

- Distribution via sideloading and third-party stores
- Using accessibility services to read call information from the screen instead
- Using notification listener to capture incoming call notifications
- Targeting pre-2019 devices where the restriction does not apply

## Common Permission Combinations

| Combination | Purpose |
|------------|---------|
| `READ_CALL_LOG` + `READ_CONTACTS` | Full communication graph: who the target knows and who they actually talk to |
| `READ_CALL_LOG` + `READ_SMS` | Complete communication surveillance across channels |
| `READ_CALL_LOG` + `INTERNET` | Call history exfiltration to C2 |
| `WRITE_CALL_LOG` + `CALL_PHONE` | Make calls and erase evidence from the log |
