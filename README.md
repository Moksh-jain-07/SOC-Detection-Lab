# SOC Detection Lab

## Overview

This project is a hands-on SOC Detection Lab built using Splunk, Sysmon, and Atomic Red Team to simulate, detect, and investigate real cyber attacks in a controlled Windows environment.

The lab focuses on:
- SIEM monitoring and log analysis
- Windows telemetry collection using Sysmon
- Detection engineering with custom SPL queries
- MITRE ATT&CK mapped attack simulations
- Incident response documentation
- Real-time alerting in Splunk

The goal of this project was to get practical experience doing the kind of work a Tier 1/2 SOC analyst does on a daily basis — ingesting logs, hunting for threats, writing detections, and investigating alerts — rather than just reading about it.

---

## Architecture

```
Windows 10 (Local Machine)
        ↓
   Sysmon (SwiftOnSecurity Config)
        ↓
   Splunk Universal Forwarder
        ↓
   Splunk Enterprise (SIEM)
        ↓
   Detections → Alerts → Dashboard
```

> See `Architecture/architecture.png` for a visual diagram.

---

## Technologies Used

| Tool | Version | Purpose |
|------|---------|---------|
| Splunk Enterprise | Free Trial | SIEM — log ingestion, search, alerting, dashboards |
| Sysmon | Latest | Windows telemetry — process, registry, network events |
| Splunk Universal Forwarder | Latest | Ships Windows logs to Splunk |
| Atomic Red Team | Latest | MITRE ATT&CK attack simulation framework |
| Windows 10 | Local machine | Target environment |
| PowerShell | v5.1 | Attack execution and lab configuration |
| MITRE ATT&CK Framework | — | Attack classification and detection mapping |

---

## Features

- Centralized Windows log collection (Sysmon + Security + PowerShell logs)
- Sysmon telemetry with SwiftOnSecurity configuration
- Splunk SIEM integration via Universal Forwarder
- 4 attack simulations using Atomic Red Team
- MITRE ATT&CK mapped detections
- Custom SPL queries with XML field extraction
- Real-time alerts with High severity triggering
- SOC-style threat detection dashboard
- Incident reports for each attack

---

## Lab Setup Summary

| Component | Detail |
|-----------|--------|
| Splunk Index | soc-lab |
| Receiving Port | 9997 |
| Sysmon Config | SwiftOnSecurity sysmonconfig.xml |
| Log Sources | Sysmon/Operational, Security, PowerShell/Operational |
| Forwarder Service Account | LocalSystem (required for Sysmon log access) |

> Full setup instructions in `Docs/setup-guide.md`

---

## Simulated Attacks

| Attack | MITRE ID | Tool | Result |
|--------|----------|------|--------|
| Encoded PowerShell Execution | T1059.001 | Atomic Red Team | Detected ✅ |
| Scheduled Task Persistence | T1053.005 | Atomic Red Team | Detected ✅ |
| Registry Run Key Persistence | T1547.001 | Atomic Red Team | Detected ✅ |
| Brute Force Login Attempts | T1110.001 | Atomic Red Team | Detected ✅ |

> Full attack documentation in `AtomicRedTeam/attack-tests.md`

---

## Detection Rules

All detections use Sysmon Event IDs and Windows Security logs. Custom SPL queries with `rex` field extraction were written because XmlWinEventLog format requires manual parsing.

### Key Sysmon Event IDs Used

| Event ID | Meaning |
|----------|---------|
| 1 | Process Creation |
| 13 | Registry Value Set |

### Sample Detection — Encoded PowerShell (T1059.001)

```spl
index=soc-lab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<EventID>(?<EventID>[^<]+)"
| where EventID="1" AND (like(CommandLine, "%-enc%") OR like(CommandLine, "%EncodedCommand%"))
| table _time, Image, CommandLine
| sort -_time
```

**What it detects:** PowerShell processes launched with encoded commands — a common obfuscation technique used by attackers to hide malicious payloads.

> All 4 detection queries in `Splunk/detections/`

---

## Alerts

4 real-time alerts were created in Splunk, each set to trigger when results are greater than 0:

| Alert Name | Severity | Type |
|------------|----------|------|
| Encoded PowerShell Detected | High | Real-time |
| Scheduled Task Persistence Detected | High | Real-time |
| Registry Persistence Detected | High | Real-time |
| Brute Force Login Detected | High | Real-time |

---

## Dashboard

Built a SOC monitoring dashboard called **SOC Lab - Threat Detection** in Splunk with all 4 detection panels in a single view.

> See `Screenshots/09_dashboard.png`

---

## Incident Reports

| Report | File |
|--------|------|
| Encoded PowerShell Investigation | `Incident-Reports/powershell_attack.md` |
| Persistence Techniques Investigation | `Incident-Reports/persistence.md` |
| Brute Force Login Investigation | `Incident-Reports/failed_logins.md` |

---

## Screenshots

| # | Screenshot |
|---|-----------|
| 1 | Sysmon events in Event Viewer |
| 2 | Security logs flowing into Splunk |
| 3 | Sysmon logs in Splunk after fixing permissions |
| 4 | PowerShell process events detected |
| 5 | Encoded PowerShell attack caught |
| 6 | Scheduled Task persistence caught |
| 7 | Registry Run key modifications caught |
| 8 | Brute force failed logins (EventCode 4625) |
| 9 | Full SOC dashboard with all 4 panels |
| 10 | All 4 alerts active in Splunk |

---

## Challenges & Troubleshooting

**Sysmon logs not forwarding to Splunk**
The Universal Forwarder runs as Network Service by default, which doesn't have read access to the Sysmon event log channel. Fixed by changing the service account to LocalSystem using `sc.exe config SplunkForwarder obj= "LocalSystem"`.

**XML field extraction in SPL**
Sysmon logs ingested as XmlWinEventLog don't auto-parse fields like `CommandLine` or `Image`. Had to write custom `rex` commands to extract them from raw XML.

**Windows Defender blocking Atomic Red Team**
Defender flagged Atomic Red Team as malware during installation. Added folder and process exclusions using `Add-MpPreference` before reinstalling.

---

## Key Learnings

- How a SIEM pipeline works end to end — log generation → forwarding → indexing → alerting
- Writing SPL queries for threat detection using regex field extraction
- How persistence techniques (T1053, T1547) look in Windows event logs
- Windows service permission troubleshooting
- Mapping real attack telemetry to MITRE ATT&CK techniques

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Splunk Documentation](https://docs.splunk.com/)

---

*Built as a self-learning project for SOC Analyst preparation. All attacks were simulated in a controlled local environment on my own machine.*
