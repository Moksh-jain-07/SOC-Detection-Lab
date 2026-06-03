# Incident Report — Encoded PowerShell Execution

## Incident Summary

| Field | Detail |
|-------|--------|
| Date | 29 May 2026 |
| Time | 19:11 |
| Severity | High |
| MITRE Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Status | Investigated |
| Host | LAPTOP-NNIC5EOM |

---

## What Happened

During attack simulation using Atomic Red Team, PowerShell was executed with encoded command arguments. The `-EncodedCommand` and `-enc` flags were used to pass base64-encoded payloads, which is a standard obfuscation technique used by threat actors to hide malicious scripts from basic string matching and antivirus signatures.

---

## Detection

The alert **Encoded PowerShell Detected** triggered in Splunk after the attack ran.

**SPL query that caught it:**
```spl
index=soc-lab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<EventID>(?<EventID>[^<]+)"
| where EventID="1" AND (like(CommandLine, "%-enc%") OR like(CommandLine, "%EncodedCommand%"))
| table _time, Image, CommandLine
| sort -_time
```

---

## Evidence

**Event 1:**
- Time: 2026-05-29 19:11:21.202
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine: `"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop}`

**Event 2:**
- Time: 2026-05-29 19:11:21.541
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine: `"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -UseEncodedArguments -EncodedArgumentsParamVariation EncodedArguments -Execute -ErrorAction Stop}`

---

## Timeline

| Time | Event |
|------|-------|
| 19:11:21 | powershell.exe launched with -EncodedCommand flag |
| 19:11:21 | Sysmon Event ID 1 generated |
| 19:11:22 | Splunk alert triggered |

---

## Analysis

The use of `-EncodedCommand` is a well-known living-off-the-land technique. Attackers base64-encode their payloads so that:
- Basic keyword filtering (like looking for "malware" in the command line) won't catch it
- The actual payload is hidden from casual inspection
- It bypasses some AV signatures that look for specific strings

This does not necessarily mean the payload itself is malicious — some legitimate tools use encoded commands — but it is suspicious enough to always investigate.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Process | powershell.exe |
| CommandLine flag | -enc, -EncodedCommand, -EncodedArguments |
| Sysmon Event ID | 1 |

---

## Remediation

1. Investigate what the decoded payload actually does
2. Check if the process spawned any child processes
3. Check for network connections from powershell.exe
4. If confirmed malicious — isolate the host and reset credentials
5. Consider enabling PowerShell Script Block Logging for better visibility

---

## Lessons Learned

- Encoded PowerShell is easy to detect at the process creation level using Sysmon
- The actual command line is still logged even when encoded — the `-enc` flag itself is visible
- Script Block Logging would give even better visibility into what the decoded payload does
