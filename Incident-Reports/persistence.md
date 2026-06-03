# Incident Report — Persistence Techniques

## Incident Summary

| Field | Detail |
|-------|--------|
| Date | 29 May 2026 |
| Time | 19:30 – 19:39 |
| Severity | High |
| MITRE Techniques | T1053.005, T1547.001 |
| Status | Investigated |
| Host | LAPTOP-NNIC5EOM |

---

## What Happened

Two persistence techniques were simulated back to back using Atomic Red Team — Scheduled Task creation (T1053.005) and Registry Run Key modification (T1547.001). Both techniques allow an attacker to survive reboots and maintain access to a compromised machine without needing to re-exploit it.

---

## Detection

Both alerts triggered in Splunk — **Scheduled Task Persistence Detected** and **Registry Persistence Detected**.

---

## Technique 1 — Scheduled Task Persistence (T1053.005)

### Evidence (selected events)

| Time | Image | CommandLine |
|------|-------|-------------|
| 19:30:20 | schtasks.exe | `/create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"` |
| 19:30:20 | schtasks.exe | `/create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"` |
| 19:30:23 | schtasks.exe | `/Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min powershell.exe -Command IEX(...base64...)"` |
| 19:30:26 | schtasks.exe | `/Create /TN "EventViewerBypass" /TR "eventvwr.msc" /SC ONLOGON /RL HIGHEST /F` |

### Analysis

Multiple scheduled tasks were created that would execute on logon or startup. The most interesting one is `ATOMIC-T1053.005` which stores a base64-encoded payload in the registry and then decodes and executes it via a scheduled task — a fileless persistence technique that is harder to detect with traditional antivirus.

The `EventViewerBypass` and `CompMgmtBypass` tasks are UAC bypass techniques — they abuse the fact that eventvwr.msc and compmgmt.msc auto-elevate, so a scheduled task running these at highest privilege can execute code without a UAC prompt.

---

## Technique 2 — Registry Run Key Persistence (T1547.001)

### Evidence (selected events)

| Time | EventType | TargetObject |
|------|-----------|-------------|
| 19:38:36 | SetValue | `HKCU\...\CurrentVersion\Run\Atomic Red Team` |
| 19:38:37 | SetValue | `HKLM\...\CurrentVersion\RunOnce\NextRun` |
| 19:38:41 | SetValue | `HKLM\...\CurrentVersion\Run\calc` |
| 19:38:41 | SetValue | `HKLM\...\Winlogon\Shell` |
| 19:38:41 | SetValue | `HKLM\...\Winlogon\Userinit` |

### Analysis

Writing to `Run` and `RunOnce` keys is one of the most commonly used persistence methods in malware. Every value written here executes automatically when the machine starts or the user logs in.

The modifications to `Winlogon\Shell` and `Winlogon\Userinit` are more dangerous — these keys control the shell that loads after login (normally `explorer.exe`) and the initialization process. Replacing these with a malicious binary gives an attacker a very privileged and stealthy persistence mechanism.

---

## Timeline

| Time | Event |
|------|-------|
| 19:30:20 | Scheduled task creation begins |
| 19:30:26 | Last scheduled task created (EventViewerBypass) |
| 19:38:36 | Registry Run key modifications begin |
| 19:38:41 | Winlogon Shell and Userinit keys modified |
| 19:38:56 | Last registry modification recorded |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Process | schtasks.exe |
| Sysmon Event ID | 1 (process), 13 (registry) |
| Registry paths | Run, RunOnce, Winlogon\Shell, Winlogon\Userinit |
| Task names | T1053_005_OnLogon, AtomicTask, ATOMIC-T1053.005, EventViewerBypass |

---

## Remediation

1. Delete all suspicious scheduled tasks:
   ```powershell
   schtasks /Delete /TN "T1053_005_OnLogon" /F
   schtasks /Delete /TN "AtomicTask" /F
   schtasks /Delete /TN "ATOMIC-T1053.005" /F
   ```

2. Clean up registry Run keys — remove any unexpected entries from:
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

3. Verify `Winlogon\Shell` is set to `explorer.exe` and `Winlogon\Userinit` is set to `C:\Windows\system32\userinit.exe`

4. Review all tasks in Task Scheduler for anything unexpected

---

## Lessons Learned

- Persistence techniques leave very clear evidence in Sysmon Event ID 1 and 13
- Registry-based persistence is easy to miss without a SIEM — there are hundreds of registry writes happening constantly, so having a specific detection for Run key paths is important
- The fileless scheduled task technique (storing payload in registry) shows why you need both process and registry monitoring together
