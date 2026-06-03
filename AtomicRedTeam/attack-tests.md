# Atomic Red Team — Attack Tests

All attacks were run using Atomic Red Team on a local Windows 10 machine. The goal was to generate real telemetry and then detect it in Splunk.

---

## How to Run Tests

First import the module in PowerShell as Administrator:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Then run any test using:

```powershell
Invoke-AtomicTest <TECHNIQUE-ID>
```

---

## Attack 1 — Encoded PowerShell Execution (T1059.001)

**Command:**
```powershell
Invoke-AtomicTest T1059.001
```

**What it does:**
Executes PowerShell commands using the `-EncodedCommand` or `-enc` flag to pass base64-encoded payloads. This is a common obfuscation technique used by attackers to hide malicious scripts from basic string-based detections.

**Tests that ran successfully:** 11, 12, 17

**What to look for in Splunk:**
- Sysmon Event ID 1 (Process Create)
- `powershell.exe` in the Image field
- `-enc` or `-EncodedCommand` in the CommandLine field

**Detection query:** `Splunk/detections/encoded_powershell.spl`

---

## Attack 2 — Scheduled Task Persistence (T1053.005)

**Command:**
```powershell
Invoke-AtomicTest T1053.005
```

**What it does:**
Creates scheduled tasks that run malicious commands on logon, startup, or at a set time. Attackers use this to maintain persistence — so even if the malware process is killed, it comes back the next time the machine starts.

**Tasks created during the test:**
- `T1053_005_OnLogon` — runs cmd.exe at logon
- `T1053_005_OnStartup` — runs cmd.exe at startup
- `AtomicTask` — runs calc.exe at logon (simulates malware)
- `ATOMIC-T1053.005` — stores payload in registry, decodes and runs via scheduled task
- `EventViewerBypass` — UAC bypass via scheduled task
- `CompMgmtBypass` — UAC bypass via scheduled task

**What to look for in Splunk:**
- Sysmon Event ID 1 (Process Create)
- `schtasks.exe` in the Image field
- `/Create` or `/Run` in the CommandLine field

**Detection query:** `Splunk/detections/scheduled_task.spl`

---

## Attack 3 — Registry Run Key Persistence (T1547.001)

**Command:**
```powershell
Invoke-AtomicTest T1547.001
```

**What it does:**
Writes entries to Windows registry Run and RunOnce keys so that a program executes automatically when the system starts or a user logs in. Also modifies Winlogon keys which control what runs during the login process.

**All 20 tests ran successfully**, including:
- Writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Writing to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Modifying `Winlogon\Shell` and `Winlogon\Userinit`
- Dropping .vbs, .jse, and .bat files in the Startup folder
- Modifying policy explorer Run keys

**What to look for in Splunk:**
- Sysmon Event ID 13 (Registry Value Set)
- TargetObject containing `Run`, `RunOnce`, or `Winlogon`

**Detection query:** `Splunk/detections/registry_persistence.spl`

---

## Attack 4 — Brute Force Login (T1110.001)

**Command:**
```powershell
Invoke-AtomicTest T1110.001
```

**What it does:**
Attempts to authenticate with a list of common passwords against a local or domain account. Simulates a password spraying or brute force attack.

**Note:** Tests 1 and 2 ran (SMB and LDAP brute force). Tests 3 and 4 failed because there is no Active Directory domain controller or Azure AD in this lab setup — which is expected in a standalone machine environment.

**What to look for in Splunk:**
- Windows Security Event ID 4625 (Failed Logon)
- Multiple failed attempts in a short time window

**Detection query:** `Splunk/detections/brute_force.spl`

---

## Summary

| Technique | ID | Tests Run | Detected |
|-----------|-----|-----------|---------|
| Encoded PowerShell | T1059.001 | 3 | ✅ |
| Scheduled Task Persistence | T1053.005 | 15 | ✅ |
| Registry Run Key Persistence | T1547.001 | 20 | ✅ |
| Brute Force Login | T1110.001 | 2 | ✅ |
