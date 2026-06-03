# Setup Guide

This guide walks through the full setup of the SOC Detection Lab from scratch. Everything runs on a single Windows 10 machine — no VMs required.

---

## Prerequisites

- Windows 10 (64-bit)
- At least 8GB RAM
- At least 20GB free disk space
- Administrator access
- A browser and internet connection

---

## Step 1 — Install Splunk Enterprise

1. Go to [splunk.com/en_us/download/splunk-enterprise.html](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Create a free Splunk account if you don't have one
3. Download the **Windows 64-bit .msi** file (~500 MB)
4. Right click the .msi → **Run as Administrator**
5. Follow the installer:
   - Accept the license agreement
   - Select **Local System**
   - Set username: `admin`
   - Set a password you'll remember
   - Click Install
6. Once installed, open your browser and go to `http://localhost:8000`
7. Login with your admin credentials — you should see the Splunk dashboard

### Create the Index

1. Go to **Settings → Indexes → New Index**
2. Index Name: `soc-lab`
3. Leave everything else as default → **Save**

### Enable Receiving Port

1. Go to **Settings → Forwarding and Receiving**
2. Under Receive Data → **Configure Receiving**
3. Click **New Receiving Port**
4. Enter port: `9997` → **Save**

---

## Step 2 — Install Sysmon

1. Go to [learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download and extract the zip
3. Download the SwiftOnSecurity config:
   - Go to [github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
   - Click `sysmonconfig-export.xml` → **Raw**
   - Press `Ctrl + S` to save
   - In the save dialog set **Save as type** to **All Files**
   - Name it `sysmonconfig.xml`
   - Save both files to `C:\soc`

4. Open **PowerShell as Administrator** and run:

```powershell
cd C:\soc
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

5. Verify Sysmon is running:

```powershell
Get-Service Sysmon64
```

Should show `Running`.

6. Verify events in Event Viewer:
   - Navigate to: `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`
   - You should see events already populating

> **Note:** Make sure `sysmonconfig.xml` saves as an actual XML file, not as HTML. If it saves as HTML, repeat the download using Raw → Save As → All Files.

---

## Step 3 — Install Splunk Universal Forwarder

1. Go to [splunk.com/en_us/download/universal-forwarder.html](https://www.splunk.com/en_us/download/universal-forwarder.html)
2. Download the **Windows 64-bit .msi**
3. Right click → **Run as Administrator**
4. Follow the installer:
   - Check the license agreement → Next
   - Username: `admin`, set a password → Next
   - Deployment Server: leave blank → Next
   - Receiving Indexer: Hostname `127.0.0.1`, Port `9997` → Add → Next
   - Click Install

### Configure Log Forwarding

1. Open **Notepad as Administrator**
2. Paste the following:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = soc-lab
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
disabled = false
renderXml = true

[WinEventLog://Security]
index = soc-lab
sourcetype = WinEventLog:Security
disabled = false

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = soc-lab
sourcetype = WinEventLog:PowerShell
disabled = false
```

3. Save the file to exactly this path:
   - `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
   - Save as type: **All Files**

4. Restart the forwarder:

```powershell
Restart-Service SplunkForwarder
```

### Fix Sysmon Permissions (Important)

By default the Universal Forwarder runs as Network Service, which doesn't have permission to read Sysmon logs. Fix this by running:

```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

### Verify Logs Are Flowing

In Splunk Search & Reporting, run:

```spl
index=soc-lab
```

You should see events coming in. To verify Sysmon specifically:

```spl
index=soc-lab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

---

## Step 4 — Install Atomic Red Team

1. Open **PowerShell as Administrator**

2. Add Windows Defender exclusions first (Atomic Red Team gets flagged as malware):

```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Add-MpPreference -ExclusionProcess "powershell.exe"
```

3. Set execution policy:

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
```

4. Install Atomic Red Team:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

This downloads ~1GB of attack simulations. Wait for it to complete.

5. Verify installation:

```powershell
Get-ChildItem "C:\AtomicRedTeam\atomics" | Measure-Object
```

Should show 300+ folders.

6. Import the module:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

7. Test it works (no attack runs, just shows details):

```powershell
Invoke-AtomicTest T1059.001 -ShowDetails
```

---

## Step 5 — Run the Lab

Once everything is set up, import the Atomic Red Team module at the start of each session:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Then run attacks and detect them in Splunk using the queries in `Splunk/detections/`.

> See `AtomicRedTeam/attack-tests.md` for the full list of tests run in this lab.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Sysmon logs not appearing in Splunk | Change forwarder service to LocalSystem (see Step 3) |
| inputs.conf not saving correctly | Open Notepad as Administrator before saving |
| Atomic Red Team install fails | Add Defender exclusions before installing |
| Splunk not accessible at localhost:8000 | Check if SplunkD service is running in Task Manager |
| XML fields empty in search results | Use `rex` commands to extract fields (see detections folder) |
