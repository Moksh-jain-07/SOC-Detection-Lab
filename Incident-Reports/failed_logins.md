# Incident Report — Brute Force Login Attempts

## Incident Summary

| Field | Detail |
|-------|--------|
| Date | 29 May 2026 |
| Time | 19:41 – 19:42 |
| Severity | High |
| MITRE Technique | T1110.001 — Brute Force: Password Guessing |
| Status | Investigated |
| Host | LAPTOP-NNIC5EOM |
| Target Account | moskh |

---

## What Happened

A brute force attack was simulated using Atomic Red Team T1110.001. The attack attempted to authenticate against the local account using a wordlist of over 100 common passwords. Each failed attempt generated a Windows Security Event ID 4625 (Failed Logon).

---

## Detection

The alert **Brute Force Login Detected** triggered in Splunk after detecting multiple 4625 events in a short window.

**SPL query that caught it:**
```spl
index=soc-lab sourcetype="WinEventLog:Security"
| rex field=_raw "EventCode=(?<EventCode>\d+)"
| where EventCode="4625"
| rex field=_raw "Account Name:\s+(?<AccountName>\S+)"
| table _time, EventCode, AccountName
| sort -_time
```

---

## Evidence

6 failed login events (Event ID 4625) were detected between 19:41:48 and 19:42:30.

| Time | EventCode | AccountName |
|------|-----------|-------------|
| 19:42:30 | 4625 | - |
| 19:42:19 | 4625 | - |
| 19:42:09 | 4625 | - |
| 19:41:59 | 4625 | - |
| 19:41:48 | 4625 | - |
| 19:41:42 | 4625 | LAPTOP-NNIC5EOM$ |

> Note: AccountName shows `-` for most events because the LDAP authentication attempts failed at the protocol level before reaching a Windows account — so no account name was recorded. This is normal behaviour for failed LDAP brute force attempts against a machine with no domain controller.

---

## Timeline

| Time | Event |
|------|-------|
| 19:41:42 | First failed login attempt recorded |
| 19:41:48 | Second attempt |
| 19:42:30 | Last failed attempt in this session |

---

## Analysis

5 failed logins in under a minute against the same host is a strong indicator of automated brute force activity. A real user mistyping their password would typically fail once or twice, not 5+ times in 60 seconds.

The fact that AccountName is `-` for most events tells us the authentication failed at the LDAP/network layer rather than the Windows login screen — meaning this was a network-based brute force, not a physical login attempt.

In a real environment this would warrant:
- Immediate account lockout investigation
- Source IP identification
- Firewall rule review

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Windows Event ID | 4625 — Failed Logon |
| Pattern | 5+ failures within 1 minute |
| Logon Type | Network (Type 3) |

---

## Remediation

1. Lock the targeted account temporarily while investigating
2. Identify the source IP of the failed attempts (check Security log Workstation Name field)
3. Block the source IP at the firewall if external
4. Check if any attempts were successful (look for Event ID 4624 from same source)
5. Enable account lockout policy — lock account after 5 failed attempts

**Recommended lockout policy:**
- Account lockout threshold: 5 attempts
- Lockout duration: 30 minutes
- Reset counter after: 15 minutes

---

## Lessons Learned

- Event ID 4625 alone is noisy — adding a threshold (more than 5 failures per minute) reduces false positives significantly
- In environments without a domain controller, LDAP brute force attempts won't show account names in the logs — but the events are still generated and detectable
- Pairing this detection with a 4624 (successful logon) search helps identify if the brute force eventually succeeded
