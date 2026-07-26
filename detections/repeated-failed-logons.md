# Detection: Repeated Failed Logons

**Source:** Independent detection specification  
**Status:** Specification complete  
**Framework mapping:** MITRE ATT&CK T1110 — Brute Force

## Goal

Identify a source generating repeated Windows failed-logon events, then distinguish password guessing against one account from password spraying across many accounts.

## Data requirements

Windows Security event `4625` with event time, target account, source address or workstation, logon type, status, substatus, and destination host. Asset and identity enrichment improve prioritization.

## Microsoft Sentinel KQL

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    TargetAccounts = dcount(TargetAccount),
    Accounts = make_set(TargetAccount, 20),
    Hosts = make_set(Computer, 20)
  by IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| extend Pattern = iff(TargetAccounts >= 5, "Possible password spray", "Repeated guessing")
| order by FailedAttempts desc
```

## Splunk SPL

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count AS failed_attempts dc(TargetUserName) AS target_accounts
        values(TargetUserName) AS accounts values(host) AS hosts
        BY _time Source_Network_Address
| where failed_attempts >= 5
| eval pattern=if(target_accounts>=5,"Possible password spray","Repeated guessing")
| sort - failed_attempts
```

Field names vary by data connector and parser and must be adapted before execution.

## Test cases

| Test | Expected result |
|---|---|
| Five failed attempts for one fictional user from one lab host | Repeated-guessing result |
| One failed attempt against six fictional users from one lab host | Possible-spray result |
| Two isolated user mistakes | No alert |
| Approved vulnerability scanner behavior | Alert enriched and dispositioned through an explicit exception |

## Triage

Review privilege of targeted accounts, source ownership, logon type, failure reason, successful logons after the failures, other targeted hosts, and whether the same password pattern appears across users.

## Limitations

Distributed guessing may remain below a per-source threshold. NAT can combine unrelated users behind one address. Missing source fields, inconsistent parsers, and service-account password changes can distort the result.
