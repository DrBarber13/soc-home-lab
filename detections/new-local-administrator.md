# Detection: New Local Administrator Membership

**Source:** Independent detection specification  
**Status:** Specification complete  
**Framework mapping:** MITRE ATT&CK T1098 — Account Manipulation

## Goal

Identify additions to a local administrators group because the change can establish or expand privileged access.

## Data requirements

Windows Security event `4732` with subject account, target group, member identity, destination host, event time, and account-domain fields. Localized group names and identifier formats require normalization.

## Microsoft Sentinel KQL

```kusto
SecurityEvent
| where EventID == 4732
| where TargetAccount =~ "Administrators"
| project TimeGenerated, Computer, SubjectAccount, MemberName, MemberSid, TargetAccount
| order by TimeGenerated desc
```

## Splunk SPL

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4732
| search Group_Name="Administrators"
| table _time host Subject_Account_Name Member_Name Member_ID Group_Name
| sort - _time
```

## Test cases

| Test | Expected result |
|---|---|
| Add a fictional lab user to local Administrators | One result with actor, member, and host |
| Add a user to a nonprivileged local group | No result |
| Approved endpoint-management action | Result retained but enriched with authorized change context |
| Remove a local administrator | Not covered by this rule; companion removal monitoring is required |

## Triage

Determine who initiated the change, whether the member is a user or group, asset criticality, approval record, sign-ins around the change, remote-management activity, and follow-on process execution.

## Limitations

This rule depends on account-management auditing and a parser that exposes the group fields. Built-in group names can be localized. Attackers may gain privilege through policy, service configuration, or directory groups without generating this exact local event.
