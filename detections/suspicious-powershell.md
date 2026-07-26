# Detection: Suspicious PowerShell Behavior

**Source:** Independent detection specification  
**Status:** Specification complete  
**Framework mapping:** MITRE ATT&CK T1059.001 — PowerShell

## Goal

Prioritize PowerShell activity that combines encoded or hidden execution with download, memory, or policy-bypass indicators. PowerShell itself is an administrative tool, so the rule uses multiple signals rather than alerting on every process.

## Data requirements

PowerShell Script Block Logging event `4104` and process-creation telemetry such as Security event `4688` or Sysmon event `1`. Useful fields include command line, script-block text, parent process, user, host, hashes, and signer information.

## Microsoft Sentinel KQL

```kusto
union isfuzzy=true
(
    Event
    | where EventLog == "Microsoft-Windows-PowerShell/Operational"
    | where EventID == 4104
    | project TimeGenerated, Computer, UserName, CommandText = RenderedDescription
),
(
    SecurityEvent
    | where EventID == 4688
    | where NewProcessName endswith "\\powershell.exe"
        or NewProcessName endswith "\\pwsh.exe"
    | project TimeGenerated, Computer, UserName = SubjectUserName,
              CommandText = CommandLine
)
| where CommandText has_any ("-enc", "EncodedCommand", "FromBase64String",
                              "DownloadString", "Invoke-WebRequest",
                              "IEX", "Bypass", "Hidden")
| extend IndicatorCount =
    toint(CommandText has_any ("-enc", "EncodedCommand", "FromBase64String")) +
    toint(CommandText has_any ("DownloadString", "Invoke-WebRequest", "IEX")) +
    toint(CommandText has_any ("Bypass", "Hidden"))
| where IndicatorCount >= 2
| order by TimeGenerated desc
```

## Test cases

| Test | Expected result |
|---|---|
| Ordinary signed administrative script | No alert unless multiple risky indicators exist |
| Benign lab command with encoded content and hidden window | Alert |
| Download command launched by an unusual parent | Alert and higher analyst priority |
| Approved management platform using encoded commands | Alert initially; tune by verified signer, parent, account, and host scope |

## Triage

Review the decoded command safely, parent-child process chain, account privilege, script signer, network destination, file writes, persistence changes, and whether the host normally runs this automation.

## Limitations

String matching is evadable and can create false positives. Script Block Logging may be disabled or incomplete. Stronger coverage correlates behavior across process, script, network, file, identity, and endpoint-control telemetry.
