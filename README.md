# SOC Home Lab

**Status:** Coursework case study complete; independent SIEM extension planned  
**Project source:** Coursework-derived case study plus independent extensions

## Overview

An isolated security operations lab for collecting endpoint telemetry, building detections, investigating alerts, and writing incident reports.

## Planned architecture

| Component | Role |
|---|---|
| Windows endpoint | Generates authentication and process telemetry |
| [Splunk / Microsoft Sentinel] | Log search, alerting, dashboards |
| Sysmon | Enhanced endpoint telemetry |
| Isolated test host | Generates safe, controlled activity |

Add an original diagram to `images/soc-topology.png`. Use documentation-safe network ranges.

## Detection roadmap

| Detection | Data source | Framework mapping | Status |
|---|---|---|---|
| [Container traffic anomaly investigation](case-studies/container-traffic-anomaly-investigation.md) | Packet capture and derived traffic features | Behavioral anomaly analysis | Complete |
| Repeated failed logons | Windows Security logs | [Validate mapping] | Planned |
| New local administrator | Windows Security logs | [Validate mapping] | Planned |
| Suspicious PowerShell | PowerShell/Sysmon | [Validate mapping] | Planned |

## Workflow

1. Define a hypothesis and required telemetry.
2. Generate benign, controlled test events.
3. Write and tune a query.
4. Validate expected and unexpected results.
5. Document false positives, limitations, and response actions.

## Skills demonstrated

Log onboarding, Windows telemetry, SIEM queries, detection engineering, alert triage, incident documentation.

## Safety

Testing is limited to systems I own or am authorized to use. No live targets, credentials, malware, private logs, or sensitive data are included.
