# Container Traffic Anomaly Investigation

**Source:** Coursework-derived case study, independently rewritten  
**Status:** Complete; SIEM recreation planned

## Objective

Build a defensible workflow for discovering systems, capturing network traffic, identifying unusual behavior, and validating machine-learning anomalies in an isolated container lab.

## Environment

- Authorized Linux container network
- Nmap for host and service discovery
- Wireshark and command-line capture tools for protocol analysis
- Python, pandas, scikit-learn, and visualization libraries
- Isolation Forest, K-Means, DBSCAN, and PCA for exploratory anomaly analysis

Original lab addresses, MAC addresses, hostnames, dates, and screenshots have been removed.

## Phase 1: Establish the asset and service baseline

I enumerated the lab network to identify active systems, exposed services, operating-system indicators, and likely system functions. Several containers exposed a notebook service, while the host provided remote administration and file-sharing services.

The result was a basic asset inventory and a list of services requiring closer monitoring.

## Phase 2: Capture and analyze traffic

I captured a short period of internal traffic and compared protocol distribution and communication pairs. Most traffic was ordinary TCP communication between containers. HTTP requests to administrative and health-check paths were treated as investigation leads rather than immediate proof of malicious activity.

The investigation recorded:

- Source and destination relationships
- Protocol and port usage
- Packet counts
- Unencrypted administrative-path requests
- Internal versus external communication

## Phase 3: Engineer usable features

Raw IP addresses are categorical strings and cannot be passed directly to many models. I converted address characteristics into numerical features, retained network context, and removed fields that could cause target leakage.

The analysis considered:

- Address components and private/public classification
- Ports and protocol values
- Packet sizes
- Frequency and communication patterns
- Missing or malformed values

## Phase 4: Detect and interpret outliers

Isolation Forest identified a small group of low-scoring observations. K-Means and DBSCAN provided additional views of common traffic groups and low-density records. PCA reduced the feature space for visualization.

These techniques prioritized review; they did not label an attack conclusively.

## Key findings

- A small number of internal communication patterns differed from the dominant traffic baseline.
- Notebook-service communications accounted for much of the repeated activity.
- Some outliers represented multicast or discovery traffic.
- Administrative-path requests deserved correlation with application logs.
- Model output required packet-level and host-level validation.

## Detection-engineering lessons

1. Asset context is necessary before interpreting alerts.
2. A rare event can still be benign.
3. Feature engineering can introduce misleading patterns if data meaning is ignored.
4. Leakage and mismatched train/test columns can invalidate results.
5. Detection documentation should state assumptions, false-positive risks, and required follow-up evidence.

## Planned independent extension

The next version will generate new synthetic traffic, ingest it into a SIEM, create a query for unusual notebook-service access, test false positives, and publish only sanitized dashboards and queries.

## Skills demonstrated

Nmap, Wireshark, network baselining, protocol analysis, Python data preparation, anomaly detection, clustering, PCA visualization, triage, false-positive analysis, and analyst documentation.
