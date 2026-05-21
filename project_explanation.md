# Project Explanation

## Introduction

Cyber Sentinel X aims to provide a mini SOC/SIEM experience by analysing pre‑ingested log files. The system detects high‑level threats, correlates events into incidents, computes risk scores and allows interactive investigation and reporting. It is intended as a final‑year industrial training project demonstration.

## Core Modules

### Log Parser & Preprocessor
Loads CSV log files and normalises column names into a standard schema for downstream processing. Handles different log formats by mapping aliases such as `time` → `timestamp` and `user` → `username`.

### Threat Detector
Applies heuristic rules to classify each log event into a threat category. For example, repeated failed logins from a single IP targeting multiple users is flagged as `Password Spraying`, while a large outbound data transfer triggers `Data Exfiltration`. The detector is intentionally simple and does not use advanced machine learning.

### Risk Engine
Assigns a numerical risk score (0–100) to each event based on its threat type and contextual attributes (e.g. number of failed attempts or bytes transferred). The score is mapped to a risk level (Low, Medium, High, Critical) and an associated confidence value.

### UEBA Engine
Flags unusual behaviour patterns such as logins outside typical hours, multiple IPs per user and multiple users from a single IP. Adds descriptive reasons to events for analyst review.

### Incident Correlator
Groups related events into incidents. Events with the same source IP and threat type occurring within a one‑hour window are assigned a common incident ID (e.g. `CSX-0001`).

### Case Manager
Maintains a simple in-memory store of incident status, priority, assigned analyst and notes. Supports status transitions (Open, Investigating, Resolved, False Positive, Needs Review) and updates via the Incident Investigation page.

### AI Security Agent
A deterministic, rule‑based assistant that generates explanations for incidents and answers a limited set of questions. Provides summaries, identifies the most critical incident, and recommends actions based on built-in playbooks. Does not call external APIs or large language models.

### Visualisations
Uses Plotly to render bar charts, histograms and timelines of events and risk scores. Visualises threat distribution, risk distributions and event timelines on the dashboard.

### Report Generator
Produces CSV reports for individual incidents and summary statistics across all events. Includes MITRE ATT&CK mappings, threat intelligence lookups and recommended actions in the incident report.

## Limitations

- The threat detection rules are simplistic and serve only to demonstrate the workflow.
- No real-time data ingestion or streaming; only batch CSV files are supported.
- The threat intelligence data is static and illustrative.
- The AI agent is rule-based and cannot handle arbitrary queries beyond the supported set.

## Future Improvements

Potential enhancements include:

- Integrating machine learning models for anomaly detection and classification.
- Adding support for syslog ingestion and real-time streaming through Kafka or similar.
- Connecting to external threat intelligence feeds via API.
- Implementing a more advanced conversational agent using a large language model (LLM) with proper safeguards.