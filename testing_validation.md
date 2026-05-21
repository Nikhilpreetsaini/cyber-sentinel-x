# Testing & Validation

## Functional Testing

1. **Load Demo Logs**: On the *Upload Logs* page, select each built‑in sample file (e.g. `brute_force_logs.csv`) and verify that events are parsed and processed correctly. Check that the risk scores and threat categories match the expected patterns.
2. **Upload Custom Logs**: Create a small CSV with columns `timestamp`, `username`, `source_ip`, `asset`, `action`, `status` and `event_message`. Upload it and confirm that the app processes it without errors and displays the data in the *Threat Detection* page.
3. **Incident Correlation**: On the *Incident Investigation* page, select an incident and verify that all associated events are listed in the timeline. Update the case status and notes; ensure the changes persist within the session.
4. **AI Agent Responses**: Ask the AI Security Agent questions such as *“What is the most critical incident?”* and *“Why is 192.168.1.250 suspicious?”*. Validate that the responses correspond to the processed data.
5. **Report Download**: On the *Report Generator* page, generate a detailed report for a chosen incident and download it as CSV. Open the file to confirm that it contains the expected fields and data.

## Validation Scenarios

| Scenario | Expected Outcome |
|---|---|
| Brute Force Demo | `brute_force_logs.csv` should result in one incident with high risk score; threat type should be *Brute Force*; AI agent should recommend blocking the source IP and enabling MFA. |
| Password Spray Demo | `password_spraying_logs.csv` should classify events as *Password Spraying* and assign medium to high risk. |
| Port Scan Demo | `port_scan_logs.csv` should detect *Port Scan* events with medium risk. |
| Malware-like Demo | `malware_like_logs.csv` should detect *Malware-like Activity* events with high risk and recommend quarantine. |
| Data Exfiltration Demo | `data_exfiltration_logs.csv` should classify events as *Data Exfiltration* with critical risk for large transfers. |

## Limitations & Edge Cases

- Events lacking a `timestamp` will be parsed as `NaT` and may affect sorting and correlation.
- Unknown or unexpected column names may be dropped or ignored during parsing. Users should ensure logs contain the required fields or provide alias columns.
- The correlation algorithm assumes a 60‑minute window for grouping; extremely long or short attacks may require tuning the window length.
- This system is not intended for real‑time detection; uploading extremely large log files (millions of rows) may exhaust memory or processing time.