# Cyber Sentinel X

**Cyber Sentinel X** is an AI‑powered Security Operations Center (SOC) analyst and threat intelligence platform built with Streamlit. It demonstrates how log data can be ingested, analysed, correlated and summarised to detect suspicious behaviour, assign risk scores, generate incident reports and provide agentic explanations.

## Features

- **Multi‑Source Log Ingestion:** Upload your own CSV logs or load built‑in demo datasets representing normal activity, brute force attacks, password spraying, port scanning, malware‑like processes and data exfiltration.
- **Threat Detection & Risk Scoring:** Identify brute force attacks, password spray attempts, port scans, malware‑like activity, data exfiltration and more using heuristic rules. Assign a risk score (0–100) and risk level (Low/Medium/High/Critical) to each event.
- **User & Entity Behaviour Analytics (UEBA):** Flag unusual behaviour such as logins outside typical hours, multiple IPs per user or multiple users from a single IP.
- **Incident Correlation:** Group related events into incidents with unique IDs based on source IP, threat type and temporal proximity.
- **SOC Dashboard:** Visualise threat distribution, risk score distribution and event timelines. View top source IPs and users.
- **Incident Investigation:** Examine individual incidents, review timelines, update case status (Open/Investigating/Resolved/False Positive/Needs Review), assign priorities and add analyst notes.
- **Analytics & Visualisations:** Explore a risk heatmap across different dimensions (user, IP, asset, hour, threat type or risk level) to see where risk concentrates. Examine a relationship graph linking source IPs to users, assets and threat types to understand how an incident flows from the network edge to the victim.
- **AI Security Agent:** Ask natural language questions about the events and receive explanations, summaries and recommendations. The agent can answer questions such as *"Why is this IP suspicious?", "What is the most critical incident?", "Which user is most targeted?"* and provide executive summaries. It runs locally and does not call external services.
- **MITRE ATT&CK Mapping & Threat Intelligence:** Map detected threats to simplified MITRE tactics and techniques. Look up IP addresses in a local threat intelligence database for reputation and suggested actions.
- **Report Generation:** Download CSV files containing all events or incident‑specific reports. Generate summary statistics by threat type and risk level.
- **Streamlit Deployment Ready:** The repository includes a `.streamlit/config.toml` to configure the app for deployment on [Streamlit Cloud](https://streamlit.io/cloud).

## Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/your-username/cyber-sentinel-x.git
cd cyber-sentinel-x
pip install -r requirements.txt
```

## Running the App

To launch Cyber Sentinel X locally, run:

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501` to explore the dashboard and features.

## Directory Structure

```
cyber-sentinel-x/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── sample_logs/        # Demo log datasets
├── data/               # MITRE mapping, threat intel and response playbooks
├── src/                # Core modules (parsing, detection, risk, UEBA, etc.)
├── docs/               # Project documentation (synopsis, system design, etc.)
├── assets/             # Screenshots and diagrams
└── .streamlit/         # Streamlit configuration
```

## Safety Notice

This project is for educational purposes only. It is a defensive cybersecurity tool and **does not** perform real hacking, scanning or exploitation of networks. All threat detection logic operates on pre‑ingested log files, and the threat intelligence database is a static, safe dataset. Do not use this tool to monitor live production systems without appropriate authorisation.

## License

This project is licensed under the MIT License.