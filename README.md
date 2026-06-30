# Cyber Sentinel X

**Cyber Sentinel X** is an AI-powered Security Operations Center (SOC) analyst and threat intelligence platform built with Streamlit. It demonstrates how log data can be ingested, analysed, correlated and summarised to detect suspicious behaviour, assign risk scores, generate incident reports and provide agentic explanations.

## Features

- **Multi-Source Log Ingestion:** Upload your own CSV logs or generate built-in demo logs representing normal activity, brute force attacks, password spraying, port scanning, malware-like processes and data exfiltration.
- **Threat Detection & Risk Scoring:** Identify brute force attacks, password spray attempts, port scans, malware-like activity, data exfiltration and suspicious logins using defensive heuristic rules.
- **User & Entity Behaviour Analytics (UEBA):** Flag unusual behaviour such as odd-hour risky activity or users appearing from many source IPs.
- **Incident Correlation:** Group related events into incident IDs based on source IP and threat type.
- **SOC Dashboard:** Visualise threat distribution, IOC summaries, risk scores and event timelines.
- **Incident Investigation:** Examine incidents, review event data, update case status, assign priorities and add analyst notes.
- **AI Security Agent:** Ask natural-language questions such as "Which incident is most critical?", "Which IPs are suspicious?" and "Show MITRE mapping". The assistant uses local rules only and does not call external APIs.
- **MITRE ATT&CK Mapping & Threat Intelligence:** Map detected threats to simplified MITRE tactics and techniques. Look up IP addresses in a local demo threat-intelligence dictionary.
- **Report Generation:** Download CSV files containing all events or incident-specific reports.
- **Streamlit Cloud Ready:** Includes `requirements.txt`, `.streamlit/config.toml`, `app.py`, and `streamlit_app.py` for simple deployment.

## Streamlit Cloud Deployment

Use these exact settings in Streamlit Community Cloud:

- Repository: `Nikhilpreetsaini/cyber-sentinel-x`
- Branch: `main`
- Main file path: `streamlit_app.py`

Alternative main file path if needed:

- `app.py`

No secrets are required. No external paid APIs are required.

## Local Installation

```bash
git clone https://github.com/Nikhilpreetsaini/cyber-sentinel-x.git
cd cyber-sentinel-x
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Then open `http://localhost:8501`.

## Directory Structure

```text
cyber-sentinel-x/
├── app.py                 # Main Streamlit application logic
├── streamlit_app.py       # Streamlit Cloud-compatible entrypoint
├── requirements.txt       # Python dependencies
├── render.yaml            # Optional Render deployment blueprint
├── .streamlit/            # Streamlit configuration
└── README.md              # Project documentation
```

## Safety Notice

This project is for educational and defensive cybersecurity purposes only. It does not perform real hacking, scanning, exploitation or unauthorised monitoring. All detections run on uploaded or generated log data.

## License

This project is licensed under the MIT License.
