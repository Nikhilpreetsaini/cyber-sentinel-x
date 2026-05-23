"""
Cyber Sentinel X Streamlit App
=============================

This Streamlit application provides a mini Security Operations Center (SOC)
dashboard for analysing log data, detecting cyber threats, assigning risk
scores, correlating incidents and generating reports. It demonstrates
principles of user and entity behaviour analytics (UEBA), MITRE ATT&CK mapping,
threat intelligence integration and agentic explanation. The app is intended
for educational use and does not perform any real-world intrusion detection.

Key features include:

* Multi-source log upload and demo log generation
* Threat detection (brute force, password spray, port scan, malware-like, data exfiltration, etc.)
* Risk scoring and risk level classification
* UEBA anomaly detection
* Incident correlation with incident IDs
* SOC dashboard summarising event and incident statistics
* Incident investigation workflow with case management
* AI security agent to explain incidents and answer questions
* Threat intelligence lookup and MITRE ATT&CK mapping
* Report generation and download
"""

import streamlit as st
import pandas as pd
import os
import io
# Add project root to sys.path so that the src package can be imported when the app
# is executed by Streamlit or other environments. Without this, the 'src' package may
# not be discoverable depending on how the app is launched (e.g. Streamlit Cloud).
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from src.log_parser import load_log
from src.preprocessor import preprocess
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from src.threat_detector import detect_threats
from src.risk_engine import compute_risk
from src.ueba_engine import analyse_ueba
from src.incident_correlator import correlate_incidents
from src.timeline_builder import build_timeline
from src.ai_agent import explain_incident, answer_question
from src.mitre_mapper import map_threat
from src.threat_intel import lookup_ip
from src.report_generator import incident_report, summary_report
from src.case_manager import initialize_case, get_case, update_case, STATUSES
from src.visualizer import (
    threat_distribution,
    risk_distribution,
    timeline_chart,
    risk_heatmap,
    relationship_graph,
)
from src.ioc_extractor import extract_iocs
from src.playbooks import get_playbook


@st.cache_data(show_spinner=False)
def load_sample_log(name: str) -> pd.DataFrame:
    path = os.path.join('sample_logs', name)
    df = load_log(path)
    df = preprocess(df)
    return df


def process_events(df: pd.DataFrame) -> pd.DataFrame:
    """Run detection, risk scoring, UEBA and incident correlation."""
    df = detect_threats(df)
    df = compute_risk(df)
    df = analyse_ueba(df)
    df = correlate_incidents(df)
    return df


def main():
    st.set_page_config(page_title="Cyber Sentinel X", layout="wide")
    st.sidebar.title("Cyber Sentinel X")
    pages = [
        "Home",
        "Upload Logs",
        "Threat Detection",
        "Incident Investigation",
        "AI Security Agent",
        "Analytics",
        "Report Generator",
        "About",
    ]
    page = st.sidebar.radio("Navigation", pages)

    # Initialize session state
    if 'events' not in st.session_state:
        st.session_state['events'] = pd.DataFrame()
    if 'processed' not in st.session_state:
        st.session_state['processed'] = pd.DataFrame()

    if page == "Home":
        st.title("SOC Dashboard")
        if st.session_state['processed'].empty:
            st.info("Upload or generate logs from the sidebar to begin analysis.")
        else:
            df = st.session_state['processed']
            # Summary metrics
            total_events = len(df)
            total_incidents = df['incident_id'].nunique()
            critical_incidents = (df['risk_level'] == 'Critical').sum()
            high_incidents = (df['risk_level'] == 'High').sum()
            unique_ips = df['source_ip'].nunique()
            unique_users = df['username'].nunique()
            avg_risk = round(df['risk_score'].mean(), 2) if not df.empty else 0
            # Display metrics in a single row of columns
            cols = st.columns(6)
            cols[0].metric("Events", total_events)
            cols[1].metric("Incidents", total_incidents)
            cols[2].metric("Unique IPs", unique_ips)
            cols[3].metric("Unique Users", unique_users)
            cols[4].metric("Critical Incidents", critical_incidents)
            cols[5].metric("Avg Risk Score", avg_risk)
            # Charts
            st.plotly_chart(threat_distribution(df), use_container_width=True)
            st.plotly_chart(risk_distribution(df), use_container_width=True)
            st.plotly_chart(timeline_chart(df), use_container_width=True)
            # Top IPs and users presented as tables
            st.subheader("Top Source IPs")
            st.table(df['source_ip'].value_counts().head())
            st.subheader("Top Users")
            st.table(df['username'].value_counts().head())

    elif page == "Upload Logs":
        st.title("Upload or Generate Logs")
        uploaded_file = st.file_uploader("Upload CSV Log File", type=['csv'])
        sample_files = os.listdir('sample_logs')
        st.markdown("**Or load a sample demo log:**")
        sample_choice = st.selectbox("Select sample log", [''] + sample_files)
        if st.button("Load Sample Log") and sample_choice:
            df = load_sample_log(sample_choice)
            st.session_state['events'] = df
            st.session_state['processed'] = process_events(df)
            st.success(f"Loaded {len(df)} events from sample log {sample_choice}.")
        if uploaded_file is not None:
            # Read uploaded file into DataFrame
            df = pd.read_csv(uploaded_file)
            df = preprocess(df)
            st.session_state['events'] = df
            st.session_state['processed'] = process_events(df)
            st.success(f"Uploaded {len(df)} events from file {uploaded_file.name}.")

    elif page == "Threat Detection":
        st.title("Threat Detection & Risk Analysis")
        if st.session_state['processed'].empty:
            st.warning("No processed log data available. Please upload or load a log first.")
        else:
            df = st.session_state['processed']
            # Filter controls
            st.subheader("Filter Events")
            levels = ['All'] + sorted(df['risk_level'].unique().tolist())
            level_sel = st.selectbox("Risk Level", levels, index=0)
            types = ['All'] + sorted(df['threat_type'].unique().tolist())
            type_sel = st.selectbox("Threat Type", types, index=0)
            df_filtered = df
            if level_sel != 'All':
                df_filtered = df_filtered[df_filtered['risk_level'] == level_sel]
            if type_sel != 'All':
                df_filtered = df_filtered[df_filtered['threat_type'] == type_sel]
            # Display filtered table
            st.dataframe(
                df_filtered[
                    [
                        'timestamp',
                        'username',
                        'source_ip',
                        'asset',
                        'action',
                        'status',
                        'threat_type',
                        'risk_level',
                        'risk_score',
                        'incident_id',
                    ]
                ],
                use_container_width=True,
            )
            st.subheader("IOC Summary")
            st.dataframe(extract_iocs(df_filtered), use_container_width=True)

    elif page == "Incident Investigation":
        st.title("Incident Investigation & Case Management")
        if st.session_state['processed'].empty:
            st.warning("Please process some log data first.")
        else:
            df = st.session_state['processed']
            # List incidents
            incidents = df[['incident_id','threat_type','risk_level','risk_score']].drop_duplicates()
            selected = st.selectbox("Select an incident", incidents['incident_id'])
            inc_df = df[df['incident_id']==selected]
            if not inc_df.empty:
                # Initialize case record if needed
                initialize_case(selected)
                case = get_case(selected)
                st.subheader(f"Incident {selected}")
                st.write(f"Threat Type: {inc_df['threat_type'].iloc[0]}")
                st.write(f"Risk Score: {inc_df['risk_score'].iloc[0]} ({inc_df['risk_level'].iloc[0]})")
                st.write(f"Source IP: {inc_df['source_ip'].iloc[0]}")
                st.write(f"Target User: {inc_df['username'].iloc[0]}")
                st.write(f"MITRE Mapping: {map_threat(inc_df['threat_type'].iloc[0])}")
                # Timeline
                st.subheader("Timeline")
                st.table(build_timeline(inc_df, selected)[['timestamp','action','status','event_message','threat_type']])
                # Case management form
                st.subheader("Case Details")
                status = st.selectbox("Status", STATUSES, index=STATUSES.index(case['status']))
                priority = st.selectbox("Priority", ['Low','Medium','High','Critical'], index=['Low','Medium','High','Critical'].index(case.get('priority','Medium')))
                analyst = st.text_input("Assigned Analyst", value=case.get('analyst',''))
                notes = st.text_area("Analyst Notes", value=case.get('notes',''))
                if st.button("Update Case"):
                    update_case(selected, status=status, priority=priority, analyst=analyst, notes=notes)
                    st.success("Case updated.")
                # Explanation
                st.subheader("AI Explanation")
                st.write(explain_incident(inc_df))

    elif page == "AI Security Agent":
        st.title("AI Security Agent")
        if st.session_state['processed'].empty:
            st.info("Load and process logs to interact with the AI agent.")
        else:
            df = st.session_state['processed']
            question = st.text_input("Ask a question about the incidents")
            if question:
                answer = answer_question(question, df)
                st.write(answer)

    elif page == "Analytics":
        st.title("Analytics & Visualisations")
        if st.session_state['processed'].empty:
            st.warning("Please load and process logs to view analytics.")
        else:
            df = st.session_state['processed']
            st.subheader("Risk Heatmap")
            # Available dimensions for heatmap axes
            dims = ['username', 'source_ip', 'asset', 'hour', 'threat_type', 'risk_level']
            col1, col2 = st.columns(2)
            with col1:
                index_dim = st.selectbox("Row dimension", dims, index=dims.index('username'))
            with col2:
                column_dim = st.selectbox("Column dimension", dims, index=dims.index('risk_level'))
            try:
                fig_heat = risk_heatmap(df, index=index_dim, column=column_dim)
                st.plotly_chart(fig_heat, use_container_width=True)
            except Exception as e:
                st.error(f"Unable to compute heatmap: {e}")
            st.subheader("Relationship Graph")
            fig_graph = relationship_graph(df)
            st.plotly_chart(fig_graph, use_container_width=True)

    elif page == "Report Generator":
        st.title("Report Generator")
        if st.session_state['processed'].empty:
            st.warning("No data available for reporting.")
        else:
            df = st.session_state['processed']
            st.subheader("Summary Report")
            st.dataframe(summary_report(df), use_container_width=True)
            # Download buttons
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download All Events (CSV)", csv, file_name="events.csv", mime='text/csv')
            # Incident-specific report download
            incidents = df['incident_id'].unique()
            inc_select = st.selectbox("Select incident for detailed report", incidents)
            rep_df = incident_report(df, inc_select)
            if not rep_df.empty:
                csv_inc = rep_df.to_csv(index=False).encode('utf-8')
                st.download_button(f"Download Report for {inc_select}", csv_inc, file_name=f"report_{inc_select}.csv", mime='text/csv')
    elif page == "About":
        st.title("About Cyber Sentinel X")
        st.markdown("""
        **Cyber Sentinel X** is a demonstration of an AI-powered SOC analyst
        platform built for educational purposes. It showcases how security logs
        can be ingested, analysed, correlated and summarised using modern
        analytics techniques. The project integrates principles of anomaly
        detection, user and entity behaviour analytics (UEBA), MITRE ATT&CK
        mapping and threat intelligence lookup, with a conversational agent
        interface to explain incidents and suggest responses.

        **Key modules:**
        - **Log Parser & Preprocessor:** Normalises and cleans raw log data.
        - **Threat Detector:** Applies heuristic rules to classify events into
          high-level threat categories.
        - **Risk Engine:** Assigns numerical risk scores and levels.
        - **UEBA Engine:** Flags unusual behaviour based on deviations from
          typical patterns.
        - **Incident Correlator:** Groups related events into incidents.
        - **AI Agent:** Generates human-readable explanations and answers
          questions about the incidents.
        - **Case Manager:** Enables analysts to update status, priority and
          notes for each incident.
        - **Report Generator:** Produces CSV reports for detailed analysis and
          summary statistics.
        """)

if __name__ == '__main__':
    main()
