import streamlit as st
import pandas as pd
import os
import plotly.express as px

"""
Simplified Cyber Sentinel X Streamlit App
-----------------------------------------
This version implements core functionality for educational purposes without
external dependencies. It reads CSV logs, performs rudimentary threat detection,
computes simple risk scores, correlates incidents, and provides basic
visualisations and reporting. The goal is to provide a working demo within
Streamlit Cloud while more advanced modules (AI agent, threat intelligence,
MITRE mapping, etc.) can be implemented later.

Disclaimer: This is not intended for production use and does not perform
real-world intrusion detection.
"""

# --------- Helper functions ---------

# L

# Deduplicate column names and ensure no blank names
def dedup_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure no blank or duplicate column names by renaming them."""
    df = df.copy()
    # Replace blank column names with generated names
    new_cols = []
    seen = {}
    for i, col in enumerate(df.columns):
        name = str(col).strip()
        if name == '':
            name = f'Unnamed_{i}'
        # Handle duplicates
        if name in seen:
            seen[name] += 1
            name = f"{name}_{seen[name]}"
        else:
            seen[name] = 0
        new_cols.append(name)
    df.columns = new_cols
    return df
og loader
def load_log(path: str) -> pd.DataFrame:
    """Load a CSV log file into a DataFrame."""
        df = pd.read_csv(path, mangle_dupe_cols=True)
    df = dedup_columns(df)
    return df

# Preprocess logs
def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    """Preprocess events: parse timestamps and derive additional fields."""
    df = df.copy()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['hour'] = df['timestamp'].dt.hour
    else:
        # if no timestamp, create a dummy
        df['timestamp'] = pd.to_datetime('now')
        df['hour'] = df['timestamp'].dt.hour
    # fill missing columns
    for col in ['username','source_ip','asset','action','status']:
        if col not in df.columns:
            df[col] = ''
    return df

# Threat detection heuristics
def detect_threats(df: pd.DataFrame) -> pd.DataFrame:
    """Assign a simple threat type based on action or status."""
    df = df.copy()
    threat_types = []
    for _, row in df.iterrows():
        action = str(row.get('action','')).lower()
        status = str(row.get('status','')).lower()
        if 'failed' in status or 'unauthorized' in status:
            threat_types.append('Brute Force')
        elif 'scan' in action:
            threat_types.append('Port Scan')
        elif 'malware' in action or 'malicious' in status:
            threat_types.append('Malware-like')
        else:
            threat_types.append('Normal Activity')
    df['threat_type'] = threat_types
    return df

# Risk scoring
def compute_risk(df: pd.DataFrame) -> pd.DataFrame:
    """Compute a risk score and level based on threat type."""
    df = df.copy()
    scores = []
    levels = []
    for t in df['threat_type']:
        if t == 'Brute Force':
            score = 80
            level = 'High'
        elif t == 'Port Scan':
            score = 60
            level = 'Medium'
        elif t == 'Malware-like':
            score = 90
            level = 'Critical'
        else:
            score = 10
            level = 'Low'
        scores.append(score)
        levels.append(level)
    df['risk_score'] = scores
    df['risk_level'] = levels
    return df

# UEBA placeholder (no modifications)
def analyse_ueba(df: pd.DataFrame) -> pd.DataFrame:
    return df

# Incident correlation
def correlate_incidents(df: pd.DataFrame) -> pd.DataFrame:
    """Group events into incidents by threat type and assign IDs."""
    df = df.copy()
    incident_ids = []
    id_counter = 1
    last_type = None
    for t in df['threat_type']:
        if t != last_type:
            incident_id = f'INC{id_counter:04d}'
            id_counter += 1
            last_type = t
        incident_ids.append(incident_id)
    df['incident_id'] = incident_ids
    return df

# Timeline builder
def build_timeline(df: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    return df[df['incident_id']==incident_id].sort_values('timestamp')

# Simple explanation
def explain_incident(inc_df: pd.DataFrame) -> str:
    t = inc_df['threat_type'].iloc[0]
    level = inc_df['risk_level'].iloc[0]
    score = inc_df['risk_score'].iloc[0]
    ip = inc_df['source_ip'].iloc[0]
    user = inc_df['username'].iloc[0]
    return (f"Incident {inc_df['incident_id'].iloc[0]} involves {t} activity from user '{user}' "
            f"at IP {ip}. It has risk score {score} ({level}).")

# Answer questions (very limited)
def answer_question(question: str, df: pd.DataFrame) -> str:
    q = question.lower()
    if 'most critical' in q:
        idx = df['risk_score'].idxmax()
        inc = df.loc[idx]
        return (f"Incident {inc['incident_id']} ({inc['threat_type']}) has the highest risk score {inc['risk_score']} "
                f"({inc['risk_level']}) from IP {inc['source_ip']}.")
    return "Please upload and process logs to ask questions about incidents."

# MITRE mapping stub
def map_threat(threat_type: str) -> str:
    mapping = {
        'Brute Force': 'Credential Access',
        'Port Scan': 'Discovery',
        'Malware-like': 'Execution',
        'Normal Activity': 'NA'
    }
    return mapping.get(threat_type, 'NA')

# Threat intelligence stub
def lookup_ip(ip: str) -> dict:
    return {'reputation':'Unknown','category':'Unknown','confidence':0.5,'action':'Monitor'}

# Report generator
def incident_report(df: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    return df[df['incident_id']==incident_id]

def summary_report(df: pd.DataFrame) -> pd.DataFrame:
    return df.groupby(['threat_type','risk_level']).size().reset_index(name='count')

# Case management
cases = {}
STATUSES = ['New','Investigating','Closed']

def initialize_case(inc_id: str):
    if inc_id not in cases:
        cases[inc_id] = {'status':'New','priority':'Medium','analyst':'','notes':''}

def get_case(inc_id: str) -> dict:
    return cases.get(inc_id, {'status':'New','priority':'Medium','analyst':'','notes':''})

def update_case(inc_id: str, status: str, priority: str, analyst: str, notes: str):
    cases[inc_id] = {'status':status,'priority':priority,'analyst':analyst,'notes':notes}

# Visualisations

def threat_distribution(df: pd.DataFrame):
    counts = df['threat_type'].value_counts().reset_index()
    counts.columns = ['threat_type','count']
    fig = px.bar(counts, x='threat_type', y='count', title='Threat Distribution')
    return fig

def risk_distribution(df: pd.DataFrame):
    counts = df['risk_level'].value_counts().reset_index()
    counts.columns = ['risk_level','count']
    fig = px.bar(counts, x='risk_level', y='count', title='Risk Level Distribution')
    return fig

def timeline_chart(df: pd.DataFrame):
    df = df.sort_values('timestamp')
    fig = px.line(df, x='timestamp', y='risk_score', color='incident_id', title='Risk over Time')
    return fig

def risk_heatmap(df: pd.DataFrame, index: str, column: str):
    pivot = pd.pivot_table(df, values='risk_score', index=index, columns=column, aggfunc='mean', fill_value=0)
    fig = px.imshow(pivot, labels={'x':column,'y':index,'color':'avg_risk'}, title='Risk Heatmap')
    return fig

def relationship_graph(df: pd.DataFrame):
    # simple scatter plot linking source_ip and username
    fig = px.scatter(df, x='source_ip', y='username', size='risk_score', color='threat_type', title='IP vs User Relationships')
    return fig

def extract_iocs(df: pd.DataFrame) -> pd.DataFrame:
    # extract IP counts
    return df['source_ip'].value_counts().reset_index().rename(columns={'index':'source_ip','source_ip':'count'})

# --------- Streamlit app ---------

def process_events(df: pd.DataFrame) -> pd.DataFrame:
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
            total_events = len(df)
            total_incidents = df['incident_id'].nunique()
            critical_incidents = (df['risk_level'] == 'Critical').sum()
            high_incidents = (df['risk_level'] == 'High').sum()
            unique_ips = df['source_ip'].nunique()
            unique_users = df['username'].nunique()
            avg_risk = round(df['risk_score'].mean(), 2) if not df.empty else 0
            cols = st.columns(6)
            cols[0].metric("Events", total_events)
            cols[1].metric("Incidents", total_incidents)
            cols[2].metric("Unique IPs", unique_ips)
            cols[3].metric("Unique Users", unique_users)
            cols[4].metric("Critical Incidents", critical_incidents)
            cols[5].metric("Avg Risk Score", avg_risk)
            st.plotly_chart(threat_distribution(df), use_container_width=True)
            st.plotly_chart(risk_distribution(df), use_container_width=True)
            st.plotly_chart(timeline_chart(df), use_container_width=True)
            st.subheader("Top Source IPs")
            st.table(df['source_ip'].value_counts().head())
            st.subheader("Top Users")
            st.table(df['username'].value_counts().head())

    elif page == "Upload Logs":
        st.title("Upload or Generate Logs")
        uploaded_file = st.file_uploader("Upload CSV Log File", type=['csv'])
        sample_files = []
        if os.path.exists('sample_logs'):
            sample_files = os.listdir('sample_logs')
        st.markdown("**Or load a sample demo log:**")
        sample_choice = st.selectbox("Select sample log", [''] + sample_files)
        if st.button("Load Sample Log") and sample_choice:
            df = load_log(os.path.join('sample_logs', sample_choice))
            df = preprocess(df)
            st.session_state['events'] = df
            st.session_state['processed'] = process_events(df)
            st.success(f"Loaded {len(df)} events from sample log {sample_choice}.")
        if uploaded_file is not None:
                    df = load_log(uploaded_file)
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
            st.dataframe(
                df_filtered[
                    [
                        'timestamp','username','source_ip','asset','action','status',
                        'threat_type','risk_level','risk_score','incident_id'
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
            incidents = df[['incident_id','threat_type','risk_level','risk_score']].drop_duplicates()
            selected = st.selectbox("Select an incident", incidents['incident_id'])
            inc_df = df[df['incident_id']==selected]
            if not inc_df.empty:
                initialize_case(selected)
                case = get_case(selected)
                st.subheader(f"Incident {selected}")
                st.write(f"Threat Type: {inc_df['threat_type'].iloc[0]}")
                st.write(f"Risk Score: {inc_df['risk_score'].iloc[0]} ({inc_df['risk_level'].iloc[0]})")
                st.write(f"Source IP: {inc_df['source_ip'].iloc[0]}")
                st.write(f"Target User: {inc_df['username'].iloc[0]}")
                st.write(f"MITRE Mapping: {map_threat(inc_df['threat_type'].iloc[0])}")
                st.subheader("Timeline")
                st.table(build_timeline(inc_df, selected)[['timestamp','action','status','threat_type']])
                st.subheader("Case Details")
                status = st.selectbox("Status", STATUSES, index=STATUSES.index(case['status']))
                priority = st.selectbox("Priority", ['Low','Medium','High','Critical'], index=['Low','Medium','High','Critical'].index(case.get('priority','Medium')))
                analyst = st.text_input("Assigned Analyst", value=case.get('analyst',''))
                notes = st.text_area("Analyst Notes", value=case.get('notes',''))
                if st.button("Update Case"):
                    update_case(selected, status=status, priority=priority, analyst=analyst, notes=notes)
                    st.success("Case updated.")
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
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download All Events (CSV)", csv, file_name="events.csv", mime='text/csv')
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
        analytics techniques. This simplified version implements core logic without
        external module dependencies to run seamlessly on Streamlit Cloud.

        **Key modules implemented here:**
        - **Log Loader & Preprocessor:** Reads CSV logs and parses timestamps.
        - **Threat Detector:** Applies heuristic rules to classify events into high-level threat categories.
        - **Risk Engine:** Assigns risk scores and levels based on threat type.
        - **Incident Correlator:** Groups related events into incidents.
        - **Visualiser:** Generates bar charts, heatmaps and relationship graphs.
        - **Case Manager:** Enables analysts to update status, priority and notes for each incident.
        - **Report Generator:** Produces CSV reports for detailed analysis and summary statistics.
        """)

if __name__ == '__main__':
    main()
