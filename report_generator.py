"""
report_generator.py
-------------------

Utilities for generating tabular reports from the incident data. This module
provides functions to prepare incident-level reports and executive summaries
that can be downloaded as CSV files or rendered in the Streamlit app.
"""

import pandas as pd
from .mitre_mapper import map_threat
from .threat_intel import lookup_ip
from .playbooks import get_playbook

def incident_report(df: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    """
    Build a detailed report for a single incident.
    
    Parameters
    ----------
    df: pandas.DataFrame
        Full events DataFrame with incident annotations.
    incident_id: str
        The incident identifier.
    
    Returns
    -------
    pandas.DataFrame
        Report DataFrame summarizing the incident.
    """
    subset = df[df['incident_id'] == incident_id].copy()
    if subset.empty:
        return pd.DataFrame()
    row = subset.iloc[0]
    mitre = map_threat(row['threat_type'])
    intel = lookup_ip(row['source_ip'])
    report_rows = []
    for _, r in subset.iterrows():
        report_rows.append({
            'Incident ID': incident_id,
            'Timestamp': r['timestamp'],
            'User': r['username'],
            'Source IP': r['source_ip'],
            'Asset': r['asset'],
            'Action': r['action'],
            'Status': r['status'],
            'Event Message': r['event_message'],
            'Threat Type': r['threat_type'],
            'Risk Score': r['risk_score'],
            'Risk Level': r['risk_level'],
            'Confidence': r['confidence'],
            'MITRE Technique': mitre['technique_id'],
            'MITRE Tactic': mitre['tactic'],
            'IP Reputation': intel['reputation'],
            'IP Category': intel['category'],
            'IP Confidence': intel['confidence'],
            'Recommended Actions': '; '.join(get_playbook(r['threat_type']))
        })
    return pd.DataFrame(report_rows)

def summary_report(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a high-level summary of incidents and risk levels.
    
    Returns
    -------
    pandas.DataFrame
        Summary statistics by threat type.
    """
    summary = df.groupby('threat_type').agg(
        incidents=('incident_id', lambda x: len(set(x))),
        events=('threat_type', 'count'),
        avg_risk=('risk_score','mean'),
        max_risk=('risk_score','max'),
        min_risk=('risk_score','min')
    ).reset_index().sort_values('events', ascending=False)
    return summary
