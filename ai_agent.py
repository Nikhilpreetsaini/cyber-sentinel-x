"""
ai_agent.py
-----------

Rule-based AI assistant for explaining threats and answering questions. This
module simulates a security analyst's reasoning with deterministic templates
instead of leveraging large language models. The agent produces natural
language descriptions of incidents and can respond to a limited set of
questions about the detected threats and risk analytics.

For the purposes of this project, the agent operates on a DataFrame of
incidents with the following expected columns:

    - incident_id
    - threat_type
    - risk_score
    - risk_level
    - source_ip
    - username
    - confidence
    - event_message

Functions:

    explain_incident(df):
        Produce a descriptive paragraph for a single-incident DataFrame.

    answer_question(question, df):
        Respond to basic queries such as:
        - Why is this IP suspicious?
        - What is the most critical incident?
        - Which user is most targeted?
        - Summarize today’s threats.
        - What action should the admin take?
        - Explain this incident for a non-technical manager.
        - Generate an executive summary.
        - Create an incident response report.
"""

import pandas as pd
from collections import Counter
from typing import Optional
from .mitre_mapper import map_threat
from .threat_intel import lookup_ip
from .risk_engine import classify_risk
from .playbooks import get_playbook


def explain_incident(incident_df: pd.DataFrame) -> str:
    """
    Generate a human-readable explanation for a given incident.

    Parameters
    ----------
    incident_df: pandas.DataFrame
        DataFrame containing events belonging to a single incident.

    Returns
    -------
    str
        A descriptive explanation of the incident.
    """
    threat_type = incident_df['threat_type'].iloc[0]
    risk_level = incident_df['risk_level'].iloc[0]
    risk_score = incident_df['risk_score'].iloc[0]
    source_ip = incident_df['source_ip'].iloc[0]
    user = incident_df['username'].iloc[0]
    intel = lookup_ip(source_ip)
    mitre = map_threat(threat_type)
    explanation = []
    explanation.append(f"Incident Summary: The system detected a {threat_type} involving user '{user}' from source IP {source_ip}.")
    explanation.append(f"Risk Assessment: This incident has a risk score of {risk_score} and is classified as {risk_level} risk.")
    if intel['reputation'] != 'Unknown':
        explanation.append(f"Threat Intelligence: The IP {source_ip} is marked as {intel['reputation']} ({intel['category']}) with confidence {intel['confidence']:.0%}.")
    if mitre['tactic'] != 'NA':
        explanation.append(f"MITRE Mapping: According to the MITRE ATT&CK framework, this corresponds to technique {mitre['technique_id']} ({mitre['technique']}) within the {mitre['tactic']} tactic.")
    # Suggest actions
    actions = get_playbook(threat_type)
    if actions:
        explanation.append("Recommended Response: " + '; '.join(actions) + '.')
    return ' '.join(explanation)


def answer_question(question: str, df: pd.DataFrame) -> str:
    """
    Provide a canned response to a limited set of questions about the incidents.

    Parameters
    ----------
    question: str
        A user query.
    df: pandas.DataFrame
        Full incident-level DataFrame (one row per event with incident_id).

    Returns
    -------
    str
        A human-readable response.
    """
    q = question.strip().lower()
    if 'most critical' in q or ('highest' in q and 'incident' in q):
        # Identify incident with highest risk score
        idx = df['risk_score'].idxmax()
        incident = df.loc[idx]
        return (f"The most critical incident is {incident['incident_id']} with a risk score of {incident['risk_score']} "
                f"({incident['risk_level']} risk). It involves {incident['threat_type']} from IP {incident['source_ip']} targeting user {incident['username']}.")
    if 'most targeted' in q or 'which user' in q:
        user_counts = df['username'].value_counts()
        user = user_counts.idxmax()
        count = user_counts.max()
        return f"User '{user}' appears most frequently in the log with {count} events."
    if 'summarize today' in q or 'summary' in q:
        total = len(df)
        threats = df['threat_type'].value_counts()
        summary_parts = [f"{t}: {c} occurrences" for t, c in threats.items()]
        return f"Today, the system analyzed {total} events. Detected threats include: " + '; '.join(summary_parts) + '.'
    if 'what action' in q:
        # Provide general actions based on top threat
        top_threat = df['threat_type'].value_counts().idxmax()
        actions = get_playbook(top_threat)
        if actions:
            return f"For a {top_threat} incident, recommended actions are: " + '; '.join(actions) + '.'
        return f"The recommended actions depend on the threat type."
    if 'manager' in q or 'non-technical' in q:
        # Provide high-level explanation of highest-risk incident
        idx = df['risk_score'].idxmax()
        incident = df.loc[idx]
        return (f"Incident {incident['incident_id']} is classified as {incident['risk_level']} risk due to {incident['threat_type']} activity. "
                "The security system detected unusual behaviour and recommends immediate attention.")
    if 'executive summary' in q:
        total = len(df)
        high_count = (df['risk_level'].isin(['High','Critical'])).sum()
        return (f"Executive Summary: The system processed {total} events. {high_count} events were flagged as high or critical risk. "
                "The main issues observed include: " + ', '.join(df['threat_type'].value_counts().index.tolist()) + '.')
    if 'incident response report' in q:
        # Provide generic statement
        return "The incident response report can be downloaded from the Report Generator tab as a CSV or PDF."
    if 'ip suspicious' in q:
        # Extract IP from question
        words = question.split()
        ip = None
        for w in words:
            if w.count('.') == 3:
                ip = w
                break
        if ip:
            intel = lookup_ip(ip)
            return (f"IP {ip} has reputation {intel['reputation']} ({intel['category']}) with confidence {intel['confidence']:.0%}. "
                    f"Recommended action: {intel['action']}")
    return "I'm sorry, I can only answer specific questions about threats and incidents."
