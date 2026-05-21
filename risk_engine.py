"""
risk_engine.py
---------------

This module assigns a numerical risk score to each event based on its threat type
and contextual attributes such as number of failed attempts and volume of data
transferred. A corresponding risk level (Low, Medium, High, Critical) and
confidence value are also computed. The goal is to provide a simple scoring
mechanism for demonstration purposes.
"""

import pandas as pd

THREAT_WEIGHTS = {
    'Brute Force': 80,
    'Password Spraying': 70,
    'Port Scan': 50,
    'Malware-like Activity': 85,
    'Data Exfiltration': 90,
    'Privilege Abuse': 75,
    'Suspicious Login': 60,
    'Admin Account Targeting': 90,
    'Unusual Login Time': 40,
    'Unknown IP Login': 50,
    'Repeated Blocked Firewall Events': 55,
    'Suspicious Admin Activity': 70,
    'Normal Activity': 10
}

def score_event(row: pd.Series) -> float:
    """Compute a risk score (0-100) for a single row."""
    base = THREAT_WEIGHTS.get(row['threat_type'], 10)
    score = base
    # Increase score for repeated failures (brute force/password spray)
    if row['threat_type'] in ['Brute Force','Password Spraying']:
        # if we have count field or event_message, use simple heuristics
        fails = 1
        if isinstance(row.get('event_message'), str) and 'failed' in row['event_message']:
            fails = 2
        score += min(20 * fails, 20)
    # Increase for data exfiltration volume
    if row['threat_type'] == 'Data Exfiltration':
        bytes_sent = row.get('bytes_sent',0)
        if bytes_sent:
            score += min(bytes_sent / 1_000_000, 10)  # add up to 10 points
    # Admin targeting increases score
    if row['threat_type'] == 'Admin Account Targeting':
        score += 10
    # Cap at 100
    score = max(0, min(100, score))
    return score

def classify_risk(score: float) -> str:
    """Convert a numerical score into a risk level."""
    if score >= 81:
        return 'Critical'
    elif score >= 61:
        return 'High'
    elif score >= 31:
        return 'Medium'
    else:
        return 'Low'

def compute_risk(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add risk_score, risk_level and confidence columns based on threat_type.

    Parameters
    ----------
    df: pandas.DataFrame
        DataFrame containing at least a 'threat_type' column.

    Returns
    -------
    pandas.DataFrame
        DataFrame with new risk_score, risk_level and confidence columns.
    """
    df = df.copy()
    df['risk_score'] = df.apply(score_event, axis=1)
    df['risk_level'] = df['risk_score'].apply(classify_risk)
    # Simple confidence: normalized risk score / 100
    df['confidence'] = (df['risk_score'] / 100.0).round(2)
    return df
