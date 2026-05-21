"""
incident_correlator.py
----------------------

This module groups related events into high-level incidents. The goal is to
provide a basic correlation engine that produces incident identifiers, which
can be used to track and investigate clusters of malicious activity. Events
are grouped primarily by source IP, threat type and a rolling time window.

The algorithm implemented here is simplistic: for each threat type and source
IP, events occurring within a one hour window are grouped into the same
incident. Each distinct combination is assigned a unique identifier.
"""

import pandas as pd
from datetime import timedelta

def correlate_incidents(df: pd.DataFrame, window_minutes: int = 60) -> pd.DataFrame:
    """
    Assign an 'incident_id' to each row based on source_ip, threat_type and
    temporal proximity.

    Parameters
    ----------
    df: pandas.DataFrame
        DataFrame containing at minimum timestamp, source_ip and threat_type.
    window_minutes: int
        The time window in minutes within which events are grouped together.

    Returns
    -------
    pandas.DataFrame
        DataFrame with a new 'incident_id' column.
    """
    df = df.copy()
    df = df.sort_values('timestamp').reset_index(drop=True)
    incident_ids = []
    current_id = 0
    last_key = None
    last_time = None
    window = timedelta(minutes=window_minutes)
    for idx, row in df.iterrows():
        key = (row['source_ip'], row['threat_type'])
        time = row['timestamp']
        if last_key is None or key != last_key or (time - last_time) > window:
            # Start a new incident
            current_id += 1
        incident_ids.append(f"CSX-{current_id:04d}")
        last_key = key
        last_time = time
    df['incident_id'] = incident_ids
    return df
