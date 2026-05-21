"""
timeline_builder.py
-------------------

Helper functions for constructing attack timelines. Given a DataFrame of
security events with incident identifiers, this module can produce a sorted
subset of events for a given incident, suitable for display in a timeline
view.
"""

import pandas as pd

def build_timeline(df: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    """
    Return a DataFrame containing events for a specific incident, ordered by
    timestamp.

    Parameters
    ----------
    df: pandas.DataFrame
        DataFrame containing at minimum 'incident_id' and 'timestamp'.
    incident_id: str
        The incident identifier to filter by.

    Returns
    -------
    pandas.DataFrame
        Sorted DataFrame subset for the given incident.
    """
    subset = df[df['incident_id'] == incident_id].copy()
    subset = subset.sort_values('timestamp').reset_index(drop=True)
    return subset
