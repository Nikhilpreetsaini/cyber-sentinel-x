"""
ueba_engine.py
---------------

User and Entity Behavior Analytics (UEBA) module.

This module implements basic analytics to identify unusual behaviour in logs. The
intent is not to replicate enterprise-grade UEBA but to illustrate how one
might flag anomalies based on deviations from typical patterns. For each event,
a column 'ueba_anomaly' and 'ueba_reason' will be added indicating whether
unusual behaviour was detected and a textual reason for the anomaly.
"""

import pandas as pd

def analyse_ueba(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add UEBA anomaly detection columns to the DataFrame.

    Parameters
    ----------
    df: pandas.DataFrame
        DataFrame containing at least timestamp, username and source_ip.

    Returns
    -------
    pandas.DataFrame
        DataFrame with 'ueba_anomaly' (bool) and 'ueba_reason' (str) columns.
    """
    df = df.copy()
    df['ueba_anomaly'] = False
    df['ueba_reason'] = ''

    # Compute typical login hours for each user (simple median hour for successes)
    user_hours = {}
    for user in df['username'].unique():
        user_logins = df[(df['username'] == user) & (df['action'] == 'login') & (df['status'] == 'success')]
        if not user_logins.empty:
            median_hour = int(user_logins['timestamp'].dt.hour.median())
            user_hours[user] = median_hour
    
    # Track unique IPs per user and unique users per IP
    ips_by_user = df.groupby('username')['source_ip'].nunique().to_dict()
    users_by_ip = df.groupby('source_ip')['username'].nunique().to_dict()

    for idx, row in df.iterrows():
        reasons = []
        # Unusual login hour for user
        if row['action'] == 'login' and row['status'] == 'success':
            hour = row['timestamp'].hour if not pd.isna(row['timestamp']) else None
            median = user_hours.get(row['username'])
            if median is not None and hour is not None:
                if abs(hour - median) >= 6:  # difference greater than 6 hours
                    reasons.append('login outside usual hours')
        # Many IPs used by this user
        if ips_by_user.get(row['username'], 0) > 3:
            reasons.append('multiple IPs used by user')
        # Many users from same IP
        if users_by_ip.get(row['source_ip'], 0) > 3:
            reasons.append('multiple users from same IP')
        # Unknown IP range (not internal 192.168 or 10.x)
        ip = row['source_ip']
        if not (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')):
            reasons.append('unknown external IP')
        if reasons:
            df.at[idx,'ueba_anomaly'] = True
            df.at[idx,'ueba_reason'] = '; '.join(sorted(set(reasons)))
    return df
