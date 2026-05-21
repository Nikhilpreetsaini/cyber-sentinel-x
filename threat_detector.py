"""
threat_detector.py
-------------------

This module contains logic for classifying log events into high-level threat
categories. The goal is not to implement a comprehensive intrusion detection
system but to provide reasonable heuristics that allow demonstration of a
cybersecurity analytics workflow.

Threat categories supported include:

    - Brute Force
    - Password Spraying
    - Port Scan
    - Malware-like Activity
    - Data Exfiltration
    - Privilege Abuse
    - Suspicious Login
    - Admin Account Targeting
    - Unusual Login Time
    - Unknown IP Login
    - Repeated Blocked Firewall Events
    - Normal Activity

The detection logic here is intentionally simple. For a production system,
advanced analytics and machine learning models would be warranted.
"""

import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from datetime import timedelta


def detect_threats(df: pd.DataFrame) -> pd.DataFrame:
    """
    Annotate the DataFrame with a 'threat_type' column based on simple rules.

    Parameters
    ----------
    df: pandas.DataFrame
        Preprocessed log events.

    Returns
    -------
    pandas.DataFrame
        DataFrame with a new 'threat_type' column.
    """
    df = df.copy()
    # Default threat type
    df['threat_type'] = 'Normal Activity'

    # Precompute counts for brute force/password spraying detection
    # Count failed login per ip/user within the dataset
    failed_login_counts_ip = defaultdict(int)
    failed_login_counts_user = defaultdict(int)
    combo_counts = defaultdict(int)
    for _, row in df.iterrows():
        if row['action'] == 'login' and row['status'] == 'failure':
            failed_login_counts_ip[row['source_ip']] += 1
            failed_login_counts_user[row['username']] += 1
            combo_counts[(row['source_ip'], row['username'])] += 1

    # Identify IPs performing password spraying
    spraying_ips = {ip for ip, count in failed_login_counts_ip.items() if count >= 10 and len({u for (src,u),c in combo_counts.items() if src==ip}) > 3}
    # Identify user targeted for brute force
    brute_force_targets = {u for u, count in failed_login_counts_user.items() if count >= 10}

    # Iterate rows to assign threat types
    for idx, row in df.iterrows():
        action = row['action']
        status = row['status']
        msg = row['event_message']
        user = row['username']
        ip = row['source_ip']

        if action == 'process_blocked' or 'suspicious process' in msg:
            df.at[idx,'threat_type'] = 'Malware-like Activity'
            continue
        if 'connection attempt on port' in msg or action == 'connection_attempt':
            df.at[idx,'threat_type'] = 'Port Scan'
            continue
        if action == 'data_transfer' or 'transferred' in msg:
            # if bytes_sent large
            bytes_sent = row.get('bytes_sent',0)
            if bytes_sent >= 1000000:
                df.at[idx,'threat_type'] = 'Data Exfiltration'
                continue
        # Failed login patterns
        if action == 'login' and status == 'failure':
            if ip in spraying_ips:
                df.at[idx,'threat_type'] = 'Password Spraying'
            elif user in brute_force_targets:
                df.at[idx,'threat_type'] = 'Brute Force'
            continue
        if action == 'login' and status == 'success':
            # success after many failures
            if user in brute_force_targets or ip in spraying_ips:
                df.at[idx,'threat_type'] = 'Admin Account Targeting' if user=='admin' else 'Suspicious Login'
            elif row['username'] == 'admin':
                df.at[idx,'threat_type'] = 'Admin Account Targeting'
            continue
        # Unusual login time (outside 6am-10pm)
        if action == 'login' and status == 'success':
            ts=row['timestamp']
            if ts is not pd.NaT and (ts.hour < 6 or ts.hour > 22):
                df.at[idx,'threat_type'] = 'Unusual Login Time'
                continue
        # Unknown IP login (local addresses vs sample safe IPs). Mark internal addresses as normal.
        if action == 'login' and status == 'success':
            if ip.startswith('192.168.1.'):
                pass
            else:
                df.at[idx,'threat_type'] = 'Unknown IP Login'
                continue
        # Repeated blocked firewall events
        if action == 'connection_attempt' and status == 'blocked':
            df.at[idx,'threat_type'] = 'Repeated Blocked Firewall Events'
            continue
        # If admin performing unusual actions
        if user == 'admin' and action not in ['login','logout']:
            df.at[idx,'threat_type'] = 'Suspicious Admin Activity'
            continue
        # Data exfil for any file access with large bytes
        if row.get('bytes_sent',0) > 5000000:
            df.at[idx,'threat_type'] = 'Data Exfiltration'
            continue
    return df
