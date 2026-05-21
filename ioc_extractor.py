"""
ioc_extractor.py
----------------

Extract indicators of compromise (IOCs) from logs. For demonstration, this
module focuses on extracting IP addresses, usernames, ports and keywords from
the log events.
"""

import pandas as pd

def extract_iocs(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build a table of IOCs found in the log DataFrame.

    Parameters
    ----------
    df: pandas.DataFrame
        DataFrame of log events.

    Returns
    -------
    pandas.DataFrame
        A DataFrame containing unique IOCs with type and count.
    """
    iocs = []
    # IPs
    for ip, count in df['source_ip'].value_counts().items():
        iocs.append({'ioc': ip, 'type': 'IP', 'count': count})
    # Users
    for user, count in df['username'].value_counts().items():
        iocs.append({'ioc': user, 'type': 'User', 'count': count})
    # Ports from event_message
    df_ports = df['event_message'].str.extractall(r'port\s(\d+)')[0].value_counts()
    for port, count in df_ports.items():
        iocs.append({'ioc': str(port), 'type': 'Port', 'count': count})
    # Keywords (very simple example)
    keywords = ['failed', 'blocked', 'transferred', 'suspicious']
    for kw in keywords:
        count = df['event_message'].str.contains(kw, case=False, na=False).sum()
        if count > 0:
            iocs.append({'ioc': kw, 'type': 'Keyword', 'count': count})
    return pd.DataFrame(iocs)
