"""
threat_intel.py
----------------

Simple threat intelligence lookup using a local CSV database. This module
provides functions to look up IP addresses and return their reputation,
category, confidence and recommended action. All data comes from
``data/threat_intel_sample.csv`` and is purely illustrative.
"""

import pandas as pd
import os

_INTEL_DF = None

def _load_intel() -> pd.DataFrame:
    global _INTEL_DF
    if _INTEL_DF is None:
        path = os.path.join(os.path.dirname(__file__), '../data/threat_intel_sample.csv')
        path = os.path.abspath(path)
        _INTEL_DF = pd.read_csv(path)
    return _INTEL_DF

def lookup_ip(ip: str) -> dict:
    """
    Look up the given IP address in the threat intelligence database.

    Parameters
    ----------
    ip: str
        IP address to look up.

    Returns
    -------
    dict
        A dictionary containing reputation, category, confidence and action.
    If the IP is not found, reputation will be 'Unknown'.
    """
    df = _load_intel()
    row = df[df['ip'] == ip]
    if row.empty:
        return {'reputation':'Unknown', 'category':'Unknown', 'confidence':0.0, 'action':'Monitor closely'}
    r = row.iloc[0]
    return {
        'reputation': r['reputation'],
        'category': r['category'],
        'confidence': float(r['confidence']),
        'action': r['action']
    }
