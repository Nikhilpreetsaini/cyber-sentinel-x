"""
mitre_mapper.py
---------------

This module maps threat categories to simplified MITRE ATT&CK tactics and
techniques based on a data file. The mapping is intended for educational
purposes and does not claim comprehensive coverage. See `data/mitre_mapping.csv`
for details.
"""

import pandas as pd
import os

_MAPPING = None

def _load_mapping() -> pd.DataFrame:
    global _MAPPING
    if _MAPPING is None:
        path = os.path.join(os.path.dirname(__file__), '../data/mitre_mapping.csv')
        path = os.path.abspath(path)
        _MAPPING = pd.read_csv(path)
    return _MAPPING

def map_threat(threat_type: str) -> dict:
    """
    Return a dictionary containing tactic, technique and technique_id for a
    given threat_type.

    Parameters
    ----------
    threat_type: str
        The high-level threat category.

    Returns
    -------
    dict
        A mapping with keys 'tactic', 'technique' and 'technique_id'. If the
        threat_type is unknown, all values will be 'NA'.
    """
    df = _load_mapping()
    row = df[df['threat_type'].str.lower() == threat_type.lower()]
    if row.empty:
        return {'tactic':'NA','technique':'NA','technique_id':'NA'}
    r = row.iloc[0]
    return {'tactic': r['tactic'], 'technique': r['technique'], 'technique_id': r['technique_id']}
