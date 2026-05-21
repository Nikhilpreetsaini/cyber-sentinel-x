"""
playbooks.py
-------------

Load and provide recommended response playbooks for each threat type. The
playbooks are defined in JSON under ``data/response_playbooks.json`` and
returned as lists of actions.
"""

import json
import os

_PLAYBOOKS = None

def _load_playbooks() -> dict:
    global _PLAYBOOKS
    if _PLAYBOOKS is None:
        path = os.path.join(os.path.dirname(__file__), '../data/response_playbooks.json')
        path = os.path.abspath(path)
        with open(path, 'r') as f:
            _PLAYBOOKS = json.load(f)
    return _PLAYBOOKS

def get_playbook(threat_type: str) -> list:
    """
    Return a list of recommended actions for a given threat type.

    Parameters
    ----------
    threat_type: str
        The high-level threat category.

    Returns
    -------
    list of str
        A list of actions. If no playbook exists, an empty list is returned.
    """
    playbooks = _load_playbooks()
    return playbooks.get(threat_type, [])
