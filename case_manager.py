"""
case_manager.py
----------------

Simplistic incident case management. This module adds and updates case
information such as status, analyst notes and priority. It operates on a
DataFrame of incidents (one row per event) and allows storing case-level
details in a separate dictionary keyed by incident_id.

The module does not persist data between sessions; it exists solely to
support demonstration workflows in the Streamlit app.
"""

from typing import Dict

# Possible statuses for cases
STATUSES = ['Open','Investigating','Resolved','False Positive','Needs Review']

# Global in-memory storage for case data
_case_store: Dict[str, dict] = {}

def initialize_case(incident_id: str) -> None:
    """
    Ensure an incident has an entry in the case store.
    """
    if incident_id not in _case_store:
        _case_store[incident_id] = {
            'status': 'Open',
            'priority': 'Medium',
            'analyst': '',
            'notes': ''
        }

def get_case(incident_id: str) -> dict:
    """Return the case record for a given incident_id."""
    return _case_store.get(incident_id, {'status':'Open','priority':'Medium','analyst':'','notes':''})

def update_case(incident_id: str, status: str = None, priority: str = None, analyst: str = None, notes: str = None) -> None:
    """
    Update fields for a given incident's case record.
    """
    initialize_case(incident_id)
    record = _case_store[incident_id]
    if status and status in STATUSES:
        record['status'] = status
    if priority:
        record['priority'] = priority
    if analyst is not None:
        record['analyst'] = analyst
    if notes is not None:
        record['notes'] = notes
