"""
log_parser.py
----------------

Utility functions for loading and normalizing security log data.

This module provides a simple interface to load various CSV log files and
normalize column names so that downstream modules can operate on a consistent
schema. It does not attempt to cleanse data exhaustively; instead it
standardizes common fields such as timestamp, username, source_ip, asset, action,
status, bytes_sent and event_message. Additional columns present in a log are
preserved for later analysis.

Example usage::

    from src.log_parser import load_log
    df = load_log("sample_logs/brute_force_logs.csv")

The resulting DataFrame will have at minimum the following columns:

    - timestamp (datetime64)
    - username (str)
    - source_ip (str)
    - asset (str)
    - action (str)
    - status (str)
    - event_message (str)
    - bytes_sent (int, optional)

Any additional columns are preserved as-is.
"""

import pandas as pd
import numpy as np

# Map possible column names to our canonical names
COLUMN_ALIASES = {
    'time': 'timestamp',
    'date': 'timestamp',
    'datetime': 'timestamp',
    'user': 'username',
    'usr': 'username',
    'src_ip': 'source_ip',
    'source': 'source_ip',
    'dest_ip': 'destination_ip',
    'dst_ip': 'destination_ip',
    'host': 'asset',
    'device': 'asset',
    'object': 'asset',
    'msg': 'event_message',
    'message': 'event_message',
    'action_type': 'action',
    'result': 'status',
    'bytes': 'bytes_sent',
}

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename DataFrame columns using COLUMN_ALIASES and ensure required columns exist."""
    # Rename using aliases
    rename_map = {col: COLUMN_ALIASES.get(col.lower(), col.lower()) for col in df.columns}
    df = df.rename(columns=rename_map)

    # Ensure canonical columns exist
    required = ['timestamp','username','source_ip','asset','action','status','event_message']
    for col in required:
        if col not in df.columns:
            # Fill missing columns with default values
            if col == 'bytes_sent':
                df[col] = 0
            else:
                df[col] = ''

    # Convert timestamp column to datetime
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # bytes_sent to numeric if present
    if 'bytes_sent' in df.columns:
        df['bytes_sent'] = pd.to_numeric(df['bytes_sent'], errors='coerce').fillna(0).astype(int)
    return df

def load_log(path: str) -> pd.DataFrame:
    """
    Load a CSV log file and normalize its columns.

    Parameters
    ----------
    path: str
        Path to the CSV file to load.

    Returns
    -------
    pandas.DataFrame
        A DataFrame with standardized columns.
    """
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        raise IOError(f"Failed to load log file {path}: {exc}")
    df = _normalize_columns(df)
    return df
