"""
preprocessor.py
----------------

Lightweight preprocessing routines for security logs.

This module provides a function to clean and prepare DataFrames of log events
before passing them to detection engines. The goal is not heavy feature
engineering but rather simple normalization like lowercasing usernames,
filling missing values, trimming whitespace and ordering events by timestamp.

Example::

    from src.log_parser import load_log
    from src.preprocessor import preprocess

    df = load_log("sample_logs/normal_activity_logs.csv")
    df = preprocess(df)
"""

import pandas as pd

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    """
    Perform simple preprocessing on the log DataFrame.

    - Lowercase usernames and IP fields
    - Strip whitespace from string columns
    - Fill missing values with sensible defaults
    - Sort events by timestamp ascending

    Parameters
    ----------
    df: pandas.DataFrame
        Raw log data.

    Returns
    -------
    pandas.DataFrame
        Cleaned log data.
    """
    # Lowercase certain columns
    for col in ['username','source_ip','asset','action','status','event_message']:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.lower()

    # Fill missing strings with empty string
    str_cols = ['username','source_ip','asset','action','status','event_message']
    for col in str_cols:
        if col in df.columns:
            df[col] = df[col].fillna('')

    # Fill missing bytes_sent with zero
    if 'bytes_sent' in df.columns:
        df['bytes_sent'] = df['bytes_sent'].fillna(0).astype(int)

    # Sort by timestamp
    if 'timestamp' in df.columns:
        df = df.sort_values('timestamp').reset_index(drop=True)

    return df
