"""
visualizer.py
-------------

Utility functions for creating simple visualisations of the security analysis
data. These functions return Plotly Figure objects that can be displayed in
Streamlit using ``st.plotly_chart``. The charts are deliberately simple and
avoid specifying custom colours to let Streamlit apply its default theme.
"""

import pandas as pd
import plotly.express as px

def threat_distribution(df: pd.DataFrame):
    """Return a bar chart of event counts by threat type."""
    counts = df['threat_type'].value_counts().reset_index()
    counts.columns = ['Threat Type','Count']
    fig = px.bar(counts, x='Threat Type', y='Count', title='Threat Distribution')
    return fig

def risk_distribution(df: pd.DataFrame):
    """Return a histogram of risk scores."""
    fig = px.histogram(df, x='risk_score', nbins=20, title='Risk Score Distribution')
    return fig

def timeline_chart(df: pd.DataFrame):
    """Return a scatter plot showing events over time coloured by threat type."""
    fig = px.scatter(df, x='timestamp', y='risk_score', color='threat_type',
                     title='Event Timeline', labels={'risk_score':'Risk Score'})
    return fig
