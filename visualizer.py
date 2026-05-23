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
import plotly.graph_objects as go

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


# -----------------------------------------------------------------------------
# Extended visualisations to support advanced analytics
# -----------------------------------------------------------------------------

def risk_heatmap(df: pd.DataFrame, index: str = 'username', column: str = 'risk_level',
                 values: str = 'risk_score', aggfunc: str = 'mean'):
    """Return a heatmap summarising risk across two dimensions.

    Parameters
    ----------
    df : DataFrame
        The processed events DataFrame. Must contain ``risk_score`` and
        ``risk_level`` columns as well as the specified ``index`` and
        ``column`` fields.
    index : str, optional
        The column to use for the y-axis (rows). Default is ``'username'``.
    column : str, optional
        The column to use for the x-axis (columns). Default is ``'risk_level'``.
    values : str, optional
        The column whose values will be aggregated. Default is ``'risk_score'``.
    aggfunc : str, optional
        The aggregation function to use. Accepts any valid Pandas aggregation
        function such as ``'mean'``, ``'sum'`` or ``'count'``. Default is
        ``'mean'``.

    Returns
    -------
    plotly.graph_objects.Figure
        A heatmap figure suitable for display in Streamlit.

    Notes
    -----
    If either the ``index`` or ``column`` is not present in the DataFrame,
    the function will raise a ``KeyError``. If the DataFrame is empty
    the resulting heatmap will be empty.
    """
    if df.empty:
        return px.imshow(pd.DataFrame())
    # Work on a copy to avoid modifying original
    tmp_df = df.copy()
    # Convert hour if requested
    if index == 'hour' and 'timestamp' in tmp_df.columns:
        tmp_df['hour'] = pd.to_datetime(tmp_df['timestamp']).dt.hour
    if column == 'hour' and 'timestamp' in tmp_df.columns:
        tmp_df['hour'] = pd.to_datetime(tmp_df['timestamp']).dt.hour
    # Build pivot table
    pivot = pd.pivot_table(tmp_df, index=index, columns=column, values=values,
                           aggfunc=aggfunc, fill_value=0)
    fig = px.imshow(pivot,
                    labels=dict(x=column, y=index,
                                color=f"{aggfunc.capitalize()} {values.replace('_',' ').title()}"),
                    title=f"Risk Heatmap ({index.title()} vs {column.title()})",
                    text_auto=True,
                    aspect='auto')
    return fig


def relationship_graph(df: pd.DataFrame):
    """Return a simple network graph linking source IPs, users, assets and threat types.

    The function constructs a layered network where each entity type occupies
    a vertical column. Source IP addresses appear in the first column,
    usernames in the second, assets in the third and threat types in the
    fourth. Lines connect related entities, illustrating how a single
    incident flows from the network edge through the user and asset to
    the identified threat category. This visualisation helps analysts
    quickly understand which users and assets are associated with each
    attacker and threat.

    Parameters
    ----------
    df : DataFrame
        The processed events DataFrame. Must contain columns
        ``source_ip``, ``username``, ``asset`` and ``threat_type``.

    Returns
    -------
    plotly.graph_objects.Figure
        A network graph figure suitable for display in Streamlit.
    """
    if df.empty:
        return go.Figure()
    # Extract unique values for each entity type
    src_ips = sorted(df['source_ip'].dropna().unique())
    users = sorted(df['username'].dropna().unique())
    assets = sorted(df['asset'].dropna().unique())
    threats = sorted(df['threat_type'].dropna().unique())
    # Build node positions: x coordinate by layer, y coordinate by index
    node_x: list[float] = []
    node_y: list[float] = []
    node_text: list[str] = []
    # Source IPs layer at x=0
    for i, val in enumerate(src_ips):
        node_x.append(0)
        node_y.append(i)
        node_text.append(val)
    # Users layer at x=1
    for i, val in enumerate(users):
        node_x.append(1)
        node_y.append(i)
        node_text.append(val)
    # Assets layer at x=2
    for i, val in enumerate(assets):
        node_x.append(2)
        node_y.append(i)
        node_text.append(val)
    # Threat types layer at x=3
    for i, val in enumerate(threats):
        node_x.append(3)
        node_y.append(i)
        node_text.append(val)
    # Map entity value to index in nodes list
    node_indices = {}
    idx = 0
    for val in src_ips:
        node_indices[('source_ip', val)] = idx
        idx += 1
    for val in users:
        node_indices[('username', val)] = idx
        idx += 1
    for val in assets:
        node_indices[('asset', val)] = idx
        idx += 1
    for val in threats:
        node_indices[('threat_type', val)] = idx
        idx += 1
    # Build edges: for each row, connect IP -> user -> asset -> threat type
    edge_x: list[float] = []
    edge_y: list[float] = []
    for _, row in df[['source_ip','username','asset','threat_type']].dropna().iterrows():
        # Source IP -> User
        i1 = node_indices[('source_ip', row['source_ip'])]
        i2 = node_indices[('username', row['username'])]
        edge_x += [node_x[i1], node_x[i2], None]
        edge_y += [node_y[i1], node_y[i2], None]
        # User -> Asset
        i1 = node_indices[('username', row['username'])]
        i2 = node_indices[('asset', row['asset'])]
        edge_x += [node_x[i1], node_x[i2], None]
        edge_y += [node_y[i1], node_y[i2], None]
        # Asset -> Threat
        i1 = node_indices[('asset', row['asset'])]
        i2 = node_indices[('threat_type', row['threat_type'])]
        edge_x += [node_x[i1], node_x[i2], None]
        edge_y += [node_y[i1], node_y[i2], None]
    # Create figure
    fig = go.Figure()
    # Add edges
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines',
                             line=dict(width=1, color='grey'),
                             hoverinfo='none'))
    # Add nodes
    fig.add_trace(go.Scatter(x=node_x, y=node_y, mode='markers+text',
                             marker=dict(size=10),
                             text=node_text, textposition='top center',
                             hoverinfo='text'))
    fig.update_layout(title="Relationship Graph (Source IP → User → Asset → Threat Type)",
                      xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      margin=dict(l=20, r=20, t=40, b=20))
    return fig
