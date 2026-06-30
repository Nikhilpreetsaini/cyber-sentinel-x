from datetime import datetime, timedelta
import os

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

APP_NAME = "Cyber Sentinel X"
RISK_ORDER = ["Low", "Medium", "High", "Critical"]
CASE_STATUSES = ["New", "Investigating", "Contained", "Resolved", "False Positive"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
BASE_COLUMNS = ["timestamp", "username", "source_ip", "asset", "action", "status"]

THREAT_INTEL = {
    "45.155.205.233": {"reputation": "Malicious", "category": "Credential attack", "action": "Block and investigate"},
    "185.220.101.45": {"reputation": "Suspicious", "category": "Anonymizer/Tor", "action": "Challenge login and monitor"},
    "91.219.236.232": {"reputation": "Malicious", "category": "Malware C2", "action": "Isolate affected asset"},
    "203.0.113.77": {"reputation": "Suspicious", "category": "Scanning", "action": "Rate-limit and review firewall logs"},
}

MITRE = {
    "Brute Force": "Credential Access / Brute Force (T1110)",
    "Password Spray": "Credential Access / Password Spraying (T1110.003)",
    "Port Scan": "Discovery / Network Service Discovery (T1046)",
    "Malware-like": "Execution / User Execution (T1204)",
    "Data Exfiltration": "Exfiltration / Exfiltration Over Web Service (T1567)",
    "Suspicious Login": "Initial Access / Valid Accounts (T1078)",
    "Normal Activity": "No ATT&CK mapping",
}


def make_unique_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    seen = {}
    cols = []
    for i, col in enumerate(df.columns):
        name = str(col).strip() or f"Unnamed_{i}"
        if name in seen:
            seen[name] += 1
            name = f"{name}_{seen[name]}"
        else:
            seen[name] = 0
        cols.append(name)
    df.columns = cols
    return df


def load_log(source) -> pd.DataFrame:
    return make_unique_columns(pd.read_csv(source))


def demo_logs(rows: int = 240) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    start = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=rows)
    users = ["nikhil", "admin", "analyst1", "finance.user", "hr.user", "guest", "service.api"]
    assets = ["vpn-gateway", "web-01", "db-prod", "endpoint-22", "mail-server", "iam-console"]
    ips = ["10.0.0.12", "10.0.0.15", "192.168.1.25", "45.155.205.233", "185.220.101.45", "91.219.236.232", "203.0.113.77"]
    probs = [0.25, 0.23, 0.20, 0.10, 0.08, 0.06, 0.08]
    actions = ["login", "file_read", "process_start", "api_call", "dns_query", "network_scan", "data_transfer"]

    data = []
    for i in range(rows):
        ip = str(rng.choice(ips, p=probs))
        action = str(rng.choice(actions))
        status = str(rng.choice(["success", "success", "success", "failed", "blocked", "unauthorized"]))
        bytes_out = int(max(0, rng.normal(350_000, 200_000)))
        if ip in {"45.155.205.233", "185.220.101.45"}:
            action = "login"
            status = str(rng.choice(["failed", "unauthorized", "failed", "success"]))
        if ip == "203.0.113.77":
            action, status = "network_scan", "blocked"
        if ip == "91.219.236.232":
            action = str(rng.choice(["malware_process", "process_start", "data_transfer"]))
            status = str(rng.choice(["malicious", "blocked", "success"]))
            bytes_out = int(max(bytes_out, rng.normal(5_000_000, 900_000)))
        data.append({
            "timestamp": (start + timedelta(minutes=i * 8)).isoformat(sep=" "),
            "username": str(rng.choice(users)),
            "source_ip": ip,
            "asset": str(rng.choice(assets)),
            "action": action,
            "status": status,
            "bytes_out": bytes_out,
        })
    return pd.DataFrame(data)


def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    df = make_unique_columns(df).copy()
    for col in BASE_COLUMNS:
        if col not in df.columns:
            df[col] = "Unknown"
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().all():
        df["timestamp"] = [pd.Timestamp.now().floor("min") - pd.Timedelta(minutes=i) for i in range(len(df), 0, -1)]
    else:
        df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.now().floor("min"))
    df["hour"] = df["timestamp"].dt.hour
    for col in ["username", "source_ip", "asset", "action", "status"]:
        df[col] = df[col].fillna("Unknown").astype(str).str.strip().replace("", "Unknown")
    if "bytes_out" not in df.columns:
        df["bytes_out"] = 0
    df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0).clip(lower=0)
    return df


def detect_and_score(df: pd.DataFrame) -> pd.DataFrame:
    df = preprocess(df)
    failed_by_ip = df["source_ip"].where(df["status"].str.lower().str.contains("failed|unauthorized", regex=True, na=False)).value_counts()
    users_by_ip = df.groupby("source_ip")["username"].nunique()
    threats = []
    for _, row in df.iterrows():
        action = str(row["action"]).lower()
        status = str(row["status"]).lower()
        ip = str(row["source_ip"])
        bytes_out = float(row.get("bytes_out", 0) or 0)
        if "malware" in action or "malicious" in status:
            threat = "Malware-like"
        elif bytes_out >= 3_000_000 or ("data_transfer" in action and bytes_out >= 1_500_000):
            threat = "Data Exfiltration"
        elif "scan" in action:
            threat = "Port Scan"
        elif failed_by_ip.get(ip, 0) >= 5 and users_by_ip.get(ip, 0) >= 3:
            threat = "Password Spray"
        elif "failed" in status or "unauthorized" in status:
            threat = "Brute Force"
        elif row["hour"] in [0, 1, 2, 3, 4, 5] and not ip.startswith(("10.", "192.168.")):
            threat = "Suspicious Login"
        else:
            threat = "Normal Activity"
        threats.append(threat)
    df["threat_type"] = threats

    base = {"Normal Activity": 10, "Suspicious Login": 55, "Port Scan": 65, "Brute Force": 75, "Password Spray": 82, "Malware-like": 92, "Data Exfiltration": 94}
    df["risk_score"] = [min(100, base.get(t, 30) + (8 if ip in THREAT_INTEL else 0) + (5 if b >= 5_000_000 else 0)) for t, ip, b in zip(df["threat_type"], df["source_ip"], df["bytes_out"])]
    df["risk_level"] = pd.cut(df["risk_score"], bins=[-1, 39, 69, 84, 100], labels=RISK_ORDER).astype(str)
    df["ueba_flag"] = "Normal"
    df.loc[df.groupby("username")["source_ip"].transform("nunique") >= 4, "ueba_flag"] = "Multiple source IPs"
    df.loc[df["hour"].isin([0, 1, 2, 3, 4, 5]) & (df["risk_score"] >= 50), "ueba_flag"] = "Odd-hour risky activity"

    df = df.sort_values("timestamp").reset_index(drop=True)
    keys = {}
    ids = []
    for _, row in df.iterrows():
        if row["threat_type"] == "Normal Activity":
            ids.append("OBS-NORMAL")
        else:
            key = (row["source_ip"], row["threat_type"])
            keys.setdefault(key, len(keys) + 1)
            ids.append(f"INC{keys[key]:04d}")
    df["incident_id"] = ids
    return df


def ioc_summary(df: pd.DataFrame) -> pd.DataFrame:
    out = df["source_ip"].astype(str).value_counts().reset_index()
    out.columns = ["source_ip", "event_count"]
    out["reputation"] = out["source_ip"].apply(lambda ip: THREAT_INTEL.get(ip, {}).get("reputation", "Unknown"))
    out["recommended_action"] = out["source_ip"].apply(lambda ip: THREAT_INTEL.get(ip, {}).get("action", "Monitor"))
    return out


def answer(question: str, df: pd.DataFrame) -> str:
    q = question.lower()
    if df.empty:
        return "Load demo logs or upload a CSV first."
    if "critical" in q or "highest" in q or "dangerous" in q:
        row = df.loc[df["risk_score"].idxmax()]
        return f"Highest risk: {row['incident_id']} ({row['threat_type']}) from {row['source_ip']} against {row['asset']}, score {row['risk_score']} ({row['risk_level']})."
    if "ip" in q and ("suspicious" in q or "bad" in q or "malicious" in q):
        bad = ioc_summary(df).query("reputation in ['Malicious', 'Suspicious']")
        return "Suspicious IPs: " + "; ".join(f"{r.source_ip} ({r.reputation}, {r.event_count} events)" for r in bad.itertuples()) if not bad.empty else "No known suspicious IPs found."
    if "mitre" in q:
        threats = sorted(t for t in df["threat_type"].unique() if t != "Normal Activity")
        return "; ".join(f"{t}: {MITRE[t]}" for t in threats) if threats else "No MITRE mapping needed for normal-only activity."
    total = len(df)
    incidents = df[df["incident_id"] != "OBS-NORMAL"]["incident_id"].nunique()
    critical = int((df["risk_level"] == "Critical").sum())
    high = int((df["risk_level"] == "High").sum())
    top = df["threat_type"].value_counts().idxmax()
    return f"Executive summary: {total} events analysed, {incidents} incidents, {critical} critical events, {high} high-risk events. Most common classification: {top}."


def ensure_state() -> None:
    st.session_state.setdefault("processed", pd.DataFrame())
    st.session_state.setdefault("cases", {})
    st.session_state.setdefault("analyst_id", "Nikhil")


def main() -> None:
    st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
    ensure_state()
    st.sidebar.title(APP_NAME)
    st.sidebar.caption("Defensive AI SOC analyst demo")
    st.sidebar.text_input("Analyst ID", key="analyst_id")
    page = st.sidebar.radio("Navigation", ["Home", "Upload Logs", "Threat Detection", "Incident Investigation", "AI Security Agent", "Analytics", "Report Generator", "About"])
    df = st.session_state["processed"]

    if page == "Home":
        st.title("SOC Dashboard")
        if df.empty:
            st.info("Load demo logs or upload a CSV file to begin analysis.")
            if st.button("Load Built-in Demo Dataset"):
                st.session_state["processed"] = detect_and_score(demo_logs())
                st.rerun()
        else:
            non_normal = df[df["incident_id"] != "OBS-NORMAL"]
            metrics = [len(df), non_normal["incident_id"].nunique(), df["source_ip"].nunique(), df["username"].nunique(), int((df["risk_level"] == "Critical").sum()), round(float(df["risk_score"].mean()), 2)]
            labels = ["Events", "Incidents", "Unique IPs", "Unique Users", "Critical Events", "Avg Risk"]
            for col, label, value in zip(st.columns(6), labels, metrics):
                col.metric(label, value)
            st.plotly_chart(px.bar(df["threat_type"].value_counts().reset_index(), x="threat_type", y="count", title="Threat Distribution"), use_container_width=True)
            st.plotly_chart(px.line(df.sort_values("timestamp"), x="timestamp", y="risk_score", color="incident_id", title="Risk Over Time"), use_container_width=True)
            st.subheader("IOC Summary")
            st.dataframe(ioc_summary(df), use_container_width=True)

    elif page == "Upload Logs":
        st.title("Upload or Generate Logs")
        if st.button("Generate Professional Demo Logs", use_container_width=True):
            st.session_state["processed"] = detect_and_score(demo_logs())
            st.success("Demo logs generated and processed.")
            df = st.session_state["processed"]
        samples = sorted(f for f in os.listdir("sample_logs")) if os.path.isdir("sample_logs") else []
        if samples:
            sample = st.selectbox("Load sample CSV", [""] + samples)
            if st.button("Load Selected Sample") and sample:
                st.session_state["processed"] = detect_and_score(load_log(os.path.join("sample_logs", sample)))
                st.success(f"Loaded {sample}.")
        uploaded = st.file_uploader("Upload CSV Log File", type=["csv"])
        if uploaded is not None:
            try:
                st.session_state["processed"] = detect_and_score(load_log(uploaded))
                st.success(f"Uploaded and processed {uploaded.name}.")
            except Exception as exc:
                st.error(f"Could not process uploaded CSV: {exc}")
        if not st.session_state["processed"].empty:
            st.dataframe(st.session_state["processed"].head(80), use_container_width=True)

    elif page == "Threat Detection":
        st.title("Threat Detection & Risk Analysis")
        if df.empty:
            st.warning("No data available. Load logs first.")
        else:
            level = st.selectbox("Risk Level", ["All"] + RISK_ORDER)
            threat = st.selectbox("Threat Type", ["All"] + sorted(df["threat_type"].unique()))
            view = df.copy()
            if level != "All":
                view = view[view["risk_level"] == level]
            if threat != "All":
                view = view[view["threat_type"] == threat]
            st.dataframe(view[["timestamp", "username", "source_ip", "asset", "action", "status", "bytes_out", "threat_type", "risk_level", "risk_score", "ueba_flag", "incident_id"]], use_container_width=True)
            st.dataframe(ioc_summary(view), use_container_width=True)

    elif page == "Incident Investigation":
        st.title("Incident Investigation & Case Management")
        incidents = df[df["incident_id"] != "OBS-NORMAL"] if not df.empty else pd.DataFrame()
        if incidents.empty:
            st.warning("No incidents available. Load logs first.")
        else:
            ids = sorted(incidents["incident_id"].unique())
            inc_id = st.selectbox("Select incident", ids)
            inc = df[df["incident_id"] == inc_id]
            row = inc.loc[inc["risk_score"].idxmax()]
            intel = THREAT_INTEL.get(row["source_ip"], {"reputation": "Unknown", "category": "Unknown", "action": "Monitor"})
            st.write(f"**{inc_id}** — {row['threat_type']} | Peak risk {row['risk_score']} ({row['risk_level']})")
            st.write(f"Source IP: `{row['source_ip']}` | Reputation: **{intel['reputation']}** | MITRE: {MITRE.get(row['threat_type'], 'N/A')}")
            st.write(f"Recommended action: {intel['action']}")
            case = st.session_state["cases"].get(inc_id, {"status": "New", "priority": "Medium", "analyst": st.session_state["analyst_id"], "notes": ""})
            c1, c2 = st.columns(2)
            with c1:
                status = st.selectbox("Status", CASE_STATUSES, index=CASE_STATUSES.index(case["status"]))
                priority = st.selectbox("Priority", PRIORITIES, index=PRIORITIES.index(case["priority"]))
            with c2:
                analyst = st.text_input("Assigned Analyst", value=case["analyst"])
                notes = st.text_area("Analyst Notes", value=case["notes"])
            if st.button("Update Case"):
                st.session_state["cases"][inc_id] = {"status": status, "priority": priority, "analyst": analyst, "notes": notes, "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                st.success("Case updated for this session.")
            st.dataframe(inc, use_container_width=True)

    elif page == "AI Security Agent":
        st.title("AI Security Agent")
        q = st.text_input("Ask about the current logs", placeholder="Give executive summary")
        cols = st.columns(4)
        suggestions = ["Give executive summary", "Which incident is most critical?", "Which IPs are suspicious?", "Show MITRE mapping"]
        for col, suggestion in zip(cols, suggestions):
            if col.button(suggestion, use_container_width=True):
                q = suggestion
        if q:
            st.success(answer(q, df))

    elif page == "Analytics":
        st.title("Analytics & Visualisations")
        if df.empty:
            st.warning("Load logs first.")
        else:
            dims = ["username", "source_ip", "asset", "hour", "threat_type", "risk_level", "ueba_flag"]
            x = st.selectbox("Heatmap rows", dims, index=0)
            y = st.selectbox("Heatmap columns", dims, index=5)
            if x != y:
                pivot = pd.pivot_table(df, values="risk_score", index=x, columns=y, aggfunc="mean", fill_value=0)
                st.plotly_chart(px.imshow(pivot, title="Average Risk Heatmap"), use_container_width=True)
            st.plotly_chart(px.scatter(df, x="source_ip", y="username", size="risk_score", color="threat_type", hover_data=["asset", "action", "status", "incident_id"], title="IP/User Relationship Map"), use_container_width=True)

    elif page == "Report Generator":
        st.title("Report Generator")
        if df.empty:
            st.warning("No data available.")
        else:
            summary = df.groupby(["threat_type", "risk_level"], observed=True).size().reset_index(name="count").sort_values("count", ascending=False)
            st.dataframe(summary, use_container_width=True)
            st.download_button("Download All Events CSV", df.to_csv(index=False).encode("utf-8"), "cyber_sentinel_x_events.csv", "text/csv")
            inc_ids = [i for i in df["incident_id"].unique() if i != "OBS-NORMAL"]
            if inc_ids:
                selected = st.selectbox("Incident report", inc_ids)
                report = df[df["incident_id"] == selected]
                st.dataframe(report, use_container_width=True)
                st.download_button(f"Download {selected} Report", report.to_csv(index=False).encode("utf-8"), f"cyber_sentinel_x_{selected}.csv", "text/csv")

    elif page == "About":
        st.title("About Cyber Sentinel X")
        st.markdown("""
        **Cyber Sentinel X** is a defensive cybersecurity and AI-SOC education project.

        It analyses uploaded or generated logs, detects suspicious activity, scores risk, maps incidents to simplified MITRE ATT&CK techniques, supports case notes, and creates CSV reports. It does **not** perform hacking, scanning, exploitation, or live attacks.
        """)


if __name__ == "__main__":
    main()
