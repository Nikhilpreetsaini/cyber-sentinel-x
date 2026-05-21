import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import re
from datetime import datetime, timedelta
# Add project root and src directory to sys.path so Streamlit can import src modules
from pathlib import Path
import sys
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
.set_page_config(page_title='Cyber Sentinel X', page_icon='🛡️', layout='wide')

st.markdown('''
<style>
.main {background-color:#0b1220;}
.stApp {background:linear-gradient(135deg,#07111f,#101827); color:#e5e7eb;}
.metric-card {padding:18px;border-radius:16px;background:#111827;border:1px solid #263244;box-shadow:0 8px 22px rgba(0,0,0,.25)}
.badge {padding:4px 10px;border-radius:999px;font-weight:700;}
.low {background:#064e3b;color:#a7f3d0}.medium{background:#78350f;color:#fde68a}.high{background:#7f1d1d;color:#fecaca}.critical{background:#881337;color:#fbcfe8}
</style>
''', unsafe_allow_html=True)

MITRE = {
    'Brute Force': 'T1110 - Credential Access',
    'Password Spraying': 'T1110.003 - Password Spraying',
    'Port Scan': 'T1046 - Network Service Discovery',
    'Suspicious Admin Activity': 'T1078 - Valid Accounts',
    'Malware-like Activity': 'T1204 - User Execution',
    'Data Exfiltration': 'T1041 - Exfiltration Over C2 Channel',
    'Privilege Abuse': 'T1068 - Exploitation for Privilege Escalation',
    'Unusual Login Time': 'T1078 - Valid Accounts',
    'Unknown IP Login': 'T1078 - Valid Accounts',
    'Normal Activity': 'N/A'
}

PLAYBOOKS = {
    'Brute Force': 'Block source IP, reset affected account password, enforce MFA, review successful logins after failures.',
    'Password Spraying': 'Apply account lockout policy, notify targeted users, monitor same IP across accounts.',
    'Port Scan': 'Validate firewall exposure, block scanner if malicious, monitor for follow-up activity.',
    'Suspicious Admin Activity': 'Verify admin activity, review privileged actions, reset admin password if suspicious.',
    'Malware-like Activity': 'Isolate endpoint, collect process evidence, run malware scan, escalate to senior analyst.',
    'Data Exfiltration': 'Disable suspicious session, review outbound traffic, check accessed data, escalate immediately.',
    'Privilege Abuse': 'Audit privilege changes, remove excessive permissions, review account history.',
    'Unusual Login Time': 'Confirm user activity, review device/IP, enforce MFA if unusual.',
    'Unknown IP Login': 'Validate user identity, inspect location/IP reputation, reset password if needed.',
    'Normal Activity': 'No action required.'
}

REQUIRED = ['timestamp','username','source_ip','destination_ip','asset','action','status','port','protocol','bytes_sent','event_message']

def normalize(df):
    aliases = {'time':'timestamp','date':'timestamp','datetime':'timestamp','user':'username','src_ip':'source_ip','source':'source_ip','dst_ip':'destination_ip','dest_ip':'destination_ip','host':'asset','device':'asset','message':'event_message','msg':'event_message','result':'status','event_type':'action'}
    df = df.copy()
    df.columns = [aliases.get(str(c).strip().lower(), str(c).strip().lower()) for c in df.columns]
    for c in REQUIRED:
        if c not in df.columns:
            df[c] = 0 if c in ['port','bytes_sent'] else ''
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['port'] = pd.to_numeric(df['port'], errors='coerce').fillna(0).astype(int)
    df['bytes_sent'] = pd.to_numeric(df['bytes_sent'], errors='coerce').fillna(0).astype(int)
    for c in ['username','source_ip','destination_ip','asset','action','status','protocol','event_message']:
        df[c] = df[c].astype(str).str.strip()
    return df.sort_values('timestamp').reset_index(drop=True)

def demo_logs(rows=120):
    base = datetime(2026,1,15,9,0,0)
    users = ['alice','bob','charlie','david','admin']
    assets = ['web-app','server-01','server-02','database','mail-server']
    rec=[]
    def add(t,u,src,dst,a,act,stat,port,proto,bytes_,msg):
        rec.append({'timestamp':t,'username':u,'source_ip':src,'destination_ip':dst,'asset':a,'action':act,'status':stat,'port':port,'protocol':proto,'bytes_sent':bytes_,'event_message':msg})
    for i in range(rows):
        add(base+timedelta(minutes=i*2), users[i%5], f'192.168.1.{10+i%45}', f'10.0.0.{5+i%8}', assets[i%5], 'login', 'success', 443, 'HTTPS', int(np.random.randint(200,3500)), 'Normal login activity')
    for i in range(28):
        add(base+timedelta(minutes=12,seconds=i*12),'admin','192.168.1.250','10.0.0.10','server-01','login','failure',22,'SSH',0,'Failed login attempt against admin')
    add(base+timedelta(minutes=22),'admin','192.168.1.250','10.0.0.10','server-01','login','success',22,'SSH',650,'Successful admin login after multiple failures')
    for u in users:
        for j in range(3):
            add(base+timedelta(minutes=45,seconds=j*20),u,'192.168.1.200','10.0.0.11','mail-server','login','failure',443,'HTTPS',0,'Failed login across multiple users')
    for i,p in enumerate([21,22,23,25,53,80,110,139,143,443,445,3389,8080,8443]):
        add(base+timedelta(minutes=70,seconds=i*8),'-','192.168.1.180','10.0.0.12','server-02','connection_attempt','blocked',p,'TCP',0,f'Connection attempt on port {p}')
    for i in range(8):
        add(base+timedelta(minutes=95,seconds=i*20),'system','192.168.1.190','10.0.0.13','server-01','process_blocked','blocked',0,'LOCAL',0,'Suspicious powershell encoded command blocked')
    for i in range(7):
        add(base+timedelta(minutes=120,seconds=i*30),'eve','192.168.1.170','10.0.0.14','database','data_transfer','success',443,'HTTPS',int(np.random.randint(3000000,12000000)),'Large outbound data transfer from database')
    return pd.DataFrame(rec)

def analyze(df):
    df = normalize(df)
    df['threat_type'] = 'Normal Activity'
    df['detection_method'] = 'Baseline'
    df['reason'] = 'No suspicious pattern detected.'
    fail = df[(df.action.str.lower()=='login') & (df.status.str.lower()=='failure')]
    brute = set(map(tuple, fail.groupby(['source_ip','username']).size().reset_index(name='n').query('n>=8')[['source_ip','username']].values))
    spray_ips = set(fail.groupby('source_ip').agg(n=('username','count'), users=('username','nunique')).reset_index().query('n>=8 and users>=3')['source_ip'])
    port_ips = set(df[df.action.str.contains('connection',case=False,na=False)].groupby('source_ip')['port'].nunique().loc[lambda s:s>=8].index)
    risky_keywords = ['powershell','encoded','mimikatz','suspicious process','malware','ransom','credential dump']
    for i,r in df.iterrows():
        msg=str(r.event_message).lower(); act=str(r.action).lower(); stat=str(r.status).lower(); user=str(r.username).lower(); src=str(r.source_ip)
        if (src,r.username) in brute and act=='login' and stat=='failure':
            df.loc[i,['threat_type','detection_method','reason']]=['Brute Force','Rule-based','Repeated failed logins against the same user.']
        elif src in spray_ips and act=='login' and stat=='failure':
            df.loc[i,['threat_type','detection_method','reason']]=['Password Spraying','Rule-based','Same IP attempted authentication against multiple users.']
        elif act=='login' and stat=='success' and user=='admin' and src in set(fail.source_ip):
            df.loc[i,['threat_type','detection_method','reason']]=['Suspicious Admin Activity','Correlation','Admin login succeeded after repeated failures.']
        elif src in port_ips and r.port>0:
            df.loc[i,['threat_type','detection_method','reason']]=['Port Scan','Rule-based','Source IP contacted many ports in a short time.']
        elif any(k in msg for k in risky_keywords) or 'process' in act:
            df.loc[i,['threat_type','detection_method','reason']]=['Malware-like Activity','Keyword/TF-IDF style','Suspicious command/process keyword detected.']
        elif act=='data_transfer' or r.bytes_sent>=3000000:
            df.loc[i,['threat_type','detection_method','reason']]=['Data Exfiltration','Anomaly scoring','Large outbound transfer volume detected.']
        elif act=='privilege_change' or 'privilege' in msg:
            df.loc[i,['threat_type','detection_method','reason']]=['Privilege Abuse','Rule-based','Privilege modification or abuse pattern detected.']
        elif act=='login' and pd.notna(r.timestamp) and (r.timestamp.hour<6 or r.timestamp.hour>22):
            df.loc[i,['threat_type','detection_method','reason']]=['Unusual Login Time','UEBA','Login outside normal working hours.']
    base={'Normal Activity':10,'Unusual Login Time':55,'Port Scan':65,'Password Spraying':72,'Brute Force':82,'Malware-like Activity':88,'Data Exfiltration':94,'Suspicious Admin Activity':96,'Privilege Abuse':85,'Unknown IP Login':60}
    df['risk_score']=df.apply(lambda r:min(100, base.get(r.threat_type,20)+(8 if str(r.username).lower()=='admin' else 0)+(5 if r.source_ip in ['192.168.1.250','192.168.1.190','192.168.1.170'] else 0)),axis=1)
    df['risk_level']=pd.cut(df.risk_score, bins=[-1,25,50,75,100], labels=['Low','Medium','High','Critical']).astype(str)
    df['confidence']=(df.risk_score/100).round(2)
    df['incident_id']=['CSX-'+str(n).zfill(4) for n in (df.groupby(['source_ip','threat_type']).ngroup()+1)]
    return df

def executive_summary(df):
    bad=df[df.threat_type!='Normal Activity']
    if df.empty: return 'No log data has been analysed yet.'
    top=bad.threat_type.value_counts().idxmax() if not bad.empty else 'None'
    return f'Cyber Sentinel X analysed {len(df)} events and identified {len(bad)} suspicious events across {bad.incident_id.nunique() if not bad.empty else 0} incidents. The top detected threat category is {top}. All findings are simulated/educational and require analyst validation.'

if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame()

st.sidebar.title('🛡️ Cyber Sentinel X')
page=st.sidebar.radio('Navigation',['Overview Dashboard','Log Upload & Analysis','Threat Detection','Incidents','Timeline','IOC Intelligence','AI Analyst','Reports','About Project'])

st.title('Cyber Sentinel X')
st.caption('AI-Powered Cyber Threat Detection & Incident Analysis — defensive mini-SOC/SIEM simulation')

if page=='Overview Dashboard':
    df=st.session_state.df
    if df.empty:
        st.info('No logs analysed yet. Go to Log Upload & Analysis and generate demo logs.')
    else:
        bad=df[df.threat_type!='Normal Activity']
        c1,c2,c3,c4=st.columns(4)
        c1.metric('Total Logs',len(df)); c2.metric('Threats Detected',len(bad)); c3.metric('Critical Events',int((df.risk_level=='Critical').sum())); c4.metric('Average Risk',round(df.risk_score.mean(),1))
        c5,c6,c7,c8=st.columns(4)
        c5.metric('Unique IPs',df.source_ip.nunique()); c6.metric('Suspicious Users',bad.username.nunique() if not bad.empty else 0); c7.metric('Confidence',f'{round(df.confidence.mean()*100,1)}%'); c8.metric('Incidents',bad.incident_id.nunique() if not bad.empty else 0)
        st.plotly_chart(px.bar(df.threat_type.value_counts().reset_index(),x='threat_type',y='count',title='Threat Category Distribution'),use_container_width=True)
        st.plotly_chart(px.histogram(df,x='risk_score',color='risk_level',title='Risk Distribution'),use_container_width=True)
        st.plotly_chart(px.scatter(df,x='timestamp',y='risk_score',color='threat_type',hover_data=['source_ip','username','incident_id'],title='Security Timeline'),use_container_width=True)

elif page=='Log Upload & Analysis':
    st.subheader('Upload CSV or generate demo security logs')
    up=st.file_uploader('Upload CSV log file',type=['csv'])
    if st.button('Generate Demo Logs'):
        st.session_state.df=analyze(demo_logs())
        st.success('Demo logs generated and analysed successfully.')
    if up:
        try:
            st.session_state.df=analyze(pd.read_csv(up))
            st.success('Uploaded logs analysed successfully.')
        except Exception as e:
            st.error(f'Unable to analyse uploaded file: {e}')
    if not st.session_state.df.empty:
        st.dataframe(st.session_state.df.head(50),use_container_width=True)

elif page=='Threat Detection':
    df=st.session_state.df
    if df.empty: st.warning('Load logs first.')
    else:
        levels=st.multiselect('Risk level filter',sorted(df.risk_level.unique()),default=sorted(df.risk_level.unique()))
        view=df[df.risk_level.isin(levels)]
        st.dataframe(view[['timestamp','username','source_ip','asset','action','status','threat_type','detection_method','risk_score','risk_level','confidence','reason']],use_container_width=True)

elif page=='Incidents':
    df=st.session_state.df
    if df.empty: st.warning('Load logs first.')
    else:
        bad=df[df.threat_type!='Normal Activity']
        if bad.empty: st.success('No suspicious incidents found.')
        else:
            incidents=bad.groupby('incident_id').agg(title=('threat_type','first'),severity=('risk_level','max'),risk_score=('risk_score','max'),first_seen=('timestamp','min'),last_seen=('timestamp','max'),related_ips=('source_ip',lambda x:', '.join(sorted(set(x)))),related_users=('username',lambda x:', '.join(sorted(set(x))))).reset_index()
            st.dataframe(incidents,use_container_width=True)
            inc=st.selectbox('Incident detail',incidents.incident_id)
            sub=bad[bad.incident_id==inc]
            t=sub.threat_type.iloc[0]
            st.markdown(f'### {inc} — {t}')
            st.write('MITRE:',MITRE.get(t,'N/A'))
            st.write('Recommended response:',PLAYBOOKS.get(t,'Review manually.'))
            st.write('Explanation:',sub.reason.iloc[0])
            st.dataframe(sub[['timestamp','username','source_ip','asset','event_message','risk_score','risk_level']],use_container_width=True)

elif page=='Timeline':
    df=st.session_state.df
    if df.empty: st.warning('Load logs first.')
    else:
        st.write(executive_summary(df))
        st.dataframe(df.sort_values('timestamp')[['timestamp','action','username','source_ip','threat_type','risk_level','reason']],use_container_width=True)

elif page=='IOC Intelligence':
    df=st.session_state.df
    if df.empty: st.warning('Load logs first.')
    else:
        rows=[]
        for col,typ in [('source_ip','IP Address'),('username','User'),('asset','Asset'),('port','Port')]:
            for v,n in df[col].astype(str).value_counts().head(25).items():
                if v and v!='0':
                    sub=df[df[col].astype(str)==v]
                    rows.append({'ioc_type':typ,'value':v,'frequency':int(n),'max_risk':int(sub.risk_score.max()),'first_seen':sub.timestamp.min(),'last_seen':sub.timestamp.max(),'category':'Simulated Threat Intelligence for Educational Demo'})
        st.dataframe(pd.DataFrame(rows),use_container_width=True)

elif page=='AI Analyst':
    df=st.session_state.df
    q=st.text_input('Ask the AI-style analyst',placeholder='What is the most critical incident?')
    if df.empty: st.info('Load logs first.')
    elif q:
        low=q.lower(); bad=df[df.threat_type!='Normal Activity']
        if 'critical' in low or 'highest' in low:
            r=df.loc[df.risk_score.idxmax()]; st.write(f'Most critical finding is {r.incident_id}: {r.threat_type} from {r.source_ip}, risk {r.risk_score}.')
        elif 'summary' in low:
            st.write(executive_summary(df))
        elif 'user' in low:
            st.write(f'Most targeted user is {bad.username.value_counts().idxmax() if not bad.empty else "none"}.')
        else:
            st.write(executive_summary(df))

elif page=='Reports':
    df=st.session_state.df
    if df.empty: st.warning('Load logs first.')
    else:
        st.subheader('Executive Summary')
        st.write(executive_summary(df))
        st.download_button('Download detected events CSV',df.to_csv(index=False).encode('utf-8'),'cyber_sentinel_x_report.csv','text/csv')
        st.download_button('Download JSON summary',df.groupby('threat_type').size().to_json().encode('utf-8'),'cyber_sentinel_summary.json','application/json')

else:
    st.markdown('''
### What is Cyber Sentinel X?
Cyber Sentinel X is a defensive, educational mini-SOC/SIEM dashboard for analysing uploaded or generated security logs. It detects suspicious patterns, scores risk, correlates events into incidents, extracts IOCs, maps findings to MITRE ATT&CK-style concepts, and generates analyst-friendly explanations.

### Safety Statement
This project does not scan, attack, exploit, crack passwords, phish, persist, evade, or interact with real targets. It only analyses uploaded or simulated log data.

### Tech Stack
Python, Streamlit, Pandas, NumPy, Plotly.
''')
