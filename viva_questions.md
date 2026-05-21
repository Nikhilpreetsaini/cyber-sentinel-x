# Viva Questions & Answers

The following sample questions can help students prepare for viva voce or oral examinations related to Cyber Sentinel X. They cover key concepts, design choices and potential extensions.

1. **What is the main objective of Cyber Sentinel X?**  
   *To demonstrate how security logs can be analysed to detect common cyber threats, assign risk scores, correlate events into incidents and provide actionable insights through a user‑friendly dashboard.*

2. **Which log formats are supported by the system?**  
   *Any CSV file containing basic fields such as timestamp, username, source IP, asset, action, status and event message can be processed. Column aliases are mapped to these standard fields.*

3. **How are threats detected?**  
   *Detection is rule‑based. For example, repeated failed logins from one IP to multiple users is flagged as password spraying, while a large outbound transfer is flagged as data exfiltration. These rules are defined in `src/threat_detector.py`.*

4. **What is a risk score and how is it computed?**  
   *Each event receives a base score depending on the threat type (e.g. brute force = 80). The score is adjusted based on contextual factors such as the number of failures or bytes transferred. It is then mapped to a risk level (Low/Medium/High/Critical).*  

5. **Describe how incidents are correlated.**  
   *Events are grouped by source IP and threat type. If consecutive events occur within a 60‑minute window, they are assigned the same incident ID. A new incident ID is generated when the source IP, threat type or time gap changes.*

6. **What is UEBA and how is it implemented here?**  
   *User and Entity Behaviour Analytics (UEBA) identifies deviations from normal patterns. In this project, anomalies such as logins outside typical hours, users using many IPs or IPs targeting many users are flagged as UEBA anomalies.*

7. **How does the AI security agent work?**  
   *The agent is a rule‑based function that constructs explanations and answers specific questions. It summarises incidents, identifies the most critical threat, provides recommended actions based on playbooks and translates technical details into plain language. It does not call external APIs.*

8. **What is MITRE ATT&CK and how is it used here?**  
   *MITRE ATT&CK is a framework of adversary tactics and techniques. Cyber Sentinel X maps each detected threat to a simplified ATT&CK technique ID and tactic to contextualise the attack.*

9. **How can this project be extended in the future?**  
   *Improvements could include integrating machine learning models for anomaly detection, supporting real‑time log ingestion, connecting to external threat intelligence feeds and using a generative AI model for more sophisticated responses.*

10. **Is this tool safe to use on real networks?**  
   *Cyber Sentinel X is intended for educational purposes. It operates only on static log files and does not perform any network scanning or exploitation. To deploy on real networks, additional validation, security controls and performance considerations would be necessary.*