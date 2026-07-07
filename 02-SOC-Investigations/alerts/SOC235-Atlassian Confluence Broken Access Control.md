
# SOC235 - Atlassian Confluence Broken Access Control 0-Day (CVE-2023-22515) 

## 🚨 Raw Alert Details
```text
EventID : 197
Event Time : Nov, 09, 2023, 09:47 AM
Rule : SOC235 - Atlassian Confluence Broken Access Control 0-Day CVE-2023-22515
Level : Security Analyst
Hostname : Confluence Data Center
Destination IP Address : 172.16.17.234
Source IP Address : 43.130.1.222
HTTP Request Method : GET
Requested URL : /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
Device Action : Allowed
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** WAF / SIEM
- **Asset Affected:** Confluence Data Center (172.16.17.234)
- **Threat Type:** Broken Access Control / Zero-Day Exploitation (CVE-2023-22515)
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding CVE-2023-22515
**CVE-2023-22515** is a CVSS 10.0 critical vulnerability affecting Atlassian Confluence Server and Data Center editions. It is a Broken Access Control vulnerability stemming from how the Apache Struts framework handles HTTP parameters.

**The Mechanics:** Confluence relies on the XWork package, which allows HTTP URL parameters to interact directly with Java class attributes via Getter/Setter methods. An unauthenticated attacker can exploit the `ServerInfoAction` class to chain Java Getters together to reach the core configuration object:
`getBootstrapStatusProvider().getApplicationConfig().setSetupComplete(false)`

By passing `bootstrapStatusProvider.applicationConfig.setupComplete=false` in the URL, the attacker forces the Confluence server to falsely believe its initial installation was never completed. This unlocks the `/setup/` endpoints, allowing the attacker to seamlessly create a new, rogue Administrator account without requiring any prior authentication.

## Investigation Steps

### 1. Alert Triage and Exploitation Signature Verification
The investigation initiated with a high-severity alert indicating an attempt to exploit CVE-2023-22515.
- **Source IP:** 43.130.1.222
- **User-Agent:** `curl/7.88.1` (Indicating automated or scripted exploitation rather than manual browser interaction).
- **Target URL:** `/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false`
- **Analysis:** This URL matches the exact Proof-of-Concept (PoC) exploit payload designed to reset the Confluence application state.

### 2. Impact Assessment & Log Correlation
To determine if the exploit was successful, the raw Confluence Access Logs were analyzed via the SIEM, filtering for the attacker's IP (`43.130.1.222`). A definitive three-step execution chain was identified within a 45-second window:

1. **State Reset (09:47:36):**
   - `GET /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false HTTP/1.1`
   - **Response:** `200 OK`
   - *Analysis: The attacker successfully flipped the application setup state to 'false'.*
2. **Rogue Account Creation (09:47:54):**
   - `POST /setup/setupadministrator.action HTTP/1.1`
   - **Response:** `302 Found / Redirect`
   - *Analysis: The attacker submitted a POST request to the newly unlocked setup endpoint to inject a new Administrator account.*
3. **Exploit Finalization (09:48:21):**
   - `POST /setup/finishsetup.action HTTP/1.1`
   - **Response:** `200 OK`
   - *Analysis: The attacker closed the setup phase to restore normal application functionality, effectively locking in their newly created rogue admin account.*

<img width="600" height="421" alt="image" src="https://github.com/user-attachments/assets/9aafa9da-13f8-4923-bf7a-31262609655f" />

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/34e6dc07-817a-4b30-86f3-52062ad6d078" />

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/65140286-832d-4e80-9b16-7545aa6518fd" />


### 3. Scope and Lateral Movement Check
A secondary search across network and authentication logs for the malicious IP (`43.130.1.222`) showed no immediate follow-on activity (such as data exfiltration or reverse shell connections). However, the creation of an administrative account grants the attacker persistent, highly privileged access to the Confluence environment.

## Analysis and Findings
The incident is a confirmed **True Positive**. The threat actor (43.130.1.222) successfully exploited CVE-2023-22515 on the Confluence Data Center instance. By leveraging Java object property manipulation, the attacker bypassed authentication, reset the server's setup state, and successfully provisioned a rogue administrative account. The server is fully compromised at the application layer.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Persistence** | T1136.003 | Create Account: Cloud/Application Account |
| **Privilege Escalation**| T1078.001 | Valid Accounts: Default Accounts |
| **Defense Evasion** | T1068 | Exploitation for Privilege Escalation |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 43.130.1.222 | Attacker Source IP |
| URL Path | `/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false` | State Reset Payload |
| URL Path | `/setup/setupadministrator.action` | Rogue Admin Creation Endpoint |
| User-Agent | `curl/7.88.1` | Exploit Tooling |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Exploit Attempt):** Alert when HTTP Request URL Contains `bootstrapStatusProvider.applicationConfig.setupComplete`.
- **Detection 2 (Post-Setup Anomalies):** Alert when HTTP POST requests target `/setup/setupadministrator.action` on a server that has been in production for more than 24 hours. (A production server should never see traffic to the `/setup/` directory).

## 🚀 Decision Tree for Broken Access Control Alerts
1. **Analyze Initial Vector:** Did an external IP access an administrative or setup-related endpoint?
   - If Yes -> Check HTTP Response Status.
2. **Verify Exploit Payload:** Does the URL contain property manipulation strings (e.g., modifying `setupComplete`)?
   - If Yes -> High probability of CVE-2023-22515.
3. **Check for Follow-on Activity:** Did the attacker subsequently access `/setup/setupadministrator.action`?
   - If Yes (Status 200/302) -> **Verdict: True Positive - Successful Compromise (Rogue Admin Created).**
4. **Action:** Isolate host, delete rogue accounts, and escalate to Tier-2 for forensic review and patching.

## Response and Closure
- **Action Taken:** The compromised Confluence Data Center (`172.16.17.234`) was immediately **Isolated** from the network to prevent the attacker from utilizing the newly created rogue account to drop a web shell or exfiltrate corporate wikis. 
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful exploitation of CVE-2023-22515 resulting in unauthorized administrative account creation.

## Recommendations
1. **Rogue Account Eradication:** Review the Confluence user database and immediately delete any administrative accounts created on or around Nov 09, 2023, 09:47 AM.
2. **Immediate Patching:** Upgrade the Confluence Data Center to a secure, patched version (e.g., 8.3.3, 8.4.3, 8.5.2, or later) to resolve the XWork package vulnerability.
3. **Endpoint Hardening (WAF):** Ensure the Web Application Firewall (WAF) is actively inspecting query strings and is configured to block requests containing `bootstrapStatusProvider`.
4. **Forensic Audit:** Conduct a comprehensive audit of all Confluence spaces and attachments to ensure the attacker did not upload malicious macros or web shells during the brief window of compromise.

## 🛠️ Skills & Tools Used
- **Application Log Forensics:** Analyzing Apache/Tomcat access logs to reconstruct a multi-step web exploit chain.
- **Vulnerability Triage:** Understanding Object Graph Navigation Library (OGNL) injection and Java property manipulation (CVE-2023-22515).
- **Incident Containment & Remediation:** Host isolation and rogue account identification strategies.
