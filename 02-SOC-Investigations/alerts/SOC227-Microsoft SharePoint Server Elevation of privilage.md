

# SOC227 - Microsoft SharePoint Server Elevation of Privilege (CVE-2023-29357) 

## 🚨 Raw Alert Details
```text
EventID : 189
Event Time : Oct, 06, 2023, 08:05 PM
Rule : SOC227 - Microsoft SharePoint Server Elevation of Privilege - Possible CVE-2023-29357 Exploitation
Level : Security Analyst
Hostname : MS-SharePointServer
Destination IP Address : 172.16.17.233
Source IP Address : 39.91.166.222
HTTP Request Method : GET
Requested URL : /_api/web/siteusers
User-Agent : python-requests/2.28.1
Device Action : Allowed
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** WAF / SIEM
- **Asset Affected:** MS-SharePointServer (172.16.17.233)
- **Threat Type:** Privilege Escalation / Authentication Bypass (Zero-Day Exploitation)
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding CVE-2023-29357
**CVE-2023-29357** is a critical Elevation of Privilege (EoP) vulnerability affecting Microsoft SharePoint Server 2019. With a CVSS score of 9.8, it allows an unauthenticated attacker to assume the privileges of any user, including Site Administrators.

**The Mechanics:** The vulnerability stems from a flaw in how SharePoint validates JWT (JSON Web Tokens) for authentication. An attacker can craft a spoofed JWT auth token. If the SharePoint server is misconfigured or unpatched, it accepts the spoofed token, bypassing the authentication check. Attackers typically use this access to hit the `/_api/web/siteusers` endpoint to dump the user directory, identify the Admin account, and then spoof a token specifically for that Admin to take full control of the SharePoint environment. When chained with other vulnerabilities (like CVE-2023-24955), this EoP leads directly to Remote Code Execution (RCE).

## Investigation Steps

### 1. Alert Triage and Host Profiling
The alert flagged an incoming HTTP GET request targeting the `/_api/web/siteusers` API endpoint on the internal host `172.16.17.233`.
- **Endpoint Verification:** EDR logs confirmed the host is a Windows Server 2019 machine acting as the corporate Microsoft SharePoint Server.
- **Directionality:** Internet to Corporate Network.
- **User-Agent Anomaly:** The request utilized `python-requests/2.28.1`. Legitimate interactions with the SharePoint API typically come from browsers or authorized internal applications. A Python script reaching out from the public internet strongly indicates an automated exploit script (PoC).

### 2. Threat Intelligence Enrichment
The source IP (`39.91.166.222`) was evaluated against threat intelligence platforms.
- **Finding:** The IP is flagged as a known malicious node associated with automated vulnerability scanning and exploitation.

<img width="1807" height="252" alt="image" src="https://github.com/user-attachments/assets/871030dc-fa9f-4c26-ac76-de0412f40e46" />


### 3. Exploit Validation (Network Log Correlation)
To determine if the exploit was successful, raw proxy and web server logs were analyzed for the specific API calls associated with the CVE-2023-29357 exploit chain.

- **Phase 1: User Enumeration (Success)**
  The attacker requested `/_api/web/siteusers`. 
  - **Result:** `HTTP 200 OK` (Size: 1453 bytes). 
  - *Analysis:* The attacker successfully bypassed authentication and dumped the list of all users registered on the SharePoint server.

<img width="605" height="320" alt="image" src="https://github.com/user-attachments/assets/73003314-1b31-4679-90fd-50f321061003" />


- **Phase 2: Exploit Fuzzing (Failed)**
  The attacker made a malformed request to `/_api/web/siteusers/web/siteusers`.
  - **Result:** `HTTP 404 Not Found`. 
  - *Analysis:* This indicates the automated script was fuzzing API endpoints to map the application structure.
  - 
<img width="607" height="342" alt="image" src="https://github.com/user-attachments/assets/5a1788ce-1766-4d4d-8869-0871e9ac4463" />


- **Phase 3: Current User Validation (Success)**
  The attacker requested `/_api/web/currentuser`.
  - **Result:** `HTTP 200 OK` (Size: 1071 bytes).
  - *Analysis:* This is the critical step in the exploit chain. The attacker validates the permissions of the spoofed JWT token. The `200 OK` response proves the SharePoint server accepted the attacker's spoofed token as a valid, highly privileged user.

<img width="603" height="342" alt="image" src="https://github.com/user-attachments/assets/8e9b30e9-7125-4efe-8816-9bc5111326ab" />


## Analysis and Findings
The incident is a confirmed **True Positive (Successful)**. An external threat actor successfully exploited the CVE-2023-29357 Authentication Bypass vulnerability on the Microsoft SharePoint Server. Correlation of the network logs proves the attacker successfully enumerated the user directory and validated a highly privileged, spoofed session token. The server is fully compromised, placing all corporate documents and wikis hosted on SharePoint at immediate risk of exfiltration or ransomware encryption.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Privilege Escalation** | T1068 | Exploitation for Privilege Escalation |
| **Defense Evasion** | T1550.004 | Use Alternate Authentication Material: Web Session Cookie (Spoofed JWT) |
| **Discovery** | T1087 | Account Discovery (`siteusers` enumeration) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 39.91.166.222 | Malicious Source IP / Exploit Node |
| URL Path | `/_api/web/siteusers` | Target endpoint for user enumeration |
| URL Path | `/_api/web/currentuser` | Target endpoint for token validation |
| User-Agent | `python-requests/2.28.1` | Signature of automated Python exploit script |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this specific CVE and similar API abuse, the following logic should be implemented in the SIEM:
- **Detection 1 (API Abuse by Scripting Tools):** Alert when HTTP URI Contains `_api/web/siteusers` OR `_api/web/currentuser` AND `User-Agent` Contains `python-requests`, `curl`, `wget`, or `Go-http-client`. (Legitimate API calls should originate from authenticated internal apps, not raw Python scripts).
- **Detection 2 (High-Volume API Enumeration):** Alert when an external IP address generates more than 5 requests to `_api/web/*` endpoints within a 1-minute window, particularly if followed by HTTP 200 OK responses.

## 🚀 Decision Tree for Authentication Bypass Alerts
1. **Analyze Initial Vector:** Did an external IP access an authentication or user-enumeration endpoint (e.g., `/siteusers`)?
   - If Yes -> Check the User-Agent. Is it a browser or a scripting tool?
2. **Verify Exploit Status:** Check the HTTP Response Code. Did the server return a `401 Unauthorized` or `403 Forbidden`?
   - If Yes -> Attack Blocked / Unsuccessful.
3. **Check for Exploit Success:** Did the server return `200 OK` to an unauthenticated external request?
   - If Yes -> **Verdict: True Positive - Successful Compromise (Auth Bypass).**
4. **Action:** Isolate the server immediately, as the attacker now holds administrative privileges over the application.

## Response and Closure
- **Action Taken:** The compromised SharePoint server (`172.16.17.233`) was immediately **Isolated** from the network to halt data exfiltration. The malicious source IP was added to the perimeter blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful Privilege Escalation and Authentication Bypass on public-facing infrastructure.

## Recommendations
1. **Immediate Patching:** Apply the latest Microsoft Security Updates for SharePoint Server 2019 to remediate CVE-2023-29357 and the closely associated CVE-2023-24955 (RCE).
2. **AMSI Integration:** Ensure the Anti-Malware Scan Interface (AMSI) is integrated and enabled for SharePoint Server to block malicious script execution attempting to pivot from this EoP to RCE.
3. **Forensic Audit:** Tier-2 Incident Response must audit the SharePoint access logs to determine exactly which files or wikis the attacker accessed or downloaded during the window of compromise.
4. **Perimeter Hardening:** Internal corporate tools like SharePoint should generally not be exposed directly to the public internet. Access should be restricted behind a corporate VPN or Zero-Trust Network Access (ZTNA) proxy requiring Multi-Factor Authentication.

## 🛠️ Skills & Tools Used
- **Log Correlation:** Analyzing web server HTTP Status Codes to verify exploit success.
- **Vulnerability Triage:** Understanding JWT Authentication Bypass mechanics (CVE-2023-29357).
- **Detection Engineering:** Creating SIEM logic to catch malicious User-Agents targeting APIs.
- **Incident Containment & Response:** Critical infrastructure isolation and forensic remediation planning.
