# SOC168 - Whoami Command Detected in Request Body 

## Alert Overview
- **Severity:** Critical
- **Detection Source:** WAF / SIEM
- **Asset Affected:** WebServer1004 (172.16.17.16)
- **Threat Type:** OS Command Injection / Remote Code Execution (RCE)
- **Status:** True Positive (Successful)

## Strategy and Technical Context
The strategy observed in this incident represents a classic post-exploitation enumeration phase. After identifying a Remote Code Execution (RCE) or Command Injection vulnerability within the web application, the threat actor utilized the HTTP POST request body to pass system-level commands to the underlying server. By executing commands such as `whoami`, the attacker's immediate technical objective is to determine the privilege level of the compromised web service account (e.g., `www-data` or `root`), which dictates the viability of subsequent privilege escalation or lateral movement attacks.

## Brief about the Concept
OS Command Injection occurs when an application passes unsafe, user-supplied data (forms, cookies, HTTP headers, or request bodies) directly to a system shell. Attackers exploit this by appending terminal commands to legitimate input using shell metacharacters (e.g., `;`, `|`, `&&`). The `whoami` command is the universal first step in situational awareness for an attacker upon gaining initial shell access.

## Investigation Steps

### 1. Alert Triage and Directionality
The investigation was initiated following an alert for a suspicious POST request containing the `whoami` command in its body.
- **Source IP:** 61.177.172.87
- **Target Asset:** WebServer1004 (172.16.17.16)
- **Directionality:** Internet to Corporate Network.

### 2. Threat Intelligence Enrichment
The source IP (61.177.172.87) was queried against threat intelligence repositories.
- **Finding:** VirusTotal identified the IP as highly malicious. The IP is geographically located in China and is associated with active exploitation and scanning activities.

### 3. Network Traffic Analysis
A query was executed in the Log Management system filtering for the malicious IP.
- **Finding:** A total of 5 HTTP POST requests originating from the attacker were identified.
- **Impact Assessment:** Every request returned an **HTTP Response Status of 200 OK**. While a 200 OK alone only proves the web application processed the request, the chronological execution of 5 successive commands indicates an interactive exploitation session.

### 4. Endpoint Execution Verification (EDR)
To definitively confirm whether the command injection was successful, the investigation shifted from the network layer to the endpoint layer. 
- **Action:** Reviewed the process and terminal logs on WebServer1004.
- **Finding:** The endpoint logs explicitly displayed the execution of the injected commands (including `whoami`). This confirms that the web application passed the malicious POST body directly to the system shell, resulting in successful Remote Code Execution.

### 5. Scheduled Test Verification
A search across the Email Security platform and change management records was conducted for the affected IP addresses, WebServer1004, and standard penetration testing keywords. No authorized testing activity was scheduled.

## Analysis and Findings
The incident is a confirmed **True Positive (Successful)**. The threat actor (61.177.172.87) successfully exploited an OS Command Injection vulnerability on WebServer1004. Correlation between the HTTP 200 network responses and the endpoint terminal history provides undeniable proof of execution. The server is compromised, granting the attacker a foothold into the corporate network to conduct enumeration and potential post-exploitation activities.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| **Discovery** | T1033 | System Owner/User Discovery |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 61.177.172.87 | Malicious Source IP (Attacker) |
| Hostname | WebServer1004 (172.16.17.16) | Compromised Web Server |
| Payload | `whoami` | Enumeration command passed in request body |

## Blind Spots
- **Exfiltrated Output:** Without full packet capture (PCAP) or detailed reverse-proxy logs capturing the HTTP response body, the exact output of the commands (e.g., whether the user was `root`) returned to the attacker cannot be definitively confirmed from network logs alone.
- **Application Vulnerability:** The specific vulnerable parameter or application script handling the POST request requires forensic analysis of the web application source code to identify and patch.

## False Positives: Legitimate Activity Comparison
- **Server Administration:** A system administrator utilizing a legitimate, authenticated web-based management panel (such as Webmin or cPanel) to run server diagnostics might generate similar logs. However, the traffic originating from a known malicious external IP entirely rules out legitimate administrative action.

## Decision Tree for Command Injection
1. **Payload Verification:** Does the HTTP request body or URL contain OS commands (`whoami`, `id`, `uname`)?
   - If Yes -> Malicious Intent confirmed.
2. **Network Impact Analysis:** Is the HTTP status code `200 OK`?
   - If Yes -> Proceed to Endpoint Verification.
3. **Endpoint Verification:** Do EDR or Syslog/Auditd logs show the web service account spawning a shell executing the injected command?
   - If Yes -> Verdict: **True Positive - Successful Compromise**.
4. **Action:** Isolate Host immediately and escalate to Tier 2 for Incident Response.

## Response and Closure
- **Action Taken:** WebServer1004 was immediately **Contained/Isolated** via the Endpoint Security console to sever the attacker's interactive session and prevent lateral movement. The malicious IP was blocked at the perimeter.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised via OS Command Injection; escalated to Tier 2.

## Recommendations
1. **Input Sanitization:** The application development team must immediately review the code handling POST requests and implement strict input validation, utilizing parameterized functions or built-in APIs rather than passing raw strings to the OS shell.
2. **WAF Enforcement:** Update the Web Application Firewall (WAF) to aggressively block incoming requests containing common Unix/Windows shell commands in the request body.
3. **Least Privilege:** Ensure the web service account (e.g., `www-data`, `apache`) operates with the absolute minimum privileges required to function, preventing a web compromise from immediately resulting in root-level access.
4. **Forensic Audit:** Tier 2 Incident Response must conduct a deep forensic audit of WebServer1004 to ensure no backdoors, web shells, or persistence mechanisms were dropped during the 5 command executions.

## Evidence / Screenshots
<img width="947" height="237" alt="image" src="https://github.com/user-attachments/assets/34eec5a4-1cc0-4dbc-b393-d24f92c07daf" />

<img width="713" height="392" alt="image" src="https://github.com/user-attachments/assets/fb811d01-47f9-48e5-a324-918e6695fab0" />

<img width="717" height="371" alt="image" src="https://github.com/user-attachments/assets/517365b3-3157-4c7c-a02f-4332458c4909" />


## Skills & Tools Used
SIEM Log Correlation, EDR Process/Terminal Analysis, Threat Intelligence (VirusTotal), Web Application Security (Command Injection Triage), Host Containment, MITRE ATT&CK Mapping.
