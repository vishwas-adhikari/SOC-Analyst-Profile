
# SOC175 - PowerShell Found in Requested URL (CVE-2022-41082 Exploitation) 

## 🚨 Raw Alert Details
```text
EventID : 125
Event Time : Sep, 30, 2022, 07:19 AM
Rule : SOC175 - PowerShell Found in Requested URL - Possible CVE-2022-41082 Exploitation
Level : Security Analyst
Hostname : Exchange Server 2
Destination IP Address : 172.16.20.8
Log Source : IIS
Source IP Address : 58.237.200.6
Request URL : /autodiscover/autodiscover.json?@evil.com/owa/&Email=autodiscover/autodiscover.json%3f@evil.com&Protocol=XYZ&FooProtocol=Powershell
HTTP Method : GET
User-Agent : Mozilla/5.0 zgrab/0.x
Action : Blocked
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** WAF / IIS Access Logs
- **Asset Affected:** Exchange Server 2 (172.16.20.8)
- **Threat Type:** Zero-Day Exploitation / Server-Side Request Forgery (SSRF) / RCE
- **Status:** True Positive (Blocked)

## 🧠 Deep Dive: Understanding "ProxyNotShell" (CVE-2022-41040 & CVE-2022-41082)
"ProxyNotShell" is a devastating, chained Microsoft Exchange vulnerability consisting of CVE-2022-41040 (SSRF) and CVE-2022-41082 (RCE). 

**The Mechanics:** The attack begins when an authenticated (or bypassed) user sends a malicious request to the Exchange `/autodiscover` endpoint. The attacker exploits a path confusion vulnerability (SSRF) that causes the frontend IIS server to improperly route the request directly to the internal Exchange PowerShell service backend. Once the request reaches the backend, the attacker abuses the PowerShell Remoting interface to execute arbitrary commands with the `SYSTEM` privileges of the Exchange service. This vulnerability was actively exploited in the wild as a zero-day prior to Microsoft's official patch.

<img width="1083" height="665" alt="image" src="https://github.com/user-attachments/assets/6e067bab-dc87-44a4-99c3-82d4a08d42a9" />


## Investigation Steps

### 1. Alert Triage and Behavioral Identification
The investigation was triggered by an IIS log alerting on the keyword `Powershell` within an HTTP GET request URL.
- **Directionality:** External (Internet) to Internal (Corporate Exchange Server).
- **User-Agent Anomaly:** The request utilized the User-Agent `Mozilla/5.0 zgrab/0.x`. `zgrab` is an open-source, internet-wide application-layer scanner. The presence of this User-Agent confirms the activity is an automated vulnerability scanning campaign rather than a targeted human attack.

### 2. Threat Intelligence Enrichment
The source IP (`58.237.200.6`) was queried against VirusTotal.
- **Finding:** The IP originates from South Korea (SK Broadband). While the IP may have a low detection rate on standard threat feeds, the behavioral context (zgrab + CVE payload) overrides standard reputation scoring. This is definitively malicious traffic.

### 3. Log Correlation and Progressive Exploitation Analysis
A query in the Log Management system for the malicious IP revealed a sequence of three rapid HTTP requests, indicating a structured, progressive exploitation probe:
1. **Probe:** `GET /autodiscover/autodiscover.json` (Checking if the endpoint exists).
2. **SSRF Attempt:** `GET /autodiscover/autodiscover.json?@evil.com/ews/exchange.asmx...` (Attempting path confusion).
3. **RCE Attempt:** The final payload attempting to hit the PowerShell backend.

<img width="1558" height="373" alt="image" src="https://github.com/user-attachments/assets/1dbba70a-703f-4dd6-a82d-7536f9dee2f8" />
<img width="604" height="254" alt="image" src="https://github.com/user-attachments/assets/42e1eb73-ffc5-4fd1-a414-f124c3ba94ee" />



### 4. Dissecting the RCE Payload
The final request contained the complete exploit payload:
`/autodiscover/autodiscover.json?@evil[.]com/owa/&Email=autodiscover/autodiscover.json%3f@evil[.]com&Protocol=XYZ&FooProtocol=Powershell`

- `?@evil[.]com/owa/`: The core bypass technique. By injecting `@evil.com` into the query string, the attacker tricks Exchange’s URL routing into misinterpreting the request origin, bypassing authentication checks (SSRF).
- `%3f@evil[.]com`: The `%3f` is a URL-encoded `?`. A double injection attempt to maximize the chance of routing success.
- `FooProtocol=Powershell`: The critical RCE vector. This parameter forces the Exchange frontend to route the request to the PowerShell remoting backend.

<img width="606" height="285" alt="image" src="https://github.com/user-attachments/assets/bf29c9b4-11d9-4701-a500-c3655a1a44ea" />


### 5. Impact Assessment & Outcome Verification
To determine if the attack successfully reached the PowerShell backend, the device action and endpoint logs were reviewed.
- **Device Action:** Blocked.
- **Endpoint Analysis:** No child processes (e.g., `cmd.exe` or `powershell.exe`) were spawned by `w3wp.exe` (the IIS worker process), and no ASP.NET web shells were dropped in Exchange web directories.
- **Conclusion:** The Web Application Firewall (WAF) or perimeter controls successfully intercepted and dropped the malformed requests before they could be processed by the Exchange backend.

## Analysis and Findings
The incident is a confirmed **True Positive (Blocked)**. An external IP (`58.237.200.6`) utilized an automated `zgrab` scanner to probe the corporate Exchange server for the "ProxyNotShell" vulnerability. The structured attack sequence successfully delivered the CVE-2022-41082 payload; however, the perimeter security controls successfully blocked the requests. The Exchange Server remains secure and uncompromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application (ProxyNotShell) |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Execution** | T1203 | Exploitation for Client Execution |
| **Reconnaissance** | T1595.002 | Active Scanning: Vulnerability Scanning (`zgrab`) |

## Indicators of Compromise (IOCs)
*Analyst Note: Only actionable artifacts were extracted. The internal victim IP and the dynamic URL payload were excluded, as they cannot be meaningfully blocked or hunted.*
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 58.237.200.6 | Malicious Scanner IP (South Korea) |
| User-Agent | `zgrab/0.x` | Automated Vulnerability Scanner |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of ProxyNotShell attacks, the following logic should be implemented in the SIEM:
- **Detection 1 (WAF Regex):** Alert and Drop requests where HTTP URI Contains `autodiscover.json` AND `\@` (to catch the `@evil.com` SSRF bypass).
- **Detection 2 (PowerShell Routing):** Alert when HTTP URI Contains `autodiscover.json` AND `Powershell`.
- **Detection 3 (Post-Exploitation Endpoint):** Alert when `ParentImage="*\w3wp.exe"` AND `Image="*\cmd.exe" OR "*\powershell.exe"`. (IIS should not be spawning administrative shells).

## 🚀 Decision Tree for Exchange SSRF/RCE Alerts
1. **Analyze Request URI:** Does the URL target an Exchange endpoint (`/autodiscover`, `/ews`, `/owa`)?
2. **Check for Path Confusion:** Does the URI contain unexpected characters like `@`, `..`, or URL-encoded symbols (`%3f`) within parameters?
   - If Yes -> High probability of SSRF attempt (ProxyLogon / ProxyNotShell).
3. **Verify Device Action:** Did the WAF/Proxy return a `Blocked` status or a `403 Forbidden`?
   - If Yes -> **Verdict: True Positive - Unsuccessful (Attack Blocked).**
4. **Endpoint Verification:** If the request was `Allowed`, check EDR for `w3wp.exe` spawning child processes.
5. **Action:** Block the source IP and verify Exchange patch levels.

## Response and Closure
- **Action Taken:** Verified the `Blocked` status of the malicious requests. Verified that the Exchange Server patch levels were current, mitigating the underlying vulnerability. Added the scanner IP to the perimeter blocklist.
- **Containment Required:** No. Attack was blocked at the perimeter.
- **Closure Reason:** True Positive. Unsuccessful automated exploitation attempt.

## Recommendations
1. **Exchange Patching:** Ensure Microsoft Exchange Server is updated with the latest Cumulative Updates (CUs) and Security Updates (SUs) to permanently remediate CVE-2022-41040 and CVE-2022-41082.
2. **URL Rewrite Mitigation:** If patching cannot be performed immediately, implement IIS URL Rewrite rules to explicitly block requests containing `.*autodiscover\.json.*\@.*Powershell.*`.
3. **Scanner Blocking:** Implement strict WAF rules to automatically drop inbound HTTP requests originating from known automated scanning agents (e.g., `zgrab`, `masscan`, `censys`).

## 🛠️ Skills & Tools Used
- **Vulnerability Triage:** Understanding the exploit chain of ProxyNotShell (SSRF to RCE).
- **HTTP Payload Dissection:** Breaking down URL-encoded parameters and path confusion bypasses.
- **Threat Intelligence Profiling:** Identifying behavioral anomalies (User-Agent `zgrab`) over raw IP reputation scores.
- **SIEM Log Correlation:** Tracking progressive exploitation attempts across sequential HTTP logs.
