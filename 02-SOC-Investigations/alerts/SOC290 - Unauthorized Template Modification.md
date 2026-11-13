
# SOC290 - Unauthorized Template Modification / Macro Backdoor 

## 🚨 Raw Alert Details
```text
EventID : 290
Event Time : 2024-08-14T13:31:02+03:00
Rule : SOC312 - Unauthorized Template Modification Detected
Role : Incident Responder
Alert Type : C2 / Persistence
Difficulty : Medium
MITRE ATT&CK : T1078, T1133, T1059.005, T1137, T1221, T1071.001
Hostname : Jonah
IP Address : 172.16.17.110
Command Line : "C:\Program Files\Microsoft Office\Office16\WINWORD.EXE" /n /f "C:\Users\LetsDefend\AppData\Roaming\Microsoft\Templates\Normal.dotm"
EDR Action : Allowed
Trigger Reason : The default generic template for Microsoft Word, Normal.dotm, has been modified.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / File Integrity Monitoring
- **Asset Affected:** Jonah (172.16.17.110 - Windows 10)
- **Threat Type:** RDP Brute Force / Office Template Persistence / VBA Reverse Shell
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
Microsoft Word utilizes a global template file named **`Normal.dotm`** to store default styles, macros, and configurations for every new document created. 

**The Mechanics:** Threat actors frequently target `Normal.dotm` for persistence. By injecting a malicious VBA macro into this global template, the attacker ensures that the backdoor executes automatically every single time Microsoft Word is opened on the host. In this specific incident, the injected VBA macro acts as a **C2 Beacon / Reverse Shell**. It uses `MSXML2.ServerXMLHTTP` to poll an external server (`http://hackdev.ciaffa.net`), retrieves system commands, executes them silently via `WScript.Shell`, and exfiltrates the output back via HTTP POST.

## Investigation Steps

### 1. Initial Access Verification (RDP Brute Force)
The investigation began by reviewing authentication logs to determine how the attacker accessed the host prior to modifying system files.
- **Failed Logins:** Raw logs captured multiple `4625 (Failed Logon)` events from user `test` originating from external IP `181.214.131.108`.
- **Successful Logon:** Following the brute-force attempts, an `4624 (Successful Logon - Type 10 / Remote Interactive)` event was generated for the user `letsdefend` from the exact same external IP.
- **Threat Intel:** AbuseIPDB flagged `181.214.131.108` (Datacamp/Datapacket in New York, USA) with an elevated abuse confidence score.

<img width="603" height="245" alt="image" src="https://github.com/user-attachments/assets/2bb662d6-0f8f-4b77-ac4b-1601a67b85f1" />
<img width="611" height="254" alt="image" src="https://github.com/user-attachments/assets/0fa6ef9a-a8eb-410d-8397-9d7f292f173c" />

<img width="597" height="609" alt="image" src="https://github.com/user-attachments/assets/eeee8acc-32dd-47cc-adcf-7f068976fd2b" />


### 2. Persistence Verification (Template Modification)
The alert triggered because the Microsoft Word global template was altered.
- **File Path:** `C:\Users\LetsDefend\AppData\Roaming\Microsoft\Templates\Normal.dotm`
- **EDR Process Log:** Captured `WINWORD.EXE` loading and modifying the template file.

<img width="610" height="476" alt="image" src="https://github.com/user-attachments/assets/fb4903f2-a939-4751-898e-8e4afea7917c" />


### 3. Malware Analysis (VBA Reverse Shell Code Review)
Inspecting the source code of the modified `Normal.dotm` template revealed a sophisticated VBA macro designed for continuous C2 polling:
- **Callback URL:** `http://hackdev.ciaffa.net`
- **Execution Loop:** The macro runs a `While` loop, sending HTTP GET requests to fetch commands (`xmlHttpReq.responseText`).
- **Command Execution:** It passes the fetched command to `shell.Exec(command)` (WScript.Shell).
- **Exfiltration:** It captures the standard output (`StdOut`) and sends it back to the attacker via an HTTP POST request.

<img width="476" height="467" alt="image" src="https://github.com/user-attachments/assets/660d9af4-4d40-46c7-8428-c444c1ee4ec5" />


### 4. Post-Exploitation Reconnaissance (Terminal History)
The EDR Terminal History confirmed the interactive attacker activity following the initial RDP breach:
- `whoami`, `whoami /groups`, `whoami /priv` (Privilege enumeration)
- `netstat -an` (Network connection discovery)
- `net user` (Account enumeration)
- `ping hackdev.ciaffa.net` (Network reachability testing)

<img width="1199" height="575" alt="image" src="https://github.com/user-attachments/assets/b4f2291c-4c3f-4150-8158-6a604ca31bd9" />
<img width="1803" height="253" alt="image" src="https://github.com/user-attachments/assets/ce389410-3501-4596-8bab-9025f9659a56" />




## Analysis & Findings
The incident is a confirmed **True Positive**. The threat actor (`181.214.131.108`) brute-forced RDP access to the workstation `Jonah` (172.16.17.110). Once inside, they planted a malicious VBA reverse shell inside Microsoft Word's global template (`Normal.dotm`). This guarantees that every time Word opens, a background HTTP beacon polls `hackdev.ciaffa.net` for remote commands. The host is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services (RDP) |
| **Credential Access** | T1110 | Brute Force |
| **Persistence** | T1137.006 | Office Application Startup: Office Template Macros |
| **Defense Evasion** | T1221 | Template Injection |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols (`ServerXMLHTTP`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 181.214.131.108 | Attacker RDP Brute-Force / C2 Source IP |
| Domain | `hackdev.ciaffa.net` | Attacker C2 Server for VBA Reverse Shell |
| File Path | `%AppData%\Microsoft\Templates\Normal.dotm` | Hijacked Word Global Template (Persistence) |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of Office template hijacking, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Unauthorized Modification of Microsoft Office Normal.dotm Template
id: f03a0695-9012-4a5e-994d-80580c5e9f04
status: experimental
description: Detects write or modification events targeting the Normal.dotm global template file by non-standard processes.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectName|contains: '\Microsoft\Templates\Normal.dotm'
    AccessMask: '0x2' # WRITE_DATA / FILE_WRITE_DATA
  condition: selection
falsepositives:
  - Legitimate administrative script updates or user-saved custom styles
level: high
tags:
  - attack.t1137.006
  - attack.t1221
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for template modifications (`Normal.dotm`)?
   - If Yes -> Check EDR Process and File Creation logs.
2. **Examine Authentication Logs:** Was there a recent RDP brute-force or unauthorized logon preceding the modification?
   - *Confirmed successful RDP logon from `181.214.131.108`.*
3. **Inspect Macro Code:** If the template contains VBA, does it make outbound HTTP requests or utilize `WScript.Shell`?
   - *Confirmed VBA reverse shell polling `hackdev.ciaffa.net`.*
4. **Action:** **Verdict: True Positive - Compromised.** Immediately isolate the host, delete the modified template, and reset user credentials.

## 📝 Playbook Questions & Answers
- **Should the device be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The attacker gained unauthorized access via brute force and left a persistent VBA reverse shell inside `Normal.dotm`, requiring immediate network isolation.
- **Determine the Scope:**
  - *Answer:* No (Localized to one machine).
  - *Reasoning:* Log queries confirmed the destination activity and compromise were isolated strictly to host `172.16.17.110`.
- **IOC Reputation Check:**
  - *Answer:* Yes.
  - *Reasoning:* The attacker IP is located in a US data center block and flagged as malicious on VirusTotal and AbuseIPDB.
- **IOC Analysis:**
  - *Answer:* Yes.
  - *Reasoning:* Confirmation that the attacker gained access via brute force and embedded a C2 reverse shell inside `Normal.dotm`.
- **Determine the type of Defense Evasion (Template Injection):**
  - *Answer:* Template Injection (T1221).
  - *Reasoning:* The attacker achieved persistence by embedding a malicious macro into `Normal.dotm`, ensuring C2 requests fire whenever Word is opened.
- **Determine the OS (Operating System):**
  - *Answer:* Windows (Windows 10).

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Jonah / 172.16.17.110`) was immediately **Isolated** from the network via EDR to sever the VBA reverse shell's polling loop.
- **Remediation:** Cleaned/deleted the modified `Normal.dotm` template file and forced a password reset for the `letsdefend` account.
- **Why:** Isolating the host stops the C2 beacon from receiving further commands and prevents potential lateral movement.

## Recommendations
1. **Delete/Reset Normal.dotm:** Forcefully delete the compromised `Normal.dotm` template file so Word generates a clean, default template upon restart.
2. **Disable VBA Macros Globally:** Implement Group Policy Objects (GPO) to disable VBA macros across the enterprise or restrict macros to digitally signed certificates from trusted internal developers.
3. **RDP Hardening:** Disable public-facing RDP (Port 3389) or require all remote connections to route through a secure VPN with MFA.

## ⚖️Lessons Learned

- **The Lesson:** Office templates are a powerful, stealthy vector for persistence because they bypass traditional `.exe` file drops. When auditing templates, always check the VBA project code (`ThisDocument`) for network objects (`ServerXMLHTTP`) or execution sinks (`WScript.Shell`). If a document is calling home via VBA, the system is deeply compromised.

## 🛠️ Skills & Tools Used
- EDR Process & File Integrity Monitoring (`Normal.dotm` tracking)
- VBA Macro Code Review & Deobfuscation
- Windows Event Log Correlation (RDP Brute Force / Event IDs 4624 & 4625)
- Incident Containment (Host Isolation)
