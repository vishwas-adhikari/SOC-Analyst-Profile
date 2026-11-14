
# SOC269 - Corporate Policy Violation (Insider Threat Data Exfiltration)


## 🚨 Raw Alert Details
```text
EventID : 242
Event Time : 2024-03-26T05:17:00+03:00
Rule : SOC269 - Corporate Policy Violation - Insider Threat Activities Detected
Role : Incident Responder
Alert Type : Data Leakage
Difficulty : Medium
MITRE ATT&CK : T1078, T1204, T1070.004, T1560, T1114, T1005, T1567
Hostname : Nathan
IP Address : 172.16.17.152
Device Action : Allowed
Trigger Reason : Corporate Policy Violation / Insider Threat Activity
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Browser Forensics / SIEM
- **Asset Affected:** Nathan (172.16.17.152 - Windows 10)
- **Threat Type:** Insider Threat / Data Exfiltration Over Web Service (GoFile.io)
- **Verdict:** True Positive (Compromised / Exfiltrated)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
An **Insider Threat** occurs when an individual with authorized access to an organization's network, systems, or data misuses that access to harm the organization's data security.

**The Mechanics:** In this scenario, the employee ("Nathan") attempted to cover his tracks by deleting his browser history prior to submitting his workstation for investigation. However, standard browser history deletion leaves behind raw binary cache artifacts in Chrome's Session folders (`AppData\Local\Google\Chrome\User Data\Default\Sessions`). By extracting and parsing these session files, investigators uncover the pre-planning phase (searching for file-hiding and anonymous upload techniques). The employee then gathered local files and emails, archived them into a password-protected 7-Zip file (`files.7z`), and programmatically uploaded them to an anonymous file-sharing service (`gofile.io`) using PowerShell.

## Investigation Steps

### 1. Initial Triage & The Cover-Up (Browser History Forensics)
The investigation began following a notice from the SOC Manager that the employee Nathan wiped his browser history prior to device submission.
- **Forensic Recovery via PowerShell:** To bypass the cleared history, advanced browser forensics were performed by targeting Chrome's binary session cache files located at `C:\Users\Letsdefend\AppData\Local\Google\Chrome\User Data\Default\Sessions\`.
- **Regex Extraction:** A PowerShell script utilizing `Select-String` and regular expressions (`https?://[^\x00-\x1F\x7F-\xFF]+`) was executed to carve out unrendered URLs into `Recovered_URLs.txt`.
- **Findings:** The recovered history revealed suspicious late-night searches (e.g., 04:02 AM) including:
  - *"How to upload files secretly"*
  - *"Anonymous file upload platform"*
  - *"How to encrypt files to be not detected"*
  - *"Undetectable data transfer methods"*
  - Visits to anonymous sharing sites like `anchormydata.com` and Chrome Web Store extensions for file uploads.

<img width="418" height="177" alt="image" src="https://github.com/user-attachments/assets/1eb88fc5-1fc1-49c0-b4e5-7d837d11b366" />

<img width="803" height="406" alt="image" src="https://github.com/user-attachments/assets/cc54e97b-a178-4cb4-a286-ca91e6e2159b" />


### 2. Collection Phase (Data Staging)
With intent established, endpoint process telemetry was reviewed to determine if files were gathered.
- **Process Creation (Event ID 1):** EDR logs captured `7zG.exe` executing with command-line arguments specifying archiving operations against the user's `Documents` directory.
- **Staged File:** The employee successfully created an archive named `files.7z` containing 16 sensitive files, including local documents and exported `.eml` email files.

<img width="728" height="200" alt="image" src="https://github.com/user-attachments/assets/026c1bde-c572-4679-aa45-332276b94022" />

<img width="712" height="338" alt="image" src="https://github.com/user-attachments/assets/2b728624-2a20-4be8-a47d-e66df3e5550d" />


### 3. Exfiltration Phase (GoFile.io Upload)
Network action and Sysmon logs were correlated to determine if the staged archive left the network.
- **Network Action:** Outbound connections were observed connecting to `store10.gofile.io` and `api.gofile.io` (IP Address: `31.14.70.252`).
- **PowerShell Execution:** Sysmon captured PowerShell using `Invoke-RestMethod` to execute an HTTP POST request, uploading `files.7z` to the GoFile server.
- **API Response:** The raw log output confirmed a successful JSON response from GoFile containing the unique download link for the exfiltrated archive (`https://pastebin.com/rM7uP09b` / GoFile storage node).

<img width="549" height="212" alt="image" src="https://github.com/user-attachments/assets/29b5b914-15bc-4ba0-973d-312ff31759e7" />
<img width="555" height="191" alt="image" src="https://github.com/user-attachments/assets/764deebf-31e5-4fcd-84db-6d966b2add7b" />


<img width="555" height="220" alt="image" src="https://github.com/user-attachments/assets/4366dd46-28cd-4940-ba5a-7e4c162e0466" />


## Analysis & Findings
The incident is a confirmed **True Positive**. Employee "Nathan" deliberately engaged in insider threat activities. After conducting clandestine online research on anonymous exfiltration methods outside of working hours, he compressed sensitive corporate documents and emails into an archive (`files.7z`). He then utilized PowerShell to upload the archive to the anonymous file-sharing platform `gofile.io`. Despite attempting to cover his tracks by wiping his browser history, forensic session parsing and EDR telemetry proved the data leakage occurred. The host is compromised by an internal actor.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1078 | Valid Accounts (Authorized Employee Access) |
| **Execution** | T1204.002 | User Execution: Malicious File / Script Execution |
| **Defense Evasion** | T1070.004 | Indicator Removal on Host: File Deletion (Clearing Browser History) |
| **Collection** | T1560 | Archive Collected Data (`7zG.exe`) |
| **Collection** | T1114 | Email Collection (`.eml` exports) |
| **Collection** | T1005 | Data from Local System (`Documents` scraping) |
| **Exfiltration** | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage (`gofile.io`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | `31.14.70.252` | GoFile.io Exfiltration Drop Server IP |
| Domain | `store10.gofile.io` / `api.gofile.io` | Anonymous File-Sharing C2 / Exfil API |
| File Path | `C:\Users\LetsDefend\Documents\files.7z` | Staged Exfiltration Archive |
| File Path | `...\Chrome\User Data\Default\Sessions\...` | Browser Cache Artifacts used for Forensics |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of insider data staging and anonymous file uploads, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Mass Archiving Followed by Anonymous File Upload via PowerShell
id: f14e0691-1234-4a5e-994d-70580c5e9f10
status: experimental
description: Detects 7-Zip archiving user documents followed by PowerShell web requests to known anonymous file-sharing APIs (gofile.io).
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection_archive:
    CommandLine|contains:
      - '7z.exe'
      - '7zG.exe'
      - 'a -t'
  selection_upload:
    CommandLine|contains:
      - 'gofile.io'
      - 'api_post.php'
  condition: selection_archive or selection_upload
falsepositives:
  - Legitimate employee personal backups or software packaging
level: high
tags:
  - attack.t1560
  - attack.t1567.002
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did an alert fire for corporate policy violations or suspicious network activity?
   - If Yes -> Check endpoint user history and EDR telemetry.
2. **Evaluate Cover-Up Behavior:** Is the browser history cleared or missing around the time of the alert?
   - If Yes -> **High probability of intentional insider threat or obfuscation.** Perform browser session forensics.
3. **Check Staging Activity:** Did the user utilize compression tools (`7z`, `WinRAR`) to bundle files from `Documents` or `Desktop`?
   - *Confirmed creation of `files.7z`.*
4. **Check Exfiltration Vectors:** Did PowerShell or browsers connect to anonymous file-sharing sites (`gofile.io`, `mega.nz`, `pastebin.com`)?
   - *Confirmed HTTP POST upload to `gofile.io`.*
5. **Action:** **Verdict: True Positive - Insider Threat (Data Exfiltration).** Immediately isolate the endpoint, preserve the user profile for Legal/HR, and escalate.

## 📝 Playbook Questions & Answers
- **Should the device be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* Considering the compromised state of the device and the active attempt to exfiltrate company data, isolating the host is mandatory to contain the threat and minimize further risk.
- **Verify whether a false positive or legit activity has occurred:**
  - *Answer:* True Positive.
  - *Reasoning:* Investigation confirmed active insider threat behavior, including browser history deletion, local file staging (`files.7z`), and successful upload to `gofile.io`.
- **Detect and Investigate Data Exfiltration:**
  - *Answer:* Exfiltration Over Web Service (T1567).
  - *Reasoning:* Logs proved the compressed files were transferred to the remote file-sharing service `gofile.io` via PowerShell REST methods.
- **Interaction-Based Data Collection Techniques:**
  - *Answer:* Archive Collected Data (T1560).
  - *Reasoning:* The insider utilized the 7-Zip tool to compress sensitive company data and emails into a password-protected/staged archive (`files.7z`).
- **Storage-Based Data Collection Techniques:**
  - *Answer:* Email Collection & Data from Local System (T1114, T1005).
  - *Reasoning:* The investigation revealed the collection of local system files and `.eml` email exports gathered directly from the user's profile directory.

## Response & Containment Actions Taken
- **Host Isolation:** Nathan's endpoint (`172.16.17.152`) was immediately **Isolated** via the Endpoint Security console to prevent further data harvesting.
- **Forensic Preservation:** The user profile, session cache files, and exfiltrated archive (`files.7z`) were preserved for HR and Legal forensics.
- **Why:** Insider threats require careful handling to ensure chain-of-custody is maintained for potential disciplinary or legal action.

## Recommendations
1. **Policy Review & DLP Solutions:** Deploy Enterprise Data Loss Prevention (DLP) solutions configured to automatically block and alert on large file compressions targeting sensitive directories coupled with outbound uploads to unapproved web-sharing services.
2. **Browser Forensic Training:** Train SOC analysts on recovering deleted history using Chrome session cache parsing (`Sessions\` and `Tabs\` binary carving) to counter insider cover-ups.
3. **Access Controls:** Implement stricter access controls and permission boundaries so individual employees cannot freely mass-export critical email stores or corporate documents.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Beyond the EDR Dashboard):** When investigating insider threats, EDR dashboards can sometimes look "clean" if standard malware isn't running—especially if the user is just using built-in Windows tools like `7-Zip` and native PowerShell scripts.
- **The Lesson:** Insider threats require a specialized forensic mindset. When an employee actively wipes their browser history, it is a massive flashing red light. Knowing how to bypass the cover-up by carving raw binary Chrome session files to recover search queries is the difference between missing an insider threat and successfully stopping a data leak.

## 🛠️ Skills & Tools Used
- Advanced Browser Forensics (Chrome Session/Tab Binary Parsing)
- PowerShell Regular Expression (Regex) Carving (`Select-String`)
- EDR File System & Process Analysis (`7zG.exe`, `Invoke-RestMethod`)
- Incident Containment & Legal/HR Forensic Preservation
