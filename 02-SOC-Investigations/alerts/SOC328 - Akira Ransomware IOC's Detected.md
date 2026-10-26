
# SOC328 - Akira Ransomware IOC's Detected 

## 🚨 Raw Alert Details
```text
EventID : 306
Rule : SOC328 - Akira Ransomware IOC's Detected
Role : Incident Responder
Alert Type : APT Group
Hostname : Vergil (172.16.17.130)
File Path : C:\Users\LetsDefend\Downloads\payment-confirmation-invoice-12345\Payment Confirmation Invoice #12345.exe
EDR Action : Detected
Trigger Reason : Executed potentially malicious files associated with Akira ransomware.
L1 Note : ...It seems that the victim ran the relevant .exe. However, I could not confirm that the ransomware variant belonged to Akira.
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / Email Security Gateway
- **Asset Affected:** Vergil (172.16.17.130)
- **Threat Type:** Ransomware / Data Exfiltration (Akira)
- **Status:** True Positive (Compromised / Encrypted)

## 🧠 Attack Context / Technical Background (Akira Ransomware)
**Akira** is a highly prolific Ransomware-as-a-Service (RaaS) group that emerged in early 2023. They employ a double-extortion tactic: they exfiltrate sensitive corporate data before encrypting the local files, threatening to leak the data on their Tor-based leak site if the ransom is not paid.

**The Mechanics:** This attack chain demonstrates classic initial access via Spearphishing. The attacker delivers a ZIP archive disguised as an invoice. Inside the archive is the ransomware payload, visually masked as a PDF or document using a double-extension trick or icon spoofing (e.g., `Invoice.pdf.exe`). Once executed, the ransomware performs rapid file encryption, appending a specific extension (like `.akira`) to affected files. Crucially, before encryption concludes, the malware uses Windows Management Instrumentation (WMI) or native tools (`vssadmin.exe`, `vssvc.exe`) to delete Volume Shadow Copies, ensuring the victim cannot easily restore the files using native Windows backup features.

## Investigation Steps

### 1. Initial Access Verification (Phishing)
The investigation began by tracing the payload delivery mechanism.
- **Email Security Check:** An email was delivered to `vergil@letsdefend.io` from `sale@thefasted[.]com`. The SMTP sender IP was `162.255.119.213`.
- **Lure:** The email subject was "Payment Confirmation," urging the user to review the attached document.
- **Attachment:** A ZIP file (`setup.zip` / `payment-confirmation-invoice-12345.zip`). The email bypassed the gateway (`Action: Allowed`).

<img width="1384" height="544" alt="image" src="https://github.com/user-attachments/assets/5c12efe6-aa55-4a07-898a-7dbb82c48236" />



### 2. Payload Delivery & Extraction (EDR)
The EDR Browser History and Terminal History for the host `Vergil` confirmed the user interacted with the malicious lure.
- **Browser History:** The user downloaded the payload via an AWS S3 bucket link: `https://files-ld.s3.us-east-2.amazonaws.com/payment-confirmation-invoice-12345[.]zip`.
- **Extraction:** The user utilized `7zG.exe` (7-Zip GUI) to extract the contents of the ZIP archive into their Downloads folder. 

<img width="1218" height="259" alt="image" src="https://github.com/user-attachments/assets/37765870-f39b-4faf-83b9-b68565f00acd" />
<img width="1191" height="244" alt="image" src="https://github.com/user-attachments/assets/b945e68d-503e-4d5b-8990-7eda74eeb98c" />


### 3. Ransomware Execution & System Evasion
The terminal and process history revealed the catastrophic execution phase of the ransomware.
- **Payload Execution:** The extracted executable, `Payment Confirmation Invoice #12345[.]exe`, was launched by the user.
- **Defense Evasion (Inhibit Recovery):** Following execution, EDR captured a critical Event ID 4104 (Execute a Remote Command) via PowerShell/WMI: 
  `Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`
  Shortly after, the process `vssvc.exe` (Volume Shadow Copy Service) was invoked. This confirms the ransomware successfully deleted all local system backups to prevent recovery.

<img width="541" height="255" alt="image" src="https://github.com/user-attachments/assets/e25bb837-fe1b-4254-a8b8-427dc9763c32" />

<img width="1164" height="240" alt="image" src="https://github.com/user-attachments/assets/0bb7b3c1-6eaf-40ac-b7e8-3b4d37e3f090" />


### 4. Ransom Note & File Encryption (Live Forensics)
To confirm the L1 Analyst's note regarding the specific ransomware variant, I investigated the endpoint directly.
- **File System Impact:** The EDR File Creation logs (Event ID 11) showed the rapid creation of `akira_readme.txt` across multiple directories, including the `STARTUP` folder.

  <img width="551" height="310" alt="image" src="https://github.com/user-attachments/assets/55ce0f72-6e22-4fea-924d-2ce1d3e3e825" />
  <img width="554" height="279" alt="image" src="https://github.com/user-attachments/assets/f25b33d5-54d5-43ae-baed-1d4642dc2ef0" />
  <img width="550" height="314" alt="image" src="https://github.com/user-attachments/assets/627f6096-3b31-43e9-8cb7-a8d216ba0299" />

- **Live VM Triage:** Connecting to the victim's machine revealed that files in the Downloads folder had been appended with the `.akira` file extension.
- 
<img width="827" height="284" alt="image" src="https://github.com/user-attachments/assets/83264f28-a967-4077-9fd8-85e2b7a8deae" />

- **The Ransom Note:** Opening the `akira_readme.txt` file revealed the extortion demands and the Tor `.onion` communication URL specific to the Akira group.
- 
<img width="984" height="698" alt="image" src="https://github.com/user-attachments/assets/9c6d5f1c-0b5a-4028-96c3-d3fe5f9cad94" />

<img width="1796" height="242" alt="image" src="https://github.com/user-attachments/assets/afd6c46d-abfa-49fa-a14c-b9b360fbee21" />
<img width="1818" height="258" alt="image" src="https://github.com/user-attachments/assets/aa0179f1-c917-46e6-bee4-e38e6f022a62" />



## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Vergil" fell victim to a spearphishing email, extracting and executing the Akira Ransomware payload disguised as an invoice. The malware successfully executed, deleted the host's Volume Shadow Copies via WMI to inhibit recovery, and encrypted the user's files with the `.akira` extension. The deployment of the `akira_readme.txt` ransom note confirms attribution to the Akira RaaS group. A check of network and email logs confirms this infection is currently isolated to the host `Vergil`, with no lateral movement observed.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Execution** | T1047 | Windows Management Instrumentation (WMI) |
| **Impact** | T1486 | Data Encrypted for Impact |
| **Impact** | T1490 | Inhibit System Recovery (Shadow Copy Deletion) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (SHA256) | `2C7AEAC07CE7F03B74952E0E243BD52F2BFA60FADC92DD71A6A1FEE2D14CDD77` | Akira Ransomware Executable |
| URL | `https://akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion` | Akira Ransom Negotiation Portal |
| Domain | `payment-confirmation.com` | Phishing / Redirect Domain |
| File Name | `akira_readme.txt` | Ransom Note |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of ransomware deployment, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Akira Ransomware Detection
id: b8058978-df4d-4c5f-994d-40460b0f5d62
status: experimental
description: Detects potential Akira ransomware behavior based on file encryption and system recovery inhibition activities.
author: SOC Analyst Portfolio
logsource:
product: windows
service: security
detection:
  selection:
    EventID: 4104
    CommandLine:
      - '*Get-WmiObject Win32_Shadowcopy*'
      - '*Remove-WmiObject*'
      - '*vssadmin.exe delete shadows*'
      - '*wbadmin.exe delete catalog*'
      - '*bcdedit.exe /set*'
      - '*cipher.exe /w*'
  condition: selection
falsepositives:
  - legitimate system administrator tasks
level: high
tags:
  - attack.t1490
  - attack.t1486
  - attack.t1489
  - ransomware
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the user execute a suspicious attachment or download?
2. **Check for Recovery Sabotage:** Did the process (or a child process) attempt to delete Volume Shadow Copies via `vssadmin`, `wmic`, or PowerShell?
   - If Yes -> **High probability of Active Ransomware.**
3. **Verify Encryption:** Are there mass file modification events, or the creation of text files containing "readme" or "decrypt" in the filename?
   - If Yes -> **Verdict: True Positive - Successful Ransomware Deployment.**
4. **Action:** Immediately contain the host at the network switch level, disconnect shared drives, and invoke the major incident response plan.

## 📝 Playbook Questions & Answers
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The executed file (`Payment Confirmation Invoice #12345.exe`) was linked to Akira ransomware. The system must be isolated immediately to prevent the spread of ransomware across the network.
- **Determine the Scope:**
  - *Answer:* No (Localized to one machine).
  - *Reasoning:* A search by sender and subject in Email Security showed the mail only came to `vergil@letsdefend.io`. Endpoint checks showed no lateral movement attempts or secondary host infections.
- **What is the initial access method used in the attack?**
  - *Answer:* Phishing (Spearphishing Attachment).
  - *Reasoning:* The user received an email from `sale@thefasted.com` with a malicious invoice attachment that was executed on the endpoint.
- **Automated Categorization Services (ID Ransomware):**
  - *Answer:* Yes.
  - *Reasoning:* Uploading `akira_readme.txt` to ID Ransomware confirmed the variant belonged to Akira.
- **Determine the type of ransomware (Variants 1, 2, 3):**
  - *Answer:* Yes (Confirmed).
  - *Reasoning:* Confirmed via ransom note filename (`akira_readme.txt`) and encrypted file extensions (`.akira`).

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Vergil / 172.16.17.130`) was immediately **Isolated** from the network via EDR to prevent the ransomware from crawling mapped network drives and encrypting file shares.
- **Email Eradication:** The phishing email was purged globally from the Exchange server.
- **Why:** Immediate containment is critical in ransomware incidents to limit the "blast radius" and prevent enterprise-wide operational paralysis.

## Recommendations
1. **Offline Backups:** Verify the integrity of offline, immutable backups. Because local shadow copies were destroyed by WMI commands, offline backups are the only recovery path.
2. **Data Exfiltration Audit:** Audit firewall egress logs prior to the encryption timestamp to determine if Akira exfiltrated sensitive data before encrypting the host.
3. **File Server Segregation:** Ensure standard endpoints lack persistent Write access to sensitive file shares, limiting the spread of future infections.

## ⚖️ Lessons Learned / Analyst Reflection
- **Analyst Reflection (Ransomware Attribution):** The L1 note stated they could not confirm if the variant was Akira. By executing a live triage on the affected endpoint and locating the `akira_readme.txt` file and the `.akira` file extension, I successfully attributed the attack to the correct threat group. 
- **The Lesson:** Relying solely on automated SIEM alerts can leave gaps in attribution. Knowing the specific calling cards of Ransomware groups—such as ransom note naming conventions and extension formats—is essential for accurate threat intelligence reporting.

## 🛠️ Skills & Tools Used
- EDR Process & Terminal Analysis
- Ransomware Forensics (T1490 Inhibit System Recovery)
- Live Endpoint Triage (Artifact Extraction)
- Incident Containment (Host Isolation)
