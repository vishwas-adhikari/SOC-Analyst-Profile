
# SOC220 - Big Head Ransomware IOC's Detected (Hornet Variant)

## 🚨 Raw Alert Details
```text
EventID : 178
Event Time : 2023-08-15T06:20:30+03:00
Rule : SOC220 - Big Head Ransomware IOC's Detected
Role : Incident Responder
Alert Type : Ransomware
Difficulty : Hard
MITRE ATT&CK : T1566.002, T1059, T1204, T1547, T1537, T1486
Hostname : Leonardo
IP Address : 172.16.17.159
Affected User : Leonardo
Hash : 6d27c1b457a34ce9edfb4060d9e04eb44d021a7b03223ee72ca569c8c4215438
Trigger Reason : Big Head Ransomware IOC's Detected
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Leonardo (172.16.17.159)
- **Threat Type:** Ransomware / Remote Access Trojan (RAT) / Telegram C2 Abuse
- **Verdict:** True Positive (Compromised / Encrypted)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
**Big Head Ransomware** (associated with the Hornet ransomware family) is a destructive payload that combines rapid file encryption with remote access capabilities (RAT). 

**The Mechanics:** Delivery typically occurs via spearphishing lures promising free media or software subscriptions (such as fake Netflix memberships). Once executed, the ransomware unpacks multiple recursive helper binaries (`1.exe`, `archive.exe`, `Xarch.exe`) to obfuscate its origin. It establishes persistence by dropping executables directly into the Windows Startup folder. Crucially, rather than building custom, easily blocked infrastructure, this malware leverages the **Telegram Bot API** (`api.telegram.org`) for Command and Control (C2) and data exfiltration, exploiting the fact that corporate firewalls universally trust Telegram traffic over HTTPS (Port 443).

## Investigation Steps

### 1. Initial Access Verification (Phishing)
The investigation began by tracing the payload delivery mechanism.
- **Email Security Check:** An email was delivered to `leonardo@letsdefend.io` from `support@netflixfree.org`.
- **Lure:** The subject was "Exclusive Gift: Enjoy a Free 1-Month Netflix Membership!", offering a complimentary subscription.
- **Payload URL:** The email contained a direct link to an AWS S3 bucket hosting a compressed archive: `https://files-ld.s3.us-east-2.amazonaws.com/free-netflix.7z`.

<img width="1564" height="638" alt="image" src="https://github.com/user-attachments/assets/23cb0b55-7f95-4f15-a0c6-62509ba9b51e" />


### 2. Browser History & Download Validation
EDR Browser History logs for the host `Leonardo` (172.16.17.159) were reviewed.
- **Finding:** Browser history confirmed that the user clicked the link and downloaded `free-netflix.7z` directly from the AWS S3 bucket.

<img width="1224" height="370" alt="image" src="https://github.com/user-attachments/assets/ce652159-a1e3-4969-88fc-e5e5642a700d" />


### 3. Execution & Recursive Staging (Process Tree)
EDR Process telemetry revealed a complex, multi-stage execution chain following the extraction of the archive.
- **Process Lineage:** `free-netflix.exe` executed from the Downloads directory. 
- **Recursive Spawning:** The initial process rapidly spawned multiple child binaries in rapid succession to evade behavioral detection, including `1.exe`, `archive.exe`, and `Xarch.exe`.
- **Cleanup Scripts:** Terminal history captured batch scripts (`update.bat` and `delback.bat`) executing via `cmd.exe` to delete temporary installation artifacts and clear tracks.

<img width="1138" height="509" alt="image" src="https://github.com/user-attachments/assets/13059b02-9689-4ac2-ba6c-9ee8c83d9af5" />
<img width="1137" height="486" alt="image" src="https://github.com/user-attachments/assets/bc2411ff-fa96-4e15-9062-ef908f283743" />

<img width="1570" height="467" alt="image" src="https://github.com/user-attachments/assets/aa599ff6-5685-4950-b58a-84cc694724b4" />


### 4. Persistence & C2 (Telegram API Abuse)
Further analysis of the endpoint revealed how the malware maintained access and communicated with the attacker.
- **Persistence (Startup Folder):** The malware dropped backdoor binaries directly into the Windows Startup directory: `C:\Users\LetsDefend\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\teleratserver.exe` (and `BXIuSsB.exe`).
- **C2 Beaconing (Sysmon Event ID 22):** Sysmon captured `teleratserver.exe` generating a DNS query for `api.telegram.org`, which resolved to the Telegram IP address `149.154.167.220`. 
- **Network Connection:** An active HTTPS (Port 443) connection was maintained between the startup RAT and Telegram infrastructure, highly indicating data exfiltration or C2 check-ins.

<img width="547" height="313" alt="image" src="https://github.com/user-attachments/assets/eac5013e-dbcd-489b-bf46-2e32b27f53b4" />

<img width="760" height="196" alt="image" src="https://github.com/user-attachments/assets/507ba2f1-0cc5-4e82-8b41-ec95e9b1dfdf" />

### 5. Live VM Triage & Impact Assessment
Connecting to the victim's machine confirmed the full impact of the breach.
- **File System Impact:** Files across the user's directory were encrypted.
- **Ransom Note:** Located a text file named `README_2465906.txt`. 
- **Attribution:** Opening the note revealed instructions directing the user to download the Tor browser and visit `.onion` sites (`v7ydve4mkao6c6tm.onion`) to pay a Bitcoin ransom. Based on the note structure and file behavior, this is identified as a variant of **Hornet / Big Head Ransomware**.

<img width="1022" height="506" alt="image" src="https://github.com/user-attachments/assets/be283429-754b-4b55-a5a6-789a84421636" />

<img width="787" height="284" alt="image" src="https://github.com/user-attachments/assets/ea9ffdd2-3b20-4f82-bdfb-8d319464d488" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Leonardo" fell victim to a spearphishing email offering a fake free Netflix subscription. The downloaded archive dropped `free-netflix.exe`, which spawned recursive helper binaries, established persistence in the Windows Startup folder via `teleratserver.exe`, and utilized the Telegram Bot API (`api.telegram.org`) for command-and-control communication. The host is fully compromised, and local files have been encrypted by the Hornet/Big Head ransomware variant.



<img width="1801" height="577" alt="image" src="https://github.com/user-attachments/assets/2f04de49-9bf4-40ca-8d96-d077c5aa2bfb" />
<img width="1784" height="573" alt="image" src="https://github.com/user-attachments/assets/a0f5178c-28d7-4b5d-bc7f-8186ca2d1d1b" />
<img width="593" height="594" alt="image" src="https://github.com/user-attachments/assets/d5467f46-e08c-4933-bb08-37b6d8a7b4f3" />


## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Persistence** | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **Exfiltration** | T1537 | Transfer Data to Cloud Account (Telegram API Abuse) |
| **Impact** | T1486 | Data Encrypted for Impact |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/free-netflix.7z` | Malicious Payload Delivery URL (AWS S3) |
| Domain | `api.telegram.org` | Abused C2 / Exfiltration Channel |
| IP Address | 149.154.167.220 | Telegram API Server IP |
| File Path | `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\teleratserver.exe` | RAT Persistence Binary |
| File Name | `README_2465906.txt` | Hornet Ransomware Note |
| Onion URL | `http://v7ydve4mkao6c6tm.onion` | Ransom Payment Portal |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of Telegram C2 abuse and Startup folder persistence, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Unauthorized Startup Folder Drop and Telegram API C2
id: b93f0693-8912-4a5e-994d-90580c5e9f01
status: experimental
description: Detects executable files dropped into the Windows Startup folder communicating with Telegram API.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: sysmon
detection:
  selection_startup:
    EventID: 11
    TargetFilename|contains:
      - '\Microsoft\Windows\Start Menu\Programs\Startup\'
  selection_c2:
    EventID: 22
    QueryName: 'api.telegram.org'
  condition: selection_startup or selection_c2
falsepositives:
  - Legitimate collaboration tools using Telegram webhooks
level: high
tags:
  - attack.t1547.001
  - attack.t1071.001
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the user download an archive from an external link (AWS S3/Phishing)?
   - If Yes -> Check EDR Process and Startup folder logs.
2. **Check for Persistence:** Did the process drop any files into the Windows Startup directory (`\Startup\`)?
   - If Yes -> **High probability of persistent RAT or Ransomware.**
3. **Analyze Network Telemetry:** Are there DNS queries or connections to legitimate cloud APIs (`api.telegram.org`, `discord.com`) from unexpected user-space executables?
   - If Yes -> **Indicates covert C2 / Data Exfiltration.**
4. **Action:** **Verdict: True Positive - Compromised (Encrypted).** Isolate host immediately, purge email, and initiate disaster recovery.

## 📝 Playbook Questions & Answers
- **What is the Initial Access method used in the attack?**
  - *Answer:* Phishing (Spearphishing Link).
  - *Reasoning:* The user received an email from `support@netflixfree.org` containing a malicious AWS S3 link to download a fake Netflix archive.
- **Has the malware been executed on the device?**
  - *Answer:* Yes.
  - *Reasoning:* EDR process and browser history confirmed the download, extraction, recursive process spawning (`1.exe`, `archive.exe`), and ultimate file encryption.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* Active ransomware deployed on the system resulted in file encryption and unauthorized remote access tool (RAT) persistence.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Leonardo / 172.16.17.159`) was immediately **Isolated** from the network via EDR to halt active exfiltration via the Telegram C2 channel and prevent network-wide encryption.
- **Email Eradication:** The phishing email was purged globally from the Exchange environment.
- **Why:** Ransomware paired with a RAT requires immediate physical/network isolation to protect shared storage and prevent the attacker from manually expanding their access.

## Recommendations
1. **Application Whitelisting (AppLocker):** Restrict execution from user-profile directories (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) to prevent malware from establishing persistence via the Startup folder.
2. **Cloud API Egress Monitoring:** Implement strict SSL inspection and Layer 7 application monitoring for traffic destined to popular cloud APIs (Telegram, Discord, GitHub) to detect unauthorized programmatic data exfiltration.
3. **Offline Immutable Backups:** Restore the affected system from a clean offline backup, as local files have been encrypted by the Hornet/Big Head ransomware variant.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Living off Trusted APIs):** When I first saw DNS queries to `api.telegram.org`, my initial assumption was that the user was simply browsing Telegram or using a web wrapper.
- **The Lesson (Contextualizing Cloud APIs):** Threat actors increasingly abuse legitimate, highly trusted APIs (Telegram bots, Discord webhooks) for command-and-control and exfiltration because firewalls almost never block them. An analyst must examine *which* process is generating the API call. A web browser accessing Telegram is normal; a hidden background process named `teleratserver.exe` running out of the Startup folder accessing Telegram is a definitive indicator of a malicious C2 channel.

## 🛠️ Skills & Tools Used
- EDR Browser & Process History Triage
- Sysmon Event Log Correlation (Event ID 22 DNS Queries & Event ID 11 File Creation)
- Ransomware Attribution (Hornet / Big Head variant identification)
- Network C2 Analysis (Telegram Bot API abuse)
- Incident Containment (Host Isolation)
