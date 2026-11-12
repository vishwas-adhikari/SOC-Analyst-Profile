
# SOC180 - BianLian Ransomware Detected

## 🚨 Raw Alert Details
```text
EventID : 130
Event Time : 2023-03-27T13:34:23+03:00
Rule : SOC180 - BianLian Ransomware Detected
Role : Incident Responder
Alert Type : Ransomware
Difficulty : Hard
MITRE ATT&CK : T1566, T1059, T1059.001, T1486
Hostname : Jordan
File Path : \Device\HarddiskVolume1\Users\LetsDefend\Downloads\46d340eaf6b78207e24b6011422f1a5b4a566e493d72365c6a1cace11c36b28b.bin\46d340eaf6b78207e24b6011422f1a5b4a566e493d72365c6a1cace11c36b28b.exe
EDR Action : Allowed
IP Address : 172.16.17.11
Affected User : Jordan
Trigger Reason : BianLian IOC detected on the host.
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Jordan (172.16.17.11)
- **Threat Type:** Ransomware / Double Extortion / Pirated Software Vector
- **Verdict:** True Positive (Compromised / Encrypted)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
**BianLian** is a sophisticated ransomware operation that emerged in late 2021. The group specializes in multi-pronged extortion, threatening both the deployment of a destructive file encryptor and the public release of stolen corporate data.

**The Mechanics:** Unlike traditional email spearphishing, BianLian campaigns frequently exploit shadow IT and employee risk-taking behavior—specifically, the downloading of cracked software, torrents, or pirated games on corporate assets. Once executed, the ransomware drops into user directories, rapidly encrypts files while appending the `.bianlian` extension, and leaves behind a ransom note instructing victims to contact the threat actors via QTox messenger or their TOR/I2P leak blogs.

## Investigation Steps

### 1. Initial Access Verification (Torrent / S3 Download)
The investigation began by reviewing the browser history of the affected host `Jordan` (172.16.17.11) to determine how the payload arrived.
- **Browser History:** Disclosed visits to suspicious domains, specifically `pc_gamescrack.com` attempting to download a torrent for a game ("NBA 2k23").
- **Payload Delivery:** The actual file was pulled from an AWS S3 bucket: `https://files-ld.s3.us-east-2.amazonaws.com/NBA+2k23.zip`.
- **Analysis:** The user attempted to download pirated software on a corporate endpoint, inadvertently downloading the BianLian ransomware stager.

<img width="1236" height="405" alt="image" src="https://github.com/user-attachments/assets/b3b995a4-4ada-4a37-98a7-9460368dc22e" />


### 2. Execution Verification (Process Lineage)
EDR process logs confirmed the user extracted and executed the downloaded archive.
- **Process Creation:** The compressed payload dropped and executed the primary ransomware binary: `46d340eaf6b78207e24b6011422f1a5b4a566e493d72365c6a1cace11c36b28b.exe`.
- **Threat Intelligence:** Querying the file hash on VirusTotal returned a 40/51 malicious detection rate, with crowdsourced Sigma rules triggering on fake recycle bin folders, startup folder writes, and anomalous office startup behavior.
<img width="1804" height="681" alt="image" src="https://github.com/user-attachments/assets/f5f2bc8a-7887-4006-9ead-75670a384723" />


### 3. File System Impact & Encryption
Reviewing the host's file structure confirmed that the encryption phase completed successfully.
- **File Extensions:** Critical documents on the Desktop were systematically renamed and appended with the `.bianlian` extension (e.g., `Examples.doc.bianlian`, `Gym.doc.bianlian`, `Meeting_Notes.docx.bianlian`).
- **Ransom Note:** A text document was dropped on the desktop titled `Look at this instruction.txt`. Opening the note displayed the ransom demands, a QTox ID, an onionmail address, and the threat actor's Tor/I2P leak site (`bianlianlbc5an4kgnay3opdemgcry2kpfgbkczopmm3dnbz3uaunad.onion`), threatening to publish stolen internal files.

<img width="774" height="259" alt="image" src="https://github.com/user-attachments/assets/a316a273-a036-4db4-a987-1978e419b46b" />

<img width="1022" height="454" alt="image" src="https://github.com/user-attachments/assets/863064e1-b424-48ef-81e2-6c6c6714c552" />


### 4. Post-Exploitation & Cleanup (Terminal History)
The EDR Terminal History captured post-encryption activities.
- **Command Line:** Evidence of `cmd.exe` running cleanup commands (`del`) to remove dropped stagers and erase immediate execution artifacts.

<img width="1201" height="352" alt="image" src="https://github.com/user-attachments/assets/875ee0dc-3532-4aef-954d-7ffee44dce7c" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Jordan" downloaded pirated software (`NBA+2k23.zip`) from an unauthorized torrent site via AWS S3. Unbeknownst to the user, the archive contained the BianLian ransomware binary. The payload executed successfully, encrypting local files with the `.bianlian` extension and dropping the `Look at this instruction.txt` ransom note. The endpoint is fully compromised and data encryption has occurred.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566 | Phishing / Drive-by Compromise (Pirated Software) |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Impact** | T1486 | Data Encrypted for Impact (BianLian) |
| **Impact** | T1567.002 | Exfiltration Over Web Service (Double Extortion via Leak Site) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/NBA+2k23.zip` | Ransomware Payload Delivery URL (AWS S3) |
| Hash (SHA256) | `46d340eaf6b78207e24b6011422f1a5b4a566e493d72365c6a1cace11c36b28b` | BianLian Ransomware Binary |
| File Name | `Look at this instruction.txt` | BianLian Ransom Note |
| Onion URL | `http://bianlianlbc5an4kgnay3opdemgcry2kpfgbkczopmm3dnbz3uaunad.onion` | BianLian Data Leak/Extortion Blog |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of mass file encryption, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: BianLian Ransomware File Extension Appended
id: e82f0592-1234-4a5e-994d-50580c4e8f92
status: experimental
description: Detects mass file modification resulting in the .bianlian extension.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    TargetFilename|endswith: '.bianlian'
  condition: selection
falsepositives:
  - None
level: critical
tags:
  - attack.t1486
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the alert trigger on an unknown executable run from the `Downloads` directory?
   - If Yes -> Check browser history for torrent or cracking sites.
2. **Verify File System Impact:** Are user files being renamed with an unfamiliar extension (e.g., `.bianlian`)?
   - If Yes -> **Critical Alert: Active Ransomware Encryption.**
3. **Check for Ransom Notes:** Is there a text file on the Desktop containing extortion demands and `.onion` links?
   - If Yes -> **Verdict: True Positive - Successful Ransomware Compromise.**
4. **Action:** Immediately isolate the host from the network, sever shared drives, and activate the incident response plan.

## 📝 Playbook Questions & Answers
- **Is the alert a True Positive or False Positive?**
  - *Answer:* True Positive.
  - *Reasoning:* EDR logs and file system artifacts confirmed the execution of the BianLian ransomware binary, resulting in mass file encryption (`.bianlian`) and ransom note creation.
- **Has the file been executed?**
  - *Answer:* Yes.
  - *Reasoning:* Process history and file system state confirm the `.exe` executed and encrypted the user's desktop files.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* Active ransomware infection requires immediate network isolation to protect shared network storage and prevent lateral movement.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Jordan / 172.16.17.11`) was immediately **Isolated** from the network via EDR to halt further encryption and prevent access to internal file shares.
- **Why:** Immediate containment is mandatory during a ransomware outbreak to restrict the "blast radius" of the infection.

## Recommendations
1. **Endpoint Rebuilding:** Because file encryption (`.bianlian`) successfully completed on the local machine, the host cannot be trusted and must be wiped, reformatted, and re-imaged from a clean backup.
2. **Web Filtering & Shadow IT:** Enforce strict web proxy filtering to block known torrenting sites (`pc_gamescrack.com`) and block unapproved execution of downloaded `.zip` or `.exe` files from non-corporate sources.
3. **Data Exfiltration Audit:** Due to BianLian's double-extortion model, check firewall egress logs for large outbound data transfers prior to the encryption timestamp to determine if data was exfiltrated to the attackers.

## 🛠️ Skills & Tools Used
- EDR Process Tree Analysis
- Ransomware Attribution (BianLian / `.bianlian` extension)
- File System Triage (Identifying ransom notes and encrypted files)
- Incident Containment (Host Isolation)
