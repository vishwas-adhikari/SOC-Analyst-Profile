
# SOC178 - WannaCry Ransomware Detected

## 🚨 Raw Alert Details
```text
EventID : 128
Event Time : 2023-03-15T14:41:50+03:00
Rule : SOC178 - WannaCry Ransomware Detected
Role : Incident Responder
Alert Type : Ransomware
Difficulty : Hard
MITRE ATT&CK : T1566.001, T1059.001, T1059.003, T1486, T1490
Hostname : Gerrard
IP Address : 172.16.17.64
File Path : \Device\HarddiskVolume1\PYTHON39\tcl\@WanaDecryptor@.exe
EDR Action : Allowed
Trigger Reason : WannaCry IOC detected on the host.
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Gerrard (172.16.17.64)
- **Threat Type:** Ransomware / Data Encryption / Spearphishing
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## Attack Context / Technical Background
**WannaCry** is a notorious ransomware cryptoworm that shocked the cybersecurity world in May 2017. While its initial outbreak relied heavily on self-propagating network exploits, threat actors frequently repurpose the underlying ransomware binary (`@WanaDecryptor@.exe`) in modern phishing campaigns as a secondary payload.

**The Mechanics:** Once the ransomware binary executes, it immediately attempts to encrypt user files while appending a specific extension. Crucially, before encryption finishes, WannaCry executes aggressive system recovery inhibition commands via native Windows utilities (`vssadmin`, `wmic`, `bcdedit`) to delete Volume Shadow Copies and disable startup recovery options. This ensures the victim cannot easily restore their files without paying the ransom.
<img width="770" height="566" alt="image" src="https://github.com/user-attachments/assets/1953dfbb-0e90-41ad-8de2-585cc6038455" />

## Investigation Steps

### 1. Initial Access Verification (Phishing & URL Deobfuscation)
The investigation began by reviewing the email delivery gateway and identifying the initial intrusion vector.
- **Email Security Check:** An email was delivered to `gerrard@letsdefend.io` from `poc.info@security.io`.
- **Lure:** The email subject was "2023 Spring Event," inviting the user to review a document linked via a shortened URL (`shorturl.at/ayFJP`).
- **Analyst Note:** Attackers use URL shorteners to mask malicious destinations from unsuspecting users and basic email scanners.

<img width="1559" height="305" alt="image" src="https://github.com/user-attachments/assets/1f1e42a7-7b04-42c1-bb3b-1293d764e4f1" />


### 2. Browser History & Payload Retrieval
EDR Browser History logs were queried for the affected host `Gerrard` (172.16.17.64) to resolve where the short URL directed.
- **Finding:** Browser history revealed the full URL destination: `https://files-ld.s3.us-east-2.amazonaws.com/Request+for+Quotation+(RFQ_196).zip`.
- **Analysis:** The user downloaded a password-protected ZIP archive masquerading as a business quotation from an AWS S3 bucket.
<img width="1206" height="282" alt="image" src="https://github.com/user-attachments/assets/6799806e-3d93-48ab-a7f4-84fd70ad541e" />


### 3. Execution Verification (Process Tree)
Process creation logs confirmed the user extracted the archive and executed the malicious installer.
- **Process Lineage:** `explorer.exe` spawned a disguised executable: `Proforma Invoice and Bank swift-REG.PI-0086547654.exe`.
- **Secondary Execution:** This dropper subsequently spawned the core ransomware binary: `@WanaDecryptor@.exe`.

<img width="1542" height="505" alt="image" src="https://github.com/user-attachments/assets/2feda5a7-1c0d-40f9-a8c6-f63e9d80e400" />
<img width="1839" height="586" alt="image" src="https://github.com/user-attachments/assets/51b4523b-82fc-45f1-971c-4310c8e4b669" />



### 4. Defense Evasion & Recovery Inhibition (Terminal History)
The definitive proof of a high-severity ransomware event was captured in the EDR Terminal History. The ransomware executed a destructive command string designed to disable system recovery:
- **Command Line:** 
  `vssadmin delete shadows /all /quiet & wmic shadowcopy delete & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no & wbadmin delete catalog -quiet`
- **Analysis:** 
  - `vssadmin` and `wmic`: Destroys all local Volume Shadow Copies.
  - `bcdedit`: Disables automatic startup repair and ignores boot failures so the system cannot boot into a repair state.
  - `wbadmin`: Deletes the Windows Backup catalog.

<img width="1592" height="495" alt="image" src="https://github.com/user-attachments/assets/2ec2849f-0451-4c35-8a11-aa7569246e9c" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Gerrard" fell victim to a spearphishing email containing a shortened URL pointing to a malicious AWS S3 archive. Upon extraction and execution, the payload deployed the infamous WannaCry ransomware binary (`@WanaDecryptor@.exe`). The malware executed system recovery inhibition commands (`vssadmin`, `wmic`, `bcdedit`) to destroy local backups and initiated file encryption. The host is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Defense Evasion** | T1490 | Inhibit System Recovery (Shadow Copy Deletion) |
| **Impact** | T1486 | Data Encrypted for Impact (WannaCry) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `shorturl.at/ayFJP` | Phishing Shortened Link |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/Request+for+Quotation+(RFQ_196).zip` | Ransomware Payload Hosting (AWS S3) |
| Binary | `@WanaDecryptor@.exe` | WannaCry Ransomware Core Binary |
| File Name | `Proforma Invoice and Bank swift-REG.PI-0086547654.exe` | Initial Dropper Executable |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of backup destruction, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Ransomware Recovery Inhibition via VSSAdmin and BCDEdit
id: e93f0692-7841-4a5e-994d-80580c4e8f90
status: experimental
description: Detects commands typically executed by ransomware to delete shadow copies and disable recovery options.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection_vss:
    CommandLine|contains:
      - 'shadowcopy delete'
      - 'vssadmin delete shadows'
  selection_bcd:
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'bootstatuspolicy ignoreallfailures'
  condition: selection_vss or selection_bcd
falsepositives:
  - Legitimate disk space management or disaster recovery scripting by admins
level: critical
tags:
  - attack.t1490
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the user execute an archive or file obtained via email/shortened link?
   - If Yes -> Proceed to Process and Terminal History.
2. **Check for Backup Destruction:** Did the executing process invoke `vssadmin`, `wmic shadowcopy`, or `bcdedit` to disable recovery?
   - If Yes -> **Critical Alert: Active Ransomware Infection.**
3. **Verify File Impact:** Are files being encrypted or is the `@WanaDecryptor@` binary present in process lists?
   - If Yes -> **Verdict: True Positive - Successful Compromise.**
4. **Action:** Immediately isolate the host from the network to stop encryption spread, purge the email, and escalate for incident response.

## 📝 Playbook Questions & Answers
- **What is the Initial Access method used in the attack?**
  - *Answer:* Phishing.
  - *Reasoning:* The user received a spearphishing email containing a shortened URL (`shorturl.at/ayFJP`) which led to a malicious ZIP archive download.
- **Has the malware been executed on the device?**
  - *Answer:* Yes.
  - *Reasoning:* EDR logs confirmed the execution of the droppers, the invocation of `@WanaDecryptor@.exe`, and the subsequent execution of shadow copy deletion commands.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* Active ransomware (`@WanaDecryptor@`) was executed on the host, requiring immediate network isolation to protect shared storage and prevent lateral movement.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Gerrard / 172.16.17.64`) was immediately **Isolated** from the network via EDR to halt encryption and prevent network-wide propagation.
- **Email Purge:** The phishing email from `poc.info@security.io` was purged globally from the Exchange server.
- **Why:** Immediate containment is critical during a ransomware outbreak to protect network shares and prevent further file destruction.

## Recommendations
1. **Immutable Backups:** Ensure critical corporate data is backed up to offline, write-once-read-many (WORM) storage that cannot be deleted by administrative command shells or ransomware APIs.
2. **URL Shortener Blocking:** Block access to common URL shortening services (`shorturl.at`, `bit.ly`, `tinyurl.com`) at the web proxy level if they do not serve a valid business purpose.
3. **EDR Behavioral Blocks:** Configure EDR policies to automatically block and kill any process attempting to execute `vssadmin delete shadows` or `wmic shadowcopy delete`.

## 🛠️ Skills & Tools Used
- EDR Terminal & Command Line Forensics (Dissecting recovery inhibition commands)
- Ransomware Attribution (`@WanaDecryptor@.exe`)
- Phishing URL Deobfuscation (Tracing short URLs to AWS S3)
- Incident Containment (Host Isolation)
