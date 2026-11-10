
# SOC200 - A Service was installed by an unauthorized user

## 🚨 Raw Alert Details
```text
EventID : 151
Event Time : 2023-05-23T22:13:55+03:00
Rule : SOC200 - A Service was installed by an unauthorized user
Role : Incident Responder
Alert Type : LOLBin / Persistence
Difficulty : Hard
MITRE ATT&CK : T1566.001, T1543.002, T1110, T1078
Hostname : Donald
IP Address : 172.16.17.52
EDR Action : Not Detected / Allowed
Trigger Reason : A non-admin user has been detected installing a service.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Windows Security Event Logs (Event ID 7045)
- **Asset Affected:** Donald (172.16.17.52)
- **Threat Type:** Unauthorized Service Installation / Persistence / Phishing
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident represents a multi-phase cyber attack combining **Spearphishing Initial Access** with **Windows Service Creation for Persistence**. 

**The Mechanics:** Attackers frequently disguise malicious payloads as routine software updates (in this case, a fake "Dropbox Update"). Once the user downloads and executes the package, the underlying script or binary establishes persistence by registering a new Windows Service using native administration tools like `sc.exe` (Service Control). By configuring the service start type to `auto` and setting its binary path to a dropped executable (`C:\Temp\DropboxUpdater.exe`), the malware ensures it executes automatically with elevated system privileges every time the machine boots, even before a user logs in.

## Investigation Steps

### 1. Phishing Email & Lure Analysis
The investigation began by reviewing the email delivery gateway to identify the initial intrusion vector.
- **Sender:** `support@appofficedrive.com` (Sent to `donald@letsdefend.io`).
- **Lure:** The email claimed an "important update is available for your system" and directed the user to download and execute an attached update file (`setup.zip`).
- **Analysis:** This social engineering tactic leverages fake software maintenance to coerce users into running untrusted code.

<img width="1243" height="532" alt="image" src="https://github.com/user-attachments/assets/13f68253-5003-4a35-891a-6f0eb94bb74a" />


### 2. Browser History & Payload Retrieval
EDR Browser History logs were queried for the affected host `Donald` (172.16.17.52).
- **Finding:** The user downloaded an archive via an AWS S3 bucket link: `https://files-ld.s3.us-east-2.amazonaws.com/dropbox+v1.3.709.zip`.
- **Analysis:** The use of AWS S3 for payload hosting allows attackers to bypass domain reputation blocks, as AWS infrastructure is trusted by default.

<img width="1224" height="344" alt="image" src="https://github.com/user-attachments/assets/d2366525-2ca1-46ab-824f-40268c05f2dd" />


### 3. Execution & Batch Script Analysis
Process execution telemetry confirmed the user extracted and executed the contents of the downloaded ZIP archive.
- **Process Lineage:** `explorer.exe` spawned `cmd.exe`, which executed a batch script: `C:\Users\LetsDefend\Downloads\dropbox+v1.3.709\dropbox v1.3.709.bat`.
- **Analysis:** The batch script acted as a stager, coordinating the setup and execution of subsequent malicious binaries on the system.

<img width="1196" height="394" alt="image" src="https://github.com/user-attachments/assets/ae4375f4-6bda-4fc2-b80c-c272dfed3ea7" />


### 4. RDP Brute-Force Correlation
Simultaneously, reviewing network and security event logs revealed unauthorized external access attempts targeting the host.
- **Brute-Force (Event ID 4625):** Multiple failed login attempts originating from external IP `149.34.244.170` attempting to access the `Donald` account.
- **Successful Logon (Event ID 4624 - Type 10):** Following the failed attempts, a successful RDP logon was recorded from the exact same external IP (`149.34.244.170`). 
- **Analysis:** The attacker successfully compromised the endpoint either via credential stuffing or by leveraging credentials harvested from the initial phishing phase.

<img width="1580" height="460" alt="image" src="https://github.com/user-attachments/assets/154cb3b7-f4bb-47c6-8580-1adeb00ae278" />
<img width="688" height="189" alt="image" src="https://github.com/user-attachments/assets/263cb004-ec4d-44d9-a74c-4e4905b817f7" />



### 5. Persistence Mechanism (Service Creation)
The alert triggered due to the creation of a new Windows service, which was captured in the security event logs (Event ID 7045).
- **Service Name:** `DropboxUpdater`
- **Service File Path:** `C:\Temp\DropboxUpdater.exe`
- **Start Type:** Auto Start (`auto start`)
- **Analysis:** The attacker utilized the `sc create` command via the terminal to establish a persistent backdoor service. Whenever Windows boots, `DropboxUpdater.exe` will automatically execute with high privileges.

<img width="893" height="501" alt="image" src="https://github.com/user-attachments/assets/7c160cf4-4177-432c-9f3a-1af7c4636d54" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Donald" was targeted by a multi-vector attack combining a fake Dropbox update phishing email with a concurrent RDP brute-force attack from `149.34.244.170`. The attacker successfully gained interactive access, executed a staging batch script (`dropbox v1.3.709.bat`), and established long-term persistence by registering an unauthorized Windows Service named `DropboxUpdater` pointing to `C:\Temp\DropboxUpdater.exe`. The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Initial Access** | T1133 | External Remote Services (RDP Brute Force) |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Persistence** | T1543.002 | Create or Modify System Process: System Service (`sc create`) |
| **Credential Access**| T1110 | Brute Force |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/dropbox+v1.3.709.zip` | Malicious Payload Delivery URL (AWS S3) |
| IP Address | 149.34.244.170 | External Attacker IP (RDP Brute Force) |
| Service Name | `DropboxUpdater` | Rogue Persistence Service |
| File Path | `C:\Temp\DropboxUpdater.exe` | Malicious Service Binary |
| Email | `support@appofficedrive.com` | Phishing Sender Address |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of unauthorized service creation, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Unauthorized Windows Service Creation via SC.exe
id: a71f9483-4321-4a5e-994d-70580b3e6d85
status: experimental
description: Detects the creation of new Windows services using sc.exe pointing to user-writable directories.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 7045
    ServiceName: '*'
    ImagePath|contains:
      - '\Temp\'
      - '\Downloads\'
      - '\AppData\'
      - 'C:\Users\'
  condition: selection
falsepositives:
  - Legitimate administrative software installations running from temp paths
level: high
tags:
  - attack.t1543.002
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for an unauthorized service installation (Event ID 7045)?
   - If Yes -> Investigate the Service Binary Path (`ImagePath`).
2. **Evaluate Path Security:** Does the service binary point to an unusual location (e.g., `C:\Temp`, `AppData`, or `Downloads`)?
   - If Yes -> High probability of malicious persistence.
3. **Check Preceding Activity:** Review process history and authentication logs (Event ID 4624/4625). Was the host recently accessed via RDP or compromised via phishing?
   - *Confirmed phishing download + RDP brute-force logon.*
4. **Action:** **Verdict: True Positive - Compromised.** Immediately isolate the host and remove the rogue service.

## 📝 Playbook Questions & Answers
- **What is the Initial Access method used in the attack?**
  - *Answer:* Phishing / Valid Accounts.
  - *Reasoning:* The attack leveraged a spearphishing email with a fake Dropbox update attachment combined with an RDP brute-force attack from `149.34.244.170`.
- **What is the persistence method used in the attack?**
  - *Answer:* Create or Modify System Process: System Service (T1543.002).
  - *Reasoning:* The attacker registered a new auto-start Windows Service named `DropboxUpdater` pointing to a malicious executable in the Temp directory.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The system is compromised, an unauthorized service was installed for persistence, and an external actor successfully logged in via RDP.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Donald / 172.16.17.52`) was immediately **Isolated** from the network via EDR to prevent lateral movement.
- **Service Eradication:** Flagged the rogue `DropboxUpdater` service for removal and deletion of `C:\Temp\DropboxUpdater.exe`.
- **Why:** Stopping the service and isolating the host prevents the attacker from maintaining persistence across system reboots or pivoting to other internal assets.

## Recommendations
1. **Remove Rogue Service:** Delete the `DropboxUpdater` service via administrative command prompt (`sc delete DropboxUpdater`) and wipe the binary from `C:\Temp\`.
2. **RDP Hardening:** Restrict RDP (Port 3389) behind a corporate VPN and enforce Multi-Factor Authentication (MFA) to prevent external brute-force logons.
3. **Service Creation Monitoring:** Restrict standard users from creating Windows services using Group Policy Object (GPO) User Rights Assignment ("Create global objects").

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Multiple Attack Vectors):** Initially, seeing both a phishing download and an RDP brute-force log made it challenging to pinpoint the exact entry vector.
- **The Lesson:** Sophisticated attacks often use "Blended Threats." The phishing email served as initial reconnaissance or credential harvesting, while the RDP brute-force provided the active interactive session used to drop the service. An analyst must correlate network, email, and authentication logs together rather than looking at a single event in isolation.

## 🛠️ Skills & Tools Used
- Windows Security Event Log Analysis (Event IDs 7045, 4624, 4625)
- EDR Process Tree & Batch Script Triage
- Service Control Management Analysis (`sc.exe`)
- Incident Containment (Host Isolation)
