
# SOC164 - Suspicious Mshta Behavior

## 🚨 Raw Alert Details
```text
EventID : 114
Event Time : 2022-03-05T10:29:16+03:00
Rule : SOC164 - Suspicious Mshta Behavior
Role : Security Analyst
Alert Type : LOLBin
Difficulty : Medium
MITRE ATT&CK : T1218.005, T1059.001, T1105
Hostname : Roberto
IP Address : 172.16.17.38
Binary Path : C:\Windows\System32\mshta.exe
Command Line : C:\Windows\System32\mshta.exe C:\Users\roberto\Desktop\Ps1.hta
MD5 Hash (Ps1.hta) : 6685c433705f558c5535789234db0e5a
EDR Action : Allowed
Trigger Reason : Low reputation HTA executed via mshta.exe
```

## Alert Overview
- **Severity:** Medium
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Roberto (172.16.17.38)
- **Threat Type:** Living off the Land (LOLBin) / HTA Execution / Stager
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
This incident highlights the abuse of **Living off the Land Binaries (LOLBins)**, specifically **`mshta.exe`**. 

**The Mechanics:** `mshta.exe` is a legitimate, signed Microsoft utility designed to execute HTML Applications (`.hta` files). HTA files run with the full privileges of a local user, supporting HTML, CSS, and full scripting languages like VBScript or JScript without the strict security sandbox enforced by traditional web browsers. 

Threat actors frequently use `mshta.exe` to execute malicious HTA files dropped into user-writable directories (such as the Desktop or Downloads folder). Once launched, the HTA script quietly drops or spawns a secondary script (often PowerShell) to fetch a remote payload from an attacker-controlled server, achieving fileless or staged execution.

## Investigation Steps

### 1. Alert Triage & Process Verification
The investigation began by reviewing Event ID 114, which flagged the execution of `mshta.exe` pointing to a file on the user's Desktop.
- **Process Lineage:** `explorer.exe` -> `mshta.exe`
- **Command Line:** `C:\Windows\System32\mshta.exe C:\Users\roberto\Desktop\Ps1.hta`
- **Analysis:** User-writable paths like the Desktop are never valid locations for executing core system binaries or administrative scripts. This immediately raised the suspicion level.

<img width="1210" height="393" alt="image" src="https://github.com/user-attachments/assets/6880c850-379a-45c9-9f50-d667bcd1bb30" />

### 2. Command Line & PowerShell Stager Analysis
Deep inspection of the endpoint telemetry exposed the contents of `Ps1.hta` and its subsequent execution chain.
- **Payload Behavior:** The HTA script dynamically built and executed a PowerShell stager. 
- **Deobfuscation:** The command utilized string concatenation loops to piece together a `.NET.WebClient` object, ultimately reaching out to an external resource: `http://193.142.58.23/Server.txt`.
- **Analysis:** This is classic stager behavior: a lightweight initial launcher (`Ps1.hta`) executes, bypassing perimeter controls to fetch the real malicious logic (`Server.txt`) into memory.

<img width="1239" height="375" alt="image" src="https://github.com/user-attachments/assets/791d22e9-5b7c-4b68-9cc2-ee5eedb76a21" />


### 3. Network Action & Log Correlation
To verify if the endpoint successfully communicated with the external IP address, network and proxy logs were queried.
- **Network Action:** Outbound connection logs confirmed that the host `Roberto` established communication with `193.142.58.23` over port 80.
- **Raw Log Confirmation:** The proxy log explicitly captured the HTTP GET request: `Request URL: http://193.142.58.23/Server.txt`.
- **Threat Intelligence:** Querying the destination IP on VirusTotal yielded 8/94 vendor detections, confirming it as malicious infrastructure.

<img width="1586" height="341" alt="image" src="https://github.com/user-attachments/assets/5498d899-72a5-4b8f-b968-9d1595f944a6" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Roberto" executed a malicious HTA file (`Ps1.hta`) from his Desktop using the native LOLBin `mshta.exe`. The HTA script successfully spawned a PowerShell stager, which made an outbound HTTP request to `193.142.58.23` to retrieve a secondary payload (`Server.txt`). Threat intelligence confirms the destination IP is malicious. The host is fully compromised and actively communicating with external attacker infrastructure.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1218.005 | Signed Binary Proxy Execution: Mshta |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Command and Control** | T1105 | Ingress Tool Transfer |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 193.142.58.23 | Attacker C2 / Payload Hosting IP |
| URL | `http://193.142.58.23/Server.txt` | Secondary Payload Staging URL |
| File Path | `C:\Users\roberto\Desktop\Ps1.hta` | Initial Dropped HTA Payload |
| Hash (MD5) | `6685c433705f558c5535789234db0e5a` | Malicious HTA File (`Ps1.hta`) |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of `mshta.exe` abuse, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Suspicious MSHTA Executing Local HTA Files
id: e81b9482-3214-4a5e-994d-30580a2e5d84
status: experimental
description: Detects mshta.exe executing .hta files from user-writable directories like Desktop, Downloads, or AppData.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image: '*\mshta.exe'
    CommandLine|contains:
      - 'Desktop'
      - 'Downloads'
      - 'AppData'
      - '\Temp\'
  condition: selection
falsepositives:
  - Rare legitimate administrative scripts running from user profiles
level: high
tags:
  - attack.t1218.005
  - attack.t1059.001
```

## 🚀 Decision Tree 
1. **Analyze Binary Execution:** Did the alert trigger on a native OS binary (LOLBin) like `mshta.exe`?
   - If Yes -> Check the file path and command line.
2. **Evaluate File Location:** Is the executed file (`.hta`, `.vbs`, `.js`) located in a user-writable directory (Desktop, Downloads, Temp)?
   - If Yes -> High probability of malicious intent.
3. **Check Network Activity:** Did the process make an outbound HTTP/HTTPS request to an external IP immediately upon execution?
   - If Yes -> **Verdict: True Positive - Successful Compromise (Stager Execution).**
4. **Action:** Isolate host immediately, block the C2 IP/URL, and escalate to Tier 2.

## 📝 Playbook Questions & Answers
- **Is the alert a True Positive or False Positive?**
  - *Answer:* True Positive.
  - *Reasoning:* EDR process logs confirmed `mshta.exe` executed an HTA file from the Desktop, which subsequently launched a PowerShell stager connecting to an external C2 IP.
- **Has the file been executed on the device?**
  - *Answer:* Yes.
  - *Reasoning:* Process history and raw logs confirmed active execution of `Ps1.hta` by `mshta.exe`.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The endpoint successfully communicated with an external malicious IP (`193.142.58.23`) to download secondary staging data, representing an active compromise.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Roberto / 172.16.17.38`) was immediately **Isolated** from the network via EDR to prevent lateral movement or further payload retrieval.
- **Perimeter Blocking:** The malicious IP (`193.142.58.23`) and URL (`http://193.142.58.23/Server.txt`) were added to the perimeter blocklist.
- **Why:** Isolating the host immediately cuts off command-and-control communication, preventing the attacker from downloading additional stages or exfiltrating data.

## Recommendations
1. **AppLocker / WDAC Enforcement:** Restrict the execution of `.hta` files entirely across standard user workstations using Application Whitelisting. Furthermore, block `mshta.exe` from executing files originating from user profiles (Desktop/Downloads).
2. **Credential Reset:** Force a password reset for the user `roberto`, as initial access vectors involving user-executed desktop files often precede credential harvesting or token theft.
3. **Egress Filtering:** Implement strict outbound web filtering to block direct HTTP connections to raw IP addresses on non-standard ports.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (VirusTotal & LOLBins):** When I first checked `mshta.exe` on VirusTotal, it returned 0/72 detections. For a brief moment, I wondered if the alert was a false alarm.
- **The Lesson (Context over Reputation):** Legitimate binaries (LOLBins) will *always* score clean on VirusTotal because the binary itself (`mshta.exe`) is safe and digitally signed by Microsoft. An analyst must never rely solely on file reputation when evaluating LOLBins. Success or failure of the triage depends entirely on **Context**: Who ran it, where was the file located, and where is it calling out to? 

## 🛠️ Skills & Tools Used
- EDR Process Tree Analysis (LOLBin tracking)
- Command-Line Forensics (PowerShell stager deobfuscation)
- Threat Intelligence Correlation (VirusTotal IP lookup)
- Incident Containment (Host Isolation)
