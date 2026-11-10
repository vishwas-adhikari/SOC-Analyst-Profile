
# SOC185 - PsExec Service Execution Alert 

## 🚨 Raw Alert Details
```text
EventID : 135
Event Time : 2023-04-10T14:34:32+03:00
Rule : SOC185 - PsExec Service Execution Alert
Role : Incident Responder
Alert Type : LOLBin
Difficulty : Medium
MITRE ATT&CK : T1078, T1569, T1136, T1543.002, T1087
Hostname : Faun
IP Address : 172.16.17.100
Binary Path : C:/Users/LetsDefend/Downloads/PsTools/PSexec64.exe
Command Line : PsExec64.exe -s cmd.exe
EDR Action : Allowed
Trigger Reason : cmd.exe spawned from system service.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Faun (172.16.17.100)
- **Threat Type:** Living off the Land (LOLBin) / PsExec Abuse / Privilege Escalation
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
**PsExec** is a legitimate administrative tool part of the Microsoft Sysinternals suite. It allows IT administrators to execute processes on remote systems. 

**The Mechanics:** PsExec achieves remote execution by dynamically creating a Windows service named `PSEXESVC` on the target machine, copying the binary over, and executing it with `NT AUTHORITY\SYSTEM` privileges. Because of this powerful capability, threat actors frequently abuse PsExec for **Lateral Movement** and **Privilege Escalation**. When an attacker executes `PsExec64.exe -s cmd.exe`, the `-s` flag forces the command shell to run with absolute system privileges, bypassing standard user constraints.

## Investigation Steps

### 1. Initial Triage & Source Verification (Browser History)
The investigation began by examining how `PsExec` arrived on the host `Faun` (172.16.17.100).
- **Browser History:** Checked the EDR browser history to see if the tool was downloaded maliciously or retrieved by an administrator.
- **Finding:** The browser history showed navigation to official Microsoft documentation and download links: `https://learn.microsoft.com/en-us/sysinternals/downloads/psexec`. 

<img width="1379" height="437" alt="image" src="https://github.com/user-attachments/assets/8d508f9c-97eb-4454-9d8e-9d79c957d287" />


### 2. Execution Verification (Process & Service Creation)
The alert triggered because `cmd.exe` was spawned directly from the `PSEXESVC` system service.
- **Process Lineage Analysis:** Reviewing the EDR Process History confirmed the classic PsExec execution chain: `services.exe` spawned `PSEXESVC.exe`, which spawned `cmd.exe` with the `-s` flag to elevate privileges. 
- **Command Line:** `PsExec64.exe -s cmd.exe`
- **Analysis:** This successful service creation granted the attacker a `SYSTEM`-level command prompt, immediately followed by native reconnaissance commands (`whoami.exe`, `ipconfig.exe`, `systeminfo.exe`).


<img width="1215" height="651" alt="image" src="https://github.com/user-attachments/assets/a1d03629-1e79-4276-a95a-b0b1ef6026da" />



### 3. Post-Exploitation Analysis (Terminal History)
The definitive proof of malicious intent was found by reviewing the EDR Terminal History for host `Faun`. Immediately following the `PsExec` execution, the attacker performed aggressive system enumeration and persistence creation:
- `14:34:27` - `whoami` *(Checking user context)*
- `14:34:40` - `whoami /groups` *(Checking group memberships)*
- `14:34:49` - `whoami /priv` *(Checking available privileges)*
- `14:34:53` - `net user` *(Listing all local users)*
- `14:35:11` - `net localgroup` *(Listing local groups)*
- `14:35:37` - `net user opse opse1337 /add` **(Creating a rogue local user account)**
- `14:35:54` - `net localgroup Administrators opse /add` **(Elevating the rogue user to local Admin)**

<img width="1384" height="693" alt="image" src="https://github.com/user-attachments/assets/36a2ffbb-949b-4dad-a5a2-0bc8f5e23511" />


## Analysis & Findings
The incident is a confirmed **True Positive**. Even though `PsExec` was downloaded from a legitimate Microsoft source, the subsequent terminal history provides undeniable proof of unauthorized activity. The actor used PsExec to launch a `SYSTEM`-level command prompt, performed local system enumeration, and created a persistent local administrative backdoor account (`opse`). The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1569.002 | System Services: Service Execution (PsExec) |
| **Discovery** | T1087.001 | Account Discovery: Local Account (`net user`) |
| **Privilege Escalation**| T1068 | Exploitation for Privilege Escalation |
| **Persistence** | T1136.001 | Create Account: Local Account (`net user /add`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| File Path | `C:\Users\LetsDefend\Downloads\PsTools\PSexec64.exe` | Downloaded Sysinternals Binary |
| Local Account | `opse` | Rogue administrative user created by attacker |
| Command | `PsExec64.exe -s cmd.exe` | Execution signature for SYSTEM shell |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of PsExec abuse, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Suspicious PsExec Service Execution and Account Creation
id: c92f0589-2345-4a5e-994d-60591b2e6f84
status: experimental
description: Detects the creation of the PSEXESVC service and subsequent administrative account creation.
author: SOC Analyst Portfolio
logsource:
  product: windows
  service: security
detection:
  selection_service:
    EventID: 4697
    ServiceName: 'PSEXESVC'
  selection_user:
    EventID: 4688
    CommandLine|contains:
      - 'net user'
      - '/add'
  condition: selection_service or selection_user
falsepositives:
  - Legitimate remote administration by authorized IT personnel using PsExec
level: high
tags:
  - attack.t1569.002
  - attack.t1136.001
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did `cmd.exe` or a shell spawn from a system service (`PSEXESVC`)?
   - If Yes -> Investigate the origin of the tool (`PsExec`).
2. **Check Download History:** Was PsExec downloaded legitimately or dropped by malware?
   - *Found user downloaded from Microsoft Learn.*
3. **Evaluate Post-Execution Terminal History:** What commands were run immediately after the tool executed?
   - *Found enumeration (`whoami`, `net user`) and account creation (`net localgroup Administrators opse /add`).*
4. **Action:** If unauthorized account creation is present -> **Verdict: True Positive - Compromised.** Immediately isolate the host.

## 📝 Playbook Questions & Answers
- **What is the Initial Access method used in the attack?**
  - *Answer:* Valid Accounts.
  - *Reasoning:* The attacker leveraged administrative privileges or compromised credentials to execute remote service binaries (`PsExec`) on the target machine.
- **Which execution method was used in the attack?**
  - *Answer:* System Services (Service Execution).
  - *Reasoning:* PsExec dynamically created and executed the `PSEXESVC` Windows service to launch a remote command shell.
- **What is the persistence method used in the attack?**
  - *Answer:* Create Account: Local Account.
  - *Reasoning:* The attacker created a new local user (`opse`) and added them to the local Administrators group.
- **Were privilege escalation techniques used in the attack?**
  - *Answer:* Yes.
  - *Reasoning:* The attacker executed `PsExec64.exe -s` to elevate their command shell to `NT AUTHORITY\SYSTEM`.
- **Have you observed any Defense Evasion technique?**
  - *Answer:* Yes.
  - *Reasoning:* The attacker used a signed, native administrative utility (PsExec LOLBin) to blend malicious administrative actions into normal system management noise.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Faun / 172.16.17.100`) was immediately **Isolated** from the network via the EDR console to prevent lateral movement.
- **Account Remediation:** Flagged the rogue account (`opse`) for immediate deletion.
- **Why:** PsExec is primarily used for lateral movement. Isolating the host stops the attacker from using this system as a jumping-off point to infect domain controllers or other internal servers.

## Recommendations
1. **Delete Rogue Accounts:** Immediately remove the unauthorized `opse` user account from the local administrators group and the system.
2. **PsExec Monitoring / Blocking:** Restrict or rename the execution of `psexec.exe` across the enterprise using AppLocker. Only authorized IT management endpoints should have execution rights for Sysinternals tools.
3. **Credential Audit:** Review Active Directory and local credential stores to ensure the attacker did not harvest administrative password hashes while operating inside the `SYSTEM` shell.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Tool Legitimacy vs. Intent):** When I saw that PsExec was downloaded directly from `learn.microsoft.com`, I initially questioned if this was a False Positive generated by an IT admin performing maintenance.
- **The Lesson:** **Legitimate tools in the hands of unauthorized actors become malicious.** Never clear an alert as a False Positive just because the tool is signed by Microsoft or downloaded from a trusted site. Always look at *what the tool did* after it opened. The moment `net user opse /add` was typed into that `SYSTEM` shell, tool utility turned into malicious abuse.

## 🛠️ Skills & Tools Used
- EDR Terminal History Analysis (`whoami`, `net user`)
- LOLBin Trivialization & Abuse Detection (`PsExec`)
- Incident Triage & Host Containment
- MITRE ATT&CK Mapping (T1569.002, T1136.001)
