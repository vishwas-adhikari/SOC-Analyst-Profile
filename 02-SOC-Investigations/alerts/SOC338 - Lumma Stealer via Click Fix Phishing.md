
# SOC338 - Lumma Stealer via Click Fix Phishing — Case #316

## Alert Overview
- **Severity:** Critical
- **Detection Source:** SIEM / EDR
- **Asset Affected:** Dylan-Workstation (172.16.17.216)
- **Threat Type:** Lumma Stealer / DLL Side-Loading
- **Status:** True Positive

## Strategy and Technical Context
The "Click Fix" (also known as "ClearFake" or "Browser Update" lures) marks a strategic shift in threat actor methodology. As organizations have successfully implemented defenses against traditional Office macros and Mark-of-the-Web (MotW) protected files, attackers have pivoted to social engineering tactics that turn the user into a trusted surrogate for execution. 

By instructing a user to manually open a run box (`Win+R`) and paste a command, the attacker effectively bypasses the browser’s automated sandbox and "safe browsing" file-scanning mechanisms. The technical objective is to execute a stager that performs DLL Side-Loading—using a legitimate, digitally signed binary to load a malicious DLL—thereby evading signature-based EDR detection.

## Brief about the Concept
Lumma Stealer is a sophisticated C-based Information Stealer. It focuses on harvesting sensitive data, including browser-stored credentials, credit card information, cryptocurrency wallets, and session cookies. The "Click Fix" delivery method leverages a fake error message (e.g., "Windows 11 update failed") to convince users to execute a PowerShell command. This command typically utilizes a hidden clipboard function to download and execute the primary malware payload.

## Investigation Steps

### 1. Phishing Email Analysis
The investigation began with the triage of a suspicious email received by `dylan@letsdefend.io`.
- **Sender:** `update@windows-update.site`
- **Subject:** "Upgrade your system to Windows 11 Pro for FREE"
- **Findings:** The email utilized a spoofed Microsoft template to drive traffic to a malicious landing page.

### 2. URL Reputation Enrichment
The embedded link was analyzed using VirusTotal and Cisco Talos.
- **URL:** `https://windows-update.site/`
- **Result:** 11/95 security vendors flagged the domain. The site was confirmed to be hosting a "Click Fix" script.

### 3. Endpoint Detection & Response (EDR) Review
Analysis of Dylan’s workstation logs showed:
- **Browser History:** User visited the malicious site at 23:26:08.
- **Terminal History:** At 23:26:19, three `PowerShell.exe` processes were initiated.
- **Observation:** The temporal correlation between the web visit and the PowerShell execution confirms the user manually executed the attacker’s command.

### 4. Post-Exploitation Evidence
EDR telemetry indicated the PowerShell stager attempted to pull a binary from the remote IP. The alert for "DLL Side-Loading" suggests that once the binary landed, it attempted to load a malicious `.dll` to initialize the Lumma Stealer logic.

## Analysis and Findings
The incident is a confirmed True Positive. The user fell victim to a social engineering lure. Evidence from the EDR logs shows a direct correlation between the site visit and the manual execution of encoded PowerShell scripts. The successful execution of these scripts facilitated the initial payload delivery of Lumma Stealer.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Execution** | T1204.001 | User Execution: Malicious Link |
| **Defense Evasion** | T1574.002 | Hijack Execution Flow: DLL Side-Loading |
| **Credential Access** | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP | 132.232.40.201 | SMTP/Web server for the phishing campaign |
| Domain | windows-update.site | Malicious domain hosting the Click Fix lure |
| Email | update@windows-update.site | Attacker source email |
| Host | 172.16.17.216 (Dylan) | Compromised internal endpoint |

## Blind Spots
The following areas presented limited visibility during the investigation:
1. **Encoded Payloads:** If the PowerShell command used advanced obfuscation or Base64 encoding, standard log monitoring might miss the specific download URL or C2 address.
2. **Encrypted C2:** Information stealers like Lumma frequently use encrypted TLS channels for exfiltration, making it difficult to determine exactly what data was stolen without SSL inspection.
3. **Clipboard Monitoring:** Most standard EDR configurations do not log clipboard history, making it difficult to capture the exact string the user copied from the malicious website.

## False Positives: Legitimate Activity Comparison
Similar activities that may trigger false alerts include:
1. **IT Support Troubleshooting:** Legitimate Helpdesk staff providing a user with a PowerShell command to fix a driver or system issue via an internal knowledge base.
2. **DevOps Setup Scripts:** Developers running automated environment configuration scripts (`.ps1`) downloaded from trusted repositories (e.g., GitHub or internal GitLab).
3. **Administrative Software Installers:** Some legacy software packages use PowerShell stagers to verify system requirements during the installation phase.

## Decision Tree for Click Fix Phishing
1. **Analyze Email:** Is the sender/domain suspicious?
   - If Yes -> Proceed to URL Analysis.
2. **URL Triage:** Is the site using "Click Fix" lures?
   - If Yes -> Proceed to EDR review.
3. **Endpoint Review:** Did the user visit the site?
   - If Yes -> Check for manual `powershell.exe` execution.
4. **Execution Check:** Did PowerShell execute around the time of the web visit?
   - If Yes -> Verdict: True Positive - Compromised.
5. **Remediation:** Isolate host and reset user credentials.

## Response and Closure
- **Action Taken:** Purged phishing email; isolated workstation (172.16.17.216) to stop data exfiltration.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised via social engineering.

## Recommendations
1. **ASR Rule Implementation:** Enable "Block process creations originating from PSCore and PowerShell commands" in Microsoft Defender.
2. **PowerShell CLM:** Implement Constrained Language Mode to restrict the execution of advanced scripts for non-admin users.
3. **Training:** Targeted education on "Copy-Paste" phishing techniques.
4. **Credential Rotation:** Immediate password reset for all applications accessed by the compromised user.

## Evidence / Screenshots
- **Malicious Email Lure**  

<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/1648929f-b1e1-42f3-87d5-69075269a73c" />


- **URL Reputation (VirusTotal)**  

<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/220f1f9b-d056-4abc-bac8-0dbe6b99994c" />


- **EDR Browser History**  

<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/aa5cc678-ece5-493d-b702-77aff06c1c15" />


- **Malicious PowerShell Execution**
- 
- <img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/0b7db3ca-476e-4181-bcea-a936f4d3c9f6" />


## Skills & Tools Used
SIEM, EDR (Process/Browser Logs), VirusTotal, Phishing Analysis, PowerShell Analysis, Incident Response, Host Containment, MITRE ATT&CK Mapping.
