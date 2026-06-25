
# SOC146 - Phishing Mail Detected (Excel 4.0 Macros) 

## Alert Overview
- **Severity:** High
- **Detection Source:** Email Security Gateway / EDR
- **Asset Affected:** LarsPRD (172.16.17.57)
- **Threat Type:** Phishing / Malicious Document / Excel 4.0 (XL4) Macros
- **Status:** True Positive (Compromised)

## Strategy and Technical Context
The strategy of the threat actor revolves around bypassing modern macro security controls. Instead of using Visual Basic for Applications (VBA), the attacker weaponized legacy Excel 4.0 (XL4) macros. XL4 macros execute directly within spreadsheet cells rather than a dedicated VBA project module, allowing them to evade many static antivirus signatures and VBA-specific heuristic scanners. The strategic objective is to act as a stealthy "Dropper," initiating an external web request to download a secondary payload (often a C2 beacon or ransomware stager).

## Brief about the Concept
Phishing campaigns frequently use Reply-Chain spoofing (`RE: Meeting Notes`) to establish false trust. The user is coerced into downloading a `.zip` file containing an `.xls` document. When the user enables content, the hidden XL4 macros execute. In this incident, the macro utilizes the host's native `excel.exe` process to make a covert HTTP GET request to an external server to download a secondary executable or script.

## Investigation Steps

### 1. Email Triage and Extraction
The investigation began with the triage of the flagged email delivered to `lars@letsdefend.io`.
- **Sender:** `trenton@tritowncomputers.com`
- **SMTP IP:** 24.213.228.54
- **Subject:** `RE: Meeting Notes`
- **Attachment:** `11f44531fb088d31307d87b01e8eabff.zip`
- **Delivery Status:** Allowed (The message bypassed the gateway and landed in the user's inbox).

### 2. Static Analysis & OSINT
The `.zip` file was extracted in a sandbox, revealing the spreadsheet `research-1646684671.xls`.
- **Hash Analysis:** Queried the file hash against VirusTotal. It was flagged as malicious by 29/60 security vendors.
- **Behavioral Analysis:** Sandbox detonation (C2AE) revealed that upon macro execution, the file automatically reaches out to the domain `nws.visionconsulting.ro` over port 443 to retrieve an HTML-disguised payload (`dot.html`).

### 3. Execution Verification (EDR and Network Logs)
Because the email was delivered, the next step was verifying if the user interacted with the payload.
- **Network Log Correlation:** A query for the malicious C2 domain (`nws.visionconsulting.ro`) in the SIEM revealed successful outbound network connections originating from the internal host `172.16.17.57`.
- **Endpoint Telemetry:** Reviewing the EDR logs for the host `LarsPRD` confirmed the execution chain. The raw log showed `excel.exe` (spawned by `explorer.exe`) making a direct HTTP GET request to the C2 URL. 
- **Analyst Note:** An Office application (`excel.exe`) making direct outbound web requests to unknown foreign domains is a definitive Indicator of Compromise (IOC).

## Analysis and Findings
The incident is a confirmed **True Positive**. The user "Lars" received a spear-phishing email, extracted the ZIP archive, and opened the malicious Excel document. The user enabled active content, allowing the legacy Excel 4.0 Macros to execute. The macros successfully commanded `excel.exe` to connect to an external C2 server (`nws.visionconsulting.ro`). The host is considered compromised, and the secondary payload was likely downloaded and executed.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Execution** | T1059.005 | Command and Scripting Interpreter: Visual Basic (XL4 Macros) |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| File Hash (SHA256) | `1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820` | Malicious XL4 Dropper (`.xls`) |
| URL | `https://nws.visionconsulting.ro/N1G1KCXA/dot.html` | C2 Payload Delivery URL |
| Email | `trenton@tritowncomputers.com` | Spoofed Sender |
| Hostname | LarsPRD (172.16.17.57) | Compromised Internal Endpoint |

## Blind Spots
- **Secondary Payload Visibility:** The HTTP GET request was made over port 443 (HTTPS). Without SSL inspection or deep memory forensics on the endpoint, the exact contents of `dot.html` (the secondary payload) cannot be definitively categorized (e.g., whether it was a Cobalt Strike beacon, Ransomware stager, or InfoStealer).

## False Positives: Legitimate Activity Comparison
- **Dynamic Data Exchange (DDE):** Financial departments occasionally use Excel features that reach out to external servers (like Bloomberg or Reuters API) to pull live stock data. However, these connections go to highly reputable domains, whereas this connection targeted an unknown Romanian domain.

## Decision Tree for Malicious Macros
1. **Analyze Attachment:** Does the email contain an Office document (or a ZIP containing one)?
2. **Determine Macro Execution:** Does EDR show `excel.exe` or `winword.exe` spawning suspicious child processes (`cmd.exe`, `powershell.exe`) or making direct external network connections?
   - If Yes -> High probability of infection.
3. **Verify Destination:** Is the contacted domain known and reputable?
   - If No -> Verdict: **True Positive - Compromised**.
4. **Action:** Purge email, isolate host, and begin incident response.

## Response and Closure
- **Action Taken:** The malicious email was immediately purged from the Exchange server to prevent other users from opening it. The affected workstation (`LarsPRD`) was **Contained** via the Endpoint Security console to halt C2 communications.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised via Excel 4.0 Macro execution.

## Recommendations
1. **Disable XL4 Macros (GPO):** Microsoft recently introduced the ability to disable legacy Excel 4.0 macros entirely via Group Policy or the Trust Center. Given their high abuse rate and low modern utility, XL4 macros should be disabled globally across the organization.
2. **ASR Rules:** Implement Microsoft Defender Attack Surface Reduction (ASR) rules to "Block Office applications from creating child processes" and "Block Office applications from initiating executable content."
3. **Email Gateway Tuning:** Configure the email gateway to quarantine or block emails containing `.zip` archives holding legacy `.xls` files (as opposed to modern `.xlsx` files), particularly from external senders.

## Evidence / Screenshots
<img width="1041" height="221" alt="image" src="https://github.com/user-attachments/assets/8a496730-0533-4e71-90de-23116fc67031" />
<img width="658" height="221" alt="image" src="https://github.com/user-attachments/assets/8f710a20-1e26-4995-a632-affc1c9bc05d" />
<img width="616" height="436" alt="image" src="https://github.com/user-attachments/assets/51b693b8-89fe-4270-bf6e-4b14358e7eb0" />


## Skills & Tools Used
SIEM Log Correlation, EDR Process Analysis (Office Application Web Requests), Threat Intelligence (VirusTotal/C2AE Sandbox), Phishing Header Analysis, Endpoint Containment, XL4 Macro Triage.
