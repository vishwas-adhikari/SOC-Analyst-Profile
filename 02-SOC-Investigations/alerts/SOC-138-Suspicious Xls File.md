
# SOC-138- Suspicious Xls File Detected — Case #100

## Alert Overview
- **Severity:** Medium
- **Detection Source:** EDR / Antivirus
- **Asset Affected:** Sofia-Workstation (172.16.17.56)
- **Threat Type:** Malicious Document (MalDoc) / Command and Control (C2)
- **Status:** True Positive (Compromised)

## Strategy and Technical Context
This incident involves a weaponized Microsoft Excel spreadsheet (`.xls`). The strategy of the threat actor is to bypass perimeter defenses by embedding malicious macros or exploits within a seemingly benign office document. Once opened, the document reaches out to an external infrastructure to download and execute a secondary payload, establishing a Command and Control (C2) channel. Because the initial `Device Action` was "Allowed," the investigation's focus immediately shifted from simple malware triage to active compromise validation and containment.

## Brief about the Concept
Attackers frequently use Excel documents equipped with malicious VBA macros or utilizing vulnerabilities like **CVE-2017-11882** (Equation Editor vulnerability) to achieve initial access. These files act as "droppers" or "stagers." Once executed, they silently invoke built-in Windows processes (like `cmd.exe` or `powershell.exe`) to connect to an attacker-controlled server, download a more robust payload (like an InfoStealer or RAT), and execute it.

## Investigation Steps

### 1. Alert Triage and OSINT Enrichment
The alert identified a suspicious file hash (`7ccf88c0bbe3b29bf19d877c4596a8d4`) on the endpoint `172.16.17.56`. 
- **VirusTotal:** The hash was flagged as malicious by 47/66 security vendors. 
- **Behavioral Analysis:** Reviewing the "Behavior" and "Relations" tabs in VirusTotal and HybridAnalysis revealed the file attempts to make network connections to a Brazilian domain (`multiwaretecnologia.com.br`) and several associated IP addresses, a strong indicator of C2 beaconing.

### 2. Internal Log Correlation (Verifying Execution)
To determine if the malware successfully executed on the endpoint, internal Log Management was queried using the source IP of the affected machine (`172.16.17.56`).
- **Network Actions:** Found two outbound connections matching the exact timestamp of the alert (Mar 13, 2021, 08:20 PM).
- **Destination:** The endpoint communicated with `177.53.143.89` over Port 443. 
- **Threat Intel Pivot:** Cross-referencing this destination IP back to the VirusTotal Relations report confirmed it is one of the specific malicious IPs contacted by the spreadsheet file in sandbox environments.

### 3. Playbook Execution and Impact Assessment
- **Threat Indicator:** Defined as *Unknown or unexpected outgoing traffic* due to the confirmed C2 beaconing.
- **Quarantine Status:** The original alert indicated `Device Action: Allowed`. The file was **Not Quarantined** by the AV, allowing execution to occur.
- **C2 Access:** Confirmed as **Accessed** based on the 443 traffic matching the OSINT sandbox reports.

## Analysis and Findings
The incident is a confirmed **True Positive**. The user "Sofia" interacted with a malicious `.xls` file that successfully bypassed the initial endpoint security controls. The execution of the file resulted in outbound network traffic to a known malicious C2 IP address (`177.53.143.89`). Given that the connection was established over an encrypted channel (Port 443), the exact nature of the secondary payload or exfiltrated data cannot be immediately determined from network logs alone, necessitating full host isolation.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |
| **Command and Control** | T1573.002 | Encrypted Channel: Asymmetric Cryptography |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (MD5) | `7ccf88c0bbe3b29bf19d877c4596a8d4` | Malicious Dropper (`.xls`) |
| Domain | `multiwaretecnologia.com.br` | Suspected Payload Delivery Domain |
| IP Address | 177.53.143.89 | C2 / Secondary Payload Infrastructure |
| Hostname | Sofia (172.16.17.56) | Compromised Internal Endpoint |

## Blind Spots
1. **Encrypted C2:** Because the beaconing occurred over port 443 (HTTPS), the contents of the payload downloaded or data exfiltrated remain invisible without SSL decryption or full memory forensics.
2. **Execution Method:** The specific mechanism of execution (e.g., VBA Macros vs. Exploit/CVE) was not definitively verified during triage, though the outcome (C2 connection) was confirmed.

## False Positives: Legitimate Activity Comparison
- **Business Macros:** Legitimate spreadsheets often contain macros that make outbound web connections to pull internal database reporting. However, legitimate files do not have 47/66 detections on VirusTotal or communicate with low-reputation foreign domains.

## Mistakes and Lessons Learned
- **Analyst Reflection:** The investigation highlights the importance of not stopping at the AV alert. Just because a system flags a file does not mean it successfully stopped it.
- **The Lesson:** Always check the `Device Action`. When a device action is "Allowed," the immediate next step must always be querying network logs to see if the malware successfully established its intended C2 connection.

## Response and Closure
- **Action Taken:** The host (`Sofia / 172.16.17.56`) was immediately isolated via the Endpoint Security console to terminate the C2 connection and prevent potential lateral movement.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised via malicious document. 

## Recommendations
1. **Forensic Image & Rebuild:** The host should remain isolated, and a forensic image should be taken to determine if data exfiltration occurred. The machine should then be wiped and re-imaged from a known good baseline.
2. **Perimeter Blocking:** Add the hash, the C2 IP (`177.53.143.89`), and the associated domain (`multiwaretecnologia.com.br`) to corporate perimeter blocklists.
3. **Macro Security:** Implement GPO policies to enforce "Disable all macros with notification" or block macros originating from the internet entirely.
4. **Credential Reset:** Issue a mandatory password reset for the user "Sofia" out of an abundance of caution regarding credential-harvesting secondary payloads.

## Evidence / Screenshots
<img width="1000" height="200" alt="image" src="https://github.com/user-attachments/assets/a0ac8ad1-a092-442d-9469-19a8abfb0e92" />
<img width="1000" height="250" alt="image" src="https://github.com/user-attachments/assets/c5b8253c-1b50-478a-ab93-f1ec3f4da03a" />
<img width="700" height="300" alt="image" src="https://github.com/user-attachments/assets/b7931a3f-9b55-4d6a-8f2c-c42f1a6a4bcd" />




## Skills & Tools Used
SIEM Log Correlation, Threat Intelligence (VirusTotal, HybridAnalysis), OSINT, Endpoint Containment, Incident Response Triage, MITRE ATT&CK Mapping.
