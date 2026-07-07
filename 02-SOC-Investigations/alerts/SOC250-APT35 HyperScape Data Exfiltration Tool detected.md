

# SOC250 - APT35 HyperScrape Data Exfiltration Tool Detected 

## 🚨 Raw Alert Details
```text
EventID : 212
Event Time : Dec, 27, 2023, 11:22 AM
Rule : SOC250 - APT35 HyperScrape Data Exfiltration Tool Detected
Level : Security Analyst
Hostname : Arthur
Ip Address : 172.16.17.72
Process Name : EmailDownloader.exe
Process Path : C:\Users\LetsDefend\Downloads\EmailDownloader.exe
Parent Process : C:\Windows\Explorer.EXE
File Hash : cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa
Device Action : Allowed
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / SIEM
- **Asset Affected:** Arthur (172.16.17.72)
- **Threat Type:** State-Sponsored APT (Charming Kitten) / Data Exfiltration
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding APT35 and HyperScrape
APT35 (also known as Charming Kitten or Phosphorus) is an Iranian state-sponsored cyber espionage group. They are notorious for conducting long-term intelligence-gathering operations targeting government, academic, and corporate entities.

**The Mechanics of HyperScrape:** Discovered in 2022, HyperScrape is a custom data theft tool used exclusively by APT35. Rather than dropping a standard backdoor, the attacker uses stolen or hijacked credentials to run this tool. HyperScrape programmatically logs into the victim's Webmail or Exchange environment, scrapes (downloads) all emails from the Inbox in an automated fashion, and exfiltrates them to a Command & Control (C2) server. To maintain extreme stealth, the tool automatically reverts the status of the stolen emails back to "Unread," ensuring the victim never realizes their inbox was viewed by a third party.

## Investigation Steps

### 1. Initial Access Verification (RDP Correlation)
The investigation began by tracing *how* the attacker gained access to the host `Arthur` to drop the `EmailDownloader.exe` payload.
- **Log Correlation:** Searched the SIEM for authentication events surrounding the alert time.
- **Finding:** A successful Windows Logon event (Event ID 4624) with Logon Type 10 (Remote Interactive / RDP) was discovered. 
- **Source IP:** The RDP connection originated from `173.209.51.54`. Threat Intelligence confirmed this is a malicious IP, indicating the attacker used compromised credentials to directly access the host via Remote Desktop Protocol.



### 2. Payload Execution & Threat Intelligence
The EDR logs confirmed that the attacker (acting as the user `Arthur` via the RDP session) manually executed the malware payload.
- **Process Tree:** `explorer.exe` spawned `EmailDownloader.exe` (PID: 6315) from the Downloads folder.
- **Threat Intel:** The hash of the executable (`cd2ba29...`) was queried against VirusTotal. It returned a 50/70 malicious confidence score, with multiple vendors explicitly tagging the binary as the `HyperScrape` tool associated with the Iranian APT35 group.



### 3. Impact Assessment (Exchange Audit Logs)
To determine if HyperScrape successfully executed its core function (stealing emails), the Exchange server audit logs were reviewed.
- **Finding:** A raw log captured an `Operation: Download` event for the user `arthur@letsdefend.io`.
- **Subject:** `Notification of Multiple Mail Download` targeting the `\Mails\Inbox` folder.
- **Analysis:** This confirms the malware successfully authenticated to the mail server via the local host and aggressively scraped the user's inbox.

<img width="478" height="444" alt="image" src="https://github.com/user-attachments/assets/bcd53417-27dc-4622-8f94-bb779a41613a" />


### 4. Data Exfiltration Validation
To verify if the scraped emails left the corporate network, firewall logs were queried for the `EmailDownloader.exe` process.
- **Finding:** A firewall log explicitly captured `EmailDownloader.exe` initiating an outbound connection over Port 80 to `136.243.108.14`. 
- **Device Action:** SUCCESS / Permitted.
- **Analysis:** The IP `136.243.108.14` acts as the attacker's Drop Server (C2). The successful firewall connection proves that Arthur's inbox contents were fully exfiltrated to the threat actor's infrastructure.

<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/cffdea8e-e1b6-48e0-a360-8fc0aa17a824" />

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/5141428f-2236-4ba7-8a67-f35e5543ee41" />

<img width="916" height="147" alt="image" src="https://github.com/user-attachments/assets/33f5b899-7189-41eb-aeb8-ef8cb40bf1fe" />




## Analysis and Findings
The incident is a confirmed **True Positive (Successful)**. The Iranian state-sponsored group APT35 successfully compromised the user "Arthur" via an external RDP connection using valid credentials. The attacker manually executed the HyperScrape tool (`EmailDownloader.exe`), which scraped the user's Exchange inbox and successfully exfiltrated the strategic data to an external C2 server (`136.243.108.14`). The host and the user's email account are completely compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1078 | Valid Accounts |
| **Initial Access** | T1133 | External Remote Services (RDP) |
| **Collection** | T1114.002 | Email Collection: Remote Email Collection (HyperScrape) |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (SHA256) | `cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa` | HyperScrape Executable (`EmailDownloader.exe`) |
| IP Address | 173.209.51.54 | Attacker Initial Access IP (RDP Source) |
| IP Address | 136.243.108.14 | Attacker C2 / Data Exfiltration Drop Server |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Hyper-Volume Mail Download):** Alert on Exchange Audit Logs where `Operation="Download"` AND volume exceeds a standard baseline (e.g., >50 emails within 60 seconds).
- **Detection 2 (Unusual RDP Execution):** Alert when a successful RDP logon (Event ID 4624, Type 10) from an external/foreign IP is immediately followed by a new, unknown executable launching from the `C:\Users\*\Downloads` directory.

## 🚀 Decision Tree for Data Exfiltration / APT Activity
1. **Analyze Execution:** Did a flagged executable run on the system?
   - If Yes -> Determine *how* the attacker got on the system to run it.
2. **Determine Initial Access:** Query authentication logs (Event ID 4624). Was there a remote login (VPN/RDP) immediately preceding the execution?
   - *Found RDP logon from Malicious IP.*
3. **Verify Target Objective:** What is the malware designed to do? Did it do it?
   - *Malware is HyperScrape. Found Exchange logs proving inbox download.*
4. **Verify Exfiltration:** Did the malicious process communicate outbound to a C2 server?
   - If Yes -> **Verdict: True Positive - Successful Compromise & Exfiltration.**
5. **Action:** Isolate host, reset domain credentials, and escalate to Tier-2/Incident Response.

## Response and Closure
- **Action Taken:** The compromised endpoint (`Arthur / 172.16.17.72`) was immediately **Isolated** from the network to halt any further exfiltration or lateral movement. The RDP source IP and Exfiltration C2 IP were added to the perimeter blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful APT exfiltration operation.

## Recommendations
1. **RDP Exposure Hardening:** Public-facing RDP (Port 3389) is the root cause of this breach. RDP must be disabled at the perimeter. Remote access must require a corporate VPN and Multi-Factor Authentication (MFA).
2. **Enterprise Credential Reset:** Because Arthur's RDP credentials were used, a full password reset for his Active Directory account is mandatory. Furthermore, all active session tokens for his Office 365 / Exchange account must be revoked.
3. **Forensic Audit:** Given the involvement of a state-sponsored APT (Charming Kitten), Tier-2 Incident Response must conduct a deep forensic audit of Arthur's endpoint to look for secondary backdoors or lateral movement that may not have triggered alerts.

## 🛠️ Skills & Tools Used
- **SIEM Log Correlation:** Bridging Windows Security Logs (Event ID 4624 Type 10) with Firewall Proxy logs.
- **Application Log Forensics:** Analyzing Microsoft Exchange Audit Logs (`Notification of Multiple Mail Download`).
- **Threat Intelligence:** Tying binary execution to a specific, named threat actor and toolset (APT35 / HyperScrape).
- **Incident Containment & Response:** Endpoint isolation and credential remediation.
