

# SOC282 - Phishing Alert - Deceptive Mail Detected — Case #257

## Alert Overview
- **Severity:** Critical
- **Detection Source:** Email Security Gateway / EDR
- **Asset Affected:** Felix-Workstation (172.16.20.151)
- **Threat Type:** Spear-Phishing / Remote Access Trojan (AsyncRAT)
- **Status:** True Positive (Compromised)

## Strategy and Technical Context
This incident highlights a sophisticated payload delivery strategy known as "Living off the Cloud." Threat actors increasingly host malicious payloads on legitimate, high-reputation cloud infrastructure (in this case, Amazon Web Services S3). Because domains like `amazonaws.com` are globally trusted and essential for business operations, traditional secure web gateways and DNS filters rarely block them. This forces defenders to rely entirely on Endpoint Detection and Response (EDR) telemetry to catch the execution phase of the attack. 

## Brief about the Concept
The attack begins with a classic social engineering lure relying on urgency ("Expires soon") and a typosquatted domain (`coffeeshoop.com`). The objective is to trick the user into downloading a ZIP archive. Inside the archive is the primary payload, **AsyncRAT**—a widely abused, open-source Remote Access Trojan designed to remotely monitor and control infected computers through an encrypted connection.

## Investigation Steps

### 1. Phishing Email Triage
The investigation was initiated by Alert 257 indicating a deceptive email bypassed the gateway (Action: Allowed).
- **Sender Analysis:** `free@coffeeshoop.com`. The domain relies on typosquatting to mimic a legitimate vendor. 
- **SMTP Source:** `103.80.134.63`.
- **Lure:** "Free Coffee Voucher" utilizing high-pressure language to force a rapid user click.

### 2. URL and Payload Enrichment
The email body contained a hyperlink directing the user to a cloud-hosted ZIP archive: `https://files-ld.s3.us-east-2.amazonaws[.]com/...free-coffee.zip`.
- **OSINT Analysis:** VirusTotal identified the URL as malicious (flagged by 3 engines as a "Silent Builder" delivery mechanism). Dynamic analysis via Any.Run confirmed the resulting payload is an AsyncRAT variant.

### 3. Endpoint Correlation (Execution)
To determine if the user interacted with the payload, EDR telemetry for the host `Felix` (172.16.20.151) was reviewed.
- **Browser History:** Confirmed the user clicked the link and downloaded the ZIP file at **12:59**.
- **Process History:** Shortly after the download, EDR recorded the execution of `Coffee.exe` (PID 6697) from the `C:\Users\Felix\Downloads\` directory. 
- **Post-Exploitation Activity:** The `Coffee.exe` process subsequently spawned `cmd.exe` (PID 6700). Terminal history confirmed these command shells were used to execute System Service and Account Discovery commands, typical of automated RAT initialization scripts.

### 4. Command and Control (C2) Validation
Network action logs were reviewed to verify successful beaconing.
- **Finding:** The `Coffee.exe` process successfully established an outbound connection to an external C2 server at `37.120.233.226`.

## Analysis and Findings
The incident is a confirmed **True Positive**. The user fell victim to a spear-phishing attack, resulting in the successful execution of AsyncRAT on the corporate endpoint. The malware successfully established a C2 connection and began local enumeration. Due to the capabilities of AsyncRAT (keylogging, credential dumping, reverse shell access), the host is considered fully compromised and a risk to the wider network.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment/Link |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| **Discovery** | T1087 | Account Discovery |
| **Discovery** | T1007 | System Service Discovery |
| **Command and Control**| T1071.001 | Application Layer Protocol: Web Protocols |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| SHA256 Hash | `CD903AD2211CF7D166646D75E57FB866000F4A3B870B5EC759929BE2FD81D334` | Malicious payload (`Coffee.exe`) |
| IP Address | 37.120.233.226 | AsyncRAT C2 Server |
| IP Address | 103.80.134.63 | Malicious SMTP Source |
| URL | `https://files-ld.s3.us-east-2.amazonaws[.]com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip` | Payload Delivery URL |
| Email | `free@coffeeshoop.com` | Spoofed Sender |

## Blind Spots
1. **Cloud Hosting Obfuscation:** Because the payload was hosted on AWS S3, standard domain reputation checks initially fail to flag the URL as malicious, creating a blind spot at the perimeter network layer.
2. **Encrypted C2:** AsyncRAT encrypts its C2 traffic. Without SSL inspection and memory forensics, the exact data exfiltrated during the beaconing phase cannot be definitively known.

## False Positives: Legitimate Activity Comparison
- **Marketing Emails:** Legitimate marketing departments frequently send vouchers via email using third-party mailers that may initially appear suspicious. However, a legitimate voucher will never require the user to extract and run a `.exe` file.

## Decision Tree for Malware Delivery via Phishing
1. **Analyze Email:** Is the sender domain newly registered or typosquatted?
   - If Yes -> Extract URL.
2. **URL Triage:** Does the URL point to a cloud storage provider (AWS, Azure, Google Drive) hosting an archive/executable?
   - If Yes -> High probability of infection. Proceed to EDR.
3. **Endpoint Review:** Did the user download and execute the file?
   - If Yes -> Check process tree for suspicious child processes (`cmd.exe`, `powershell.exe`).
4. **Execution Check:** Are there outbound connections to unknown IPs?
   - If Yes -> Verdict: **True Positive - Compromised**.

## Response and Closure
- **Action Taken:** 
  1. Endpoint isolated via EDR to sever the C2 connection and prevent lateral movement.
  2. Malicious email purged from the Exchange server to prevent further interactions.
  3. Forced password reset for user `felix@letsdefend.io`.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised by AsyncRAT.

## Recommendations
1. **Attack Surface Reduction (ASR):** Implement Microsoft Defender ASR rules to block the execution of unsigned executable files originating from USB drives and webmail/download directories (e.g., `%USERPROFILE%\Downloads`).
2. **Gateway Tuning:** Enhance the email security gateway to aggressively flag or quarantine emails originating from newly registered domains or domains with a high Levenshtein distance to known brands (Typosquatting protection).
3. **User Awareness:** Reinforce phishing simulation training for this department, focusing specifically on urgency-based social engineering tactics.

## Mistakes and Lessons Learned
- **Analyst Reflection:** The email gateway allowed the email to pass through to the user's inbox despite the clear domain typo (`coffeeshoop.com`). 
- **The Lesson:** This incident underscores the extreme danger of treating "Allowed" gateway alerts as benign. Security tools rely heavily on reputation; when attackers leverage trusted cloud infrastructure (AWS) and fresh domains, those tools fail. Endpoint telemetry—specifically monitoring the process tree for user-space executables spawning command shells—must be the ultimate source of truth for an analyst.

## Evidence / Screenshots
- **EDR Process History (Malware Execution)**  
![Insert Screenshot: EDR showing Coffee.exe executed from Downloads folder and the SHA256 Hash]
- **EDR Browser History (Payload Download)**  
![Insert Screenshot: EDR showing navigation to the AWS S3 free-coffee.zip URL]

## Skills & Tools Used
SIEM, EDR (Process Tree Analysis), OSINT (VirusTotal, Any.Run), Phishing Header Analysis, Malware Capability Mapping (AsyncRAT), Host Containment.


<img width="700" height="382" alt="image" src="https://github.com/user-attachments/assets/8808422e-08f1-4c84-a9ce-a36466eb2a6f" />
<img width="700" height="246" alt="image" src="https://github.com/user-attachments/assets/2d111788-b229-4448-b333-2edde7298e79" />

