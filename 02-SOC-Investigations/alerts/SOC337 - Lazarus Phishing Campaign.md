
# SOC337 - Lazarus Phishing Campaign Detected (APT38)

## 🚨 Raw Alert Details
```text
EventID : 315
Event Time : 2025-03-06T07:15:00+03:00
Rule : SOC337 - Lazarus Phishing Campaign Detected (APT38)
Role : Incident Responder
Alert Type : APT Group
SMTP Address : 152.89.61.96
Device Action : Allowed
E-mail Subject : Invitation: Coinbase Crypto Trader Hiring Assessment
Source Address : trevorgreer9312@gmail.com
Destination Address : Ellen@letsdefend.io
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** Email Security Gateway / EDR
- **Asset Affected:** Ellen (Endpoint)
- **Threat Type:** State-Sponsored APT (Lazarus/APT38) / Spearphishing / Social Engineering
- **Status:** True Positive (Compromised / Link Clicked)

## 🧠 Attack Context / Technical Background (Operation Dream Job)
**Lazarus Group (APT38)** is a highly prolific, North Korean state-sponsored threat actor primarily motivated by financial theft (to fund state operations) and espionage. 

**The Mechanics:** This specific alert perfectly aligns with their long-running campaign dubbed **"Operation Dream Job."** Lazarus operatives research targets on LinkedIn and send highly tailored spearphishing emails offering lucrative positions at prominent cryptocurrency companies (in this case, *Coinbase*). 

To bypass standard email security authentication protocols (SPF/DKIM/DMARC), they frequently utilize free, legitimate email providers like Gmail. The email directs the victim to click a link to take a "Hiring Assessment" or view a "Job Description." This link typically leads to a credential harvesting portal or initiates the download of a trojanized PDF reader, cryptocurrency app, or malware-laced ZIP file containing a remote access trojan (RAT).

## Investigation Steps

### 1. Phishing Email & Sender Analysis
The investigation was initiated by reviewing the flagged email delivered to `ellen@letsdefend.io`.
- **Sender:** `trevorgreer9312@gmail.com`. The use of a freemail account is a classic evasion tactic to ensure the email passes SPF/DKIM checks at the gateway.
- **Sender IP:** `152.89.61.96`. Queried on VirusTotal, this IP scored 4/92 and is associated with malicious activity. 
- **Lure:** A highly professional, formatted email masquerading as a Coinbase hiring assessment, requiring the user to click a "Continue" button to take a 20-minute test.

<img width="947" height="192" alt="image" src="https://github.com/user-attachments/assets/0ed4bb97-1679-40f1-a98e-73b0afd84f49" />
<img width="1511" height="625" alt="image" src="https://github.com/user-attachments/assets/dcd13123-8f19-4db9-a371-a5ab79030851" />
<img width="1795" height="237" alt="image" src="https://github.com/user-attachments/assets/fed4231c-d2c8-4334-a60b-505a30b7f441" />




### 2. Payload and URL Enrichment
The URL embedded behind the "Continue" button in the email was extracted for analysis.
- **URL:** `https://blockchainjobhub.com/invite/E3fM8yF7`
- **Threat Intelligence:** The domain `blockchainjobhub.com` is a highly specific, attacker-controlled domain designed to add legitimacy to the crypto-recruitment lure. Queried against VirusTotal, the URL was flagged by 14/92 security vendors as malicious.

<img width="1812" height="256" alt="image" src="https://github.com/user-attachments/assets/4701bf56-39b6-4cde-8da2-8fca3cd63ec4" />


### 3. Endpoint Execution Verification
Because the email gateway marked the delivery as "Allowed," the investigation pivoted to Ellen's endpoint telemetry to determine if she fell for the social engineering lure.
- **Browser History:** The EDR Browser History logs explicitly showed the user navigating to `https://blockchainjobhub.com/invite/E3fM8yF7` at 00:21:35. 
- **Analysis:** This confirms the user clicked the malicious link in the email, exposing the endpoint to the attacker's infrastructure.

<img width="1173" height="272" alt="image" src="https://github.com/user-attachments/assets/d73e0e2b-c902-4be9-9598-95c90a24823f" />


## Analysis & Findings
The incident is a confirmed **True Positive**. The user "Ellen" was targeted by a sophisticated spearphishing campaign attributed to the Lazarus Group (APT38). The attacker utilized an "Operation Dream Job" lure (Coinbase assessment) sent from a Gmail account to bypass gateway filters. Endpoint telemetry confirms the user clicked the malicious link and visited the attacker-controlled domain `blockchainjobhub.com`. Because this is an advanced persistent threat, the endpoint must be treated as compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Reconnaissance** | T1598.002 | Phishing for Information: Spearphishing |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1204.001 | User Execution: Malicious Link |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Email Address | `trevorgreer9312@gmail.com` | APT38 Persona / Phishing Sender |
| IP Address | 152.89.61.96 | Malicious SMTP Source IP |
| Domain | `blockchainjobhub.com` | APT38 Infrastructure / Phishing Landing Page |
| URL | `https://blockchainjobhub.com/invite/E3fM8yF7` | Malicious Assessment Link |

## Blind Spots 
- **Post-Click Activity:** The EDR Browser History confirms the link was clicked, but it does not reveal *what happened next*. Without proxy logs or SSL decryption, it is currently unknown if the website presented a credential harvesting page (and if Ellen entered her passwords) or if the website initiated a drive-by download of a malicious payload. 

## Detection Engineering / Hunting Queries
To improve automated detection of this specific APT campaign, the following logic should be implemented in the SIEM:
- **Detection 1 (Targeted Lures):** Alert when inbound emails from freemail domains (`@gmail.com`, `@yahoo.com`) contain Subject lines matching `*Coinbase*`, `*Crypto*`, `*Hiring*`, or `*Assessment*`.
- **Detection 2 (High-Risk Domains):** Route all web traffic to newly registered domains containing the words `crypto`, `blockchain`, `job`, or `hub` to an isolated browser environment or present a user warning block-page.

## Decision Trees 
1. **Analyze Initial Vector:** Did the user receive a highly targeted recruitment or job assessment email?
2. **Examine Sender Authenticity:** Is a corporate recruitment email arriving from a generic Gmail or ProtonMail address?
   - If Yes -> High probability of social engineering / spearphishing.
3. **Verify Execution:** Check EDR Browser History. Did the user navigate to the provided link?
   - If Yes -> **Verdict: True Positive - Compromised (User Clicked).**
4. **Action:** Isolate the host immediately, force a password reset, and investigate proxy logs for secondary payload downloads.

## Response & Containment Actions Taken
- **Host Isolation:** The endpoint (`Ellen`) was immediately isolated from the corporate network to prevent potential lateral movement or data exfiltration by the APT group.
- **Email Eradication:** The malicious email was purged from the corporate Exchange server.
- **Perimeter Blocking:** The domain `blockchainjobhub.com` and the sender IP were added to the enterprise blocklist.
- **Why:** State-sponsored actors move quickly once a link is clicked. Immediate isolation is required until a full forensic audit confirms whether malware was dropped onto the system.

## Recommendations
1. **Mandatory Password Reset:** Force a password reset for the user `ellen@letsdefend.io` and revoke all active session tokens, as the landing page was likely a credential harvester.
2. **Proxy Log Audit (Tier 2):** Incident Response must review the proxy logs for the exact timeframe after the link was clicked to determine if any `.exe`, `.pdf`, or `.zip` files were downloaded to the host.
3. **Targeted Security Awareness Training:** Users in finance, executive, and HR roles must receive specialized training regarding "Operation Dream Job" tactics, specifically recognizing the red flag of major corporations utilizing freemail addresses for official hiring.

## Lessons Learned / Analyst Reflection
- **Analyst Reflection (Attribution):** It is easy to dismiss a generic Gmail phishing attempt as low-level spam. 
- **The Lesson:** This case proves the importance of reading the actual *lure* (the email body). Recognizing the TTPs (Tactics, Techniques, and Procedures) of specific threat actors—like Lazarus Group's affinity for cryptocurrency job lures—elevates a standard phishing investigation into a critical APT incident response. Relying purely on IPs and Hashes will cause analysts to miss the broader strategic intent of the attack.

## Skills & Tools Used
- **Threat Actor Attribution:** Correlating specific social engineering lures with known state-sponsored campaigns (APT38 / Lazarus Group).
- **Phishing Triage:** Analyzing email headers, sender domains, and embedded URLs.
- **EDR Telemetry Correlation:** Verifying user execution via Browser History tracking.
- **Threat Intelligence:** Utilizing VirusTotal to validate malicious infrastructure.
