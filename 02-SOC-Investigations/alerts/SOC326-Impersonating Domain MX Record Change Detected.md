

# SOC326 - Impersonating Domain MX Record Change Detected 

## 🚨 Raw Alert Details
```text
EventID : 304
Event Time : Sep, 17, 2024, 12:05 PM
Rule : SOC326 - Impersonating Domain MX Record Change Detected
Level : Security Analyst
Source Address : no-reply@cti-report.io
Destination Address : soc@letsdefend.io
Subject : Impersonating Domain MX Record Change Detected
Trigger Reason : The MX record of a suspicious domain was changed, suggesting potential phishing activity.
Domain : letsdefwnd[.]io
Mx_record : mail.mailerhost[.]net
Device Action : Allowed
```

## Alert Overview
- **Severity:** High
- **Detection Source:** Cyber Threat Intelligence (CTI) Feed
- **Asset Affected:** Mateo (Endpoint)
- **Threat Type:** Typosquatting / Spear-Phishing / Adversary Infrastructure Setup
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding MX Records & Typosquatting
Typosquatting is a social engineering technique where threat actors register domain names that are visually similar to a target organization's domain (e.g., `letsdefwnd.io` mimicking `letsdefend.io`). 

**The Mechanics:** Simply registering a domain isn't enough to launch an attack. To actually send and receive phishing emails that look somewhat legitimate, the attacker must configure the domain's DNS records—specifically the **MX (Mail Exchange) records**. An MX record tells the internet which mail server is responsible for accepting email on behalf of that domain. When a CTI platform detects a known typosquatted domain suddenly updating its MX records to point to a hosting provider (like `mail.mailerhost.net`), it is a massive red flag indicating that an active phishing campaign utilizing that fake domain is imminent. 

## Investigation Steps

### 1. CTI Triage and Infrastructure Profiling
The investigation was initiated by an internal CTI alert. The report flagged the impersonating domain `letsdefwnd.io` and its newly configured MX record.
- **CTI Data:** The report also provided a list of IP addresses actively resolving to the attacker's infrastructure.
- **OSINT Verification:** I cross-referenced several of the provided IPs against external threat intelligence platforms, confirming them as malicious hosting nodes.
<img width="728" height="433" alt="image" src="https://github.com/user-attachments/assets/349368f4-faf2-45b1-8558-35107f625dd9" />


### 2. Proactive Threat Hunting (Email Logs)
Armed with the malicious typosquatted domain, I pivoted to the Email Security gateway to determine if the attacker had already weaponized the infrastructure against our users.
- **Hunting Query:** Searched sender domains for `*@letsdefwnd.io`.
- **Finding:** A highly deceptive phishing email was discovered targeting `mateo@letsdefend.io`.
- **Lure:** The email subject was "Congratulations! You've Won a Voucher," utilizing classic greed/urgency social engineering tactics. The email bypassed the gateway (Action: Allowed).

<img width="908" height="379" alt="image" src="https://github.com/user-attachments/assets/d631138f-5859-4de8-bc7e-37d06180860c" />


### 3. Endpoint Execution Verification (EDR)
To assess the impact, I shifted the investigation to Mateo's endpoint to see if the user interacted with the phishing lure.
- **Browser History:** The EDR Browser History explicitly showed the user (Mateo) navigating to `http://www.letsdefwnd.io/` via `chrome.exe` at 13:32:13. This confirmed the user clicked the malicious link in the email.

<img width="909" height="231" alt="image" src="https://github.com/user-attachments/assets/3269311f-96f2-44d6-bc98-7ba1b7ec80b9" />


### 4. Network Log Correlation (C2/Payload Validation)
To determine where the browser was directed and if a payload was executed, network action logs were reviewed.
- **Finding:** The endpoint established a successful connection to `45.33.23.183`. 
- **Analysis:** This IP address perfectly matches one of the malicious IPs provided in the initial CTI report. Raw log analysis confirmed the firewall permitted the traffic, indicating the endpoint is actively communicating with the attacker's infrastructure.

<img width="914" height="267" alt="image" src="https://github.com/user-attachments/assets/cbf3c763-1d05-47e9-9bbe-77ab3961202d" />

<img width="800" height="200" alt="image" src="https://github.com/user-attachments/assets/1b65c40a-65c9-4c34-b33a-16054b1e8658" />

<img width="500" height="200" alt="image" src="https://github.com/user-attachments/assets/b58a797e-5df8-41ee-aa0c-d26bc7d8984d" />

## Analysis and Findings
The incident is a confirmed **True Positive**. The SOC successfully utilized proactive CTI telemetry to hunt down a live spear-phishing campaign. The attacker registered a typosquatted domain (`letsdefwnd.io`), configured MX records to facilitate email delivery, and successfully phished the user Mateo. Correlation between the email logs, EDR browser history, and network connections to known attacker IPs confirms that the endpoint is compromised. 

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Resource Development**| T1583.001 | Acquire Infrastructure: Domains (Typosquatting) |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1204.001 | User Execution: Malicious Link |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `letsdefwnd.io` | Typosquatted Impersonation Domain |
| Email | `voucher@letsdefwnd.io` | Phishing Sender Address |
| IP Address | 45.33.23.183 | Attacker Web/C2 Infrastructure |
| DNS Record | `mail.mailerhost.net` | Malicious MX Record |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Levenshtein Distance):** Implement a detection rule on the Email Gateway that calculates the Levenshtein distance (edit distance) of inbound sender domains against the corporate domain (`letsdefend.io`). Flag or quarantine incoming external emails with a distance of 1 or 2 characters.
- **Detection 2 (Newly Registered Domains):** Route all HTTP/HTTPS requests to domains registered within the last 30 days to a warning block page requiring explicit user acknowledgment.

## 🚀 Decision Tree for CTI / Impersonation Alerts
1. **Analyze CTI Data:** What infrastructure was flagged? (e.g., Domain, IP, Hash).
2. **Hunt for Delivery:** Search Email and Web Proxy logs for any interaction with the flagged domain.
   - *Found inbound phishing email from the typosquatted domain.*
3. **Check Endpoint Interaction:** Did the user click the link or download the file? (Check EDR Browser/Process History).
   - *Found browser history matching the domain.*
4. **Validate Network Traffic:** Did the endpoint communicate with the CTI-flagged IPs?
   - If Yes -> **Verdict: True Positive - Compromised.**
5. **Action:** Isolate host, purge malicious emails globally, and update perimeter blocklists.

## Response and Closure
- **Action Taken:** The compromised endpoint (Mateo) was immediately **Isolated** from the network to halt communication with the attacker's infrastructure. The phishing email was purged from the Exchange server. All IPs from the CTI report and the `letsdefwnd.io` domain were added to the enterprise blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Phishing compromise identified via proactive threat hunting.

## Recommendations
1. **Defensive Domain Registration:** The organization should preemptively purchase common misspellings of the corporate domain to prevent threat actors from utilizing them.
2. **Credential Reset:** Force a password reset for the user `mateo@letsdefend.io`, as it is highly likely the typosquatted domain hosted a credential-harvesting login page.
3. **DMARC / SPF Enforcement:** Ensure strict SPF, DKIM, and DMARC policies are enforced at the gateway to drop unauthorized senders, though typosquatting bypasses this by using a technically valid (but fake) domain.

## 🛠️ Skills & Tools Used
- **Proactive Threat Hunting:** Translating external CTI alerts into actionable internal SIEM queries.
- **Email Security Analysis:** Tracking spear-phishing campaigns originating from typosquatted infrastructure.
- **EDR Telemetry Correlation:** Verifying user execution via Browser History and tracking outbound connections to CTI-provided IP addresses.
- **Incident Containment:** Endpoint isolation and enterprise-wide IOC blocking.
