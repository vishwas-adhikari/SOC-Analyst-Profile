

# SOC101 - Phishing Mail Detected 

## 🚨 Raw Alert Details
```text
EventID : 87
Event Time : 2021-04-04T23:00:15+03:00
Rule : SOC101 - Phishing Mail Detected
Level : Security Analyst
Alert Type : Exchange
SMTP Address : 146.56.195.192
Source Address : lethuyan852@gmail.com
Destination Address : mark@letsdefend.io
E-mail Subject : Its a Must have for your Phone
Device Action : Allowed
```

## Alert Overview
- **Severity:** Low / Beginner
- **Detection Source:** Email Security Gateway
- **Asset Affected:** Mark (Endpoint)
- **Threat Type:** Phishing / Suspicious Link Delivery
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Newly Registered Domains (NRDs) and `.xyz` Abuse
Threat actors frequently utilize inexpensive or free Top-Level Domains (TLDs) like `.xyz`, `.top`, or `.site` to host disposable phishing and malware delivery infrastructure. Because these domains are incredibly cheap to register, attackers spin them up, launch a rapid spam/phishing campaign, and abandon them before major Threat Intelligence vendors (like VirusTotal) have time to crawl, analyze, and blacklist the URLs. In SOC environments, unsolicited emails containing links to obscure TLDs should be treated with high suspicion, regardless of a "clean" reputation score.

## Investigation Steps

### 1. Phishing Email Triage
The investigation began by analyzing the flagged email delivered to `mark@letsdefend.io`.
- **Sender Analysis:** `lethuyan852@gmail.com`. The use of a generic, free Webmail provider (`@gmail.com`) for a marketing/product pitch is a common indicator of spam or low-effort phishing.
- **Lure:** The email relies on curiosity and an informal tone: "Its a Must have for your Phone. Check out this product! Your life will be less difficult."
- **Payload:** The email contains a direct hyperlink to `http://nuangaybantiep.xyz`.
- **Delivery Status:** The email successfully bypassed the perimeter filters (`Action: Allowed`).

<img width="605" height="302" alt="image" src="https://github.com/user-attachments/assets/8abc92ac-f29a-4460-a9ad-fbf58cb580d2" />


### 2. URL Threat Intelligence
The embedded link (`nuangaybantiep.xyz`) was analyzed using external threat intelligence.
- **Finding:** VirusTotal returned a score of only 1/90 detections. 
- **Analyst Note:** Despite the low detection rate, the combination of an unsolicited `@gmail.com` sender and an obscure `.xyz` TLD strongly suggests malicious intent. The low score is likely due to the domain being newly registered (a "Zero-Day Domain") at the time of the attack.

<img width="1787" height="230" alt="image" src="https://github.com/user-attachments/assets/65362685-50e4-4d38-ba58-1cc4f7656597" />


### 3. Endpoint Execution Verification
Because the email was allowed into the user's inbox, the endpoint logs for the user `Mark` were queried to determine if the link was clicked.
- **Log Management / Proxy Logs:** A raw log confirmed that `chrome.exe` initiated an HTTP GET request to `http://nuangaybantiep.xyz`.
- **Device Action:** Allowed.
- **Analysis:** This confirms the user successfully clicked the link in the email, and the corporate web proxy permitted the traffic to reach the destination domain.

<img width="605" height="302" alt="image" src="https://github.com/user-attachments/assets/6b79baa6-3399-49fc-9899-54f29168328d" />


## Analysis and Findings
The incident is a confirmed **True Positive**. The user "Mark" received a generic phishing/spam email containing a suspicious link to a `.xyz` domain. Endpoint and proxy logs confirm that the user engaged with the email and clicked the link, successfully navigating to the potentially malicious site. Because the proxy permitted the traffic, the endpoint must be considered potentially compromised by either credential harvesting or a drive-by download.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1204.001 | User Execution: Malicious Link |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `nuangaybantiep.xyz` | Suspicious Link / Phishing Destination |
| Email | `lethuyan852@gmail.com` | Phishing Sender Address |
| IP Address | 146.56.195.192 | SMTP Sender IP |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this specific threat vector, the following logic should be implemented in the SIEM or Email Gateway:
- **Detection 1 (High-Risk TLDs):** Route all inbound emails containing links to `.xyz`, `.top`, `.click`, or `.site` TLDs to a quarantine queue for manual review, or rewrite the URLs to force them through an isolated browser environment.
- **Detection 2 (Webmail Filtering):** Flag emails originating from `@gmail.com` or `@yahoo.com` that contain marketing keywords ("product", "must have", "buy") and direct links to non-major domains.

## 🚀 Decision Tree for Phishing Links
1. **Analyze Email:** Does the email originate from an external, untrusted, or generic (e.g., Gmail) address?
   - If Yes -> Extract the URL.
2. **URL Triage:** Is the URL pointing to a high-risk TLD or a recently registered domain?
   - If Yes -> High probability of phishing/spam. Proceed to log review.
3. **Endpoint Review:** Did the user click the link? (Check Proxy or EDR Browser logs).
   - If Yes (Action: Allowed) -> **Verdict: True Positive - Compromised (User Interaction Confirmed).**
4. **Action:** Purge the email globally, isolate the host, and block the domain at the proxy level.

## Response and Closure
- **Action Taken:** The host (Mark) was **Isolated** via the endpoint management console to prevent potential post-exploitation activity. The email was purged from the Exchange server, and the domain `nuangaybantiep.xyz` was added to the web proxy blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Phishing link successfully clicked by the user.

## Recommendations
1. **Phishing Simulation Training:** The user (Mark) must be enrolled in remedial phishing awareness training, specifically focused on identifying suspicious sender addresses and hovering over links to check the destination TLD before clicking.
2. **Credential Reset:** As a precaution, a mandatory password reset should be initiated for Mark's Active Directory account, as the destination site may have hosted a credential harvesting portal.

## 🛠️ Skills & Tools Used
- **Phishing Triage:** Analyzing sender intent, context, and high-risk Top Level Domains (TLDs).
- **Threat Intelligence Nuance:** Understanding the limitations of reputation scoring for Newly Registered Domains (NRDs).
- **Log Correlation:** Connecting email delivery to endpoint browser execution logs.
- **Incident Containment:** Executing host isolation protocols in response to confirmed user interaction with hostile infrastructure.
