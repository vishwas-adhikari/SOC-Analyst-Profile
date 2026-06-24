
# SOC167 - LS Command Detected in Requested URL 

## Alert Overview
- **Severity:** High
- **Detection Source:** WAF / SIEM
- **Asset Affected:** EliotPRD (172.16.17.46)
- **Threat Type:** OS Command Injection (False Alarm)
- **Status:** False Positive

## Strategy and Technical Context
This alert is designed to catch OS Command Injection attempts. Attackers frequently attempt to execute the `ls` (list directories) command within URL parameters to map the underlying file system of a vulnerable Linux web server. However, the strategy of the detection rule in this instance relies on a "greedy" string match rather than strict Regular Expressions (Regex). The rule flags any URL containing the consecutive characters "ls", leading to significant False Positives when legitimate English words containing "ls" (such as "skills", "also", or "false") are passed through web parameters.

## Brief about the Concept
Command Injection occurs when an application passes unsafe user-supplied data to a system shell. Defenders write SIEM and WAF rules to monitor web traffic for common Linux/Unix shell commands like `cat`, `whoami`, `pwd`, and `ls`. If these rules lack strict boundaries (like requiring spaces or command separators before and after the keyword), they will trigger on benign, everyday web traffic, contributing to Alert Fatigue.

## Investigation Steps

### 1. Alert Triage and Directionality
The alert was triggered by an outbound HTTP GET request.
- **Source:** EliotPRD / 172.16.17.46 (Internal Ubuntu 16.04.4 Workstation)
- **Destination:** 188.114.96.15 (External Web Server)
- **Directionality:** Corporate Network to Internet.
- **Device Action:** Allowed.

### 2. Payload and URL Analysis
The raw log showed the following HTTP request:
- **Requested URL:** `https://letsdefend.io/blog/?s=skills`
- **User-Agent:** `Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0`
- **Parameter Analysis:** The `?s=` parameter is the default search query parameter for WordPress websites. The user searched the blog for the word "skills". The detection engine triggered because the substring "ls" is present at the end of the word "ski**ls**".

### 3. Endpoint and User Correlation
To verify this was a legitimate user action and not an automated malware beacon, the EDR logs for the host `EliotPRD` were reviewed.
- **Browser History:** The exact URL (`https://letsdefend.io/blog/?s=skills`) was found in the endpoint's browser history at 00:36, perfectly correlating with the network alert.
- **Process Review:** No malicious child processes, unexpected bash shells, or anomalous outbound connections were observed.

### 4. Threat Intelligence Validation
The destination IP (`188.114.96.15`) was analyzed using VirusTotal and AbuseIPDB.
- **Finding:** The IP is owned by Cloudflare and holds a neutral/clean reputation. It is functioning as a legitimate Content Delivery Network (CDN) for the `letsdefend.io` domain.

## Analysis and Findings
The incident is a confirmed **False Positive**. The alert was triggered by benign outbound web browsing. A corporate user (Eliot) was utilizing Mozilla Firefox to search a cybersecurity blog for the term "skills". The SIEM rule "URL Contains LS" was overly broad and matched the substring within the search parameter. There is no malicious traffic, no command injection attempt, and no risk to the organization.

## MITRE ATT&CK Mapping
*Note: This maps the intended technique the rule was designed to detect, though the event itself is benign.*
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| **Initial Access** | T1190 | Exploit Public-Facing Application |

## Indicators of Compromise (IOCs)
*Note: The following indicators are benign and provided for context only.*
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 188.114.96.15 | Benign Destination (Cloudflare CDN) |
| URL Path | `/?s=skills` | Benign WordPress Search Parameter |
| Keyword | `ls` | The string that triggered the False Positive |

## Blind Spots
- **Regex Inefficiency:** Rules written with greedy string matching (e.g., `*ls*`) obscure genuine attacks by burying analysts in hundreds of false alerts daily. If an actual attack occurred during a flood of these false positives, it might be overlooked (Alert Fatigue).

## False Positives: Legitimate Activity Comparison
This entire incident is a False Positive. Other legitimate activities that will trigger this poorly written rule include:
- Users visiting sites with words like "fa**ls**e", "e**ls**e", or "too**ls**" in the URL path.
- Developers pushing code containing `.x**ls**x` file extensions.

## Decision Tree for Command Injection Alerts
1. **Identify Payload:** What command triggered the alert (e.g., `ls`, `cat`)?
2. **Contextualize the String:** Is the command part of a legitimate English word or file extension?
   - If Yes -> High probability of False Positive.
3. **Analyze the Target:** Is the traffic outbound (user browsing) or inbound (attacker targeting an internal server)?
   - If Outbound browsing to a safe site -> Verdict: **False Positive**.
4. **Action:** Close alert and submit a SIEM tuning request.

## Response and Closure
- **Action Taken:** Verified the benign nature of the traffic. Documented the flaw in the detection rule logic.
- **Containment Required:** No.
- **Closure Reason:** False Positive. Alert triggered by a legitimate search query.

## Recommendations
1. **SIEM Rule Tuning (Immediate):** The detection engineering team must rewrite the `SOC167` rule using strict Regular Expressions (Regex) to enforce word boundaries. 
   - **Current Logic:** `URL CONTAINS "ls"`
   - **Recommended Logic:** Use regex word boundaries `\bls\b` or look for command separators typically associated with injection, such as `;ls`, `|ls`, `&&ls`, or URL-encoded equivalents like `%20ls%20`.
2. **Alert Fatigue Review:** Audit other Command Injection rules (e.g., `cat`, `id`, `pwd`) to ensure they also utilize boundary enforcement, preventing similar False Positives.

## Evidence / Screenshots

<img width="915" height="412" alt="image" src="https://github.com/user-attachments/assets/d6ef6125-9386-4dc3-9a03-8f0750f084b5" />


## Skills & Tools Used
Log Analysis, SIEM Rule Tuning, Regular Expressions (Regex) Logic, False Positive Triage, Endpoint Behavior Correlation.
