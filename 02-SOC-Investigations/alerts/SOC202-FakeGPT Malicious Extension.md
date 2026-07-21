
# SOC202 - FakeGPT Malicious Chrome Extension — Case #153

## 🚨 Raw Alert Details
```text
EventID : 153
Event Time : May, 29, 2023, 01:01 PM
Rule : SOC202 - FakeGPT Malicious Chrome Extension
Level : Security Analyst
Hostname : Samuel
IP Address : 172.16.17.173
File Name : hacfaophiklaeolhnmckojjjjbnappen.crx
File Path : C:\Users\LetsDefend\Download\hacfaophiklaeolhnmckojjjjbnappen.crx
File Hash : 7421f9abe5e618a0d517861f4709df53292a5f137053a227bfb4eb8e152a4669
Command Line : chrome.exe --single-argument C:\Users\LetsDefend\Download\hacfaophiklaeolhnmckojjjjbnappen.crx
Trigger Reason : Suspicious extension added to the browser.
Device Action : Allowed
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Sysmon
- **Asset Affected:** Samuel (172.16.17.173)
- **Threat Type:** Malicious Browser Extension / InfoStealer / Session Hijacking
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding "FakeGPT" and Cookie Theft
Threat actors constantly adapt their lures to match trending technologies. The "FakeGPT" campaign relies on tricking users into installing a malicious Google Chrome extension (`.crx` file) that claims to integrate ChatGPT directly into their browser search results. 

**The Mechanics:** Browser extensions run with elevated permissions *within the context of the browser*. They do not need to exploit the underlying Windows OS. Once installed, a malicious extension like FakeGPT can read and modify all data on the websites a user visits. Its primary objective is to silently harvest authentication cookies (especially session tokens for high-value targets like ChatGPT, Google, or corporate portals). By stealing the active session cookie, the attacker can hijack the user's account from a remote machine, completely bypassing Multi-Factor Authentication (MFA) because the cookie acts as pre-authenticated proof of identity.

## Investigation Steps

### 1. Alert Triage and Execution Verification
The investigation began by verifying the execution of the flagged Chrome extension (`.crx`) on the endpoint `Samuel` (172.16.17.173).
- **Process Review:** The EDR Process logs confirmed that the user manually executed the extension file from their Desktop.
- **Command Line:** `"C:\Program Files\Google\Chrome\Application\chrome.exe" --single-argument C:\Users\LetsDefend\Desktop\hacfaophiklaeolhnmckojjjjbnappen.crx`
- **Analysis:** This confirms the extension was successfully sideloaded into the Chrome browser.

<img width="1192" height="357" alt="image" src="https://github.com/user-attachments/assets/933330c1-1664-46d4-813d-fddcfc84ec84" />


### 2. Browser History Correlation
To understand the context of the installation, the user's browser history was reviewed.
- **Timeline:** At `13:01:44`, the user navigated to the Chrome Webstore to view the extension (`hacfaophiklaeolhnmckojjjjbnappen`).
- **Warning:** At `13:01:47`, the user navigated to a Google Support page explaining a `crx_warning`. This indicates Chrome warned the user about installing an unverified or potentially dangerous extension, but the user ignored the warning and proceeded with the installation at `13:01:55` (`chrome://extensions`).
- **Post-Installation:** At `13:10:18`, the user navigated to `https://chat.openai.com/auth/login`. This is the exact moment the malicious extension would activate to harvest the authentication cookies.

<img width="1260" height="535" alt="image" src="https://github.com/user-attachments/assets/ce30c312-8acb-49b6-82d0-6ecdcfc96ecf" />


### 3. Command and Control (C2) Validation
To determine if the extension successfully exfiltrated data, network and Sysmon logs were correlated.
- **DNS Query (Sysmon Event ID 22):** At `13:02:47`, `chrome.exe` queried the domain `www.chatgptforgoogle.pro`, which resolved to `52.76.101.124`.
- **Network Action:** Immediately following the DNS resolution, a direct HTTP connection on Port 80 was established to `chatgptforgoogle.pro`.

<img width="650" height="387" alt="image" src="https://github.com/user-attachments/assets/70bdcb87-65b5-4d2c-b169-996fdf8b4afe" />

<img width="626" height="311" alt="image" src="https://github.com/user-attachments/assets/3fd9eeac-7d66-4100-a8cf-45be9773cdb9" />



### 4. Threat Intelligence Enrichment
The target domain (`chatgptforgoogle.pro`) was queried against VirusTotal.
- **Finding:** The domain was flagged by 7/91 security vendors as Malicious/Phishing. The use of a `.pro` Top Level Domain (TLD) mimicking a legitimate service is a classic typosquatting/impersonation tactic used for C2 infrastructure.

<img width="1332" height="701" alt="image" src="https://github.com/user-attachments/assets/6b047030-6bf5-49f1-ae2c-1f07367b7114" />


## Analysis and Findings
The incident is a confirmed **True Positive**. The user "Samuel" ignored browser security warnings and manually installed a malicious Chrome extension (`FakeGPT`). The EDR and Network logs confirm the extension successfully executed and immediately established an outbound connection to an attacker-controlled C2 domain (`chatgptforgoogle.pro`). Because the user subsequently logged into `chat.openai.com`, it is highly probable that their session cookies and authentication tokens were successfully exfiltrated. 

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1204.002 | User Execution: Malicious File (`.crx`) |
| **Persistence** | T1176 | Browser Extensions |
| **Credential Access** | T1539 | Steal Web Session Cookie |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Hash (SHA256) | `7421f9abe5e618a0d517861f4709df53292a5f137053a227bfb4eb8e152a4669` | Malicious Chrome Extension (`.crx`) |
| Extension ID | `hacfaophiklaeolhnmckojjjjbnappen` | Unique identifier for the malicious extension |
| Domain | `chatgptforgoogle.pro` | Attacker C2 / Exfiltration Domain |
| IP Address | 52.76.101.124 | IP hosting the C2 Domain |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Sideloaded Extensions):** Alert when `Image="*\chrome.exe" OR "*\msedge.exe"` AND `CommandLine Contains ".crx"`. Legitimate extensions are installed directly via the Webstore API; manual execution of `.crx` files via the command line is highly anomalous.
- **Detection 2 (High-Risk Domains):** Implement proxy alerts for newly registered domains (NRDs) containing the strings `chatgpt`, `openai`, or `ai` combined with non-standard TLDs (e.g., `.pro`, `.xyz`, `.top`).

## 🚀 Decision Tree for Browser Extension Alerts
1. **Verify Installation:** Did the user install the extension? Check EDR Process logs for `.crx` execution or Browser History for `chrome://extensions`.
   - *Confirmed manual installation despite warnings.*
2. **Identify Capabilities:** What does the extension do? (Requires OSINT or Sandbox analysis).
   - *Identified as an InfoStealer/Cookie Harvester.*
3. **Check Network Activity:** Did the browser reach out to an unknown/unusual domain immediately after installation?
   - *Confirmed C2 connection to `chatgptforgoogle.pro`.*
4. **Determine Impact:** Did the user log into any sensitive portals after the extension was active?
   - *Confirmed login to OpenAI.*
5. **Verdict: True Positive - Compromised (Data Leakage).**

## Response and Closure
- **Action Taken:** The host (`Samuel / 172.16.17.173`) was **Contained** via the Endpoint Security console to halt any further session token exfiltration. The malicious domain (`chatgptforgoogle.pro`) and IP were added to the perimeter blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised via malicious browser extension resulting in likely credential theft.

## Recommendations
1. **Force Extension Removal:** Utilize enterprise browser management (e.g., Google Admin Console or Intune) to forcefully remove the extension ID `hacfaophiklaeolhnmckojjjjbnappen` from all corporate browsers.
2. **Implement Extension Whitelisting:** Shift corporate browser policies from a "Blacklist" approach to a "Whitelist" approach. Users should only be permitted to install extensions that have been explicitly vetted and approved by the IT/Security team.
3. **Credential Reset & Token Revocation:** Samuel must reset his ChatGPT password. More importantly, he must actively terminate all active sessions within the OpenAI portal, as resetting a password does not always invalidate a stolen, active session cookie.

## 🛠️ Skills & Tools Used
- **EDR Browser Forensics:** Reconstructing user actions (warnings ignored, extension installation, target logins) via Browser History.
- **Sysmon Log Correlation:** Tracking DNS queries (Event ID 22) generated by `chrome.exe` to identify the C2 domain.
- **Threat Intelligence:** Utilizing VirusTotal to classify the C2 domain.
- **Identity and Access Management:** Understanding the mechanics of Cookie Theft and Session Hijacking to assess the true impact of the breach.
